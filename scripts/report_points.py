# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Read point identities and verdicts from audit JSON without altering it."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from fault_classification import (
    _effective_boot_result, _effective_boot_signals, classify_failure_class, result_has_initial_timeout,
    result_is_brick, result_is_infrastructure_error, result_is_skipped,
    result_is_timeout, result_issue_reasons,
)
from fault_inject import encode_multi_fault_sequence
from fault_types import FAULT_TYPE_NAME_TO_CODE
from point_counts import build_point_counts, classify_point_kind

_CODE_NAMES = {code: name for name, code in FAULT_TYPE_NAME_TO_CODE.items()}
CAMPAIGNS = ("runtime_sweep_results", "multi_fault_results", "terminal_error_results")


def wire_point(row):
    code = str(row.get("fault_requested_type") or row.get("fault_type") or "w")
    if code == "mf" and row.get("fault_sequence"):
        code = encode_multi_fault_sequence(row["fault_sequence"], row.get("fault_stage_codes"))
    if code == "cascade" and row.get("cascade"):
        cascade = row["cascade"]
        code = f"c:{cascade['write_fault_at']}:{cascade['erase_fault_at']}"
    return {
        "FAULT_POINTS_CSV": str(row.get("fault_requested", row.get("fault_at", 0))),
        "FAULT_TYPE_CSV": code,
    }


def point_cuts(row):
    """Return the requested cut sequence as profile operation indices and names."""
    search = row.get("recovery_state_search") or {}
    chain = row.get("phase2_fault_chain") or {}
    cuts = (search.get("chain") or {}).get("cuts") or chain.get("requested_cuts") or chain.get("cuts")
    if cuts:
        result = []
        for cut in cuts:
            fault = cut.get("fault_type") or ("e" if cut.get("operation") == "erase" else "w")
            result.append([cut.get("operation_index", cut.get("fault_at")), _CODE_NAMES.get(fault, fault)])
        return result
    pair = row.get("phase2_fault") or {}
    if "p2_fault_at" in pair:
        return [[pair.get(prefix + "_fault_at", row.get("fault_at")),
                 _CODE_NAMES.get(pair.get(prefix + "_fault_type", "w"),
                                 pair.get(prefix + "_fault_type"))] for prefix in ("p1", "p2")]
    return []


def reproduction(row):
    if row.get("is_control"):
        return {"FAULT_AT": "-1"}
    cuts = point_cuts(row)
    if len(cuts) >= 2:
        phase2 = {"enabled": True}
        if len(cuts) == 2:
            phase2.update(first_fault_types=[cuts[0][1]], fault_types=[cuts[1][1]],
                          pairs=[[cuts[0][0], cuts[1][0]]])
        else:
            phase2["chains"] = [cuts]
        sweep = {"phase2_fault": phase2}
        if cuts[0][1] == "interrupted_erase":
            sweep["include_erase_fault_points"] = True
        return {"fault_sweep": sweep}
    if cuts:
        index, name = cuts[0]
        return {"FAULT_POINTS_CSV": str(index), "FAULT_TYPE_CSV": FAULT_TYPE_NAME_TO_CODE[name]}
    return wire_point(row)


def point_label(row):
    if row.get("is_control"):
        return "clean control"
    cuts = point_cuts(row)
    if cuts:
        label = " → ".join(f"{name}[{index}]" for index, name in cuts)
        search = row.get("recovery_state_search") or {}
        if search:
            label += f" (state {search.get('state_identity', '?')}, generation {search.get('generation', 1)})"
        return label
    point = wire_point(row)
    return f"{point['FAULT_TYPE_CSV']}[{point['FAULT_POINTS_CSV']}]"


def _seconds(value, divisor=1):
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0:
        return value / divisor
    return None


def point_time(row):
    signals = row.get("signals") or {}
    if (total := _seconds(signals.get("total_ms"), 1000)) is not None:
        return total + (_seconds(signals.get("followup_ms"), 1000) or 0)
    cycles = row.get("boot_cycles") or ()
    cycle0 = (cycles[0].get("signals") or {}) if cycles and isinstance(cycles[0], dict) else {}
    phase1 = signals.get("phase1_ms") if "phase1_ms" in signals else cycle0.get("phase1_ms")
    parts = [
        phase1,
        *(signals.get(k) for k in ("phase2_ms", "phase3_ms", "hook_ms", "confirm_ms",
                                   "final_boot_ms", "multi_fault_recovery_ms", "followup_ms")),
        *(signals.get("cut_ms") or ()),
        *((s.get("signals") or {}).get("stage_ms") for s in (row.get("per_fault_states") or ()) if isinstance(s, dict)),
    ]
    if ms := sum(v for p in parts if (v := _seconds(p)) is not None):
        return ms / 1000
    for source, key in (
        (row, "elapsed_s"),
        (row.get("phase2_fault_chain") or {}, "elapsed_s"),
        (row.get("phase2_fault") or {}, "elapsed_s"),
        (row.get("cascade") or {}, "elapsed_s"),
        (row.get("hook_fault") or {}, "elapsed_s"),
        (signals, "sequence_elapsed_s"),
        (signals, "timed_reset_elapsed_s"),
    ):
        if (elapsed := _seconds(source.get(key))) is not None:
            return elapsed
    if cycle_s := sum(v for c in cycles if isinstance(c, dict) and (v := _seconds(c.get("elapsed_s"))) is not None):
        return cycle_s
    for record in (row.get("per_component") or {}).values():
        if isinstance(record, dict) and (elapsed := point_time(record)) is not None:
            return elapsed
    return None


def suite_time(run, case_times=()):
    summary = run.data.get("summary") or {}
    campaigns = [
        _seconds(section.get("wall_time_s")) or _seconds(section.get("elapsed_s"))
        for name in ("runtime_sweep", "multi_fault_runtime_sweep", "terminal_error_campaign", "combined")
        if isinstance(section := summary.get(name), dict)
    ]
    if total := sum(v for v in campaigns if v is not None):
        return total
    for source, key, divisor in (
        (summary.get("recovery_state_search") or {}, "elapsed_s", 1),
        (((summary.get("runtime_sweep") or {}).get("timing") or {}).get("totals") or {}, "total_ms", 1000),
        (summary, "wall_time_s", 1),
        (summary, "elapsed_s", 1),
        (run.data, "wall_time_s", 1),
        (run.data, "elapsed_s", 1),
    ):
        if (elapsed := _seconds(source.get(key), divisor)) is not None:
            return elapsed
    if run.components:
        if total := sum(v for c in run.components if (v := suite_time(c)) is not None):
            return total
    if total := sum(v for v in case_times if v is not None):
        return total
    return None


def point_status(row):
    outcome, _ = _effective_boot_result(row)
    if result_is_infrastructure_error(row):
        return "error", str(row.get("error") or row.get("error_kind") or "infrastructure error")
    if result_has_initial_timeout(row):
        return "skipped", "initial boot timed out"
    if result_is_skipped(row) or (not row.get("is_control") and row.get("fault_injected") is not True):
        return "skipped", str(row.get("skip_reason") or "fault was not injected")
    if outcome in ("unknown", "inconclusive"):
        return "skipped", str(outcome)
    return "", ""


@dataclass(frozen=True)
class Finding:
    rule: str
    subject: str
    message: str


def point_findings(row, expected, campaign):
    outcome, _ = _effective_boot_result(row)
    if campaign == "terminal_error_results":
        reasons = ["terminal_error_path_escape"] if (row.get("signals") or {}).get("terminal_error_escaped") else []
    else:
        reasons = result_issue_reasons(row, expected)
    for reason in reasons:
        if reason == "boot_outcome":
            rule = classify_failure_class(row)
            if rule == "unrecoverable" and result_is_brick(row):
                rule = "brick"
            if row.get("severity") == "security_bypass":
                rule = "security_bypass"
            yield Finding(rule, str(outcome), f"{rule}: observed {outcome}, expected {expected}")
        elif reason == "memory_check" and _effective_boot_signals(row).get("failed_memory_checks"):
            for check in _effective_boot_signals(row)["failed_memory_checks"]:
                identity = f"{check.get('index')} @ {check.get('address', '?')}"
                yield Finding(reason, identity, check.get("summary") or identity)
        elif reason in ("invariant", "semantic_assertion", "metadata_delta"):
            field = {"invariant": "invariant_violations", "semantic_assertion": "semantic_assertion_failures",
                     "metadata_delta": "metadata_delta_violations"}[reason]
            for item in row[field]:
                if not isinstance(item, dict):
                    yield Finding(reason, str(item), str(item))
                    continue
                rule = item.get("finding_category") or reason
                subject = " ".join(str(item[key]) for key in ("scope", "name", "finding", "path", "field") if item.get(key))
                detail = item.get("description") or json.dumps(item, sort_keys=True)
                yield Finding(rule, subject, f"{subject}: {detail}" if subject else detail)
        else:
            yield Finding(reason, "", reason.replace("_", " "))


@dataclass
class Point:
    kind: str
    name: str
    row: dict
    status: str
    message: str
    findings: list[Finding]
    selector: dict | None = None
    component: str | None = None
    elf: Path | None = None


@dataclass
class ReportRun:
    data: dict
    name: str
    profile_path: Path | None = None
    elf: Path | None = None

    components: tuple[ReportRun, ...] = ()

    @cached_property
    def counts(self):
        summary = self.data.get("summary") or {}
        recorded = (summary.get("runtime_sweep") or summary.get("combined") or {}).get("point_counts")
        if recorded:
            return recorded
        expected = (self.data.get("expect") or {}).get("control_outcome") or "success"
        rows = [r for c in CAMPAIGNS for r in self.data.get(c, [])]
        terminal = {id(r) for r in self.data.get("terminal_error_results", [])}

        def has_issue(row):
            if id(row) in terminal:
                return bool((row.get("signals") or {}).get("terminal_error_escaped"))
            return bool(result_issue_reasons(row, expected))

        return build_point_counts(rows, expected_control_points=sum(bool(r.get("is_control")) for r in rows),
                                  issue_predicate=has_issue, first_cut_states=self.data.get("first_cut_states"))

    def points(self):
        for component in self.components:
            for point in component.points():
                point.name = f"{component.name} / {point.name}"
                point.component = component.name
                point.elf = component.elf
                yield point
        expected = (self.data.get("expect") or {}).get("control_outcome") or "success"
        kinds = self.counts["kinds"]
        for campaign in CAMPAIGNS:
            for index, row in enumerate(self.data.get(campaign, [])):
                kind = classify_point_kind(row)
                # Older pair records only identify their selection in the counts.
                if (kind == "two_cut_grid" and not kinds.get("two_cut_grid", {}).get("run")
                        and kinds.get("two_cut_pairs", {}).get("run")):
                    kind = "two_cut_pairs"
                status, message = point_status(row)
                findings = [] if status else list(point_findings(row, expected, campaign))
                if findings:
                    status = "failure"
                    message = "; ".join(f.message for f in findings)
                elif not status and (result_is_timeout(row) or row.get("semantic_observation_failures")):
                    status, message = "skipped", "incomplete follow-up or semantic observation"
                name = f"{campaign.removesuffix('_results')} #{index + 1} {point_label(row)}"
                yield Point(kind, name, row, status, message, findings)
        if not self.components and self.data.get("multi_component"):
            yield from self.saved_component_points()
        if not any(key in self.data for key in (*CAMPAIGNS, "combined_results")) and not self.components:
            verdict = str(self.data.get("verdict", ""))
            if self.data.get("error") or verdict.startswith("INCONCLUSIVE"):
                message = str(self.data.get("error") or verdict)
                yield Point("infrastructure", "audit setup", {}, "error", message, [])

    def saved_component_points(self):
        # Combined JSON stores the reliable point observations and observed
        # controls. The live writer additionally has the complete raw sweeps.
        for component, row in (self.data.get("control_state") or {}).items():
            yield self._combined_point({**row, "is_control": True}, component)
        for row in self.data.get("combined_results", []):
            yield self._combined_point(row, row["faulted_component"])

    def _combined_point(self, row, component):
        record = (row.get("per_component") or {}).get(component, row)
        findings = []
        if row.get("component_reliable") and row.get("component_issue") and not row.get("non_reportable"):
            for reason in row.get("component_issue_reasons", []):
                rule = (row.get("fault_class") or record.get("boot_outcome")) if reason == "boot_outcome" else reason
                findings.append(Finding(rule or reason, component, str(record.get("boot_outcome") or reason)))
        status = "failure" if findings else ("" if row.get("reliable") else "skipped")
        message = ", ".join(f.message for f in findings) or ("incomplete component observation" if status else "")
        return Point(classify_point_kind(row), f"{component} / {point_label(row)}", row, status, message,
                     findings, component=component)

    def additional_findings(self):
        """Finding-bearing evidence outside the canonical runtime point counts."""
        for row in self.data.get("partial_staging_results", []):
            rule = row["classification"]
            if rule in ("brick", "wrong_image", "partial_image_booted"):
                offset = row["truncation_point"]["offset"]
                yield Point("partial_staging", f"staging prefix {offset}", row, "failure", rule,
                            [Finding(rule, "", rule)], {"fault_sweep": {"partial_staging": {"truncation_points": "explicit", "offsets": [offset]}}})
        for row in self.data.get("state_fuzz_results", []):
            if row.get("finding"):
                findings = [Finding(reason, "", reason) for reason in row["issue_reasons"]]
                index = row["scenario_index"]
                yield Point("state_fuzz", f"state fuzz scenario {index}", row, "failure", "", findings,
                            {key: row[key] for key in ("scenario_index", "mode", "crc_mode", "field_values", "blob_sha256")})
        for row in self.data.get("fuzz_crash_results", []):
            if row.get("security_finding"):
                yield Point("fuzz_crash", row["generated_profile"], row, "failure", "",
                            [Finding("fuzz_crash", row["sha256"], str(row["verdict"]))],
                            {"profile": row["generated_profile"], "crash_file": row["crash_file"], "sha256": row["sha256"]})
        for row in (self.data.get("authorization_review_analysis") or {}).get("findings", []):
            if row.get("severity") != "configuration":
                evidence = row.get("evidence") or {}
                yield Point("authorization_review", row["sequence"], row, "failure", row["message"],
                            [Finding(row["id"], evidence.get("field", ""), row["message"])],
                            {"sequence": row["sequence"], "model_digest": evidence.get("model_digest")})
        combined = self.data.get("combined_results", [])
        control = self.data.get("control_combined_result")
        for row in [*combined, *([control] if control else [])]:
            if row.get("reliable") and row.get("security_issue"):
                for source in row.get("issue_sources", []):
                    if source in ("combined_outcome", "state_relation"):
                        rule = row["combined_outcome"] if source == "combined_outcome" else source
                        component = row.get("faulted_component", "control")
                        yield Point("multi_component", point_label(row), row, "failure", rule,
                                    [Finding(rule, component, rule)], component=component)
