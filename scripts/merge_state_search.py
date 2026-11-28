# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Merge recovery search reports offline, replaying discovery over recorded edges."""

from __future__ import annotations

import copy
import json
import re
import tempfile
from pathlib import Path
from collections import defaultdict
from types import SimpleNamespace

from audit_report import (
    compute_region_breakdown, compute_verdict, ownership_plan_for_report,
    qualify_ownership_verdict, summarize_runtime_sweep,
)
from fault_classification import (
    _effective_boot_result, result_is_infrastructure_error, result_is_skipped,
    result_is_timeout, result_issue_reasons,
)
from profile_loader import ExpectConfig
from recovery_search import RecoveryStateExplorer
from recovery_search_shard import chain_key, state_owner
from report_security_status import attach_security_aggregate


INPUTS = ("firmware_sha256", "profile_sha256", "tardigrade_revision", "renode_version", "shard_count")


def ordered_shards(reports):
    by_index = {}
    inputs = {}
    for report in reports:
        shard = report.get("state_search_shard")
        if not isinstance(shard, dict):
            raise ValueError("expected an audit report containing state_search_shard")
        index, count = shard.get("shard_index"), shard.get("shard_count")
        if type(count) is not int or count < 2 or type(index) is not int or not 0 <= index < count:
            raise ValueError(f"invalid shard_index {index} for shard_count {count}")
        for field in INPUTS:
            value = shard.get(field)
            if field != "shard_count" and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"shard {index} missing {field}")
            if field.endswith("sha256") and not re.fullmatch("[a-f0-9]{64}", value):
                raise ValueError(f"shard {index} invalid {field}")
            if field == "tardigrade_revision" and not re.fullmatch("[a-f0-9]{40}|(?:source-sha256:)?[a-f0-9]{64}", value):
                raise ValueError(f"shard {index} invalid {field}")
            if field in inputs and inputs[field] != value:
                raise ValueError(f"shard {index} mismatched {field}")
            inputs[field] = value
        if index in by_index:
            raise ValueError(f"duplicate shard {index}")
        if by_index:
            reference = next(iter(by_index.values()))["state_search_shard"]
            for field in ("max_cuts", "max_new_states", "cross_check_every", "report_context"):
                if shard.get(field) != reference.get(field):
                    raise ValueError(f"shard {index} mismatched {field}")
        by_index[index] = report
    if not by_index:
        raise ValueError("no shard reports")
    for index in range(inputs["shard_count"]):
        if index not in by_index:
            raise ValueError(f"missing shard {index}")
    return [by_index[i] for i in sorted(by_index)], inputs


class StateID(str):
    """The explorer only needs identity during offline traversal."""

    def identity_hex(self):
        return str(self)


def collect_edges(target, edges):
    for cut, identity in edges:
        if not isinstance(identity, str) or not re.fullmatch("[0-9a-f]{64}", identity):
            raise ValueError(f"invalid persistent state identity {identity!r}")
        op = {"kind": cut["operation"], "operation_index": cut["operation_index"],
              "sequence": cut["trace_sequence"], "offset": int(cut["address"], 16),
              "target": StateID(identity)}
        if target.setdefault(op["sequence"], op) != op:
            raise ValueError(f"conflicting trace operation at {cut['address']}")


def trace(edges):
    return tuple(edges[i] for i in sorted(edges))


class RecordedSearch(RecoveryStateExplorer):
    """Feed the original breadth-first traversal state IDs and observed boot results."""

    _normalize_trace = staticmethod(tuple)

    def __init__(self, reports):
        self.has_trace_counts = all("first_cut_traces" in r["summary"]["runtime_sweep"]["recovery_state_search"]
                                    for r in reports)
        self.trace_counts = {}
        self.missing = {}
        self.rows = {}
        self.edges = defaultdict(dict)
        self.filters = {}
        self.terminal = {}
        self.checks = {}
        self.stops = {}
        roots = {}
        for report in reports:
            part = report["state_search_shard"]
            index = part["shard_index"]
            summary = report["summary"]["runtime_sweep"]["recovery_state_search"]
            reason = summary["stopped_reason"]
            if reason != "complete":
                if reason not in ("max_new_states", "max_wall_time_s"):
                    raise ValueError(f"shard {index} has unknown stopped_reason {reason}")
                self.stops[index] = reason
            collect_edges(roots, part["roots"])
            for key, check in part["cross_checks"]:
                self.record_check(index, tuple(key), check)
            rows = [r for r in report["runtime_sweep_results"] if "recovery_state_search" in r]
            if len(rows) != summary["states_booted"]:
                raise ValueError(f"shard {index} is missing boot records")
            roots_by_cut = {chain_key(r["recovery_state_search"]["chain"]["cuts"]):
                            r["recovery_state_search"]["state_identity"] for r in rows
                            if r["recovery_state_search"]["generation"] == 1}
            for sizes in summary.get("first_cut_traces", ()):
                identity = roots_by_cut[chain_key([sizes["first_cut"]])]
                counts = (sizes["trace_operations"], sizes["generation_two_candidates"])
                if self.trace_counts.setdefault(identity, counts) != counts:
                    raise ValueError(f"shards disagree on first-cut trace counts for {identity}")
            for row in rows:
                self.record(row, part, report["expect"]["control_outcome"])
        self.count = len(reports)
        operations = trace(roots)
        super().__init__(
            initial_state=None, calibration_operations=operations,
            first_cuts=[(op["kind"], op["operation_index"]) for op in operations],
            max_cuts=part["max_cuts"], max_new_states=part["max_new_states"],
            max_wall_time_s=1, clock=lambda: 0, boot_state=self.read_boot,
            recovery_fault_types=("power_loss", "interrupted_erase"),
            cross_check_every=part.get("cross_check_every", 1),
        )

    def record_check(self, index, key, check):
        if not isinstance(check, dict) or check.get("matched") is not True or check.get("infrastructure_error"):
            raise ValueError(f"shard {index} has no positive cross-check evidence for {key}")
        self.checks[key] = check

    def record(self, row, part, expected):
        meta = row["recovery_state_search"]
        identity = meta["state_identity"]
        previous = self.rows.get(identity)
        if previous:
            def outcome(r):
                return (r.get("boot_outcome"), r.get("boot_slot"), _effective_boot_result(r),
                        r.get("fault_class"), result_is_infrastructure_error(r), result_is_timeout(r),
                        result_is_skipped(r), result_issue_reasons(r, expected))
            if outcome(previous) != outcome(row):
                raise ValueError(f"conflicting outcomes for state {identity} in shard {part['shard_index']}")
        def order(r):
            m = r["recovery_state_search"]
            return m["generation"], chain_key(m["chain"]["cuts"])
        if previous is None or order(row) < order(previous):
            self.rows[identity] = row
        for chain in [meta, *meta.get("equivalent_chains", [])]:
            if "cross_check" in chain:
                cuts = chain.get("chain", chain)["cuts"]
                self.record_check(part["shard_index"], chain_key(cuts), chain["cross_check"])
        if "shard_depth_excluded" in row:
            self.terminal[identity] = row["shard_depth_excluded"]
        expansion = row.get("shard_expansion")
        if expansion is not None:
            if meta["generation"] == 1 and any(
                state_owner(child, part["shard_count"]) != part["shard_index"]
                for _, child in expansion["edges"]
            ):
                raise ValueError(f"foreign generation-two candidate in shard {part['shard_index']}")
            collect_edges(self.edges[identity], expansion["edges"])
            collect_edges(self.edges[identity], expansion.get("peer_edges", []))
            # Overlapping boots see the same trace. A wall limit can leave
            # one runner with a shorter prefix of that trace.
            old_type, old_addr = self.filters.get(identity, (0, 0))
            self.filters[identity] = (max(old_type, expansion["excluded_by_fault_type"]),
                                      max(old_addr, expansion["excluded_by_address"]))

    def read_boot(self, state, chain, generation):
        local_fields = {"recovery_state_search_summary", "recovery_state_search",
                        "shard_expansion", "shard_depth_excluded"}
        row = {k: copy.deepcopy(v) for k, v in self.rows[state].items() if k not in local_fields}
        if generation == self.max_cuts:
            self.summary["recovery_operations_excluded_by_max_cuts"] += self.terminal.get(state, 0)
            return row, ()
        if state not in self.filters and "max_wall_time_s" not in self.stops.values():
            raise ValueError(f"missing expansion for state {state}")
        excluded_type, excluded_addr = self.filters.get(state, (0, 0))
        self.summary["recovery_operations_excluded_by_fault_type"] += excluded_type
        self.summary["recovery_operations_excluded_by_address"] += excluded_addr
        self.summary["recovery_operations_seen"] += excluded_type + excluded_addr
        return row, trace(self.edges[state])

    def _first_cut_traces(self, results):
        if self.has_trace_counts:
            return super()._first_cut_traces(results)
        return []

    def _trace_counts(self, index):
        identity = self.results[index]["recovery_state_search"]["state_identity"]
        return self.trace_counts[identity]

    def _expand(self, frames, selected, counts, preview=False):
        parent, index, _, _ = frames.popleft()
        operations, _ = self._source(parent)
        op = operations[index]
        if index + 1 < len(operations):
            frames.appendleft((parent, index + 1, None, 0))
        self._selected(op, parent is None, selected, counts)
        return parent, index, op["target"]

    def _boot(self, state, chain, generation, operation=None, cross_check_ordinal=None):
        if state not in self.rows:
            owner = state_owner(state, self.count)
            reason = self.stops.get(owner) if generation == 2 else None
            if not self.stops or (generation == 2 and reason is None):
                raise ValueError(f"missing boot result for state {state}")
            if state not in self.missing:
                reason = reason or ("max_wall_time_s" if "max_wall_time_s" in self.stops.values()
                                    else "max_new_states")
                field = ("states_excluded_by_wall_time" if reason == "max_wall_time_s"
                         else "states_excluded_by_max_new_states")
                self.summary[field] += 1
                self.missing[state] = reason
            return
        super()._boot(state, chain, generation, operation, cross_check_ordinal)

    def _maybe_cross_check(self, state, chain, generation, operation, selection_ordinal=None):
        selected = (
            int(selection_ordinal)
            if selection_ordinal is not None
            else self.summary["states_booted"] + 1
        )
        if (
            generation < 2
            or self.cross_check_every <= 0
            or selected % self.cross_check_every != 0
        ):
            return None
        check = self.checks.get(chain_key(chain))
        if check is None:
            if "max_wall_time_s" not in self.stops.values():
                raise ValueError(f"missing cross-check evidence for {chain_key(chain)}")
            return None
        self.summary["cross_checks_run"] += 1
        self.summary["cross_checks_passed"] += 1
        return check


def merge_reports(reports):
    reports, inputs = ordered_shards(reports)
    first = reports[0]
    search = RecordedSearch(reports)
    states, summary = search.run()
    if not search.has_trace_counts:
        summary.pop("first_cut_traces")
    local = [r["summary"]["runtime_sweep"]["recovery_state_search"] for r in reports]
    for key, value in local[0].items():
        if (key.startswith("calibration_") or key.endswith(("_out_of_range", "_selected"))
                or key in ("deferred_tracking_base", "recovery_tracking_start_address")):
            if any(s.get(key) != value for s in local[1:]):
                raise ValueError(f"shards disagree on {key}")
            summary[key] = value
    if "recovery_boots_reaching_deferred_gate" in local[0]:
        for reached, key in [(True, "recovery_boots_reaching_deferred_gate"),
                             (False, "recovery_boots_before_deferred_gate")]:
            summary[key] = sum(r.get("recovery_tracking_gate", {}).get("reached") is reached for r in states)
    if search.stops:
        summary["complete"] = False
        summary["unique_states_seen"] += len(search.missing)
        summary["stopped_reason"] = ("max_wall_time_s" if "max_wall_time_s" in search.stops.values()
                                     else "max_new_states")
    summary["elapsed_s"] = max(s["elapsed_s"] for s in local)
    if states:
        states[0]["recovery_state_search_summary"] = summary
    if any("is_control" in r for r in states):
        states.sort(key=lambda r: r.get("fault_at", -1) != 0)
    # Ordinary runtime points and the clean control are repeated on all shards.
    rows = [r for r in first["runtime_sweep_results"] if r.get("fault_type") != "rs"]
    rows = states + copy.deepcopy(rows)
    first_sweep = first["summary"]["runtime_sweep"]
    context = first["state_search_shard"]["report_context"]
    expect = ExpectConfig(**context["expect"])
    memory = SimpleNamespace(page_size=context["page_size"],
                             slots={k: SimpleNamespace(**v) for k, v in context["slots"].items()})
    sweep = summarize_runtime_sweep(
        rows, total_writes=context["total_writes"], profile=SimpleNamespace(memory=memory, expect=expect),
        planned_fault_types=context["planned_fault_types"],
        expected_fault_points=first["fault_points_tested"],
        expected_control_points=first_sweep["campaign_integrity"]["expected_control_points"],
        expected_outcome_override=expect.control_outcome,
        calibration_coverage=first_sweep.get("calibration_coverage"),
        calibration_point_coverage=context["calibration_point_coverage"],
        rc_injection_config_override=first.get("rc_injection_config"),
    )
    for key in ("configured_fault_types", "allowed_images", "compatibility_field_scopes"):
        if key in first_sweep:
            sweep[key] = first_sweep[key]
    regions = compute_region_breakdown(rows, expect.control_outcome)
    if regions:
        sweep["region_breakdown"] = regions
    sweep["point_counts"]["sources"] = ["runtime_sweep"]
    sweep["recovery_state_search"] = summary
    verdict = compute_verdict(sweep, expect)
    if summary["stopped_reason"] != "complete":
        sweep["campaign_complete"] = sweep["campaign_integrity"]["complete"] = False
        verdict = f"INCONCLUSIVE -- state search stopped on {summary['stopped_reason']}"
    report = {k: first[k] for k in ("profile", "schema_version", "expect", "git", "calibrated_writes",
                                     "calibrated_erases", "fault_points_tested", "fault_points_tested_scope",
                                     "calibration", "target_source", "security_policy", "contracts") if k in first}
    ownership = ownership_plan_for_report(first["summary"].get("ownership_layout"))
    report.update({
        "engine": "renode-test", "runtime_sweep_results": rows,
        "summary": {"runtime_sweep": sweep, "ownership_layout": ownership},
        "verdict": qualify_ownership_verdict(verdict, ownership),
        "state_search_merge": {**inputs, "stopped_shards": search.stops},
    })
    attach_security_aggregate(report)
    return report


def merge_files(paths, output):
    reports = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not an audit report")
        reports.append(data)
    try:
        result = merge_reports(reports)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError(f"malformed state search shard report ({exc})") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False, mode="w", encoding="utf-8") as stream:
        temporary = Path(stream.name)
        try:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.close()
            temporary.replace(output)
        finally:
            temporary.unlink(missing_ok=True)
