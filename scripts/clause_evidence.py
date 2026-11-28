# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Project captured audit evidence onto clause selectors without running firmware."""

from collections import Counter
from dataclasses import dataclass
from html import escape

from audit_report import _campaign_integrity_gate_reason
from clause_mapping import load_mapping, profile_label, validate_mapping
from fault_classification import (
    _effective_boot_result, _effective_boot_signals, is_resilient_rollback,
    result_has_issues, result_is_timeout,
)
from report_points import point_cuts, point_status
from report_security_status import _runtime_incomplete_reasons

LIMIT = ("Emulation only. Observations cover the selected firmware, model, inputs and "
         "fault points. Hardware behaviour, product scope and regulatory applicability "
         "require independent assessment.")
CAMPAIGNS = {
    "runtime_sweep": "runtime_sweep_results",
    "multi_fault_runtime_sweep": "multi_fault_results",
}


def _interrupted(row):
    cuts = point_cuts(row)
    if cuts:
        return all(fault in {"power_loss", "interrupted_erase", "reset_at_time"} for _, fault in cuts)
    return row.get("fault_type") in {"w", "e", "t", "power_loss", "interrupted_erase", "reset_at_time"}


def _observations(row):
    """Require an observed result as well as a configured success criterion."""
    config = row.get("effective_success_criteria")
    config = config if isinstance(config, dict) else {}
    signals = _effective_boot_signals(row)
    observed = {}
    if config.get("vtor_slot") and type(signals.get("vtor_ok")) is bool:
        observed["boot_handoff"] = "criterion_met" if signals["vtor_ok"] else "criterion_failed"

    running = signals.get("approved_image_running") or {}
    if config.get("approved_image_running") and isinstance(running, dict) and type(running.get("ok")) is bool:
        observed["running_image"] = "matched" if running["ok"] else "criterion_failed"
        digest = running.get("digest") or {}
        if isinstance(digest, dict) and digest.get("observed_sha256") and type(digest.get("ok")) is bool:
            observed["image_digest"] = "reference_match" if digest["ok"] else "reference_check_failed"
    if config.get("image_hash") is True and signals.get("image_hash_actual"):
        match = signals.get("image_hash_match")
        if match in {"exec_image", "staging_image", "expected_image", "unknown"}:
            observed["image_digest"] = match if match != "unknown" else "outside_reference_set"

    probes = signals.get("verification_probes")
    if isinstance(probes, dict):
        reached = [p for p in probes.values() if isinstance(p, dict) and p.get("reached") is True]
        if reached:
            # The runtime initializes the flags to false before a probe returns.
            observed["verification_probe"] = "reached"
            returned = [p for p in reached if p.get("first_return_value") is not None]
            if any(p.get("first_bypassed") is True for p in returned):
                observed["verification_probe"] = "configured_success_return"
            elif len(returned) == len(reached) and all(p.get("first_bypassed") is False for p in returned):
                observed["verification_probe"] = "other_return"
    return observed


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _coverage(sweep):
    counts = sweep.get("point_counts") or {}
    coverage = {}
    for operation, values in (counts.get("calibration") or {}).items():
        if operation in {"program", "erase"} and isinstance(values, dict):
            coverage[operation] = {
                field: values[field] for field in (
                    "calibrated", "cut_directly", "represented_without_cut",
                    "not_cut_or_represented", "outside_planned_range",
                ) if _count(values.get(field)) is not None
            }
    search = sweep.get("recovery_state_search")
    if isinstance(search, dict):
        coverage["state_search"] = {
            field: search[field] for field in (
                "states_booted", "states_reused", "states_excluded_by_max_new_states",
                "states_excluded_by_wall_time", "states_excluded_by_coverage_plateau",
            ) if _count(search.get(field)) is not None
        }
    return coverage


@dataclass
class Campaign:
    requested: int | None
    fault_rows: list
    coverage: dict
    gaps: list[str]


def _read_campaign(report, name):
    sweep = (report.get("summary") or {}).get(name) or {}
    integrity = sweep.get("campaign_integrity") or {}
    raw = report.get(CAMPAIGNS[name])
    rows = raw if isinstance(raw, list) else []
    fault_rows = [r for r in rows if isinstance(r, dict) and not r.get("is_control")]
    requested = _count(integrity.get("requested", sweep.get("requested_fault_points")))
    gaps = []
    if report.get("error") or str(report.get("verdict") or "").upper().startswith("INCONCLUSIVE"):
        gaps.append("Report records an error or an inconclusive run.")
    if not isinstance(raw, list) and not sweep:
        gaps.append("Campaign absent from the report.")
    else:
        if not isinstance(raw, list) or any(not isinstance(r, dict) for r in rows):
            gaps.append("Point records missing or malformed.")
        if integrity.get("planner_count_supplied") is not True:
            gaps.append("Independent planned fault count unavailable.")
        try:
            search = sweep.get("recovery_state_search") or {}
            reason = _campaign_integrity_gate_reason(sweep)
            if search.get("complete") is False:
                stopped = search.get("stopped_reason")
                if stopped in {"max_new_states", "max_wall_time_s", "coverage_plateau"}:
                    gaps.append(f"Recovery state search stopped at {stopped}.")
                else:
                    gaps.append("Recovery state search is incomplete.")
            elif reason:
                gaps.append(reason)
            else:
                # Older reports can record a failure only in the summary counters.
                reasons = _runtime_incomplete_reasons(sweep, name)
                if reasons:
                    gaps.append(reasons[0])
                elif sweep.get("campaign_complete") is not True or integrity.get("complete") is not True:
                    gaps.append("Campaign completeness unavailable.")
        except (TypeError, ValueError):
            gaps.append("Malformed campaign accounting.")
        control_count = sum(isinstance(row, dict) and bool(row.get("is_control")) for row in rows)
        if integrity.get("control_points") != control_count or any(
            isinstance(row, dict) and row.get("is_control") and row.get("fault_injected") is True for row in rows
        ):
            gaps.append("Observed controls disagree with the campaign accounting.")
        if requested != len(fault_rows):
            gaps.append("Observed fault records do not account for the requested plan.")
        if (report.get("execution") or {}).get("slice_count"):
            gaps.append("Merged records have no independent completeness check across source plans.")
        errors = 0
        unresolved = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            status, _ = point_status(row)
            if status == "error":
                errors += 1
            elif status or result_is_timeout(row) or row.get("semantic_observation_failures"):
                unresolved += 1
        if errors:
            gaps.append(f"Infrastructure errors in {errors} returned records.")
        if unresolved:
            gaps.append(f"Skipped or inconclusive observations in {unresolved} returned records.")
    return Campaign(requested, fault_rows, _coverage(sweep), gaps)


def _select(campaign, clause, name, expected):
    gaps = campaign.gaps.copy()
    evaluated = 0
    verdicts = Counter()
    outcomes = Counter()
    criteria = {key: Counter() for key in clause["criteria"]}
    if not gaps:
        for row in campaign.fault_rows:
            if clause["fault_scope"] == "interruption" and not _interrupted(row):
                continue
            measured = _observations(row)
            selected = criteria.keys() & measured.keys()
            if not selected:
                continue
            evaluated += 1
            for key in selected:
                criteria[key][measured[key]] += 1
            verdicts["finding" if result_has_issues(row, expected) else "observation"] += 1
            outcome, _ = _effective_boot_result(row)
            if is_resilient_rollback(row):
                outcome = "resilient_rollback"
            outcomes[profile_label(outcome)] += 1
        if not evaluated:
            gaps.append("No fault point with a selected observation.")
    return {
        "campaign": name, "requested_fault_points": campaign.requested, "returned_fault_points": len(campaign.fault_rows),
        "points_evaluated": evaluated, "returned_points_omitted": len(campaign.fault_rows) - evaluated,
        "verdicts": dict(verdicts), "boot_outcomes": dict(outcomes),
        "criteria": {key: dict(values) for key, values in criteria.items()},
        "absent_criteria": [key for key, values in criteria.items() if not values],
        "campaign_coverage": campaign.coverage, "gaps": gaps,
    }


def clause_evidence(report, mapping=None):
    """Build a section from a report and a validated mapping."""
    if mapping is None and "clause_evidence" in report:
        # Re-evaluate stored selectors, never trust observations or HTML from a file.
        stored = report["clause_evidence"]
        mapping = {"schema_version": stored["schema_version"], "mapping_version": stored["mapping_version"],
                   "clauses": [item["definition"] for item in stored["clauses"]]}
    mapping = load_mapping() if mapping is None else validate_mapping(mapping)
    selected_campaigns = {name for clause in mapping["clauses"] for name in clause["campaigns"]}
    campaigns = {name: _read_campaign(report, name) for name in selected_campaigns}
    expected = (report.get("expect") or {}).get("control_outcome") or "success"
    clauses = []
    for clause in mapping["clauses"]:
        title = f'evidence relevant to {clause["regulation"]}, {clause["paragraph"]}'
        clauses.append({
            "title": title, "definition": clause,
            "campaigns": [_select(campaigns[name], clause, name, expected) for name in clause["campaigns"]],
        })
    used = {CAMPAIGNS[name] for name in campaigns}
    omitted = sorted(key for key in (
        *CAMPAIGNS.values(), "combined_results", "initial_state_results", "boundary_campaign_results",
        "terminal_error_results", "partial_staging_results", "fuzz_crash_results", "state_fuzz_results",
    ) if key in report and key not in used)
    return {
        "unmapped_campaigns": omitted,
        "schema_version": 1, "mapping_version": mapping["mapping_version"],
        "profile": profile_label(report.get("profile")), "limit": LIMIT, "clauses": clauses,
    }


def _counts(counts):
    return ", ".join(f"{escape(key)} {value:d}" for key, value in counts.items()) or "none"


def clause_html(section):
    parts = ["<section><h3>Software update clause evidence</h3>",
             f'<p>Profile <code>{escape(section["profile"])}</code> · Mapping {section["mapping_version"]:d}</p>',
             f'<p>{escape(section["limit"])}</p>']
    if section["unmapped_campaigns"]:
        parts.append("<p>Report records outside this mapping · "
                     + ", ".join(escape(key) for key in section["unmapped_campaigns"]) + "</p>")
    for clause in section["clauses"]:
        definition = clause["definition"]
        parts.extend([f'<h4>{escape(clause["title"])}</h4>',
                      f'<p>{escape(definition["paraphrase"])} <a href="{escape(definition["citation"], quote=True)}">Official text</a></p>',
                      f'<p>Scope <code>{escape(definition["fault_scope"])}</code>. {escape(definition["limit"])}</p>'])
        for campaign in clause["campaigns"]:
            planned = campaign["requested_fault_points"]
            parts.append(f'<h5>{escape(campaign["campaign"])}</h5><p>'
                         f'{campaign["points_evaluated"]:d} points evaluated for this clause. '
                         f'Campaign requested {planned if planned is not None else "unknown"}, '
                         f'returned {campaign["returned_fault_points"]:d}, '
                         f'omitted from clause evidence {campaign["returned_points_omitted"]:d}.</p>')
            parts.append(f'<p>Point verdicts · {_counts(campaign["verdicts"])}<br>'
                         f'Boot outcomes · {_counts(campaign["boot_outcomes"])}</p><ul>')
            for key, counts in campaign["criteria"].items():
                label = _counts(counts) if counts else "no observation"
                parts.append(f"<li>{escape(key)} · {label}</li>")
            parts.append("</ul>")
            coverage = campaign["campaign_coverage"]
            if not coverage:
                parts.append("<p>Campaign calibration coverage unavailable.</p>")
            for op, counts in coverage.items():
                parts.append(f"<p>Campaign {escape(op)} coverage · {_counts(counts)}</p>")
            for gap in campaign["gaps"]:
                parts.append(f"<p>Gap · {escape(gap)}</p>")
    parts.append("</section>")
    return "".join(parts)
