"""Normalize security findings and campaign reliability across audit reports.

``audit_bootloader`` emits several report layouts: ordinary runtime sweeps,
multi-component sweeps, initial-state matrices, and early preflight failures.
This module is the single accounting boundary used both when the report is
written and when the GitHub Action publishes its status.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, MutableMapping, Sequence, Set, Tuple

from verdicts import (
    EXPECTATION_MODES,
    expectation_mode,
    expectation_requires_findings,
    is_pass_verdict,
)
from fault_types import _fault_type_label


SECURITY_AGGREGATE_VERSION = 1
SECURITY_STATUSES = {"CLEAN", "FINDINGS", "INCONCLUSIVE"}

_KNOWN_SUMMARY_SECTIONS = {
    "combined",
    "fuzz_crash",
    "geometry_preflight",
    "initial_states",
    "multi_fault_plan",
    "multi_fault_runtime_sweep",
    "partial_staging",
    "per_component",
    "persistent_state_layout",
    "runtime_sweep",
    "security_state_erase",
    "state_fuzz",
    "swap_progress_inference",
    "terminal_error_campaign",
    "terminal_error_paths",
    "trigger_discovery",
}


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("{} must be an object".format(context))
    return value


def _nonnegative_int(
    container: Mapping[str, Any],
    name: str,
    *,
    context: str,
    default: int = 0,
) -> int:
    value = container.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("{} {} must be a non-negative integer".format(context, name))
    return value


def _collection_count(value: Any, context: str) -> int:
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ValueError("{} must be a list or non-negative integer".format(context))


def _normalise_outcome(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def _classify_combined_outcome(outcomes: Mapping[str, Any]) -> str:
    """Mirror the producer's combined-outcome classifier for validation."""
    if not outcomes:
        return "unknown"
    values = {_normalise_outcome(value) for value in outcomes.values()}
    success = values == {"success"}
    brick = {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}
    all_failed = all(value in brick or value == "wrong_image" for value in values)
    any_success = "success" in values
    any_failed = any(value in brick or value == "wrong_image" for value in values)
    if success:
        return "success"
    if all_failed:
        return "all_failed"
    if any_success and any_failed:
        return "split_brain"
    return "degraded"


def _relation_findings(value: Any, context: str) -> Tuple[List[Mapping[str, Any]], List[Mapping[str, Any]]]:
    """Split genuine relation violations from explicit evaluation errors."""
    if value is None:
        return [], []
    violations = value if isinstance(value, list) else None
    if violations is None:
        raise ValueError("{} must be a list".format(context))
    findings: List[Mapping[str, Any]] = []
    errors: List[Mapping[str, Any]] = []
    for index, item in enumerate(violations):
        item = _mapping(item, "{}[{}]".format(context, index))
        name = str(item.get("name") or "")
        if name == "state_relations":
            findings.append(item)
        elif name in {"state_relations_error", "state_relations_infrastructure_error"} or item.get("infrastructure_error") is True:
            errors.append(item)
        else:
            raise ValueError("{}[{}] has unsupported relation evidence".format(context, index))
    return findings, errors


def _rate(value: Any, context: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
        or value > 1
    ):
        raise ValueError("{} must be between 0 and 1".format(context))
    return float(value)


def _record_findings(
    state: MutableMapping[str, Any], source: str, count: int
) -> None:
    if count <= 0:
        return
    state["issue_points"] += count
    sources = state["finding_sources"]
    sources[source] = int(sources.get(source, 0)) + count


def _record_inconclusive(state: MutableMapping[str, Any], reason: str) -> None:
    reasons: List[str] = state["inconclusive_reasons"]
    if reason not in reasons:
        reasons.append(reason)


def _runtime_incomplete_reasons(
    runtime: Mapping[str, Any], source: str
) -> List[str]:
    reasons: List[str] = []
    if runtime.get("campaign_complete") is False:
        reasons.append("{} campaign is incomplete".format(source))
    integrity = runtime.get("campaign_integrity")
    if integrity is not None:
        integrity = _mapping(integrity, "{} campaign_integrity".format(source))
        if integrity.get("complete") is False:
            reasons.append("{} campaign integrity is incomplete".format(source))
    for key in (
        "infrastructure_error_points",
        "timeout_points",
        "missing_result_points",
        "extra_result_points",
        "malformed_result_points",
        "control_infrastructure_error_points",
        "control_timeout_points",
        "control_skipped_points",
        "malformed_control_points",
        "faulted_control_points",
        "skipped_fault_points",
        "terminal_error_unresolved_points",
    ):
        if key in runtime and _nonnegative_int(runtime, key, context=source) > 0:
            reasons.append("{} reports {}".format(source, key))
    return reasons


def _collect_runtime(
    state: MutableMapping[str, Any],
    runtime_value: Any,
    source: str,
    *,
    record_findings: bool = True,
) -> Tuple[int, int]:
    runtime = _mapping(runtime_value, source)
    if "issue_points" in runtime:
        issues = _nonnegative_int(runtime, "issue_points", context=source)
    else:
        issues = _nonnegative_int(runtime, "bricks", context=source)

    # ``summarize_runtime_sweep`` historically included injected runner
    # failures in ``issue_points`` because their synthetic ``infra_error``
    # outcome differs from the expected boot outcome.  Those observations are
    # not trustworthy security findings.  Prefer the emitted overlap count;
    # for older reports, subtract the maximum possible overlap so an
    # infrastructure-only run remains inconclusive instead of being promoted
    # to FINDINGS.
    unreliable_issue_points = 0
    failure_outcomes = runtime.get("failure_outcomes")
    if failure_outcomes is not None:
        failure_outcomes = _mapping(
            failure_outcomes, "{} failure_outcomes".format(source)
        )
        unreliable_issue_points = sum(
            _nonnegative_int(
                failure_outcomes,
                key,
                context="{} failure_outcomes".format(source),
            )
            for key in ("infra_error", "timeout")
            if key in failure_outcomes
        )
    else:
        unreliable_issue_points = min(
            issues,
            sum(
                _nonnegative_int(runtime, key, context=source)
                for key in ("infrastructure_error_points", "timeout_points")
                if key in runtime
            ),
        )
    fault_issues = max(0, issues - min(issues, unreliable_issue_points))

    control = runtime.get("control")
    control_issues = 0
    if control is not None:
        control = _mapping(control, "{} control".format(source))
        reported_control_issues = _nonnegative_int(
            control, "issue_count", context="{} control".format(source)
        )
        unreliable_control = any(
            _nonnegative_int(runtime, key, context=source) > 0
            for key in (
                "control_infrastructure_error_points",
                "control_timeout_points",
                "control_skipped_points",
                "malformed_control_points",
                "faulted_control_points",
            )
            if key in runtime
        )
        if not unreliable_control:
            # A control summary describes one observed control point even if
            # several assertions failed at that point.
            control_issues = int(reported_control_issues > 0)
    if record_findings:
        _record_findings(state, source, fault_issues + control_issues)

    bypasses = _nonnegative_int(
        runtime, "security_bypass_points", context=source
    )
    state["security_bypass_points"] += bypasses
    if bypasses:
        bypass_sources = state["security_bypass_sources"]
        bypass_sources[source] = int(bypass_sources.get(source, 0)) + bypasses

    if "brick_rate" in runtime:
        state["brick_rates"].append(_rate(runtime["brick_rate"], "{} brick_rate".format(source)))
    for reason in _runtime_incomplete_reasons(runtime, source):
        _record_inconclusive(state, reason)
    return fault_issues, control_issues


_TRACE_COVERAGE_FAULT_TYPES = frozenset(
    {
        "interrupted_erase",
        "multi_sector_atomicity",
        "power_loss",
        "security_state_erase",
        "swap_progress",
    }
)


def _configured_fault_types(summary: Mapping[str, Any]) -> Optional[Set[str]]:
    """Read explicit selector metadata when the producer emitted it."""
    runtime = summary.get("runtime_sweep")
    if not isinstance(runtime, dict):
        return None
    raw = runtime.get("configured_fault_types")
    if raw is None:
        raw = runtime.get("fault_types")
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("summary.runtime_sweep configured fault types must be a list")
    normalized: Set[str] = set()
    for value in raw:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "summary.runtime_sweep configured fault types must contain non-empty strings"
            )
        text = value.strip().lower()
        label = _fault_type_label(text).strip().lower()
        normalized.add(label or text.split(":", 1)[0])
    return normalized


def _coverage_check_required(
    summary: Mapping[str, Any], check: str
) -> bool:
    """Tell optional coverage apart from a required-but-missing check.

    Current producers emit selector metadata.  For older complete runtime
    summaries, absence of that metadata means optional coverage; an orphan
    coverage section without a runtime campaign remains inconclusive.
    """
    configured = _configured_fault_types(summary)
    if configured is not None:
        if check == "calibration":
            return bool(configured & _TRACE_COVERAGE_FAULT_TYPES)
        return check in configured
    # A legacy report did not carry selector metadata.  Preserve its
    # fail-closed meaning when it explicitly emitted one of these summaries;
    # only a current report with explicit metadata can prove that coverage is
    # optional.
    if check == "swap_progress" and "swap_progress_inference" in summary:
        return True
    if check == "security_state_erase" and "security_state_erase" in summary:
        return True
    if (
        check == "calibration"
        and isinstance(summary.get("runtime_sweep"), dict)
        and "calibration_coverage" in summary["runtime_sweep"]
    ):
        return True
    return not isinstance(summary.get("runtime_sweep"), dict)


def _collect_summary(
    state: MutableMapping[str, Any], summary_value: Any, *, prefix: str = "summary"
) -> None:
    summary = _mapping(summary_value, prefix)
    unknown = sorted(set(summary) - _KNOWN_SUMMARY_SECTIONS)
    for name in unknown:
        _record_inconclusive(
            state, "{} contains unsupported section {!r}".format(prefix, name)
        )

    if "runtime_sweep" in summary:
        _collect_runtime(state, summary["runtime_sweep"], "{}.runtime_sweep".format(prefix))
        runtime = _mapping(summary["runtime_sweep"], "{}.runtime_sweep".format(prefix))
        configured = _configured_fault_types(summary)
        coverage = runtime.get("calibration_coverage")
        if (
            configured is not None
            and configured & _TRACE_COVERAGE_FAULT_TYPES
            and coverage is None
        ):
            _record_inconclusive(
                state,
                "{}.runtime_sweep calibration coverage is missing".format(prefix),
            )
        if isinstance(coverage, dict) and coverage.get("status") in {
            "unavailable",
            "metadata_only",
            "outside_slots_only",
            "no_nvm_activity",
        } and _coverage_check_required(summary, "calibration"):
            _record_inconclusive(
                state,
                "{}.runtime_sweep calibration coverage is {}".format(
                    prefix, coverage.get("status") or "unavailable"
                ),
            )
    if "multi_fault_runtime_sweep" in summary:
        _collect_runtime(
            state,
            summary["multi_fault_runtime_sweep"],
            "{}.multi_fault_runtime_sweep".format(prefix),
        )

    partial = summary.get("partial_staging")
    if partial is not None:
        partial = _mapping(partial, "{}.partial_staging".format(prefix))
        partial_context = "{}.partial_staging".format(prefix)
        partial_issues = _nonnegative_int(
            partial, "issue_count", context=partial_context
        )
        unreliable_partial = sum(
            _nonnegative_int(partial, key, context=partial_context)
            for key in ("infrastructure_error", "timeout", "complete_image_failed")
            if key in partial
        )
        _record_findings(
            state,
            partial_context,
            max(0, partial_issues - min(partial_issues, unreliable_partial)),
        )
        if partial.get("campaign_complete") is False:
            _record_inconclusive(state, "{}.partial_staging campaign is incomplete".format(prefix))
        for key in (
            "infrastructure_error",
            "timeout",
            "complete_image_failed",
            "missing_result_points",
            "extra_result_points",
        ):
            if key in partial and _nonnegative_int(
                partial, key, context="{}.partial_staging".format(prefix)
            ) > 0:
                _record_inconclusive(
                    state, "{}.partial_staging reports {}".format(prefix, key)
                )

    state_fuzz = summary.get("state_fuzz")
    if state_fuzz is not None:
        state_fuzz = _mapping(state_fuzz, "{}.state_fuzz".format(prefix))
        _record_findings(
            state,
            "{}.state_fuzz".format(prefix),
            _nonnegative_int(state_fuzz, "findings", context="{}.state_fuzz".format(prefix)),
        )
        requested = _nonnegative_int(
            state_fuzz, "iterations_requested", context="{}.state_fuzz".format(prefix)
        )
        completed = _nonnegative_int(
            state_fuzz, "iterations_completed", context="{}.state_fuzz".format(prefix)
        )
        if (
            requested <= 0
            or requested != completed
            or state_fuzz.get("status") != "completed"
        ):
            _record_inconclusive(state, "{}.state_fuzz campaign is incomplete".format(prefix))
        for key in ("infrastructure_errors", "timeouts"):
            if _nonnegative_int(
                state_fuzz, key, context="{}.state_fuzz".format(prefix)
            ) > 0:
                _record_inconclusive(state, "{}.state_fuzz reports {}".format(prefix, key))

    fuzz_crash = summary.get("fuzz_crash")
    if fuzz_crash is not None:
        fuzz_crash = _mapping(fuzz_crash, "{}.fuzz_crash".format(prefix))
        _record_findings(
            state,
            "{}.fuzz_crash".format(prefix),
            _nonnegative_int(
                fuzz_crash, "security_findings", context="{}.fuzz_crash".format(prefix)
            ),
        )
        generated = _nonnegative_int(
            fuzz_crash, "generated_profiles", context="{}.fuzz_crash".format(prefix)
        )
        results = _nonnegative_int(
            fuzz_crash, "results", context="{}.fuzz_crash".format(prefix)
        )
        if generated <= 0 or generated != results or fuzz_crash.get("status") != "completed":
            _record_inconclusive(state, "{}.fuzz_crash campaign is incomplete".format(prefix))

    terminal = summary.get("terminal_error_campaign")
    if terminal is not None:
        terminal = _mapping(terminal, "{}.terminal_error_campaign".format(prefix))
        _record_findings(
            state,
            "{}.terminal_error_campaign".format(prefix),
            _collection_count(
                terminal.get("findings"),
                "{}.terminal_error_campaign findings".format(prefix),
            ),
        )
        candidates = _nonnegative_int(
            terminal, "candidates", context="{}.terminal_error_campaign".format(prefix)
        )
        results = _collection_count(
            terminal.get("results"), "{}.terminal_error_campaign results".format(prefix)
        )
        if candidates <= 0:
            _record_inconclusive(
                state, "{}.terminal_error_campaign planned no candidates".format(prefix)
            )
        elif candidates > results:
            _record_inconclusive(
                state, "{}.terminal_error_campaign did not evaluate every candidate".format(prefix)
            )
        for key in ("unresolved_candidates", "infrastructure_errors"):
            if _collection_count(
                terminal.get(key), "{}.terminal_error_campaign {}".format(prefix, key)
            ) > 0:
                _record_inconclusive(
                    state, "{}.terminal_error_campaign reports {}".format(prefix, key)
                )

    terminal_paths = summary.get("terminal_error_paths")
    if terminal_paths is not None:
        terminal_paths = _mapping(
            terminal_paths, "{}.terminal_error_paths".format(prefix)
        )
        for key in ("unresolved_candidates", "infrastructure_errors"):
            if _collection_count(
                terminal_paths.get(key), "{}.terminal_error_paths {}".format(prefix, key)
            ) > 0:
                _record_inconclusive(
                    state, "{}.terminal_error_paths reports {}".format(prefix, key)
                )
        if terminal is None:
            terminal_candidates = _nonnegative_int(
                terminal_paths,
                "candidates",
                context="{}.terminal_error_paths".format(prefix),
            )
            _record_inconclusive(
                state,
                (
                    "{}.terminal_error_paths candidates were not evaluated"
                    if terminal_candidates > 0
                    else "{}.terminal_error_paths discovered no candidates"
                ).format(prefix),
            )

    combined = summary.get("combined")
    per_component = summary.get("per_component")
    if combined is not None and per_component is None:
        _record_inconclusive(
            state, "{}.combined is missing per-component evidence".format(prefix)
        )
    if per_component is not None and combined is None:
        _record_inconclusive(
            state, "{}.per_component is missing combined evidence".format(prefix)
        )
    component_fault_issues = 0
    component_control_issues = 0
    if per_component is not None:
        per_component = _mapping(per_component, "{}.per_component".format(prefix))
        if not per_component:
            _record_inconclusive(state, "{}.per_component has no component results".format(prefix))
        for name, component in per_component.items():
            fault_issues, control_issues = _collect_runtime(
                state,
                component,
                "{}.per_component.{}".format(prefix, name),
                record_findings=combined is None,
            )
            component_fault_issues += fault_issues
            component_control_issues += control_issues
    if combined is not None:
        combined = _mapping(combined, "{}.combined".format(prefix))
        combined_context = "{}.combined".format(prefix)
        total_fault_points = _nonnegative_int(
            combined, "total_fault_points", context=combined_context
        )
        if "security_issue_points" in combined:
            required_canonical = {
                "control_security_issue_points",
                "component_reliable_fault_points",
                "reliable_fault_points",
                "unreliable_fault_points",
                "control_reliable",
            }
            missing_canonical = sorted(required_canonical - set(combined))
            if missing_canonical:
                raise ValueError(
                    "{} canonical accounting is missing {}".format(
                        combined_context, ", ".join(missing_canonical)
                    )
                )
            combined_fault_issues = _nonnegative_int(
                combined, "security_issue_points", context=combined_context
            )
            combined_control_issues = _nonnegative_int(
                combined, "control_security_issue_points", context=combined_context
            )
            if combined_fault_issues > total_fault_points:
                raise ValueError(
                    "{} security_issue_points exceeds total_fault_points".format(
                        combined_context
                    )
                )
            if combined_control_issues > 1:
                raise ValueError(
                    "{} control_security_issue_points must be zero or one".format(
                        combined_context
                    )
                )
            reliable_fault_points = _nonnegative_int(
                combined, "reliable_fault_points", context=combined_context
            )
            component_reliable_fault_points = _nonnegative_int(
                combined,
                "component_reliable_fault_points",
                context=combined_context,
            )
            unreliable_fault_points = _nonnegative_int(
                combined, "unreliable_fault_points", context=combined_context
            )
            if reliable_fault_points + unreliable_fault_points != total_fault_points:
                raise ValueError(
                    "{} reliability counts do not equal total_fault_points".format(
                        combined_context
                    )
                )
            if reliable_fault_points > component_reliable_fault_points:
                raise ValueError(
                    "{} fully reliable points exceed component-reliable points".format(
                        combined_context
                    )
                )
            if component_reliable_fault_points > total_fault_points:
                raise ValueError(
                    "{} component-reliable points exceed total_fault_points".format(
                        combined_context
                    )
                )
            if combined_fault_issues > component_reliable_fault_points:
                raise ValueError(
                    "{} security_issue_points exceeds component-reliable fault points".format(
                        combined_context
                    )
                )
            control_reliable = combined.get("control_reliable")
            if not isinstance(control_reliable, bool):
                raise ValueError(
                    "{} control_reliable must be boolean".format(combined_context)
                )
            if component_control_issues and not combined_control_issues:
                raise ValueError(
                    "{} control_security_issue_points undercounts component controls".format(
                        combined_context
                    )
                )
            relation_control_count = _nonnegative_int(
                combined,
                "state_relation_control_violations",
                context=combined_context,
            )
            if (
                control_reliable
                and relation_control_count
                and not combined_control_issues
            ):
                raise ValueError(
                    "{} control_security_issue_points omits control relation findings".format(
                        combined_context
                    )
                )
            combined_issues = combined_fault_issues + combined_control_issues
            if unreliable_fault_points:
                _record_inconclusive(
                    state,
                    "{} reports unreliable_fault_points".format(combined_context),
                )
            if not control_reliable:
                _record_inconclusive(
                    state, "{} control is unreliable".format(combined_context)
                )
        else:
            # Older reports expose overlapping marginal totals only.  The
            # maximum is a safe lower bound for the point union and preserves
            # finding status without inventing a double-counted total.
            adverse_combined = sum(
                _nonnegative_int(combined, key, context=combined_context)
                for key in ("split_brain", "all_failed", "degraded")
            )
            relation_findings = _nonnegative_int(
                combined, "state_relation_violations", context=combined_context
            )
            relation_control = _nonnegative_int(
                combined,
                "state_relation_control_violations",
                context=combined_context,
            )
            combined_issues = max(
                component_fault_issues,
                adverse_combined,
                relation_findings,
            ) + int(component_control_issues > 0 or relation_control > 0)
            if combined_issues:
                _record_inconclusive(
                    state,
                    "{} lacks exact unique issue accounting".format(combined_context),
                )
        _record_findings(state, "{}.combined".format(prefix), combined_issues)
        if total_fault_points <= 0:
            _record_inconclusive(state, "{}.combined planned no fault points".format(prefix))

    geometry = summary.get("geometry_preflight")
    if geometry is not None:
        geometry = _mapping(geometry, "{}.geometry_preflight".format(prefix))
        if geometry.get("status") not in {"match", "ok"}:
            _record_inconclusive(
                state, "{}.geometry_preflight status is {}".format(prefix, geometry.get("status") or "missing")
            )

    swap = summary.get("swap_progress_inference")
    if swap is not None:
        swap = _mapping(swap, "{}.swap_progress_inference".format(prefix))
        if (
            swap.get("status") != "inferred"
            and _coverage_check_required(summary, "swap_progress")
        ):
            _record_inconclusive(
                state, "{}.swap_progress_inference status is {}".format(prefix, swap.get("status") or "missing")
            )
    elif "swap_progress" in (_configured_fault_types(summary) or set()):
        _record_inconclusive(
            state, "{}.swap_progress_inference status is missing".format(prefix)
        )

    security_erase = summary.get("security_state_erase")
    if security_erase is not None:
        security_erase = _mapping(
            security_erase, "{}.security_state_erase".format(prefix)
        )
        status = security_erase.get("status")
        if (
            status not in {"clean", "selected"}
            and _coverage_check_required(summary, "security_state_erase")
        ):
            _record_inconclusive(
                state, "{}.security_state_erase status is {}".format(prefix, status or "missing")
            )
        if (
            status == "selected"
            and not security_erase.get("cutpoints")
            and _coverage_check_required(summary, "security_state_erase")
        ):
            _record_inconclusive(
                state, "{}.security_state_erase selected no cutpoints".format(prefix)
            )

    layout = summary.get("persistent_state_layout")
    if layout is not None:
        layout = _mapping(layout, "{}.persistent_state_layout".format(prefix))
        candidates = _collection_count(
            layout.get("findings"), "{}.persistent_state_layout findings".format(prefix)
        )
        if layout.get("status") != "analyzed":
            _record_inconclusive(
                state, "{}.persistent_state_layout was not analyzed".format(prefix)
            )
        if candidates and (
            security_erase is None or security_erase.get("status") != "selected"
        ):
            _record_inconclusive(
                state,
                "{}.persistent_state_layout candidates lack a security-state erase campaign".format(prefix),
            )

    plan = summary.get("multi_fault_plan")
    if plan is not None:
        plan = _mapping(plan, "{}.multi_fault_plan".format(prefix))
        sequences = _nonnegative_int(
            plan, "sequences", context="{}.multi_fault_plan".format(prefix)
        )
        if sequences <= 0:
            _record_inconclusive(
                state, "{}.multi_fault_plan generated no sequences".format(prefix)
            )
        elif "multi_fault_runtime_sweep" not in summary:
            _record_inconclusive(
                state, "{}.multi_fault_plan was not executed".format(prefix)
            )

    trigger = summary.get("trigger_discovery")
    if trigger is not None:
        trigger = _mapping(trigger, "{}.trigger_discovery".format(prefix))
        selected = trigger.get("selected_strategy")
        if not isinstance(selected, str) or not selected.strip():
            _record_inconclusive(
                state, "{}.trigger_discovery did not select a strategy".format(prefix)
            )

    initial = summary.get("initial_states")
    if initial is not None:
        initial = _mapping(initial, "{}.initial_states".format(prefix))
        requested = _nonnegative_int(
            initial, "requested", context="{}.initial_states".format(prefix)
        )
        completed = _nonnegative_int(
            initial, "completed", context="{}.initial_states".format(prefix)
        )
        if requested <= 0 or completed != requested:
            _record_inconclusive(state, "{}.initial_states matrix is incomplete".format(prefix))


def _validate_multi_component_point_evidence(report: Mapping[str, Any]) -> None:
    """Verify canonical multi-component totals against point-level evidence."""
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return
    combined = summary.get("combined")
    if not isinstance(combined, dict) or "security_issue_points" not in combined:
        return

    records = report.get("combined_results")
    if not isinstance(records, list):
        raise ValueError(
            "canonical multi-component report must include combined_results"
        )
    summary_components = _mapping(summary.get("per_component"), "summary.per_component")
    component_names: Set[str] = set(summary_components)
    if not component_names:
        raise ValueError("summary.per_component must contain components")
    expected_outcomes_value = combined.get("expected_outcomes")
    if expected_outcomes_value is None:
        expected_outcomes: Dict[str, str] = {
            name: "success" for name in component_names
        }
    else:
        expected_outcomes = dict(
            _mapping(expected_outcomes_value, "summary.combined expected_outcomes")
        )
        if set(expected_outcomes) != component_names:
            raise ValueError(
                "summary.combined expected_outcomes does not match components"
            )
        expected_outcomes = {
            name: _normalise_outcome(value)
            for name, value in expected_outcomes.items()
        }
    expected_combined_outcome = _normalise_outcome(
        combined.get("expected_combined_outcome")
        or _classify_combined_outcome(expected_outcomes)
    )
    if expected_combined_outcome not in {
        "success", "split_brain", "all_failed", "degraded", "unknown"
    }:
        raise ValueError("summary.combined expected_combined_outcome is invalid")

    observed_fault_issues = 0
    observed_component_reliable = 0
    observed_reliable = 0
    observed_outcomes = {
        "split_brain": 0,
        "all_failed": 0,
        "success": 0,
        "degraded": 0,
    }
    observed_relation_points = 0
    for index, record_value in enumerate(records):
        context = "report combined_results[{}]".format(index)
        record = _mapping(record_value, context)
        if record.get("fault_injected") is not True:
            raise ValueError("{} must identify an injected fault".format(context))
        faulted_component = record.get("faulted_component")
        if not isinstance(faulted_component, str) or faulted_component not in component_names:
            raise ValueError("{} faulted_component is not a configured component".format(context))
        record_expected = record.get("expected_outcomes")
        if record_expected is not None:
            record_expected = dict(_mapping(record_expected, "{}.expected_outcomes".format(context)))
            record_expected = {name: _normalise_outcome(value) for name, value in record_expected.items()}
            if record_expected != expected_outcomes:
                raise ValueError("{} expected_outcomes disagrees with canonical map".format(context))
        record_expected_combined = record.get("expected_combined_outcome")
        if record_expected_combined is not None and _normalise_outcome(record_expected_combined) != expected_combined_outcome:
            raise ValueError("{} expected_combined_outcome disagrees with canonical map".format(context))
        nested_value = record.get("per_component")
        nested = _mapping(nested_value, "{}.per_component".format(context))
        if set(nested) != component_names:
            raise ValueError("{}.per_component does not match configured components".format(context))
        nested_outcomes: Dict[str, str] = {}
        faulted_count = 0
        for name in component_names:
            child = _mapping(nested[name], "{}.per_component.{}".format(context, name))
            child_outcome = child.get("boot_outcome")
            if not isinstance(child_outcome, str) or not child_outcome.strip():
                raise ValueError("{}.per_component.{} boot_outcome is missing".format(context, name))
            nested_outcomes[name] = _normalise_outcome(child_outcome)
            is_faulted = child.get("faulted")
            observed_control = child.get("observed_control")
            if not isinstance(is_faulted, bool) or not isinstance(observed_control, bool):
                raise ValueError("{}.per_component.{} fault markers must be boolean".format(context, name))
            if is_faulted != (name == faulted_component) or observed_control == is_faulted:
                raise ValueError("{}.per_component.{} fault/control map is inconsistent".format(context, name))
            faulted_count += int(is_faulted)
            nested_expected = child.get("expected_outcome")
            if nested_expected is not None and _normalise_outcome(nested_expected) != expected_outcomes[name]:
                raise ValueError("{}.per_component.{} expected_outcome disagrees with canonical map".format(context, name))
        if faulted_count != 1:
            raise ValueError("{} must identify exactly one faulted component".format(context))
        computed_outcome = _classify_combined_outcome(nested_outcomes)
        combined_outcome = _normalise_outcome(record.get("combined_outcome"))
        if computed_outcome != combined_outcome:
            raise ValueError("{} combined_outcome does not match nested component outcomes".format(context))
        reliable = record.get("reliable")
        component_reliable = record.get("component_reliable")
        component_issue = record.get("component_issue")
        security_issue = record.get("security_issue")
        if not isinstance(component_reliable, bool):
            raise ValueError("{} component_reliable must be boolean".format(context))
        if not isinstance(reliable, bool):
            raise ValueError("{} reliable must be boolean".format(context))
        if not isinstance(component_issue, bool):
            raise ValueError("{} component_issue must be boolean".format(context))
        if not isinstance(security_issue, bool):
            raise ValueError("{} security_issue must be boolean".format(context))
        component_reasons = record.get("component_issue_reasons")
        if not isinstance(component_reasons, list) or any(
            not isinstance(reason, str) or not reason
            for reason in component_reasons
        ):
            raise ValueError(
                "{} component_issue_reasons must be a list of strings".format(
                    context
                )
            )
        if component_issue != bool(component_reasons):
            raise ValueError(
                "{} component_issue does not match component_issue_reasons".format(
                    context
                )
            )
        if reliable and not component_reliable:
            raise ValueError(
                "{} combined reliability requires reliable component evidence".format(
                    context
                )
            )
        relation_findings, relation_errors = _relation_findings(
            record.get("invariant_violations"), "{}.invariant_violations".format(context)
        )
        has_relation = bool(relation_findings)
        if relation_errors and reliable:
            raise ValueError("{} is reliable despite relation evaluation errors".format(context))
        if combined_outcome not in observed_outcomes:
            raise ValueError("{} combined_outcome is invalid".format(context))
        non_reportable = _normalise_outcome(record.get("fault_class")) in {
            "bus_fault", "dos_only", "safe_dos", "harness", "harness_artifact"
        }
        if "non_reportable" in record:
            if not isinstance(record["non_reportable"], bool):
                raise ValueError("{} non_reportable must be boolean".format(context))
            if (
                record["non_reportable"] != non_reportable
                and str(record.get("fault_class") or "").strip()
            ):
                raise ValueError("{} non_reportable does not match fault class".format(context))
            non_reportable = record["non_reportable"]
        if non_reportable and security_issue:
            raise ValueError("{} non-reportable fault cannot be a security issue".format(context))
        expected_sources: List[str] = []
        if component_reliable and component_issue and not non_reportable:
            expected_sources.append("component")
        if reliable and combined_outcome != expected_combined_outcome and not non_reportable:
            expected_sources.append("combined_outcome")
        if reliable and has_relation and not non_reportable:
            expected_sources.append("state_relation")
        issue_sources = record.get("issue_sources")
        if issue_sources != expected_sources:
            raise ValueError(
                "{} issue_sources does not match its reliable evidence".format(
                    context
                )
            )
        should_be_issue = bool(expected_sources)
        if security_issue != should_be_issue:
            raise ValueError("{} security_issue does not match its evidence".format(context))
        observed_component_reliable += int(component_reliable)
        observed_reliable += int(reliable)
        observed_fault_issues += int(security_issue)
        observed_outcomes[combined_outcome] += 1
        observed_relation_points += int(has_relation)

    expected_fault_issues = _nonnegative_int(
        combined, "security_issue_points", context="summary.combined"
    )
    expected_reliable = _nonnegative_int(
        combined, "reliable_fault_points", context="summary.combined"
    )
    expected_component_reliable = _nonnegative_int(
        combined, "component_reliable_fault_points", context="summary.combined"
    )
    expected_unreliable = _nonnegative_int(
        combined, "unreliable_fault_points", context="summary.combined"
    )
    expected_total = _nonnegative_int(
        combined, "total_fault_points", context="summary.combined"
    )
    if len(records) != expected_total:
        raise ValueError(
            "summary.combined total_fault_points does not match combined_results"
        )
    if observed_fault_issues != expected_fault_issues:
        raise ValueError(
            "summary.combined security_issue_points does not match combined_results"
        )
    if observed_component_reliable != expected_component_reliable:
        raise ValueError(
            "summary.combined component_reliable_fault_points does not match combined_results"
        )
    if observed_reliable != expected_reliable:
        raise ValueError(
            "summary.combined reliable_fault_points does not match combined_results"
        )
    if len(records) - observed_reliable != expected_unreliable:
        raise ValueError(
            "summary.combined unreliable_fault_points does not match combined_results"
        )
    for outcome, count in observed_outcomes.items():
        if _nonnegative_int(
            combined, outcome, context="summary.combined"
        ) != count:
            raise ValueError(
                "summary.combined {} does not match combined_results".format(
                    outcome
                )
            )
    if _nonnegative_int(
        combined, "state_relation_violations", context="summary.combined"
    ) != observed_relation_points:
        raise ValueError(
            "summary.combined state_relation_violations does not match combined_results"
        )

    control_value = report.get("control_combined_result")
    control = _mapping(control_value, "report control_combined_result")
    if control.get("fault_injected") is not False:
        raise ValueError("report control_combined_result must identify a control")
    control_reliable = control.get("reliable")
    control_component_reliable = control.get("component_reliable")
    control_component_issue = control.get("component_issue")
    control_security_issue = control.get("security_issue")
    if not isinstance(control_component_reliable, bool):
        raise ValueError(
            "report control_combined_result component_reliable must be boolean"
        )
    if not isinstance(control_reliable, bool):
        raise ValueError("report control_combined_result reliable must be boolean")
    if control_reliable and not control_component_reliable:
        raise ValueError(
            "report control_combined_result reliable control lacks component evidence"
        )
    if not isinstance(control_component_issue, bool):
        raise ValueError(
            "report control_combined_result component_issue must be boolean"
        )
    if not isinstance(control_security_issue, bool):
        raise ValueError(
            "report control_combined_result security_issue must be boolean"
        )
    control_nested = _mapping(control.get("per_component"), "report control_combined_result.per_component")
    if set(control_nested) != component_names:
        raise ValueError("report control_combined_result.per_component does not match components")
    control_expected = control.get("expected_outcomes")
    if control_expected is not None:
        control_expected = {
            name: _normalise_outcome(value)
            for name, value in dict(_mapping(control_expected, "report control_combined_result.expected_outcomes")).items()
        }
        if control_expected != expected_outcomes:
            raise ValueError("report control expected_outcomes disagrees with canonical map")
    control_expected_combined = control.get("expected_combined_outcome")
    if control_expected_combined is not None and _normalise_outcome(control_expected_combined) != expected_combined_outcome:
        raise ValueError("report control expected_combined_outcome disagrees with canonical map")
    control_outcomes: Dict[str, str] = {}
    for name in component_names:
        child = _mapping(control_nested[name], "report control_combined_result.per_component.{}".format(name))
        outcome = child.get("boot_outcome")
        if not isinstance(outcome, str) or not outcome.strip():
            raise ValueError("report control_combined_result component outcome is missing")
        control_outcomes[name] = _normalise_outcome(outcome)
        if child.get("faulted") is not False or child.get("observed_control") is not True:
            raise ValueError("report control_combined_result control map is inconsistent")
        nested_expected = child.get("expected_outcome")
        if nested_expected is not None and _normalise_outcome(nested_expected) != expected_outcomes[name]:
            raise ValueError("report control component expected_outcome disagrees with canonical map")
    if _normalise_outcome(control.get("combined_outcome")) != _classify_combined_outcome(control_outcomes):
        raise ValueError("report control_combined_result combined_outcome does not match component outcomes")
    control_state = report.get("control_state")
    if control_state is not None:
        control_state = _mapping(control_state, "report control_state")
        if set(control_state) != component_names:
            raise ValueError("report control_state does not match components")
        for name in component_names:
            state = _mapping(control_state[name], "report control_state.{}".format(name))
            if _normalise_outcome(state.get("boot_outcome")) != control_outcomes[name]:
                raise ValueError("report control_state outcome disagrees with control evidence")
    top_relations, top_relation_errors = _relation_findings(
        report.get("control_invariant_violations"), "report control_invariant_violations"
    )
    if top_relation_errors and control_reliable:
        raise ValueError("report control is reliable despite relation evaluation errors")
    if top_relation_errors and control_security_issue:
        raise ValueError("report control relation errors cannot be a security issue")
    expected_control_sources: List[str] = []
    if control_component_reliable and control_component_issue:
        expected_control_sources.append("component")
    if control_reliable and top_relations:
        expected_control_sources.append("state_relation")
    expected_control_issue = bool(expected_control_sources)
    if control.get("issue_sources") != expected_control_sources:
        raise ValueError(
            "report control_combined_result issue_sources does not match its evidence"
        )
    if control_security_issue != expected_control_issue:
        raise ValueError(
            "report control_combined_result security_issue does not match its evidence"
        )
    if _nonnegative_int(
        combined,
        "state_relation_control_violations",
        context="summary.combined",
    ) != len(top_relations):
        raise ValueError(
            "summary.combined state_relation_control_violations does not match control evidence"
        )
    summary_control_reliable = combined.get("control_reliable")
    if not isinstance(summary_control_reliable, bool):
        raise ValueError("summary.combined control_reliable must be boolean")
    if summary_control_reliable != control_reliable:
        raise ValueError(
            "summary.combined control_reliable does not match control evidence"
        )
    if _nonnegative_int(
        combined, "control_security_issue_points", context="summary.combined"
    ) != int(control_security_issue):
        raise ValueError(
            "summary.combined control_security_issue_points does not match control evidence"
        )


def build_security_aggregate(report_value: Any) -> Dict[str, Any]:
    """Return the normalized Action security accounting for one audit report."""
    report = _mapping(report_value, "report")
    verdict = report.get("verdict")
    if not isinstance(verdict, str) or not verdict.strip():
        raise ValueError("report verdict must be a non-empty string")
    expect = _mapping(report.get("expect"), "report expect")
    should_find = expect.get("should_find_issues")
    if not isinstance(should_find, bool):
        raise ValueError("report expect.should_find_issues must be boolean")
    expectation = dict(expect)
    if "mode" in expectation:
        mode = expectation["mode"]
        if not isinstance(mode, str) or mode.strip().lower() not in EXPECTATION_MODES:
            raise ValueError("report expect.mode is invalid")
        expectation["mode"] = expectation_mode(expectation)
    else:
        expectation["mode"] = "regression"

    state: Dict[str, Any] = {
        "issue_points": 0,
        "security_bypass_points": 0,
        "brick_rates": [],
        "finding_sources": {},
        "security_bypass_sources": {},
        "inconclusive_reasons": [],
    }
    _validate_multi_component_point_evidence(report)
    _collect_summary(state, report.get("summary"), prefix="summary")

    authorization = report.get("authorization_review_analysis")
    if authorization is not None:
        authorization = _mapping(
            authorization, "report authorization_review_analysis"
        )
        authorization_verdict = str(authorization.get("verdict") or "")
        authorization_findings = authorization.get("findings")
        if not isinstance(authorization_findings, list):
            raise ValueError(
                "report authorization_review_analysis findings must be a list"
            )
        infrastructure_findings = sum(
            1
            for finding in authorization_findings
            if isinstance(finding, dict)
            and finding.get("id") == "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR"
        )
        if authorization_verdict == "FAIL":
            semantic_count = len(authorization_findings) - infrastructure_findings
            _record_findings(
                state, "authorization_review_analysis", max(1, semantic_count)
            )
        if infrastructure_findings:
            _record_inconclusive(
                state,
                "authorization_review_analysis contains incomplete evidence",
            )
        if authorization_verdict not in {"PASS", "FAIL"}:
            _record_inconclusive(
                state, "authorization_review_analysis is incomplete"
            )

    trigger_discovery = report.get("trigger_discovery")
    if trigger_discovery is not None:
        trigger_discovery = _mapping(
            trigger_discovery, "report trigger_discovery"
        )
        selected = trigger_discovery.get("selected_strategy")
        if not isinstance(selected, str) or not selected.strip():
            _record_inconclusive(
                state, "trigger_discovery did not select a strategy"
            )
        geometry_override = trigger_discovery.get("geometry_override")
        flash_map = trigger_discovery.get("flash_map_check")
        if (
            isinstance(flash_map, dict)
            and flash_map.get("status") == "mismatch"
            and (
                not isinstance(geometry_override, dict)
                or geometry_override.get("status") != "applied"
            )
        ):
            _record_inconclusive(
                state, "trigger_discovery flash-map mismatch was not overridden"
            )

    boundary_reports = report.get("boundary_campaign_results")
    if boundary_reports is not None:
        if not isinstance(boundary_reports, list):
            raise ValueError("report boundary_campaign_results must be a list")
        for index, boundary in enumerate(boundary_reports):
            boundary = _mapping(
                boundary, "report boundary_campaign_results[{}]".format(index)
            )
            boundary_verdict = str(boundary.get("verdict") or "")
            if boundary_verdict == "FAIL":
                _record_findings(
                    state, "boundary_campaign_results", 1
                )
            elif boundary_verdict != "PASS":
                _record_inconclusive(
                    state,
                    "boundary_campaign_results[{}] is incomplete".format(index),
                )

    initial_results = report.get("initial_state_results")
    if initial_results is not None:
        if not isinstance(initial_results, list):
            raise ValueError("report initial_state_results must be a list")
        for index, entry in enumerate(initial_results):
            entry = _mapping(
                entry, "report initial_state_results[{}]".format(index)
            )
            child_summary = entry.get("summary")
            if child_summary is not None:
                _collect_summary(
                    state,
                    child_summary,
                    prefix="initial_state_results[{}].summary".format(index),
                )
                child_combined = (
                    child_summary.get("combined")
                    if isinstance(child_summary, dict)
                    else None
                )
                if isinstance(child_combined, dict) and "security_issue_points" in child_combined:
                    # A wrapper must carry the child's point-level evidence
                    # when it carries canonical multi-component accounting.
                    # Keep any already-confirmed child finding count, but mark
                    # the wrapper inconclusive if the evidence was stripped.
                    child_evidence = {
                        "summary": child_summary,
                        "combined_results": entry.get("combined_results"),
                        "control_combined_result": entry.get("control_combined_result"),
                        "control_state": entry.get("control_state"),
                        "control_invariant_violations": entry.get(
                            "control_invariant_violations"
                        ),
                    }
                    if not isinstance(child_evidence["combined_results"], list):
                        _record_inconclusive(
                            state,
                            "initial_state_results[{}] canonical child point evidence is missing".format(index),
                        )
                    else:
                        try:
                            _validate_multi_component_point_evidence(child_evidence)
                        except ValueError as exc:
                            _record_inconclusive(
                                state,
                                "initial_state_results[{}] canonical child evidence invalid: {}".format(index, exc),
                            )
            returncode = entry.get("returncode")
            child_verdict = entry.get("verdict")
            if returncode != 0 or not isinstance(child_verdict, str):
                _record_inconclusive(
                    state, "initial_state_results[{}] is incomplete".format(index)
                )
            elif child_verdict.upper().startswith("INCONCLUSIVE"):
                _record_inconclusive(
                    state, "initial_state_results[{}] is inconclusive".format(index)
                )

    top_control = report.get("control_invariant_violations")
    if top_control is not None:
        if not isinstance(top_control, list):
            raise ValueError("report control_invariant_violations must be a list")
        combined_summary = report.get("summary", {}).get("combined", {})
        accounted = 0
        canonical_control_accounting = False
        if isinstance(combined_summary, dict):
            if "control_security_issue_points" in combined_summary:
                canonical_control_accounting = True
                accounted = _nonnegative_int(
                    combined_summary,
                    "control_security_issue_points",
                    context="summary.combined",
                )
            else:
                accounted = int(
                    _nonnegative_int(
                        combined_summary,
                        "state_relation_control_violations",
                        context="summary.combined",
                    )
                    > 0
                )
        if top_control and not accounted and not canonical_control_accounting:
            _record_findings(
                state,
                "control_invariant_violations",
                1,
            )

    normalized_verdict = verdict.strip().upper()
    if normalized_verdict.startswith("INCONCLUSIVE"):
        _record_inconclusive(state, "report verdict is inconclusive")
    elif not is_pass_verdict(verdict) and state["issue_points"] == 0:
        _record_inconclusive(
            state, "report failed without normalized finding evidence"
        )
    if expectation_requires_findings(expectation) and state["issue_points"] == 0:
        _record_inconclusive(
            state, "profile expected findings but the report accounted for none"
        )

    # Confirmed findings remain actionable even when another campaign could
    # not complete.  Preserve the reliability diagnostics alongside the
    # FINDINGS status rather than allowing an incomplete auxiliary campaign
    # to hide definite evidence.
    if state["issue_points"] > 0 or state["security_bypass_points"] > 0:
        status = "FINDINGS"
    elif state["inconclusive_reasons"]:
        status = "INCONCLUSIVE"
    else:
        status = "CLEAN"

    rates: Sequence[float] = state["brick_rates"]
    return {
        "schema_version": SECURITY_AGGREGATE_VERSION,
        "status": status,
        "issue_points": state["issue_points"],
        "security_bypass_points": state["security_bypass_points"],
        "brick_rate": max(rates) if rates else 0.0,
        "finding_sources": dict(sorted(state["finding_sources"].items())),
        "security_bypass_sources": dict(
            sorted(state["security_bypass_sources"].items())
        ),
        "inconclusive_reasons": state["inconclusive_reasons"],
    }


def validate_security_aggregate(value: Any) -> Dict[str, Any]:
    """Validate and return a normalized aggregate loaded from JSON."""
    aggregate = dict(_mapping(value, "report security_aggregate"))
    if (
        not isinstance(aggregate.get("schema_version"), int)
        or isinstance(aggregate.get("schema_version"), bool)
        or aggregate.get("schema_version") != SECURITY_AGGREGATE_VERSION
    ):
        raise ValueError("report security_aggregate schema_version is unsupported")
    if aggregate.get("status") not in SECURITY_STATUSES:
        raise ValueError("report security_aggregate status is invalid")
    for key in ("issue_points", "security_bypass_points"):
        _nonnegative_int(aggregate, key, context="report security_aggregate")
    _rate(aggregate.get("brick_rate"), "report security_aggregate brick_rate")
    for key in ("finding_sources", "security_bypass_sources"):
        sources = _mapping(aggregate.get(key), "report security_aggregate {}".format(key))
        for source, count in sources.items():
            if not isinstance(source, str) or not source:
                raise ValueError("report security_aggregate source names must be non-empty strings")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("report security_aggregate source counts must be non-negative integers")
    reasons = aggregate.get("inconclusive_reasons")
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str) or not reason for reason in reasons
    ):
        raise ValueError("report security_aggregate inconclusive_reasons must be strings")
    return aggregate


def attach_security_aggregate(report: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a freshly computed aggregate and return *report*."""
    report["security_aggregate"] = build_security_aggregate(report)
    return report
