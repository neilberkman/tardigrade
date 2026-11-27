# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Canonical accounting for requested and evaluated audit points."""

from __future__ import annotations

from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)


POINT_COUNT_SCHEMA_VERSION = 2

POINT_KIND_LABELS: Dict[str, str] = {
    "single_cut_program": "single-cut program",
    "single_cut_erase": "single-cut erase",
    "state_search_single_cut": "single-cut program (state search)",
    "state_search_single_cut_erase": "single-cut erase (state search)",
    "two_cut_grid": "two-cut (grid selection)",
    "two_cut_pairs": "two-cut (explicit pairs)",
    "two_cut_state_search": "two-cut (state search)",
    "n_cut_explicit": "three-or-more-cut (explicit chains)",
    "deeper_cut": "deeper-cut state search",
    "multi_fault": "multi-fault sequence",
    "cascading": "cascading write/erase",
    "glitch_instruction_skip": "glitch / instruction skip",
    "read_fault": "read fault",
    "control": "clean control",
    "other": "other configured fault",
}

POINT_KIND_ORDER: Tuple[str, ...] = tuple(POINT_KIND_LABELS)

_PROGRAM_CODES = frozenset(("w", "b", "s", "g", "x", "d", "l", "r"))
_ERASE_CODES = frozenset(("e", "a"))
_GLITCH_CODES = frozenset(("i",))
_READ_CODES = frozenset(("f",))
_COUNT_FIELDS = (
    "requested",
    "run",
    "evaluated",
    "skipped",
    "infrastructure_error",
    "timeout",
    "reused",
    "missing",
    "issues",
)
_TRACE_REPLAY_CROSS_CHECK_FIELDS = ("run", "passed", "failed")


def _base_code(value: Any) -> str:
    return str(value or "w").strip().lower().split(":", 1)[0]


def _new_kind(kind: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "label": POINT_KIND_LABELS[kind],
        **{field: 0 for field in _COUNT_FIELDS},
        "skip_reasons": {},
    }
    return row


def _new_counts() -> Dict[str, Any]:
    return {
        "schema_version": POINT_COUNT_SCHEMA_VERSION,
        "kinds": {kind: _new_kind(kind) for kind in POINT_KIND_ORDER},
        "totals": {field: 0 for field in _COUNT_FIELDS},
        "trace_replay_cross_checks": {
            field: 0 for field in _TRACE_REPLAY_CROSS_CHECK_FIELDS
        },
        "calibration": {
            "program": _new_calibration_row(),
            "erase": _new_calibration_row(),
        },
    }


def _new_calibration_row() -> Dict[str, Any]:
    return {
        "calibrated": 0,
        "planned_range": 0,
        "cut_directly": 0,
        "represented_without_cut": 0,
        "outside_planned_range": 0,
        "not_cut_or_represented": 0,
        "representation": [],
    }


def _profile_phase2_selection(profile: Any) -> str:
    fault_sweep = getattr(profile, "fault_sweep", None)
    phase2 = getattr(fault_sweep, "phase2_fault", None)
    if phase2 is None:
        return "grid"
    state_search = getattr(phase2, "state_search", None)
    if bool(getattr(state_search, "enabled", False)):
        return "state_search"
    if getattr(phase2, "pairs", None):
        return "pairs"
    return "grid"


def _phase2_selection(result: Mapping[str, Any], profile: Any) -> str:
    explicit = str(
        result.get("phase2_selection")
        or (result.get("phase2_fault") or {}).get("selection")
        or ""
    ).strip().lower()
    if explicit in {"grid", "pairs", "state_search"}:
        return explicit
    return _profile_phase2_selection(profile)


def _state_search_generation(result: Mapping[str, Any]) -> int:
    metadata = result.get("recovery_state_search")
    if isinstance(metadata, Mapping):
        try:
            return max(1, int(metadata.get("generation", 1)))
        except (TypeError, ValueError):
            return 1
    return 1


def _state_search_first_operation(result: Mapping[str, Any]) -> str:
    metadata = result.get("recovery_state_search")
    chain = metadata.get("chain") if isinstance(metadata, Mapping) else None
    cuts = chain.get("cuts") if isinstance(chain, Mapping) else None
    first = cuts[0] if cuts else None
    return (
        "erase"
        if isinstance(first, Mapping)
        and str(first.get("operation") or "write").strip().lower() == "erase"
        else "write"
    )


def classify_point_kind(result: Mapping[str, Any], profile: Any = None) -> str:
    """Return the canonical accounting kind for one result record."""
    if bool(result.get("is_control")):
        return "control"
    raw = str(result.get("fault_type") or "w").strip().lower()
    base = _base_code(raw)
    if base == "rs" or isinstance(result.get("recovery_state_search"), Mapping):
        generation = _state_search_generation(result)
        if generation == 1:
            if _state_search_first_operation(result) == "erase":
                return "state_search_single_cut_erase"
            return "state_search_single_cut"
        if generation == 2:
            return "two_cut_state_search"
        return "deeper_cut"
    if base == "pc" or isinstance(result.get("phase2_fault_chain"), Mapping):
        return "n_cut_explicit"
    if base == "p2" or isinstance(result.get("phase2_fault"), Mapping):
        return "two_cut_{}".format(_phase2_selection(result, profile))
    if base == "mf" or result.get("fault_sequence") is not None:
        return "multi_fault"
    if base in {"c", "cascade"} or isinstance(result.get("cascade"), Mapping):
        return "cascading"
    if base in _GLITCH_CODES:
        return "glitch_instruction_skip"
    if base in _READ_CODES or isinstance(result.get("read_fault"), Mapping):
        return "read_fault"
    operation_kind = str(result.get("operation_kind") or "").strip().lower()
    if operation_kind == "erase" or base in _ERASE_CODES:
        return "single_cut_erase"
    if operation_kind == "program" or base in _PROGRAM_CODES:
        return "single_cut_program"
    return "other"


def classify_planned_kind(
    fault_type: Any,
    *,
    profile: Any = None,
    phase2_selection: Optional[str] = None,
) -> str:
    raw = str(fault_type or "w").strip().lower()
    base = _base_code(raw)
    if base == "rs":
        # The one wire request expands dynamically. Its computed states are
        # accounted from the state-search results and summary instead.
        return "two_cut_state_search"
    if base == "pc":
        return "n_cut_explicit"
    if base == "p2":
        selection = phase2_selection or _profile_phase2_selection(profile)
        return "two_cut_{}".format(selection)
    if base == "mf":
        return "multi_fault"
    if base in {"c", "cascade"}:
        return "cascading"
    if base in _GLITCH_CODES:
        return "glitch_instruction_skip"
    if base in _READ_CODES:
        return "read_fault"
    if base in _ERASE_CODES:
        return "single_cut_erase"
    if base in _PROGRAM_CODES:
        return "single_cut_program"
    return "other"


def _is_infrastructure_error(result: Mapping[str, Any]) -> bool:
    outcome = str(result.get("boot_outcome") or "").strip().lower()
    return bool(result.get("infrastructure_error")) or outcome in {
        "infra_error",
        "infrastructure_error",
    }


def _is_timeout(result: Mapping[str, Any]) -> bool:
    outcome = str(result.get("boot_outcome") or "").strip().lower()
    return bool(result.get("timeout")) or outcome == "timeout"


def _is_skipped(result: Mapping[str, Any]) -> bool:
    outcome = str(result.get("boot_outcome") or "").strip().lower()
    return outcome == "skipped" or (
        not bool(result.get("is_control"))
        and result.get("fault_injected") is False
        and not _is_infrastructure_error(result)
        and not _is_timeout(result)
    )


def _skip_reason(result: Mapping[str, Any]) -> str:
    reason = str(result.get("skip_reason") or "").strip()
    if reason:
        return reason
    phase2 = result.get("phase2_fault")
    if isinstance(phase2, Mapping):
        reason = str(phase2.get("skip_reason") or "").strip()
    return reason or "unspecified"


def _state_search_summary(results: Sequence[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    for result in results:
        value = result.get("recovery_state_search_summary")
        if isinstance(value, Mapping):
            return value
    return None


def _record_reused_state_chains(
    counts: Dict[str, Any], results: Sequence[Mapping[str, Any]]
) -> int:
    found = 0
    for result in results:
        metadata = result.get("recovery_state_search")
        if not isinstance(metadata, Mapping):
            continue
        for chain in metadata.get("equivalent_chains") or []:
            if not isinstance(chain, Mapping):
                continue
            try:
                cut_count = int(chain.get("cut_count", len(chain.get("cuts") or [])))
            except (TypeError, ValueError):
                cut_count = 2
            if cut_count <= 1:
                cuts = chain.get("cuts") or []
                first = cuts[0] if cuts else None
                kind = (
                    "state_search_single_cut_erase"
                    if isinstance(first, Mapping)
                    and str(first.get("operation") or "write") == "erase"
                    else "state_search_single_cut"
                )
            elif cut_count == 2:
                kind = "two_cut_state_search"
            else:
                kind = "deeper_cut"
            counts["kinds"][kind]["requested"] += 1
            counts["kinds"][kind]["reused"] += 1
            found += 1
    return found


def _record_state_search_remainder(
    counts: Dict[str, Any],
    results: Sequence[Mapping[str, Any]],
    reused_from_chains: int,
) -> Dict[str, int]:
    summary = _state_search_summary(results)
    if summary is None:
        return {}
    try:
        reported_reused = max(0, int(summary.get("states_reused", 0) or 0))
    except (TypeError, ValueError):
        reported_reused = 0
    unassigned_reused = max(0, reported_reused - reused_from_chains)
    if unassigned_reused:
        row = counts["kinds"]["two_cut_state_search"]
        row["requested"] += unassigned_reused
        row["reused"] += unassigned_reused

    try:
        states_computed = max(0, int(summary.get("states_computed", 0) or 0))
    except (TypeError, ValueError):
        states_computed = 0
    already_requested = len(results) + reported_reused
    remainder = max(0, states_computed - already_requested)
    if not remainder:
        return {}
    reason = str(summary.get("stopped_reason") or "not_booted").strip()
    if reason == "complete":
        reason = "computed_without_boot"
    try:
        first_cut_computed = max(
            0, int(summary.get("first_cut_states_computed", 0) or 0)
        )
        first_program_computed = max(
            0,
            int(
                summary.get(
                    "first_cut_program_states_computed", first_cut_computed
                )
                or 0
            ),
        )
        first_erase_computed = max(
            0, int(summary.get("first_cut_erase_states_computed", 0) or 0)
        )
    except (TypeError, ValueError):
        first_cut_computed = 0
        first_program_computed = 0
        first_erase_computed = 0
    first_program_known = int(
        counts["kinds"]["state_search_single_cut"]["requested"]
    )
    first_erase_known = int(
        counts["kinds"]["state_search_single_cut_erase"]["requested"]
    )
    program_remainder = min(
        remainder, max(0, first_program_computed - first_program_known)
    )
    erase_remainder = min(
        remainder - program_remainder,
        max(0, first_erase_computed - first_erase_known),
    )
    by_kind = {
        "state_search_single_cut": program_remainder,
        "state_search_single_cut_erase": erase_remainder,
        # Generation metadata is unavailable for computed states that were
        # never booted. Remaining states are conservatively two-cut.
        "two_cut_state_search": remainder - program_remainder - erase_remainder,
    }
    for kind, count in by_kind.items():
        if not count:
            continue
        row = counts["kinds"][kind]
        row["requested"] += count
        row["skipped"] += count
        row["skip_reasons"][reason] = row["skip_reasons"].get(reason, 0) + count
    return {kind: count for kind, count in by_kind.items() if count}


def _direct_calibration_cuts(
    results: Sequence[Mapping[str, Any]],
) -> Dict[str, Set[int]]:
    cuts: Dict[str, Set[int]] = {"program": set(), "erase": set()}
    for result in results:
        if bool(result.get("is_control")):
            continue
        raw = str(result.get("fault_type") or "w").strip().lower()
        base = _base_code(raw)
        metadata = result.get("recovery_state_search")
        if (
            isinstance(metadata, Mapping)
            and result.get("fault_injected") is True
        ):
            chains = [metadata.get("chain")]
            chains.extend(metadata.get("equivalent_chains") or [])
            for chain in chains:
                chain_cuts = (
                    chain.get("cuts") if isinstance(chain, Mapping) else None
                )
                if not chain_cuts:
                    continue
                first = chain_cuts[0]
                if isinstance(first, Mapping):
                    operation = str(first.get("operation") or "write")
                    try:
                        cuts["erase" if operation == "erase" else "program"].add(
                            int(first.get("operation_index"))
                        )
                    except (TypeError, ValueError):
                        pass
            continue
        phase2 = result.get("phase2_fault")
        if isinstance(phase2, Mapping):
            if phase2.get("p1_injected") is True:
                operation = "erase" if _base_code(phase2.get("p1_fault_type")) in _ERASE_CODES else "program"
                try:
                    cuts[operation].add(int(phase2.get("p1_fault_at")))
                except (TypeError, ValueError):
                    pass
            continue
        phase2_chain = result.get("phase2_fault_chain")
        if isinstance(phase2_chain, Mapping):
            chain_cuts = phase2_chain.get("cuts") or []
            first_cut = chain_cuts[0] if chain_cuts else None
            if isinstance(first_cut, Mapping) and first_cut.get("injected") is True:
                operation = (
                    "erase"
                    if str(first_cut.get("operation") or "write") == "erase"
                    else "program"
                )
                try:
                    cuts[operation].add(int(first_cut.get("fault_at")))
                except (TypeError, ValueError):
                    pass
            continue
        if result.get("fault_injected") is not True:
            continue
        operation = str(result.get("operation_kind") or "").strip().lower()
        if operation not in {"program", "erase"}:
            if base in _ERASE_CODES:
                operation = "erase"
            elif base in _PROGRAM_CODES:
                operation = "program"
            else:
                continue
        try:
            cuts[operation].add(int(result.get("fault_at")))
        except (TypeError, ValueError):
            pass
    return cuts


def _populate_calibration(
    counts: Dict[str, Any],
    results: Sequence[Mapping[str, Any]],
    calibration: Optional[Mapping[str, Mapping[str, Any]]],
) -> None:
    direct = _direct_calibration_cuts(results)
    for operation in ("program", "erase"):
        supplied = (calibration or {}).get(operation) or {}
        row = counts["calibration"][operation]
        calibrated = max(0, int(supplied.get("calibrated", 0) or 0))
        planned_range = max(
            0,
            min(calibrated, int(supplied.get("planned_range", calibrated) or 0)),
        )
        direct_count = len(
            {index for index in direct[operation] if 0 <= index < calibrated}
        )
        representation = supplied.get("representation") or []
        if isinstance(representation, str):
            representation = [representation]
        representation = sorted(
            {str(value) for value in representation if str(value).strip()}
        )
        represented = (
            max(0, planned_range - direct_count)
            if {"heuristic", "quick"}.intersection(representation)
            else 0
        )
        outside = max(0, calibrated - planned_range)
        not_cut = max(0, calibrated - direct_count - represented - outside)
        row.update(
            {
                "calibrated": calibrated,
                "planned_range": planned_range,
                "cut_directly": direct_count,
                "represented_without_cut": represented,
                "outside_planned_range": outside,
                "not_cut_or_represented": not_cut,
                "representation": representation,
            }
        )


def _refresh_totals(counts: Dict[str, Any]) -> None:
    for field in _COUNT_FIELDS:
        counts["totals"][field] = sum(
            int(row.get(field, 0) or 0) for row in counts["kinds"].values()
        )


def _populate_trace_replay_cross_checks(
    counts: Dict[str, Any], results: Sequence[Mapping[str, Any]]
) -> None:
    row = counts["trace_replay_cross_checks"]
    for result in results:
        check = result.get("trace_replay_cross_check")
        if not isinstance(check, Mapping) or check.get("checked") is not True:
            continue
        row["run"] += 1
        row["passed" if check.get("matched") is True else "failed"] += 1


def build_point_counts(
    results: Iterable[Mapping[str, Any]],
    *,
    planned_fault_types: Optional[Sequence[Any]] = None,
    expected_fault_points: Optional[int] = None,
    expected_control_points: int = 1,
    profile: Any = None,
    issue_predicate: Optional[Callable[[Mapping[str, Any]], bool]] = None,
    calibration: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the shared point-accounting block used by every report renderer."""
    result_list: List[Mapping[str, Any]] = list(results)
    counts = _new_counts()
    counts["kinds"]["control"]["requested"] = max(0, int(expected_control_points))

    state_search_wire_request = False
    observed_phase2_selections = {
        _phase2_selection(result, profile)
        for result in result_list
        if _base_code(result.get("fault_type")) == "p2"
        or isinstance(result.get("phase2_fault"), Mapping)
    }
    planned_phase2_selection = (
        next(iter(observed_phase2_selections))
        if len(observed_phase2_selections) == 1
        else None
    )
    if planned_fault_types is not None:
        for fault_type in planned_fault_types:
            if _base_code(fault_type) == "rs":
                state_search_wire_request = True
                continue
            kind = classify_planned_kind(
                fault_type,
                profile=profile,
                phase2_selection=planned_phase2_selection,
            )
            counts["kinds"][kind]["requested"] += 1
    elif expected_fault_points is not None:
        # Result-derived kinds preserve exact accounting for returned records.
        # Any missing planner records remain explicit under ``other``.
        for result in result_list:
            if not result.get("is_control"):
                counts["kinds"][classify_point_kind(result, profile)]["requested"] += 1
        missing_plan = max(
            0,
            int(expected_fault_points)
            - sum(
                row["requested"]
                for kind, row in counts["kinds"].items()
                if kind != "control"
            ),
        )
        counts["kinds"]["other"]["requested"] += missing_plan
    else:
        for result in result_list:
            if not result.get("is_control"):
                counts["kinds"][classify_point_kind(result, profile)]["requested"] += 1

    for result in result_list:
        kind = classify_point_kind(result, profile)
        row = counts["kinds"][kind]
        row["run"] += 1
        infra = _is_infrastructure_error(result)
        timeout = _is_timeout(result)
        skipped = _is_skipped(result)
        if infra:
            row["infrastructure_error"] += 1
        if timeout:
            row["timeout"] += 1
        if skipped:
            row["skipped"] += 1
            reason = _skip_reason(result)
            row["skip_reasons"][reason] = row["skip_reasons"].get(reason, 0) + 1
        evaluated = False
        if not infra and not timeout and not skipped:
            if bool(result.get("is_control")) or result.get("fault_injected") is True:
                row["evaluated"] += 1
                evaluated = True
        if evaluated and issue_predicate is not None and issue_predicate(result):
            row["issues"] += 1

    state_results = [
        result
        for result in result_list
        if _base_code(result.get("fault_type")) == "rs"
        or isinstance(result.get("recovery_state_search"), Mapping)
    ]
    dynamic_skipped_without_result: Dict[str, int] = {}
    if state_results:
        # Dynamic state-search records are the authoritative requested count;
        # discard the ordinary result-derived increment before rebuilding it.
        if planned_fault_types is None or state_search_wire_request:
            for kind in (
                "state_search_single_cut",
                "state_search_single_cut_erase",
                "two_cut_state_search",
                "deeper_cut",
            ):
                state_run = sum(
                    1 for result in state_results if classify_point_kind(result, profile) == kind
                )
                if planned_fault_types is None:
                    counts["kinds"][kind]["requested"] = max(
                        0, counts["kinds"][kind]["requested"] - state_run
                    )
                counts["kinds"][kind]["requested"] += state_run
            reused = _record_reused_state_chains(counts, state_results)
            dynamic_skipped_without_result = _record_state_search_remainder(
                counts, state_results, reused
            )

    for row in counts["kinds"].values():
        # Skipped points have returned records and are already part of run.
        row["missing"] = max(
            0,
            int(row["requested"]) - int(row["run"]) - int(row["reused"]),
        )
    for kind, skipped in dynamic_skipped_without_result.items():
        state_row = counts["kinds"][kind]
        state_row["missing"] = max(0, int(state_row["missing"]) - skipped)

    _populate_calibration(counts, result_list, calibration)
    _populate_trace_replay_cross_checks(counts, result_list)
    _refresh_totals(counts)
    return counts


def merge_point_counts(*blocks: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Merge campaign blocks while retaining the first calibration baseline."""
    merged = _new_counts()
    calibration_set = False
    for block in blocks:
        if not isinstance(block, Mapping):
            continue
        kinds = block.get("kinds")
        if isinstance(kinds, Mapping):
            for kind in POINT_KIND_ORDER:
                source = kinds.get(kind)
                if not isinstance(source, Mapping):
                    continue
                target = merged["kinds"][kind]
                for field in _COUNT_FIELDS:
                    target[field] += int(source.get(field, 0) or 0)
                for reason, value in (source.get("skip_reasons") or {}).items():
                    target["skip_reasons"][str(reason)] = (
                        target["skip_reasons"].get(str(reason), 0) + int(value or 0)
                    )
        calibration = block.get("calibration")
        if not calibration_set and isinstance(calibration, Mapping):
            if any(
                int((calibration.get(operation) or {}).get("calibrated", 0) or 0)
                for operation in ("program", "erase")
            ):
                merged["calibration"] = {
                    operation: dict(calibration.get(operation) or _new_calibration_row())
                    for operation in ("program", "erase")
                }
                calibration_set = True
        cross_checks = block.get("trace_replay_cross_checks")
        if isinstance(cross_checks, Mapping):
            for field in _TRACE_REPLAY_CROSS_CHECK_FIELDS:
                merged["trace_replay_cross_checks"][field] += int(
                    cross_checks.get(field, 0) or 0
                )
    _refresh_totals(merged)
    return merged


def point_count_rows(block: Mapping[str, Any], *, include_zero: bool = False) -> List[Dict[str, Any]]:
    """Return ordered renderer rows from a canonical point-count block."""
    kinds = block.get("kinds") or {}
    rows: List[Dict[str, Any]] = []
    for kind in POINT_KIND_ORDER:
        source = kinds.get(kind) or {}
        if not include_zero and not any(int(source.get(field, 0) or 0) for field in _COUNT_FIELDS):
            continue
        rows.append({"kind": kind, **_new_kind(kind), **dict(source)})
    return rows


def render_point_counts_text(block: Mapping[str, Any]) -> str:
    """Render the canonical block as compact human-readable lines."""
    lines = [
        "Point counts by kind "
        "(requested / run / evaluated / skipped / infrastructure error / "
        "timeout / reused / missing / issues):"
    ]
    rows = point_count_rows(block)
    if not rows:
        lines.append("  no requested or returned points")
    for row in rows:
        lines.append(
            "  {label}: {requested} / {run} / {evaluated} / {skipped} / "
            "{infrastructure_error} / {timeout} / {reused} / {missing} / "
            "{issues}".format(**row)
        )
        if row.get("skip_reasons"):
            reasons = ", ".join(
                "{}={}".format(reason, count)
                for reason, count in sorted(row["skip_reasons"].items())
            )
            lines.append("    skipped by reason: {}".format(reasons))
    cross_checks = block.get("trace_replay_cross_checks") or {}
    lines.append(
        "Trace replay cross-checks (run / passed / failed): "
        "{run} / {passed} / {failed}".format(
            **{
                field: int(cross_checks.get(field, 0) or 0)
                for field in _TRACE_REPLAY_CROSS_CHECK_FIELDS
            }
        )
    )
    calibration = block.get("calibration") or {}
    lines.append(
        "Calibration coverage "
        "(calibrated / planned range / cut directly / represented without cutting / "
        "outside planned range / not cut or represented):"
    )
    for operation, label in (("program", "writes"), ("erase", "erases")):
        row = calibration.get(operation) or {}
        representation = ", ".join(row.get("representation") or []) or "none"
        lines.append(
            "  {label}: {calibrated} / {planned_range} / {cut_directly} / "
            "{represented_without_cut} / {outside_planned_range} / "
            "{not_cut_or_represented} "
            "(representation: {representation})".format(
                label=label,
                calibrated=int(row.get("calibrated", 0) or 0),
                planned_range=int(row.get("planned_range", 0) or 0),
                cut_directly=int(row.get("cut_directly", 0) or 0),
                represented_without_cut=int(
                    row.get("represented_without_cut", 0) or 0
                ),
                outside_planned_range=int(
                    row.get("outside_planned_range", 0) or 0
                ),
                not_cut_or_represented=int(
                    row.get("not_cut_or_represented", 0) or 0
                ),
                representation=representation,
            )
        )
    return "\n".join(lines)


def render_point_counts_markdown(block: Mapping[str, Any]) -> str:
    """Render the canonical block as Markdown tables."""
    lines = [
        "### Point counts by kind",
        "",
        "| Kind | Requested | Run | Evaluated | Skipped | Infrastructure error | Timeout | Reused | Missing | Issues |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    rows = point_count_rows(block)
    if not rows:
        lines.append(
            "| No requested or returned points | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |"
        )
    for row in rows:
        render_row = dict(row)
        render_row["label"] = str(row["label"]).replace("|", "\\|")
        lines.append(
            "| {label} | {requested} | {run} | {evaluated} | {skipped} | "
            "{infrastructure_error} | {timeout} | {reused} | {missing} | "
            "{issues} |".format(
                **render_row,
            )
        )
        if row.get("skip_reasons"):
            reasons = ", ".join(
                "{}={}".format(reason, count)
                for reason, count in sorted(row["skip_reasons"].items())
            ).replace("|", "\\|")
            lines.append(
                "| ↳ skipped by reason: {} |  |  |  |  |  |  |  |  |  |".format(
                    reasons
                )
            )
    cross_checks = block.get("trace_replay_cross_checks") or {}
    lines.extend(
        [
            "",
            "### Trace replay cross-checks",
            "",
            "| Run | Passed | Failed |",
            "| ---: | ---: | ---: |",
            "| {run} | {passed} | {failed} |".format(
                **{
                    field: int(cross_checks.get(field, 0) or 0)
                    for field in _TRACE_REPLAY_CROSS_CHECK_FIELDS
                }
            ),
        ]
    )
    lines.extend(
        [
            "",
            "### Calibration operation coverage",
            "",
            "| Operation | Calibrated | Planned range | Cut directly | Represented without cutting | Outside planned range | Not cut or represented | Representation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    calibration = block.get("calibration") or {}
    for operation, label in (("program", "writes"), ("erase", "erases")):
        row = calibration.get(operation) or {}
        representation = ", ".join(row.get("representation") or []) or "none"
        lines.append(
            "| {label} | {calibrated} | {planned_range} | {cut_directly} | "
            "{represented_without_cut} | {outside_planned_range} | "
            "{not_cut_or_represented} | {representation} |".format(
                label=label,
                calibrated=int(row.get("calibrated", 0) or 0),
                planned_range=int(row.get("planned_range", 0) or 0),
                cut_directly=int(row.get("cut_directly", 0) or 0),
                represented_without_cut=int(
                    row.get("represented_without_cut", 0) or 0
                ),
                outside_planned_range=int(
                    row.get("outside_planned_range", 0) or 0
                ),
                not_cut_or_represented=int(
                    row.get("not_cut_or_represented", 0) or 0
                ),
                representation=representation,
            )
        )
    return "\n".join(lines) + "\n"
