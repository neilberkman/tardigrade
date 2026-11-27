# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from action_helpers import publish_report  # noqa: E402
from audit_bootloader import (  # noqa: E402
    _calibrated_program_operation_count,
    _calibration_point_coverage,
)
from audit_report import summarize_runtime_sweep  # noqa: E402
from boot_cycle_analysis import analyze_boot_cycles  # noqa: E402
from fault_classification import (  # noqa: E402
    result_has_initial_timeout,
    result_has_issues,
    result_is_infrastructure_error,
    result_is_skipped,
    result_is_timeout,
)
from point_counts import (  # noqa: E402
    POINT_KIND_LABELS,
    build_point_counts,
    merge_point_counts,
    point_count_rows,
    render_point_counts_markdown,
    render_point_counts_text,
)
from render_results_html import render_point_counts_panel  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from zero_day_results import format_profile_cell  # noqa: E402
from zero_day_summary import format_console_summary, format_step_summary  # noqa: E402


def _boot_span_result(
    initial_outcome: str,
    *,
    followup_outcome: str | None = None,
    followup_stop_reason: str = "completed",
) -> dict:
    cycles = [
        {
            "cycle": 0,
            "boot_outcome": initial_outcome,
            "stop_reason": (
                "budget" if initial_outcome == "timeout" else "completed"
            ),
        }
    ]
    if initial_outcome == "timeout":
        cycles[0]["boot_outcome"] = "no_boot"
    if initial_outcome in {"infra_error", "infrastructure_error"}:
        cycles[0].update(
            {
                "infrastructure_error": True,
                "stop_reason": "runfor_infrastructure_error",
                "error_kind": "runfor_exception",
            }
        )
    if followup_outcome is not None:
        followup = {
            "cycle": 1,
            "boot_outcome": followup_outcome,
            "stop_reason": followup_stop_reason,
        }
        if followup_outcome in {"infra_error", "infrastructure_error"}:
            followup.update(
                {
                    "infrastructure_error": True,
                    "error_kind": "runfor_exception",
                }
            )
        cycles.append(followup)

    analysis = analyze_boot_cycles(cycles, requested_cycles=len(cycles))
    result = {
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": cycles[0]["boot_outcome"],
        "initial_boot_outcome": cycles[0]["boot_outcome"],
        "boot_cycles": cycles,
        "multi_boot_analysis": analysis,
    }
    if len(cycles) > 1:
        result["final_boot_outcome"] = cycles[-1]["boot_outcome"]
    return result


def _summarize_one_point(result: dict) -> tuple[dict, dict]:
    summary = summarize_runtime_sweep(
        [result],
        expected_fault_points=1,
        expected_control_points=0,
        planned_fault_types=["w"],
    )
    row = summary["point_counts"]["kinds"]["single_cut_program"]
    return summary, row


def test_initial_hard_fault_remains_evaluated_issue_after_followup_timeout() -> None:
    result = _boot_span_result(
        "hard_fault",
        followup_outcome="no_boot",
        followup_stop_reason="budget",
    )

    summary, row = _summarize_one_point(result)

    assert result_is_timeout(result) is True
    assert result_has_initial_timeout(result) is False
    assert result_has_issues(result, "success") is True
    assert summary["timeout_points"] == 1
    assert summary["issue_points"] == 1
    assert summary["campaign_complete"] is False
    assert row["timeout"] == 1
    assert row["evaluated"] == 1
    assert row["issues"] == 1
    assert summary["point_counts"]["totals"]["timeout"] == 1
    assert summary["point_counts"]["totals"]["evaluated"] == 1
    assert summary["point_counts"]["totals"]["issues"] == 1


def test_initial_timeout_remains_unevaluated() -> None:
    result = _boot_span_result("timeout")

    summary, row = _summarize_one_point(result)

    assert result_is_timeout(result) is True
    assert result_has_initial_timeout(result) is True
    assert result_has_issues(result, "success") is False
    assert summary["timeout_points"] == 1
    assert summary["issue_points"] == 0
    assert summary["campaign_complete"] is False
    assert row["timeout"] == 1
    assert row["evaluated"] == 0
    assert row["issues"] == 0


def test_initial_success_remains_evaluated_after_followup_timeout() -> None:
    result = _boot_span_result(
        "success",
        followup_outcome="no_boot",
        followup_stop_reason="budget",
    )

    summary, row = _summarize_one_point(result)

    assert result_is_timeout(result) is True
    assert result_has_initial_timeout(result) is False
    assert result_has_issues(result, "success") is False
    assert summary["timeout_points"] == 1
    assert summary["issue_points"] == 0
    assert summary["campaign_complete"] is False
    assert row["timeout"] == 1
    assert row["evaluated"] == 1
    assert row["issues"] == 0


@pytest.mark.parametrize("initial_outcome", ["hard_fault", "success"])
def test_followup_infrastructure_error_remains_point_wide(
    initial_outcome: str,
) -> None:
    result = _boot_span_result(
        initial_outcome,
        followup_outcome="infra_error",
        followup_stop_reason="runfor_infrastructure_error",
    )

    summary, row = _summarize_one_point(result)

    assert result_is_infrastructure_error(result) is True
    assert summary["infrastructure_error_points"] == 1
    assert summary["total_fault_points"] == 0
    assert summary["issue_points"] == 0
    assert summary["campaign_complete"] is False
    assert row["infrastructure_error"] == 1
    assert row["evaluated"] == 0
    assert row["issues"] == 0


def test_initial_infrastructure_error_remains_unevaluated() -> None:
    result = _boot_span_result("infra_error")

    summary, row = _summarize_one_point(result)

    assert result_is_infrastructure_error(result) is True
    assert summary["infrastructure_error_points"] == 1
    assert summary["total_fault_points"] == 0
    assert summary["issue_points"] == 0
    assert summary["campaign_complete"] is False
    assert row["infrastructure_error"] == 1
    assert row["evaluated"] == 0
    assert row["issues"] == 0


def test_recorded_cycle_terminal_result_outranks_stale_timeout_flag() -> None:
    result = {
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "hard_fault",
        "timeout": True,
        "boot_cycles": [
            {
                "cycle": 0,
                "boot_outcome": "hard_fault",
                "stop_reason": "wall_timeout_after_terminal_result",
            }
        ],
        "multi_boot_analysis": {"status": "timeout"},
    }

    summary = summarize_runtime_sweep(
        [result],
        expected_fault_points=1,
        expected_control_points=0,
        planned_fault_types=["w"],
    )
    row = summary["point_counts"]["kinds"]["single_cut_program"]

    assert result_is_timeout(result) is False
    assert summary["timeout_points"] == 0
    assert row["timeout"] == 0
    assert row["evaluated"] == 1


@pytest.mark.parametrize(
    ("boot_outcome", "timeout", "evaluated"),
    [
        ("success", 0, 1),
        ("wrong_image", 0, 1),
        ("timeout", 1, 0),
    ],
)
def test_single_boot_point_counts_remain_unchanged(
    boot_outcome: str,
    timeout: int,
    evaluated: int,
) -> None:
    result = {
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": boot_outcome,
    }

    counts = build_point_counts(
        [result],
        planned_fault_types=["w"],
        expected_control_points=0,
    )
    row = counts["kinds"]["single_cut_program"]

    assert row["timeout"] == timeout
    assert row["evaluated"] == evaluated


@pytest.mark.parametrize(
    ("final_outcome", "field", "classifier"),
    [
        ("infra_error", "infrastructure_error", result_is_infrastructure_error),
        ("skipped", "skipped", result_is_skipped),
    ],
)
def test_effective_non_evaluated_outcomes_match_runtime_classification(
    final_outcome: str,
    field: str,
    classifier: Callable[[dict], bool],
) -> None:
    result = {
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "success",
        "final_boot_outcome": final_outcome,
    }

    summary = summarize_runtime_sweep(
        [result],
        expected_fault_points=1,
        expected_control_points=0,
        planned_fault_types=["w"],
    )
    row = summary["point_counts"]["kinds"]["single_cut_program"]

    assert classifier(result) is True
    assert row[field] == 1
    assert row["evaluated"] == 0


def test_issue_count_matches_effective_cycle_classification() -> None:
    result = {
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "success",
        "final_boot_outcome": "hard_fault",
        "boot_cycles": [
            {"cycle": 0, "boot_outcome": "success"},
            {"cycle": 1, "boot_outcome": "hard_fault"},
        ],
        "multi_boot_analysis": {
            "status": "failed_after_success",
            "final_outcome": "hard_fault",
        },
    }

    summary = summarize_runtime_sweep(
        [result],
        expected_fault_points=1,
        expected_control_points=0,
        planned_fault_types=["w"],
    )
    row = summary["point_counts"]["kinds"]["single_cut_program"]

    assert result_has_issues(result, "success") is True
    assert summary["issue_points"] == 1
    assert row["issues"] == 1
    assert row["evaluated"] == 1


@pytest.mark.parametrize(
    ("planned_type", "result", "expected_kind"),
    [
        ("w", {"fault_type": "w"}, "single_cut_program"),
        ("e", {"fault_type": "e"}, "single_cut_erase"),
        (
            "rs",
            {"fault_type": "rs", "recovery_state_search": {"generation": 1}},
            "state_search_single_cut",
        ),
        (
            "rs",
            {
                "fault_type": "rs",
                "recovery_state_search": {
                    "generation": 1,
                    "chain": {"cuts": [{"operation": "erase"}]},
                },
            },
            "state_search_single_cut_erase",
        ),
        (
            "p2:1:2:w:w",
            {"fault_type": "p2", "phase2_selection": "grid"},
            "two_cut_grid",
        ),
        (
            "p2:1:2:w:w",
            {"fault_type": "p2", "phase2_selection": "pairs"},
            "two_cut_pairs",
        ),
        (
            "rs",
            {"fault_type": "rs", "recovery_state_search": {"generation": 2}},
            "two_cut_state_search",
        ),
        (
            "rs",
            {"fault_type": "rs", "recovery_state_search": {"generation": 3}},
            "deeper_cut",
        ),
        (
            "pc:1:w:2:e:3:w",
            {"fault_type": "pc", "phase2_fault_chain": {"cut_count": 3}},
            "n_cut_explicit",
        ),
        (
            "mf:1:2",
            {"fault_type": "mf:1:2", "fault_sequence": [1, 2]},
            "multi_fault",
        ),
        ("c:1:2", {"fault_type": "c:1:2", "cascade": {}}, "cascading"),
        (
            "i:0x1000",
            {"fault_type": "i:0x1000"},
            "glitch_instruction_skip",
        ),
        ("f", {"fault_type": "f"}, "read_fault"),
        ("nv", {"fault_type": "nv"}, "other"),
    ],
)
def test_every_fault_kind_has_an_explicit_denominator(
    planned_type: str,
    result: dict,
    expected_kind: str,
) -> None:
    result = {
        **result,
        "fault_injected": True,
        "boot_outcome": "wrong_image",
        "issue": True,
    }
    if planned_type == "rs":
        result["recovery_state_search_summary"] = {
            "states_computed": 1,
            "states_reused": 0,
            "stopped_reason": "complete",
        }
    counts = build_point_counts(
        [result],
        planned_fault_types=[planned_type],
        expected_control_points=0,
        issue_predicate=lambda item: bool(item.get("issue")),
    )

    row = counts["kinds"][expected_kind]
    assert row["requested"] == 1
    assert row["run"] == 1
    assert row["evaluated"] == 1
    assert row["issues"] == 1


def test_control_kind_has_its_own_denominator() -> None:
    counts = build_point_counts(
        [
            {
                "is_control": True,
                "fault_type": "control",
                "fault_injected": False,
                "boot_outcome": "wrong_image",
                "issue": True,
            }
        ],
        planned_fault_types=[],
        expected_control_points=1,
        issue_predicate=lambda item: bool(item.get("issue")),
    )

    assert counts["kinds"]["control"]["requested"] == 1
    assert counts["kinds"]["control"]["run"] == 1
    assert counts["kinds"]["control"]["evaluated"] == 1
    assert counts["kinds"]["control"]["issues"] == 1


def test_explicit_chain_accounts_first_cut_in_calibration_coverage() -> None:
    counts = build_point_counts(
        [
            {
                "fault_type": "pc",
                "fault_injected": True,
                "boot_outcome": "success",
                "phase2_fault_chain": {
                    "cuts": [
                        {
                            "fault_at": 3,
                            "operation": "erase",
                            "injected": True,
                        },
                        {"fault_at": 1, "operation": "write", "injected": True},
                        {"fault_at": 2, "operation": "write", "injected": True},
                    ]
                },
            }
        ],
        planned_fault_types=["pc:3:e:1:w:2:w"],
        expected_control_points=0,
        calibration={
            "program": {"calibrated": 5, "planned_range": 5},
            "erase": {"calibrated": 5, "planned_range": 5},
        },
    )

    assert counts["kinds"]["n_cut_explicit"]["evaluated"] == 1
    assert counts["calibration"]["erase"]["cut_directly"] == 1
    assert counts["calibration"]["program"]["cut_directly"] == 0


def test_explicit_chain_with_a_later_unreached_cut_is_evaluated() -> None:
    counts = build_point_counts(
        [
            {
                "fault_type": "pc:3:w:99:w:2:w",
                "fault_injected": True,
                "boot_outcome": "hard_fault",
                "fault_class": "unrecoverable",
                "phase2_fault_chain": {
                    "cut_count": 1,
                    "requested_cut_count": 3,
                    "first_unreached_cut": 2,
                    "cuts": [
                        {
                            "fault_at": 3,
                            "operation": "write",
                            "injected": True,
                        }
                    ],
                    "requested_cuts": [
                        {"fault_at": 3, "fault_type": "w"},
                        {"fault_at": 99, "fault_type": "w"},
                        {"fault_at": 2, "fault_type": "w"},
                    ],
                },
            }
        ],
        planned_fault_types=["pc:3:w:99:w:2:w"],
        expected_control_points=0,
        issue_predicate=lambda result: result["boot_outcome"] == "hard_fault",
    )

    row = counts["kinds"]["n_cut_explicit"]
    assert row["requested"] == 1
    assert row["run"] == 1
    assert row["evaluated"] == 1
    assert row["skipped"] == 0
    assert row["issues"] == 1
    assert row["missing"] == 0


def test_state_search_budget_exclusions_are_skipped_not_missing() -> None:
    counts = build_point_counts(
        [
            {
                "fault_type": "rs",
                "fault_injected": True,
                "boot_outcome": "success",
                "recovery_state_search": {"generation": 1},
                "recovery_state_search_summary": {
                    "first_cut_states_computed": 3,
                    "states_computed": 3,
                    "states_reused": 0,
                    "stopped_reason": "max_new_states",
                },
            }
        ],
        planned_fault_types=["rs"],
        expected_control_points=0,
    )

    row = counts["kinds"]["state_search_single_cut"]
    assert row["requested"] == 3
    assert row["run"] == 1
    assert row["skipped"] == 2
    assert row["missing"] == 0
    assert row["skip_reasons"] == {"max_new_states": 2}
    assert counts["kinds"]["two_cut_state_search"]["requested"] == 0


def test_erase_first_state_search_accounting_is_separate_including_reuse() -> None:
    counts = build_point_counts(
        [
            {
                "fault_type": "rs",
                "fault_injected": True,
                "boot_outcome": "success",
                "recovery_state_search": {
                    "generation": 1,
                    "chain": {
                        "cut_count": 1,
                        "cuts": [{"operation": "erase", "operation_index": 0}],
                    },
                    "equivalent_chains": [
                        {
                            "cut_count": 1,
                            "cuts": [
                                {"operation": "erase", "operation_index": 1}
                            ],
                        }
                    ],
                },
                "recovery_state_search_summary": {
                    "first_cut_states_computed": 3,
                    "first_cut_program_states_computed": 0,
                    "first_cut_erase_states_computed": 3,
                    "states_computed": 3,
                    "states_reused": 1,
                    "stopped_reason": "max_new_states",
                },
            }
        ],
        planned_fault_types=["rs"],
        expected_control_points=0,
    )

    row = counts["kinds"]["state_search_single_cut_erase"]
    assert row["requested"] == 3
    assert row["run"] == 1
    assert row["evaluated"] == 1
    assert row["reused"] == 1
    assert row["skipped"] == 1
    assert row["skip_reasons"] == {"max_new_states": 1}
    assert counts["kinds"]["state_search_single_cut"]["requested"] == 0


def test_calibration_plan_scope_distinguishes_pairs_state_search_and_heuristic() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pairs_profile = load_profile(
        repo_root / "profiles" / "mcuboot_pr3011_move_broken.yaml"
    )
    pairs = _calibration_point_coverage(
        profile=pairs_profile,
        fault_points=[2, 2, 3],
        planned_fault_types=["p2:2:6:w:w", "p2:2:7:w:w", "p2:3:0:w:w"],
        calibrated_program_operations=23815,
        planned_program_operations=23815,
        calibrated_erases=42,
        fault_start=None,
        fault_end=None,
        quick=False,
        heuristic_used=True,
    )
    assert pairs["program"] == {
        "calibrated": 23815,
        "planned_range": 2,
        "representation": [],
    }
    assert pairs["erase"] == {
        "calibrated": 42,
        "planned_range": 0,
        "representation": [],
    }

    state_profile = load_profile(
        repo_root / "profiles" / "mcuboot_pr3011_move_broken_state_search.yaml"
    )
    state_search = _calibration_point_coverage(
        profile=state_profile,
        fault_points=[0],
        planned_fault_types=["rs"],
        calibrated_program_operations=23815,
        planned_program_operations=23815,
        calibrated_erases=42,
        fault_start=None,
        fault_end=None,
        quick=False,
        heuristic_used=True,
    )
    assert state_search["program"] == {
        "calibrated": 23815,
        "planned_range": 9,
        "representation": [],
    }

    state_profile.fault_sweep.phase2_fault.first_fault_types = [
        "interrupted_erase"
    ]
    erase_state_search = _calibration_point_coverage(
        profile=state_profile,
        fault_points=[0],
        planned_fault_types=["rs"],
        calibrated_program_operations=23815,
        planned_program_operations=23815,
        calibrated_erases=42,
        fault_start=None,
        fault_end=None,
        quick=False,
        heuristic_used=True,
    )
    assert erase_state_search["program"]["planned_range"] == 0
    assert erase_state_search["erase"] == {
        "calibrated": 42,
        "planned_range": 9,
        "representation": [],
    }

    heuristic = _calibration_point_coverage(
        profile=state_profile,
        fault_points=[0, 5, 9, 0, 1],
        planned_fault_types=["w", "w", "w", "e", "e"],
        calibrated_program_operations=20,
        planned_program_operations=10,
        calibrated_erases=2,
        fault_start=None,
        fault_end=None,
        quick=False,
        heuristic_used=True,
    )
    assert heuristic["program"] == {
        "calibrated": 20,
        "planned_range": 20,
        "representation": ["heuristic"],
        "representative_groups": {"0": 3, "5": 5, "9": 12},
    }
    assert heuristic["erase"] == {
        "calibrated": 2,
        "planned_range": 2,
        "representation": [],
    }

    bounded_erases = _calibration_point_coverage(
        profile=state_profile,
        fault_points=[1, 2],
        planned_fault_types=["e", "e"],
        calibrated_program_operations=20,
        planned_program_operations=10,
        calibrated_erases=5,
        fault_start=1,
        fault_end=3,
        quick=False,
        heuristic_used=False,
    )
    assert bounded_erases["erase"] == {
        "calibrated": 5,
        "planned_range": 2,
        "representation": [],
    }


def test_active_heuristic_uses_complete_trace_as_calibrated_program_domain() -> None:
    capped_calibration = type("CappedCalibration", (), {"total_writes": 512})()

    assert _calibrated_program_operation_count(
        calibration=capped_calibration,
        planned_program_operations=256,
        heuristic_summary={"total_writes": 23815},
    ) == 23815
    assert _calibrated_program_operation_count(
        calibration=capped_calibration,
        planned_program_operations=256,
        heuristic_summary=None,
    ) == 512


def test_sampled_coverage_requires_each_representative_to_be_evaluated() -> None:
    counts = build_point_counts(
        [
            {
                "fault_at": 0,
                "fault_type": "w",
                "operation_kind": "program",
                "fault_injected": True,
                "boot_outcome": "success",
            },
            {
                "fault_at": 4,
                "fault_type": "w",
                "operation_kind": "program",
                "fault_injected": True,
                "boot_outcome": "infra_error",
                "infrastructure_error": True,
            },
            {
                "fault_at": 9,
                "fault_type": "w",
                "operation_kind": "program",
                "fault_injected": False,
                "boot_outcome": "skipped",
            },
        ],
        planned_fault_types=["w", "w", "w"],
        expected_control_points=0,
        calibration={
            "program": {
                "calibrated": 12,
                "planned_range": 10,
                "representation": ["quick"],
                "representative_groups": {"0": 3, "4": 4, "9": 3},
            }
        },
    )

    program = counts["calibration"]["program"]
    assert program["cut_directly"] == 2
    assert program["represented_without_cut"] == 2
    assert program["outside_planned_range"] == 2
    assert program["not_cut_or_represented"] == 6


def test_calibration_coverage_emits_representative_groups_for_quick_plan() -> None:
    profile = load_profile(
        Path(__file__).resolve().parents[1]
        / "profiles"
        / "mcuboot_pr3011_move_broken.yaml"
    )
    coverage = _calibration_point_coverage(
        profile=profile,
        fault_points=[0, 5, 9],
        planned_fault_types=["w", "w", "w"],
        calibrated_program_operations=12,
        planned_program_operations=10,
        calibrated_erases=0,
        fault_start=None,
        fault_end=None,
        quick=True,
        heuristic_used=False,
    )

    assert coverage["program"]["representative_groups"] == {
        "0": 3,
        "5": 5,
        "9": 2,
    }


def test_mixed_campaign_accounts_every_kind_and_status() -> None:
    results = [
        {
            "is_control": True,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
        },
        {
            "fault_at": 1,
            "fault_type": "w",
            "operation_kind": "program",
            "fault_injected": True,
            "boot_outcome": "success",
        },
        {
            "fault_at": 2,
            "fault_type": "e",
            "operation_kind": "erase",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "issue": True,
        },
        {
            "fault_at": 3,
            "fault_type": "p2",
            "phase2_selection": "pairs",
            "fault_injected": False,
            "boot_outcome": "skipped",
            "skip_reason": "phase2_unsupported_backend",
            "phase2_fault": {
                "p1_fault_at": 3,
                "p2_fault_at": 4,
                "p1_fault_type": "w",
                "p2_fault_type": "w",
                "p1_injected": True,
                "p2_injected": False,
            },
        },
        {
            "fault_at": 4,
            "fault_type": "f",
            "fault_injected": False,
            "boot_outcome": "infra_error",
            "infrastructure_error": True,
        },
        {
            "fault_at": 5,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "success",
            "recovery_state_search": {
                "generation": 1,
                "chain": {
                    "cut_count": 1,
                    "cuts": [{"operation": "write", "operation_index": 5}],
                },
            },
            "recovery_state_search_summary": {
                "states_computed": 3,
                "states_booted": 2,
                "states_reused": 1,
                "stopped_reason": "complete",
            },
        },
        {
            "fault_at": 5,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "issue": True,
            "recovery_state_search": {
                "generation": 2,
                "chain": {
                    "cut_count": 2,
                    "cuts": [
                        {"operation": "write", "operation_index": 5},
                        {"operation": "write", "operation_index": 7},
                    ],
                },
                "equivalent_chains": [
                    {
                        "cut_count": 2,
                        "cuts": [
                            {"operation": "write", "operation_index": 6},
                            {"operation": "write", "operation_index": 8},
                        ],
                    }
                ],
            },
        },
    ]

    counts = build_point_counts(
        results,
        planned_fault_types=["w", "e", "p2:3:4:w:w", "f", "rs"],
        expected_control_points=1,
        issue_predicate=lambda result: bool(result.get("issue")),
        calibration={
            "program": {
                "calibrated": 10,
                "planned_range": 8,
                "representation": ["quick"],
            },
            "erase": {
                "calibrated": 4,
                "planned_range": 4,
                "representation": ["heuristic"],
            },
        },
    )

    kinds = counts["kinds"]
    assert kinds["control"] == {
        "label": "clean control",
        "requested": 1,
        "run": 1,
        "evaluated": 1,
        "skipped": 0,
        "infrastructure_error": 0,
        "timeout": 0,
        "reused": 0,
        "missing": 0,
        "issues": 0,
        "skip_reasons": {},
    }
    assert kinds["single_cut_program"]["requested"] == 1
    assert kinds["single_cut_program"]["run"] == 1
    assert kinds["single_cut_program"]["evaluated"] == 1
    assert kinds["state_search_single_cut"]["requested"] == 1
    assert kinds["state_search_single_cut"]["run"] == 1
    assert kinds["state_search_single_cut"]["evaluated"] == 1
    assert kinds["single_cut_erase"]["requested"] == 1
    assert kinds["single_cut_erase"]["run"] == 1
    assert kinds["single_cut_erase"]["issues"] == 1
    assert kinds["two_cut_pairs"]["requested"] == 1
    assert kinds["two_cut_pairs"]["run"] == 1
    assert kinds["two_cut_pairs"]["skipped"] == 1
    assert kinds["two_cut_pairs"]["skip_reasons"] == {
        "phase2_unsupported_backend": 1
    }
    assert kinds["two_cut_state_search"]["requested"] == 2
    assert kinds["two_cut_state_search"]["run"] == 1
    assert kinds["two_cut_state_search"]["evaluated"] == 1
    assert kinds["two_cut_state_search"]["reused"] == 1
    assert kinds["two_cut_state_search"]["issues"] == 1
    assert kinds["read_fault"]["requested"] == 1
    assert kinds["read_fault"]["run"] == 1
    assert kinds["read_fault"]["infrastructure_error"] == 1

    expected_kinds = {
        kind: {
            "label": label,
            "requested": 0,
            "run": 0,
            "evaluated": 0,
            "skipped": 0,
            "infrastructure_error": 0,
            "timeout": 0,
            "reused": 0,
            "missing": 0,
            "issues": 0,
            "skip_reasons": {},
        }
        for kind, label in POINT_KIND_LABELS.items()
    }
    expected_kinds["control"].update(requested=1, run=1, evaluated=1)
    expected_kinds["single_cut_program"].update(
        requested=1, run=1, evaluated=1
    )
    expected_kinds["single_cut_erase"].update(
        requested=1, run=1, evaluated=1, issues=1
    )
    expected_kinds["two_cut_pairs"].update(
        requested=1,
        run=1,
        skipped=1,
        skip_reasons={"phase2_unsupported_backend": 1},
    )
    expected_kinds["read_fault"].update(
        requested=1, run=1, infrastructure_error=1
    )
    expected_kinds["state_search_single_cut"].update(
        requested=1, run=1, evaluated=1
    )
    expected_kinds["two_cut_state_search"].update(
        requested=2, run=1, evaluated=1, reused=1, issues=1
    )
    assert kinds == expected_kinds
    assert counts["totals"] == {
        "requested": 8,
        "run": 7,
        "evaluated": 5,
        "skipped": 1,
        "infrastructure_error": 1,
        "timeout": 0,
        "reused": 1,
        "missing": 0,
        "issues": 2,
    }

    assert counts["calibration"] == {
        "program": {
            "calibrated": 10,
            "planned_range": 8,
            "cut_directly": 4,
            "represented_without_cut": 0,
            "outside_planned_range": 2,
            "not_cut_or_represented": 4,
            "representation": ["quick"],
        },
        "erase": {
            "calibrated": 4,
            "planned_range": 4,
            "cut_directly": 1,
            "represented_without_cut": 0,
            "outside_planned_range": 0,
            "not_cut_or_represented": 3,
            "representation": ["heuristic"],
        },
    }


def test_renderer_rows_lead_with_nonzero_kinds() -> None:
    counts = build_point_counts(
        [{"fault_type": "i", "fault_injected": True, "boot_outcome": "timeout"}],
        planned_fault_types=["i", "i"],
        expected_control_points=0,
    )

    assert [row["kind"] for row in point_count_rows(counts)] == [
        "glitch_instruction_skip"
    ]
    text = render_point_counts_text(counts)
    assert text.startswith("Point counts by kind")
    assert "glitch / instruction skip: 2 / 1 / 0 / 0 / 0 / 1 / 0 / 1 / 0" in text
    assert "writes: 0 / 0 / 0 / 0 / 0 / 0" in text
    markdown = render_point_counts_markdown(counts)
    assert markdown.startswith("### Point counts by kind")
    assert (
        "| glitch / instruction skip | 2 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |"
        in markdown
    )
    assert "### Calibration operation coverage" in markdown
    assert "| Operation | Calibrated | Planned range |" in markdown


def test_passing_and_failing_replay_cross_checks_use_canonical_accounting() -> None:
    counts = build_point_counts(
        [
            {
                "fault_at": 0,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "success",
                "trace_replay_cross_check": {
                    "checked": True,
                    "matched": True,
                },
            },
            {
                "fault_at": 1,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "infra_error",
                "infrastructure_error": True,
                "error_kind": "trace_replay_cross_check_mismatch",
                "trace_replay_cross_check": {
                    "checked": True,
                    "matched": False,
                },
            },
        ],
        planned_fault_types=["w", "w"],
        expected_control_points=0,
    )

    assert counts["schema_version"] == 2
    assert counts["trace_replay_cross_checks"] == {
        "run": 2,
        "passed": 1,
        "failed": 1,
    }
    program = counts["kinds"]["single_cut_program"]
    assert program["requested"] == 2
    assert program["run"] == 2
    assert program["evaluated"] == 1
    assert program["infrastructure_error"] == 1
    assert counts["totals"]["run"] == 2
    assert counts["totals"]["infrastructure_error"] == 1
    merged = merge_point_counts(counts, counts)
    assert merged["trace_replay_cross_checks"] == {
        "run": 4,
        "passed": 2,
        "failed": 2,
    }
    assert merged["kinds"]["single_cut_program"]["run"] == 4
    assert merged["kinds"]["single_cut_program"]["infrastructure_error"] == 2

    text = render_point_counts_text(counts)
    assert "Trace replay cross-checks (run / passed / failed): 2 / 1 / 1" in text
    markdown = render_point_counts_markdown(counts)
    assert "### Trace replay cross-checks" in markdown
    assert "| 2 | 1 | 1 |" in markdown
    html = render_point_counts_panel(
        {"summary": {"runtime_sweep": {"point_counts": counts}}}
    )
    assert "trace replay cross-checks" in html
    assert "<td>2</td><td>1</td><td>1</td>" in html
    profile_cell = format_profile_cell(
        {
            "verdict": "INCONCLUSIVE",
            "security_status": "INCONCLUSIVE",
            "point_counts": counts,
        }
    )
    assert "trace replay cross-checks: run 2, passed 1, failed 1" in profile_cell


def test_json_summary_and_html_render_from_the_same_count_block() -> None:
    results = [
        {
            "is_control": True,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
        },
        {
            "fault_at": 2,
            "fault_type": "e",
            "operation_kind": "erase",
            "fault_injected": False,
            "boot_outcome": "skipped",
            "skip_reason": "unsupported_backend",
        },
    ]
    summary = summarize_runtime_sweep(
        results,
        expected_fault_points=1,
        planned_fault_types=["e"],
        calibration_point_coverage={
            "program": {"calibrated": 7, "planned_range": 0},
            "erase": {
                "calibrated": 3,
                "planned_range": 3,
                "representation": ["quick"],
            },
        },
    )
    counts = summary["point_counts"]
    assert counts["kinds"]["single_cut_erase"]["requested"] == 1
    assert counts["kinds"]["single_cut_erase"]["run"] == 1
    assert counts["kinds"]["single_cut_erase"]["skipped"] == 1
    assert counts["kinds"]["single_cut_erase"]["skip_reasons"] == {
        "unsupported_backend": 1
    }
    assert counts["calibration"]["program"]["outside_planned_range"] == 7
    assert counts["calibration"]["erase"]["represented_without_cut"] == 0
    assert counts["calibration"]["erase"]["not_cut_or_represented"] == 3

    html = render_point_counts_panel(
        {"summary": {"runtime_sweep": {"point_counts": counts}}}
    )
    assert html.index("point counts by kind") < html.index("calibration operation coverage")
    assert "single-cut erase" in html
    assert "unsupported_backend=1" in html
    assert "Represented without cutting" in html
    assert "<th>Planned range</th>" in html
    assert "<th>Timeout</th>" in html
    assert "<th>Missing</th>" in html


def test_action_publishes_the_canonical_count_block(tmp_path: Path) -> None:
    counts = build_point_counts(
        [{"fault_type": "w", "fault_injected": True, "boot_outcome": "success"}],
        planned_fault_types=["w"],
        expected_control_points=0,
    )
    report = tmp_path / "report.json"
    outputs = tmp_path / "outputs"
    report.write_text(
        json.dumps(
            {
                "verdict": "PASS",
                "expect": {"should_find_issues": False},
                "summary": {
                    "runtime_sweep": {
                        "brick_rate": 0.0,
                        "issue_points": 0,
                        "point_counts": counts,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert publish_report(report, outputs, audit_exit=0) is True
    values = dict(
        line.split("=", 1)
        for line in outputs.read_text(encoding="utf-8").splitlines()
    )
    assert json.loads(values["point_counts_json"]) == counts

    summary_markdown = format_step_summary(
        {
            "profile": "proof",
            "mcuboot_commit": "abc",
            "zephyr_commit": "def",
            "verdict": "PASS",
            "security_status": "CLEAN",
            "points": 1,
            "issue_points": 0,
            "bricks": 0,
            "timeouts": 0,
            "wall_time_s": 1.0,
            "point_counts": counts,
        }
    )
    assert summary_markdown.index("Point counts by kind") < summary_markdown.index(
        "Calibration operation coverage"
    )
    assert summary_markdown.index("Point counts by kind") < summary_markdown.index(
        "| Field | Value |"
    )
    console_summary = format_console_summary(
        {
            "profile": "proof",
            "mcuboot_commit": "abc",
            "zephyr_commit": "def",
            "verdict": "PASS",
            "security_status": "CLEAN",
            "points": 1,
            "issue_points": 0,
            "bricks": 0,
            "timeouts": 0,
            "wall_time_s": 1.0,
            "point_counts": counts,
        }
    )
    assert console_summary.startswith("Point counts by kind")
    assert console_summary.index("single-cut program") < console_summary.index(
        "Main-runtime injected points"
    )
    profile_cell = format_profile_cell(
        {
            "verdict": "PASS",
            "security_status": "CLEAN",
            "points": 1,
            "issue_points": 0,
            "bricks": 0,
            "timeouts": 0,
            "point_counts": counts,
        }
    )
    assert (
        "single-cut program: requested 1, run 1, evaluated 1, skipped 0, "
        "infrastructure error 0, timeout 0, reused 0, missing 0, issues 0"
        in profile_cell
    )
    assert profile_cell.index("single-cut program") < profile_cell.index("`PASS`")
