"""Coverage for normalized security accounting across audit report layouts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from action_helpers import publish_report  # noqa: E402
from report_security_status import (  # noqa: E402
    attach_security_aggregate,
    build_security_aggregate,
    validate_security_aggregate,
)
from sweep import (  # noqa: E402
    _multi_component_issue_annotation,
    _multi_component_security_counts,
)


def _report(summary, *, verdict="PASS", should_find=False, **extra):
    return {
        "verdict": verdict,
        "expect": {"should_find_issues": should_find},
        "summary": summary,
        **extra,
    }


@pytest.mark.parametrize(
    ("summary", "status", "issues"),
    [
        (
            {"runtime_sweep": {"issue_points": 0, "brick_rate": 0.0}},
            "CLEAN",
            0,
        ),
        (
            {"runtime_sweep": {"issue_points": 2, "brick_rate": 0.25}},
            "FINDINGS",
            2,
        ),
        (
            {
                "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
                "multi_fault_runtime_sweep": {
                    "issue_points": 1,
                    "brick_rate": 0.5,
                },
            },
            "FINDINGS",
            1,
        ),
        (
            {
                "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
                "partial_staging": {
                    "issue_count": 1,
                    "campaign_complete": True,
                },
            },
            "FINDINGS",
            1,
        ),
        (
            {
                "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
                "state_fuzz": {
                    "status": "completed",
                    "iterations_requested": 2,
                    "iterations_completed": 2,
                    "findings": 1,
                    "infrastructure_errors": 0,
                    "timeouts": 0,
                },
            },
            "FINDINGS",
            1,
        ),
        (
            {
                "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
                "fuzz_crash": {
                    "status": "completed",
                    "generated_profiles": 1,
                    "results": 1,
                    "security_findings": 1,
                },
            },
            "FINDINGS",
            1,
        ),
        (
            {
                "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
                "terminal_error_paths": {
                    "candidates": 1,
                    "unresolved_candidates": 0,
                    "infrastructure_errors": 0,
                },
                "terminal_error_campaign": {
                    "candidates": 1,
                    "results": [{}],
                    "findings": [{"finding": "TERMINAL_ERROR_PATH_ESCAPED"}],
                    "unresolved_candidates": [],
                    "infrastructure_errors": [],
                },
            },
            "FINDINGS",
            1,
        ),
        (
            {
                "combined": {
                    "total_fault_points": 2,
                    "split_brain": 1,
                    "all_failed": 0,
                    "degraded": 0,
                    "state_relation_violations": 0,
                    "state_relation_control_violations": 0,
                },
                "per_component": {
                    "app": {
                        "campaign_complete": True,
                        "issue_points": 0,
                        "brick_rate": 0.0,
                    },
                    "radio": {
                        "campaign_complete": True,
                        "issue_points": 0,
                        "brick_rate": 0.0,
                    },
                },
            },
            "FINDINGS",
            1,
        ),
    ],
)
def test_supported_finding_summaries_are_accounted(summary, status, issues):
    aggregate = build_security_aggregate(_report(summary))
    assert aggregate["status"] == status
    assert aggregate["issue_points"] == issues


def _canonical_multi_component_report(
    *,
    record,
    component_issue_points=0,
    control_record=None,
    control_violations=None,
):
    record = dict(record)
    record.setdefault("fault_injected", True)
    record.setdefault("component_reliable", record["reliable"])
    record.setdefault("faulted_component", "app")
    record.setdefault(
        "component_issue_reasons", ["component"] if record["component_issue"] else []
    )
    record.setdefault(
        "issue_sources",
        (
            (
                ["component"]
                if record["component_reliable"] and record["component_issue"]
                else []
            )
            + (
                ["combined_outcome"]
                if record["reliable"]
                and record["combined_outcome"] != "success"
                else []
            )
            + (
                ["state_relation"]
                if record["reliable"] and record.get("invariant_violations")
                else []
            )
        ),
    )
    control_record = control_record or {
        "fault_injected": False,
        "component_reliable": True,
        "reliable": True,
        "component_issue": False,
        "security_issue": False,
    }
    control_record = dict(control_record)
    control_record.setdefault("component_reliable", control_record["reliable"])
    control_violations = control_violations or []
    control_record.setdefault(
        "issue_sources",
        (
            (
                ["component"]
                if control_record["component_reliable"] and control_record["component_issue"]
                else []
            )
            + (
                ["state_relation"]
                if control_record["reliable"] and control_violations
                else []
            )
        ),
    )
    combined_child_outcomes = {
        "app": {
            "split_brain": "no_boot",
            "all_failed": "no_boot",
            "success": "success",
            "degraded": "no_boot",
        }.get(record["combined_outcome"], "success"),
        "radio": {
            "split_brain": "success",
            "all_failed": "no_boot",
            "success": "success",
            "degraded": "unknown",
        }.get(record["combined_outcome"], "success"),
    }
    record.setdefault(
        "per_component",
        {
            "app": {
                "boot_outcome": combined_child_outcomes["app"],
                "faulted": True,
                "observed_control": False,
                "expected_outcome": "success",
            },
            "radio": {
                "boot_outcome": combined_child_outcomes["radio"],
                "faulted": False,
                "observed_control": True,
                "expected_outcome": "success",
            },
        },
    )
    control_record.setdefault(
        "per_component",
        {
            "app": {
                "boot_outcome": "success",
                "faulted": False,
                "observed_control": True,
                "expected_outcome": "success",
            },
            "radio": {
                "boot_outcome": "success",
                "faulted": False,
                "observed_control": True,
                "expected_outcome": "success",
            },
        },
    )
    control_record.setdefault("combined_outcome", "success")
    records = [record]
    component_reliable = sum(item["component_reliable"] for item in records)
    reliable = sum(item["reliable"] for item in records)
    security_issues = sum(item["security_issue"] for item in records)
    outcome = record["combined_outcome"]
    combined = {
        "total_fault_points": len(records),
        "component_reliable_fault_points": component_reliable,
        "reliable_fault_points": reliable,
        "unreliable_fault_points": len(records) - reliable,
        "control_reliable": control_record["reliable"],
        "security_issue_points": security_issues,
        "control_security_issue_points": int(control_record["security_issue"]),
        "split_brain": int(outcome == "split_brain"),
        "all_failed": int(outcome == "all_failed"),
        "success": int(outcome == "success"),
        "degraded": int(outcome == "degraded"),
        "state_relation_violations": sum(
            1
            for violation in (record.get("invariant_violations") or [])
            if violation.get("name") == "state_relations"
        ),
        "state_relation_control_violations": sum(
            1
            for violation in control_violations
            if violation.get("name") == "state_relations"
        ),
        "expected_outcomes": {"app": "success", "radio": "success"},
        "expected_combined_outcome": "success",
    }
    return _report(
        {
            "combined": combined,
            "per_component": {
                "app": {
                    "campaign_complete": record["component_reliable"],
                    "issue_points": component_issue_points,
                    "infrastructure_error_points": int(
                        not record["component_reliable"]
                    ),
                    "brick_rate": 0.0,
                },
                "radio": {
                    "campaign_complete": True,
                    "issue_points": 0,
                    "brick_rate": 0.0,
                },
            },
        },
        combined_results=records,
        control_combined_result=control_record,
        control_invariant_violations=control_violations,
    )


def test_multi_component_exact_union_does_not_double_count_overlapping_sources():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": True,
            "component_issue": True,
            "security_issue": True,
            "combined_outcome": "split_brain",
            "invariant_violations": [{"name": "state_relations"}],
        },
        component_issue_points=1,
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["finding_sources"] == {"summary.combined": 1}


def test_multi_component_semantic_only_component_finding_is_not_lost():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": True,
            "component_issue": True,
            "security_issue": True,
            "combined_outcome": "success",
        },
        component_issue_points=1,
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1


def test_multi_component_control_relations_count_one_control_observation():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": True,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "success",
        },
        control_record={
            "fault_injected": False,
            "reliable": True,
            "component_issue": False,
            "security_issue": True,
        },
        control_violations=[
            {"name": "state_relations", "description": "one"},
            {"name": "state_relations", "description": "two"},
        ],
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1


def test_control_relation_error_preserves_inconclusive_evidence():
    report = _canonical_multi_component_report(
        record={
            "reliable": True,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "success",
        },
        control_record={
            "fault_injected": False,
            "component_reliable": True,
            "reliable": False,
            "component_issue": False,
            "security_issue": False,
        },
        control_violations=[
            {
                "name": "state_relations_error",
                "infrastructure_error": True,
            }
        ],
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0
    assert "summary.combined control is unreliable" in aggregate["inconclusive_reasons"]


def test_multi_component_unreliable_degraded_record_is_inconclusive_not_finding():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": False,
            "component_issue": True,
            "security_issue": False,
            "combined_outcome": "degraded",
        },
        component_issue_points=1,
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0


def test_multi_component_local_finding_survives_unreliable_combined_context():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "component_reliable": True,
            "reliable": False,
            "component_issue": True,
            "security_issue": True,
            "combined_outcome": "success",
        },
        component_issue_points=1,
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"] == [
        "summary.combined reports unreliable_fault_points"
    ]


def test_producer_local_finding_with_bad_supporting_control_validates():
    record = _multi_component_issue_annotation(
        {
            "fault_injected": True,
            "boot_outcome": "success",
            "semantic_assertion_failures": [{"name": "version"}],
        },
        expected_outcome="success",
        combined_outcome="split_brain",
        relation_violations=[{"name": "state_relations"}],
        require_fault=True,
        supporting_controls_reliable=False,
    )
    record.update({
        "combined_outcome": "split_brain",
        "invariant_violations": [{"name": "state_relations"}],
    })
    control = _multi_component_issue_annotation(
        {"fault_injected": False, "boot_outcome": "success"},
        expected_outcome="success",
        combined_outcome="success",
        relation_violations=[],
        require_fault=False,
    )
    report = _canonical_multi_component_report(
        record=record,
        component_issue_points=1,
        control_record=control,
    )
    report["summary"]["combined"].update(
        _multi_component_security_counts([record], control)
    )

    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"] == [
        "summary.combined reports unreliable_fault_points"
    ]


def test_legacy_multi_component_overlap_uses_lower_bound_and_fails_closed():
    aggregate = build_security_aggregate(
        _report({
            "combined": {
                "total_fault_points": 1,
                "split_brain": 1,
                "all_failed": 0,
                "degraded": 0,
                "state_relation_violations": 1,
                "state_relation_control_violations": 0,
            },
            "per_component": {
                "app": {"issue_points": 1, "brick_rate": 0.0},
                "radio": {"issue_points": 0, "brick_rate": 0.0},
            },
        })
    )
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"] == [
        "summary.combined lacks exact unique issue accounting"
    ]


def test_canonical_multi_component_count_mismatch_is_rejected():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": True,
            "component_issue": True,
            "security_issue": True,
            "combined_outcome": "success",
        },
        component_issue_points=1,
    )
    report["summary"]["combined"]["security_issue_points"] = 0
    with pytest.raises(ValueError, match="does not match combined_results"):
        build_security_aggregate(report)


def test_canonical_multi_component_source_mismatch_is_rejected():
    report = _canonical_multi_component_report(
        record={
            "fault_injected": True,
            "reliable": False,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "split_brain",
            "issue_sources": ["combined_outcome"],
        }
    )
    with pytest.raises(ValueError, match="issue_sources"):
        build_security_aggregate(report)


def test_canonical_nested_component_map_mismatch_is_rejected():
    report = _canonical_multi_component_report(
        record={
            "faulted_component": "app",
            "reliable": True,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "split_brain",
        }
    )
    report["combined_results"][0]["per_component"]["app"]["faulted"] = False
    with pytest.raises(ValueError, match="fault/control map"):
        build_security_aggregate(report)


def test_canonical_combined_outcome_is_recomputed_from_nested_components():
    report = _canonical_multi_component_report(
        record={
            "reliable": True,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "split_brain",
        }
    )
    report["combined_results"][0]["per_component"]["radio"]["boot_outcome"] = "unknown"
    with pytest.raises(ValueError, match="combined_outcome"):
        build_security_aggregate(report)


def test_expected_non_success_combined_baseline_is_not_promoted():
    report = _canonical_multi_component_report(
        record={
            "reliable": True,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "all_failed",
        }
    )
    report["summary"]["combined"]["expected_outcomes"] = {
        "app": "no_boot",
        "radio": "no_boot",
    }
    report["summary"]["combined"]["expected_combined_outcome"] = "all_failed"
    for child in report["combined_results"][0]["per_component"].values():
        child["expected_outcome"] = "no_boot"
        child["boot_outcome"] = "no_boot"
    report["combined_results"][0]["expected_outcomes"] = {
        "app": "no_boot", "radio": "no_boot"
    }
    report["combined_results"][0]["expected_combined_outcome"] = "all_failed"
    report["combined_results"][0]["issue_sources"] = []
    report["control_combined_result"]["expected_outcomes"] = {
        "app": "no_boot", "radio": "no_boot"
    }
    report["control_combined_result"]["expected_combined_outcome"] = "all_failed"
    for child in report["control_combined_result"]["per_component"].values():
        child["expected_outcome"] = "no_boot"
        child["boot_outcome"] = "no_boot"
    report["control_combined_result"]["combined_outcome"] = "all_failed"
    report["control_state"] = report["control_combined_result"]["per_component"]
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "CLEAN"
    assert aggregate["issue_points"] == 0


def test_relation_evaluation_error_is_inconclusive_without_becoming_finding():
    report = _canonical_multi_component_report(
        record={
            "reliable": False,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "split_brain",
            "invariant_violations": [
                {"name": "state_relations_error", "infrastructure_error": True}
            ],
        }
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0


def test_non_reportable_fault_class_cannot_be_promoted_by_combined_outcome():
    report = _canonical_multi_component_report(
        record={
            "reliable": False,
            "component_issue": False,
            "security_issue": False,
            "combined_outcome": "split_brain",
            "fault_class": "bus_fault",
        }
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0


def test_initial_wrapper_missing_canonical_child_evidence_is_inconclusive():
    child_summary = {
        "combined": {
            "total_fault_points": 1,
            "component_reliable_fault_points": 1,
            "reliable_fault_points": 1,
            "unreliable_fault_points": 0,
            "control_reliable": True,
            "security_issue_points": 1,
            "control_security_issue_points": 0,
            "split_brain": 1,
            "all_failed": 0,
            "success": 0,
            "degraded": 0,
            "state_relation_violations": 0,
            "state_relation_control_violations": 0,
        },
        "per_component": {"app": {}, "radio": {}},
    }
    aggregate = build_security_aggregate(_report(
        {"initial_states": {"requested": 1, "completed": 1}},
        initial_state_results=[
            {"returncode": 0, "verdict": "PASS", "summary": child_summary}
        ],
    ))
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert any("point evidence is missing" in reason for reason in aggregate["inconclusive_reasons"])


def test_initial_wrapper_validates_retained_canonical_child_evidence():
    child = _canonical_multi_component_report(
        record={
            "reliable": True,
            "component_issue": False,
            "security_issue": True,
            "combined_outcome": "split_brain",
        }
    )
    entry = {
        "returncode": 0,
        "verdict": "PASS",
        "summary": child["summary"],
        "combined_results": child["combined_results"],
        "control_combined_result": child["control_combined_result"],
        "control_state": child.get("control_state"),
        "control_invariant_violations": child["control_invariant_violations"],
    }
    aggregate = build_security_aggregate(_report(
        {"initial_states": {"requested": 1, "completed": 1}},
        initial_state_results=[entry],
    ))
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert not any("canonical child" in reason for reason in aggregate["inconclusive_reasons"])


@pytest.mark.parametrize(
    "summary",
    [
        {
            "runtime_sweep": {
                "issue_points": 0,
                "brick_rate": 0.0,
                "campaign_complete": False,
            }
        },
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "partial_staging": {
                "issue_count": 0,
                "campaign_complete": False,
            },
        },
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "state_fuzz": {
                "status": "completed",
                "iterations_requested": 2,
                "iterations_completed": 1,
                "findings": 0,
                "infrastructure_errors": 0,
                "timeouts": 0,
            },
        },
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "fuzz_crash": {
                "status": "completed",
                "generated_profiles": 2,
                "results": 1,
                "security_findings": 0,
            },
        },
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "terminal_error_paths": {
                "candidates": 1,
                "unresolved_candidates": 0,
                "infrastructure_errors": 0,
            },
        },
        {
            "combined": {
                "total_fault_points": 0,
                "split_brain": 0,
                "all_failed": 0,
                "degraded": 0,
                "state_relation_violations": 0,
                "state_relation_control_violations": 0,
            },
            "per_component": {},
        },
        {"geometry_preflight": {"status": "mismatch"}},
        {"swap_progress_inference": {"status": "unavailable"}},
        {"security_state_erase": {"status": "unavailable"}},
        {"multi_fault_plan": {"sequences": 2}},
        {
            "initial_states": {
                "requested": 2,
                "completed": 1,
                "passed": 1,
            }
        },
        {"future_campaign": {"findings": 0}},
    ],
)
def test_supported_incomplete_summaries_never_publish_clean(summary):
    aggregate = build_security_aggregate(_report(summary))
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["inconclusive_reasons"]


def test_security_state_static_candidates_require_runtime_campaign():
    layout = {
        "status": "analyzed",
        "findings": [{"code": "SECURITY_STATE_SHARED_ERASE_UNIT"}],
    }
    missing = build_security_aggregate(
        _report({"persistent_state_layout": layout})
    )
    assert missing["status"] == "INCONCLUSIVE"

    evaluated = build_security_aggregate(
        _report({
            "runtime_sweep": {
                "issue_points": 0,
                "brick_rate": 0.0,
                "campaign_complete": True,
            },
            "persistent_state_layout": layout,
            "security_state_erase": {
                "status": "selected",
                "cutpoints": [{"fault_at": 1}],
            },
        })
    )
    assert evaluated["status"] == "CLEAN"


@pytest.mark.parametrize(
    "summary",
    [
        {"geometry_preflight": {"status": "match"}},
        {"geometry_preflight": {"status": "ok"}},
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "swap_progress_inference": {
                "status": "inferred",
                "boundary_count": 1,
            },
        },
        {"security_state_erase": {"status": "clean", "cutpoints": []}},
        {
            "runtime_sweep": {"issue_points": 0, "brick_rate": 0.0},
            "multi_fault_plan": {"sequences": 1},
            "multi_fault_runtime_sweep": {
                "issue_points": 0,
                "brick_rate": 0.0,
            },
        },
        {
            "state_fuzz": {
                "status": "completed",
                "iterations_requested": 1,
                "iterations_completed": 1,
                "findings": 0,
                "infrastructure_errors": 0,
                "timeouts": 0,
            },
        },
        {
            "fuzz_crash": {
                "status": "completed",
                "generated_profiles": 1,
                "results": 1,
                "security_findings": 0,
            },
        },
        {
            "terminal_error_paths": {
                "candidates": 1,
                "unresolved_candidates": 0,
                "infrastructure_errors": 0,
            },
            "terminal_error_campaign": {
                "candidates": 1,
                "results": [{}],
                "findings": [],
                "unresolved_candidates": [],
                "infrastructure_errors": [],
            },
        },
        {
            "persistent_state_layout": {
                "status": "analyzed",
                "findings": [],
            },
        },
        {
            "trigger_discovery": {
                "selected_strategy": "mcuboot_permanent_upgrade",
                "flash_map_check": {"status": "match"},
            },
        },
    ],
)
def test_supported_clean_summary_forms_remain_clean(summary):
    aggregate = build_security_aggregate(_report(summary))
    assert aggregate["status"] == "CLEAN"


@pytest.mark.parametrize(
    ("extra", "verdict", "status", "issues"),
    [
        (
            {"authorization_review_analysis": {
                "verdict": "FAIL",
                "findings": [{"id": "SIGNED_FIELD_NOT_REVIEWED"}],
            }},
            "FAIL -- authorization review mismatch",
            "FINDINGS",
            1,
        ),
        (
            {"authorization_review_analysis": {
                "verdict": "INCONCLUSIVE",
                "findings": [{"id": "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR"}],
            }},
            "INCONCLUSIVE -- authorization evidence incomplete",
            "INCONCLUSIVE",
            0,
        ),
        (
            {"boundary_campaign_results": [{"verdict": "FAIL"}]},
            "FAIL -- boundary campaign failed",
            "FINDINGS",
            1,
        ),
        (
            {"boundary_campaign_results": [{"verdict": "INCONCLUSIVE"}]},
            "INCONCLUSIVE -- boundary campaign incomplete",
            "INCONCLUSIVE",
            0,
        ),
    ],
)
def test_top_level_campaigns_are_accounted(extra, verdict, status, issues):
    aggregate = build_security_aggregate(
        _report({"runtime_sweep": {"issue_points": 0, "brick_rate": 0.0}}, verdict=verdict, **extra)
    )
    assert aggregate["status"] == status
    assert aggregate["issue_points"] == issues


def test_authorization_semantic_finding_retains_incomplete_evidence_diagnostic():
    aggregate = build_security_aggregate(
        _report(
            {"runtime_sweep": {"issue_points": 0, "brick_rate": 0.0}},
            verdict="FAIL -- authorization review mismatch",
            authorization_review_analysis={
                "verdict": "FAIL",
                "findings": [
                    {"id": "SIGNED_FIELD_NOT_REVIEWED"},
                    {"id": "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR"},
                ],
            },
        )
    )
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"]


def test_initial_state_matrix_accounts_for_nested_runtime_results():
    report = _report(
        {"initial_states": {"requested": 1, "completed": 1, "passed": 1}},
        should_find=True,
        initial_state_results=[{
            "returncode": 0,
            "verdict": "PASS",
            "summary": {
                "runtime_sweep": {"issue_points": 2, "brick_rate": 0.5}
            },
        }],
        boundary_campaign_results=[],
    )
    aggregate = build_security_aggregate(report)
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 2
    assert aggregate["brick_rate"] == 0.5


def test_trigger_discovery_failure_uses_report_verdict_as_fail_safe():
    aggregate = build_security_aggregate(
        _report(
            {"trigger_discovery": {"selected_strategy": None}},
            verdict="INCONCLUSIVE -- could not trigger firmware update",
        )
    )
    assert aggregate["status"] == "INCONCLUSIVE"


def test_successful_trigger_discovery_accepts_real_match_schema():
    trigger = {
        "selected_strategy": "mcuboot_permanent_upgrade",
        "failure_reason": None,
        "flash_map_check": {"status": "match"},
        "swap_algorithm": {"strategy": "swap_scratch"},
        "geometry_override": None,
        "attempts": [{"name": "mcuboot_permanent_upgrade", "selected": True}],
    }
    aggregate = build_security_aggregate(
        _report(
            {"trigger_discovery": {
                "selected_strategy": trigger["selected_strategy"],
                "flash_map_check": trigger["flash_map_check"],
            }},
            trigger_discovery=trigger,
        )
    )
    assert aggregate["status"] == "CLEAN"


def test_successful_trigger_discovery_accepts_applied_geometry_override():
    trigger = {
        "selected_strategy": "mcuboot_offset_image",
        "failure_reason": None,
        "flash_map_check": {"status": "mismatch"},
        "geometry_override": {"status": "applied"},
        "attempts": [{"name": "mcuboot_offset_image", "selected": True}],
    }
    aggregate = build_security_aggregate(
        _report(
            {"trigger_discovery": {
                "selected_strategy": trigger["selected_strategy"],
                "flash_map_check": trigger["flash_map_check"],
            }},
            trigger_discovery=trigger,
        )
    )
    assert aggregate["status"] == "CLEAN"


def test_expected_findings_without_evidence_are_inconclusive():
    aggregate = build_security_aggregate(
        _report(
            {"runtime_sweep": {"issue_points": 0, "brick_rate": 0.0}},
            should_find=True,
        )
    )
    assert aggregate["status"] == "INCONCLUSIVE"


def test_confirmed_findings_take_precedence_over_incomplete_campaigns():
    aggregate = build_security_aggregate(
        _report({
            "runtime_sweep": {
                "issue_points": 1,
                "brick_rate": 0.5,
                "campaign_complete": False,
            },
        })
    )
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"]


def test_runtime_infrastructure_error_is_not_a_confirmed_finding():
    aggregate = build_security_aggregate(
        _report({
            "runtime_sweep": {
                "issue_points": 1,
                "brick_rate": 0.0,
                "campaign_complete": False,
                "infrastructure_error_points": 1,
                "failure_outcomes": {"infra_error": 1},
            },
        })
    )
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0
    assert aggregate["finding_sources"] == {}


def test_confirmed_runtime_finding_survives_separate_infrastructure_error():
    aggregate = build_security_aggregate(
        _report({
            "runtime_sweep": {
                "issue_points": 2,
                "brick_rate": 0.5,
                "campaign_complete": False,
                "infrastructure_error_points": 1,
                "failure_outcomes": {"infra_error": 1, "no_boot": 1},
            },
        })
    )
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"]


def test_unreliable_control_issue_is_not_a_confirmed_finding():
    aggregate = build_security_aggregate(
        _report({
            "runtime_sweep": {
                "issue_points": 0,
                "brick_rate": 0.0,
                "campaign_complete": False,
                "control_infrastructure_error_points": 1,
                "control": {"issue_count": 1},
            },
        })
    )
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0


@pytest.mark.parametrize(
    "unreliable",
    [
        {"infrastructure_error": 1},
        {"timeout": 1},
        {"complete_image_failed": 1},
    ],
)
def test_partial_staging_unreliable_result_is_not_a_confirmed_finding(unreliable):
    aggregate = build_security_aggregate(
        _report({
            "partial_staging": {
                "issue_count": 1,
                "campaign_complete": False,
                **unreliable,
            },
        })
    )
    assert aggregate["status"] == "INCONCLUSIVE"
    assert aggregate["issue_points"] == 0


def test_partial_staging_finding_survives_separate_infrastructure_error():
    aggregate = build_security_aggregate(
        _report({
            "partial_staging": {
                "issue_count": 2,
                "campaign_complete": False,
                "partial_image_booted": 1,
                "infrastructure_error": 1,
            },
        })
    )
    assert aggregate["status"] == "FINDINGS"
    assert aggregate["issue_points"] == 1
    assert aggregate["inconclusive_reasons"]


def test_action_rejects_tampered_emitted_aggregate(tmp_path):
    report = _report(
        {"runtime_sweep": {"issue_points": 1, "brick_rate": 0.5}},
        verdict="PASS",
        should_find=True,
    )
    attach_security_aggregate(report)
    report["security_aggregate"]["status"] = "CLEAN"
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match report evidence"):
        publish_report(path, tmp_path / "outputs", audit_exit=0, regression_mode=True)


def test_regression_mode_does_not_accept_incomplete_campaigns(tmp_path):
    report = _report(
        {"runtime_sweep": {
            "issue_points": 1,
            "brick_rate": 0.5,
            "campaign_complete": False,
        }},
        verdict="PASS",
        should_find=True,
    )
    attach_security_aggregate(report)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    outputs = tmp_path / "outputs"
    assert not publish_report(path, outputs, audit_exit=0, regression_mode=True)
    written = outputs.read_text(encoding="utf-8")
    assert "security_status=FINDINGS\n" in written
    assert "verdict=FAIL\n" in written


@pytest.mark.parametrize(
    "report",
    [
        _report({"runtime_sweep": []}),
        _report({"runtime_sweep": {"issue_points": -1, "brick_rate": 0.0}}),
        _report({"runtime_sweep": {"issue_points": 0, "brick_rate": 2.0}}),
        _report({"terminal_error_campaign": {
            "candidates": 1,
            "results": [],
            "findings": {},
        }}),
        _report({"per_component": []}),
    ],
)
def test_malformed_report_evidence_is_rejected(report):
    with pytest.raises(ValueError):
        build_security_aggregate(report)


def test_malformed_emitted_aggregate_is_rejected():
    aggregate = build_security_aggregate(
        _report({"runtime_sweep": {"issue_points": 0, "brick_rate": 0.0}})
    )
    aggregate["schema_version"] = True
    with pytest.raises(ValueError, match="schema_version"):
        validate_security_aggregate(aggregate)
