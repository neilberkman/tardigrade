#!/usr/bin/env python3
"""Unit tests for _effective_boot_result and its integration into verdicting."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_classification import (
    _effective_boot_result,
    _effective_boot_signals,
    classify_failure_class,
    classify_issue_category,
    result_has_issues,
    result_is_brick,
    result_is_timeout,
    result_issue_reasons,
)
from audit_report import summarize_runtime_sweep


class EffectiveBootResultTests(unittest.TestCase):
    """Core helper logic."""

    def test_no_multi_boot_returns_raw(self):
        result = {"boot_outcome": "wrong_image", "boot_slot": "staging"}
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "wrong_image")
        self.assertEqual(slot, "staging")

    def test_rollback_converged_uses_final(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "rollback_converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "success")
        self.assertEqual(slot, "exec")

    def test_converged_uses_final(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "success")
        self.assertEqual(slot, "exec")

    def test_rollback_missing_returns_raw(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "rollback_missing",
                "final_outcome": "success",
                "final_slot": "staging",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "wrong_image")
        self.assertEqual(slot, "staging")

    def test_rollback_late_returns_raw(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "rollback_late",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "wrong_image")
        self.assertEqual(slot, "staging")

    def test_oscillating_returns_raw(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "rollback_observed_oscillating",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "wrong_image")
        self.assertEqual(slot, "staging")

    def test_annotated_non_success_statuses_are_not_promoted(self):
        """annotate_boot_span_result copies final_boot_outcome regardless of status;
        _effective_boot_result must still refuse to promote non-success statuses."""
        non_promoted = (
            "oscillating",
            "rollback_missing",
            "rollback_late",
            "rollback_observed_unconfirmed",
            "rollback_observed_oscillating",
            "changed_unconfirmed",
            "stuck_revert",
            "initial_no_boot_recovered",
            "timeout",
        )
        for status in non_promoted:
            with self.subTest(status=status):
                result = {
                    "boot_outcome": "hard_fault",
                    "boot_slot": None,
                    "initial_boot_outcome": "hard_fault",
                    "initial_boot_slot": None,
                    "final_boot_outcome": "success",
                    "final_boot_slot": "exec",
                    "multi_boot_analysis": {
                        "status": status,
                        "initial_outcome": "hard_fault",
                        "final_outcome": "success",
                        "final_slot": "exec",
                    },
                }
                self.assertEqual(_effective_boot_result(result), ("hard_fault", None))
                self.assertTrue(result_is_brick(result))

    def test_recovered_after_failure_is_promoted(self):
        result = {
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "initial_boot_outcome": "hard_fault",
            "initial_boot_slot": None,
            "final_boot_outcome": "success",
            "final_boot_slot": "exec",
            "multi_boot_analysis": {
                "status": "recovered_after_failure",
                "initial_outcome": "hard_fault",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        self.assertEqual(_effective_boot_result(result), ("success", "exec"))
        self.assertFalse(result_is_brick(result))

    def test_failed_after_success_promotes_failing_cycle_and_signals(self):
        for outcome, slot, is_brick, failure_class, expected_reasons in (
            (
                "hard_fault",
                None,
                True,
                "unrecoverable",
                ["boot_outcome", "memory_check"],
            ),
            (
                "no_boot",
                None,
                True,
                "unrecoverable",
                ["boot_outcome"],
            ),
            (
                "memory_checks_unmet",
                "exec",
                False,
                "memory_checks_unmet",
                ["boot_outcome", "memory_check"],
            ),
        ):
            with self.subTest(outcome=outcome):
                c0_signals = {"expectations_met": True, "memory_checks_ok": True}
                c1_signals = (
                    {"expectations_met": False, "memory_checks_ok": False}
                    if outcome != "no_boot"
                    else {"execution_observed": False}
                )
                result = {
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "fault_class": "recoverable",
                    "initial_boot_outcome": "success",
                    "initial_boot_slot": "exec",
                    "final_boot_outcome": outcome,
                    "final_boot_slot": slot,
                    "signals": dict(c0_signals),
                    "boot_cycles": [
                        {
                            "cycle": 0,
                            "boot_outcome": "success",
                            "boot_slot": "exec",
                            "signals": dict(c0_signals),
                        },
                        {
                            "cycle": 1,
                            "boot_outcome": outcome,
                            "boot_slot": slot,
                            "signals": dict(c1_signals),
                        },
                    ],
                    "multi_boot_analysis": {
                        "status": "failed_after_success",
                        "failed_at_cycle": 1,
                        "initial_outcome": "success",
                        "final_outcome": outcome,
                        "final_slot": slot,
                    },
                }
                self.assertEqual(_effective_boot_result(result), (outcome, slot))
                self.assertEqual(_effective_boot_signals(result), c1_signals)
                self.assertEqual(result_is_brick(result), is_brick)
                self.assertTrue(result_has_issues(result, "success"))
                self.assertEqual(result_issue_reasons(result, "success"), expected_reasons)
                self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")
                self.assertEqual(classify_failure_class(result), failure_class)

    def test_changed_unconfirmed_revert_stays_unpromoted(self):
        for final_outcome in ("success", "wrong_image"):
            with self.subTest(final_outcome=final_outcome):
                result = {
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "initial_boot_outcome": "success",
                    "initial_boot_slot": "staging",
                    "final_boot_outcome": final_outcome,
                    "final_boot_slot": "exec",
                    "signals": {"expectations_met": True, "vtor_ok": True},
                    "boot_cycles": [
                        {
                            "cycle": 0,
                            "boot_outcome": "success",
                            "boot_slot": "staging",
                            "signals": {"expectations_met": True, "vtor_ok": True},
                        },
                        {
                            "cycle": 1,
                            "boot_outcome": final_outcome,
                            "boot_slot": "exec",
                            "signals": {
                                "expectations_met": final_outcome == "success",
                                "vtor_ok": final_outcome == "success",
                            },
                        },
                    ],
                    "multi_boot_analysis": {
                        "status": "changed_unconfirmed",
                        "initial_outcome": "success",
                        "final_outcome": final_outcome,
                        "final_slot": "exec",
                    },
                }
                self.assertEqual(_effective_boot_result(result), ("success", "staging"))
                self.assertTrue(_effective_boot_signals(result)["vtor_ok"])
                self.assertFalse(result_is_brick(result))
                self.assertFalse(result_has_issues(result, "success"))

    def test_oscillating_ending_in_failure_after_initial_success_is_promoted(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "initial_boot_outcome": "success",
            "initial_boot_slot": "exec",
            "final_boot_outcome": "hard_fault",
            "final_boot_slot": None,
            "signals": {"expectations_met": True, "memory_checks_ok": True},
            "boot_cycles": [
                {
                    "cycle": 0,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "signals": {"expectations_met": True, "memory_checks_ok": True},
                },
                {
                    "cycle": 1,
                    "boot_outcome": "hard_fault",
                    "boot_slot": None,
                    "signals": {"expectations_met": False, "memory_checks_ok": False},
                },
                {
                    "cycle": 2,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "signals": {"expectations_met": True, "memory_checks_ok": True},
                },
                {
                    "cycle": 3,
                    "boot_outcome": "hard_fault",
                    "boot_slot": None,
                    "signals": {"expectations_met": False, "memory_checks_ok": False},
                },
            ],
            "multi_boot_analysis": {
                "status": "oscillating",
                "initial_outcome": "success",
                "final_outcome": "hard_fault",
                "final_slot": None,
            },
        }
        self.assertEqual(_effective_boot_result(result), ("hard_fault", None))
        self.assertFalse(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertTrue(result_is_brick(result))
        self.assertEqual(
            result_issue_reasons(result, "success"),
            ["boot_outcome", "memory_check"],
        )
        self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")

    def test_converged_with_no_final_outcome_returns_raw(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "converged",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "wrong_image")
        self.assertEqual(slot, "staging")

    def test_timeout_flag_promotes_raw_no_boot_to_timeout(self):
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "timeout": True,
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "timeout")
        self.assertIsNone(slot)


class RawFieldsPreservedTests(unittest.TestCase):
    """Verify _effective_boot_result does NOT mutate the result dict."""

    def test_raw_fields_unchanged(self):
        result = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "multi_boot_analysis": {
                "status": "rollback_converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        _effective_boot_result(result)
        self.assertEqual(result["boot_outcome"], "wrong_image")
        self.assertEqual(result["boot_slot"], "staging")


class IssueDetectionIntegrationTests(unittest.TestCase):
    """Verify that verdicting functions use effective results."""

    def _rollback_converged_result(self):
        return {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
            "multi_boot_analysis": {
                "status": "rollback_converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }

    def _rollback_missing_result(self):
        return {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
            "multi_boot_analysis": {
                "status": "rollback_missing",
                "final_outcome": "success",
                "final_slot": "staging",
            },
        }

    def test_rollback_converged_no_boot_outcome_issue(self):
        """rollback_converged + final success should NOT flag boot_outcome."""
        reasons = result_issue_reasons(self._rollback_converged_result(), "success")
        self.assertNotIn("boot_outcome", reasons)

    def test_rollback_missing_flags_boot_outcome(self):
        """rollback_missing should still flag boot_outcome."""
        reasons = result_issue_reasons(self._rollback_missing_result(), "success")
        self.assertIn("boot_outcome", reasons)

    def test_rollback_converged_has_no_issues(self):
        self.assertFalse(
            result_has_issues(self._rollback_converged_result(), "success")
        )

    def test_rollback_missing_has_issues(self):
        self.assertTrue(
            result_has_issues(self._rollback_missing_result(), "success")
        )

    def test_rollback_converged_not_brick(self):
        self.assertFalse(result_is_brick(self._rollback_converged_result()))

    def test_no_boot_with_converged_not_brick(self):
        """no_boot raw + converged final success is NOT a brick."""
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "multi_boot_analysis": {
                "status": "converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        self.assertFalse(result_is_brick(result))

    def test_no_boot_without_execution_recovery_stays_brick(self):
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "signals": {"execution_observed": False},
            "multi_boot_analysis": {
                "status": "initial_no_boot_recovered",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        self.assertTrue(result_is_brick(result))

    def test_no_boot_without_multi_boot_is_brick(self):
        result = {"boot_outcome": "no_boot", "boot_slot": None}
        self.assertTrue(result_is_brick(result))

    def test_followup_timeout_preserves_initial_no_boot_without_convergence(self):
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "initial_boot_outcome": "no_boot",
            "initial_boot_slot": None,
            "final_boot_outcome": "timeout",
            "final_boot_slot": None,
            "boot_cycles": [
                {
                    "cycle": 0,
                    "boot_outcome": "no_boot",
                    "stop_reason": "no_boot_stall(20s_emulated)",
                },
                {
                    "cycle": 1,
                    "boot_outcome": "timeout",
                    "stop_reason": "wall_timeout(10s)",
                },
            ],
            "multi_boot_analysis": {
                "status": "timeout",
                "initial_outcome": "no_boot",
                "final_outcome": "timeout",
            },
        }
        outcome, slot = _effective_boot_result(result)
        self.assertEqual(outcome, "no_boot")
        self.assertIsNone(slot)
        self.assertTrue(result_is_brick(result))
        self.assertTrue(result_is_timeout(result))

    def test_classify_rollback_converged_is_recoverable(self):
        self.assertEqual(
            classify_failure_class(self._rollback_converged_result()),
            "recoverable",
        )

    def test_classify_rollback_missing_is_wrong_image(self):
        self.assertEqual(
            classify_failure_class(self._rollback_missing_result()),
            "wrong_image",
        )


class SummarizeRuntimeSweepTests(unittest.TestCase):
    """Verify summarize_runtime_sweep uses effective results for control."""

    def test_control_with_rollback_converged_no_issues(self):
        """Control point with raw wrong_image but rollback_converged should
        have issue_count=0 and effective_outcome=success."""
        control = {
            "is_control": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": False,
            "multi_boot_analysis": {
                "status": "rollback_converged",
                "final_outcome": "success",
                "final_slot": "exec",
            },
        }
        summary = summarize_runtime_sweep([control])
        ctrl_summary = summary["control"]
        # Raw fields preserved in summary.
        self.assertEqual(ctrl_summary["boot_outcome"], "wrong_image")
        self.assertEqual(ctrl_summary["boot_slot"], "staging")
        # Effective fields present.
        self.assertEqual(ctrl_summary["effective_outcome"], "success")
        self.assertEqual(ctrl_summary["effective_slot"], "exec")
        # No issues since effective outcome is success.
        self.assertEqual(ctrl_summary["issue_count"], 0)

    def test_control_with_rollback_missing_has_issues(self):
        control = {
            "is_control": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": False,
            "multi_boot_analysis": {
                "status": "rollback_missing",
                "final_outcome": "success",
                "final_slot": "staging",
            },
        }
        summary = summarize_runtime_sweep([control])
        ctrl_summary = summary["control"]
        self.assertEqual(ctrl_summary["effective_outcome"], "wrong_image")
        self.assertGreater(ctrl_summary["issue_count"], 0)

    def test_control_summary_preserves_fault_snapshot_file(self):
        control = {
            "is_control": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_injected": False,
            "fault_snapshot_file": "/tmp/control_snapshot.bin",
        }
        summary = summarize_runtime_sweep([control])
        self.assertEqual(
            summary["control"]["fault_snapshot_file"],
            "/tmp/control_snapshot.bin",
        )

    def test_sweep_rollback_converged_not_counted_as_failure(self):
        """A fault point with raw wrong_image but rollback_converged final
        success should not be an issue point."""
        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            {
                "is_control": False,
                "boot_outcome": "wrong_image",
                "boot_slot": "staging",
                "fault_injected": True,
                "fault_at": 5,
                "multi_boot_analysis": {
                    "status": "rollback_converged",
                    "final_outcome": "success",
                    "final_slot": "exec",
                },
            },
        ]
        summary = summarize_runtime_sweep(results)
        self.assertEqual(summary["issue_points"], 0)
        self.assertEqual(summary["bricks"], 0)
        self.assertEqual(summary["recoveries"], 1)

    def test_timeout_point_is_counted_separately_not_as_brick_or_recovery(self):
        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            {
                "is_control": False,
                "fault_at": 17,
                "fault_injected": True,
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "timeout": True,
                "error": "renode-test batch timed out",
            },
        ]
        summary = summarize_runtime_sweep(results)
        self.assertEqual(summary["timeout_points"], 1)
        self.assertEqual(summary["bricks"], 0)
        self.assertEqual(summary["issue_points"], 0)
        self.assertEqual(summary["recoveries"], 0)


if __name__ == "__main__":
    unittest.main()
