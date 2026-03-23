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
    classify_failure_class,
    result_has_issues,
    result_is_brick,
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
