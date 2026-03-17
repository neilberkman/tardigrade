#!/usr/bin/env python3
"""Unit tests for explicit initial/final boot-span reporting."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import compute_verdict, summarize_runtime_sweep  # noqa: E402
from fault_classification import (  # noqa: E402
    classify_failure_class,
    is_resilient_rollback,
    result_has_issues,
    result_issue_reasons,
)
from profile_loader import ExpectConfig  # noqa: E402
from render_results_html import render_audit_card, render_fault_grid  # noqa: E402
from run_oss_validation import is_brick  # noqa: E402


class OssValidationBootSpanTests(unittest.TestCase):
    def test_is_brick_uses_final_boot_outcome(self) -> None:
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "initial_boot_outcome": "no_boot",
            "final_boot_outcome": "success",
            "final_boot_slot": "exec",
        }
        self.assertFalse(is_brick(result))

    def test_is_brick_falls_back_to_raw_outcome(self) -> None:
        self.assertTrue(is_brick({"boot_outcome": "hard_fault", "boot_slot": None}))


class HtmlBootSpanRenderingTests(unittest.TestCase):
    def test_fault_grid_uses_final_boot_outcome_for_color(self) -> None:
        html_doc = render_fault_grid(
            [
                {
                    "fault_type": "w",
                    "fault_at": 7,
                    "fault_injected": True,
                    "boot_outcome": "wrong_image",
                    "initial_boot_outcome": "wrong_image",
                    "final_boot_outcome": "success",
                }
            ]
        )
        self.assertIn("#059669", html_doc)
        self.assertIn("initial=wrong_image final=success", html_doc)

    def test_audit_card_shows_control_initial_and_final_outcomes(self) -> None:
        card, summary = render_audit_card(
            Path("/tmp/report.json"),
            {
                "profile": "demo",
                "verdict": "pass",
                "summary": {
                    "runtime_sweep": {
                        "bricks": 0,
                        "total_fault_points": 1,
                        "brick_rate": 0.0,
                        "control": {
                            "boot_outcome": "wrong_image",
                            "initial_boot_outcome": "wrong_image",
                            "final_boot_outcome": "success",
                            "effective_outcome": "success",
                        },
                    }
                },
                "runtime_sweep_results": [],
            },
        )
        self.assertIn("control initial", card)
        self.assertIn("control final", card)
        self.assertEqual(summary["control_initial_outcome"], "wrong_image")
        self.assertEqual(summary["control_final_outcome"], "success")


class ResilientRollbackTests(unittest.TestCase):
    """Verify that correct rollback after fault injection is not an issue."""

    def _resilient_rollback_result(self) -> dict:
        """A fault during OTA update; bootloader rolled back to original image."""
        return {
            "fault_injected": True,
            "fault_at": 42,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "initial_boot_outcome": "success",
            "initial_boot_slot": "exec",
            "final_boot_outcome": "wrong_image",
            "final_boot_slot": "exec",
        }

    def test_is_resilient_rollback_positive(self) -> None:
        self.assertTrue(is_resilient_rollback(self._resilient_rollback_result()))

    def test_is_resilient_rollback_no_fault_injected(self) -> None:
        r = self._resilient_rollback_result()
        r["fault_injected"] = False
        self.assertFalse(is_resilient_rollback(r))

    def test_is_resilient_rollback_raw_not_success(self) -> None:
        r = self._resilient_rollback_result()
        r["boot_outcome"] = "no_boot"
        r["initial_boot_outcome"] = "no_boot"
        self.assertFalse(is_resilient_rollback(r))

    def test_is_resilient_rollback_final_not_wrong_image(self) -> None:
        r = self._resilient_rollback_result()
        r["final_boot_outcome"] = "no_boot"
        self.assertFalse(is_resilient_rollback(r))

    def test_resilient_rollback_not_issue_reason(self) -> None:
        reasons = result_issue_reasons(self._resilient_rollback_result(), "success")
        self.assertNotIn("boot_outcome", reasons)

    def test_resilient_rollback_no_issues(self) -> None:
        self.assertFalse(
            result_has_issues(self._resilient_rollback_result(), "success")
        )

    def test_resilient_rollback_classified_correctly(self) -> None:
        self.assertEqual(
            classify_failure_class(self._resilient_rollback_result()),
            "resilient_rollback",
        )

    def test_resilient_rollback_with_invariant_still_reports_invariant(self) -> None:
        """Invariant violations are independent of rollback classification."""
        r = self._resilient_rollback_result()
        r["invariant_violations"] = [{"name": "multi_boot_converges"}]
        reasons = result_issue_reasons(r, "success")
        self.assertNotIn("boot_outcome", reasons)
        self.assertIn("invariant", reasons)

    def test_summary_counts_resilient_rollbacks(self) -> None:
        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            self._resilient_rollback_result(),
        ]
        summary = summarize_runtime_sweep(results)
        self.assertEqual(summary["resilient_rollbacks"], 1)
        self.assertEqual(summary["issue_points"], 0)
        self.assertEqual(summary["bricks"], 0)
        self.assertEqual(summary["recoveries"], 1)

    def test_verdict_pass_with_resilient_rollbacks(self) -> None:
        summary = {
            "total_fault_points": 6,
            "bricks": 0,
            "issue_points": 0,
            "semantic_issue_points": 0,
            "invariant_issue_points": 0,
            "recoveries": 6,
            "resilient_rollbacks": 6,
        }
        expect = ExpectConfig(should_find_issues=False)
        verdict = compute_verdict(summary, expect)
        self.assertTrue(verdict.startswith("PASS"))
        self.assertIn("6 resilient rollbacks", verdict)
        self.assertNotIn("FAIL", verdict)

    def test_verdict_pass_with_rollbacks_and_invariant_observations(self) -> None:
        summary = {
            "total_fault_points": 9,
            "bricks": 0,
            "issue_points": 0,
            "semantic_issue_points": 0,
            "invariant_issue_points": 3,
            "recoveries": 9,
            "resilient_rollbacks": 6,
        }
        expect = ExpectConfig(should_find_issues=False)
        verdict = compute_verdict(summary, expect)
        self.assertTrue(verdict.startswith("PASS"))
        self.assertIn("6 resilient rollbacks", verdict)
        self.assertIn("3 invariant observations", verdict)

    def test_real_wrong_image_without_rollback_still_fails(self) -> None:
        """wrong_image without successful raw boot is still an issue."""
        result = {
            "fault_injected": True,
            "fault_at": 10,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "final_boot_outcome": "wrong_image",
            "final_boot_slot": "staging",
        }
        self.assertFalse(is_resilient_rollback(result))
        reasons = result_issue_reasons(result, "success")
        self.assertIn("boot_outcome", reasons)
        self.assertEqual(classify_failure_class(result), "wrong_image")


if __name__ == "__main__":
    unittest.main()
