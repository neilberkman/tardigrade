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


if __name__ == "__main__":
    unittest.main()
