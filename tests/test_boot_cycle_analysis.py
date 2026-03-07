#!/usr/bin/env python3
"""Unit tests for pure boot-cycle analysis helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.boot_cycle_analysis import analyze_boot_cycles


class BootCycleAnalysisTests(unittest.TestCase):
    def test_converged_without_rollback_expectation(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "converged")
        self.assertEqual(analysis["converged_at_cycle"], 0)
        self.assertEqual(analysis["final_slot"], "exec")

    def test_rollback_converged(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=3,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(analysis["status"], "rollback_converged")
        self.assertEqual(analysis["rollback_cycle"], 1)
        self.assertEqual(analysis["rollback_target_slot"], "exec")

    def test_rollback_missing(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "staging", "boot_outcome": "success"},
            ],
            requested_cycles=3,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(analysis["status"], "rollback_missing")
        self.assertNotIn("rollback_cycle", analysis)

    def test_rollback_not_applicable_when_target_matches_initial(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=2,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(analysis["status"], "converged")
        self.assertTrue(analysis["rollback_not_applicable"])

    def test_rollback_late(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=3,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(analysis["status"], "rollback_late")
        self.assertEqual(analysis["rollback_cycle"], 2)


if __name__ == "__main__":
    unittest.main()
