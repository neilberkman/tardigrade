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

    def test_rollback_skipped_when_target_matches_initial(self) -> None:
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
        self.assertTrue(analysis["rollback_skipped"])

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

    def test_initial_no_boot_without_execution_is_not_promoted_to_converged(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "no_boot",
                    "signals": {"execution_observed": False},
                },
                {
                    "cycle": 1,
                    "boot_slot": "exec",
                    "boot_outcome": "success",
                    "signals": {"execution_observed": True},
                },
                {
                    "cycle": 2,
                    "boot_slot": "exec",
                    "boot_outcome": "success",
                    "signals": {"execution_observed": True},
                },
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "initial_no_boot_recovered")
        self.assertFalse(analysis["initial_execution_observed"])

    def test_initial_wall_timeout_is_inconclusive(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "timeout",
                    "stop_reason": "wall_timeout(30s)",
                    "signals": {"execution_observed": False},
                },
                {
                    "cycle": 1,
                    "boot_slot": "exec",
                    "boot_outcome": "success",
                },
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["status"], "timeout")
        self.assertEqual(analysis["timeout_cycles"], [0])
        self.assertNotIn("converged_at_cycle", analysis)

    def test_followup_wall_timeout_does_not_erase_initial_no_boot_stall(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "no_boot",
                    "stop_reason": "no_boot_stall(20.00s_emulated)",
                    "signals": {"execution_observed": False},
                },
                {
                    "cycle": 1,
                    "boot_slot": None,
                    "boot_outcome": "timeout",
                    "stop_reason": "wall_timeout(10s)",
                },
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["initial_outcome"], "no_boot")
        self.assertEqual(analysis["final_outcome"], "timeout")
        self.assertEqual(analysis["status"], "timeout")
        self.assertNotIn("converged_at_cycle", analysis)

    def test_no_boot_stall_remains_a_concrete_terminal_observation(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "no_boot",
                    "stop_reason": "no_boot_stall(20.00s_emulated)",
                    "signals": {"execution_observed": False},
                },
                {
                    "cycle": 1,
                    "boot_slot": None,
                    "boot_outcome": "no_boot",
                    "stop_reason": "no_boot_stall(20.00s_emulated)",
                },
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["status"], "converged")


if __name__ == "__main__":
    unittest.main()
