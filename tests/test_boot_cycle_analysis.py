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

    def test_terminal_usage_fault_outranks_wall_budget_reason(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "bus_fault",
                    "stop_reason": "wall_timeout(9s)",
                    "signals": {
                        "bus_fault_detected": True,
                        "cfsr": "0x00030000",
                    },
                },
            ],
            requested_cycles=1,
        )
        self.assertEqual(analysis["status"], "single_boot")
        self.assertNotIn("timeout_cycles", analysis)

    def test_emulation_budget_without_terminal_evidence_is_inconclusive(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "no_boot",
                    "stop_reason": "budget",
                    "signals": {"execution_observed": False},
                },
            ],
            requested_cycles=1,
        )
        self.assertEqual(analysis["status"], "timeout")
        self.assertEqual(analysis["timeout_cycles"], [0])

    def test_terminal_fault_outranks_emulation_budget_reason(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": None,
                    "boot_outcome": "bus_fault",
                    "stop_reason": "budget",
                    "signals": {"cfsr": "0x00030000"},
                },
            ],
            requested_cycles=1,
        )
        self.assertEqual(analysis["status"], "single_boot")
        self.assertNotIn("timeout_cycles", analysis)

    def test_observed_execution_at_budget_is_still_incomplete(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {
                    "cycle": 0,
                    "boot_slot": "exec",
                    "boot_outcome": "no_boot",
                    "stop_reason": "budget",
                    "signals": {
                        "execution_observed": True,
                        "liveness_established": False,
                    },
                },
            ],
            requested_cycles=1,
        )
        self.assertEqual(analysis["status"], "timeout")
        self.assertEqual(analysis["timeout_cycles"], [0])

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

    def test_two_cycle_hard_fault_then_success_is_recovered_after_failure(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": None, "boot_outcome": "hard_fault"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["status"], "recovered_after_failure")
        self.assertEqual(analysis["recovered_at_cycle"], 1)
        self.assertEqual(analysis["initial_outcome"], "hard_fault")
        self.assertEqual(analysis["final_outcome"], "success")
        self.assertEqual(analysis["final_slot"], "exec")
        self.assertNotIn("converged_at_cycle", analysis)

    def test_two_cycle_memory_checks_unmet_then_success_is_recovered_after_failure(
        self,
    ) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "memory_checks_unmet"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["status"], "recovered_after_failure")
        self.assertEqual(analysis["recovered_at_cycle"], 1)

    def test_two_cycle_success_then_failure_is_failed_after_success(
        self,
    ) -> None:
        for outcome, slot in (
            ("hard_fault", None),
            ("no_boot", None),
            ("memory_checks_unmet", "exec"),
            ("wrong_pc", None),
            ("misaligned_vtor", None),
            ("bus_fault", None),
            ("config_crash", None),
            ("config_lost", "exec"),
            ("rollback_accepted", "exec"),
            ("toctou_corruption", "exec"),
        ):
            with self.subTest(outcome=outcome):
                analysis = analyze_boot_cycles(
                    [
                        {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                        {"cycle": 1, "boot_slot": slot, "boot_outcome": outcome},
                    ],
                    requested_cycles=2,
                )
                self.assertEqual(analysis["status"], "failed_after_success")
                self.assertEqual(analysis["failed_at_cycle"], 1)
                self.assertEqual(analysis["initial_outcome"], "success")
                self.assertEqual(analysis["final_outcome"], outcome)
                self.assertEqual(analysis["final_slot"], slot)
                self.assertNotIn("recovered_at_cycle", analysis)
                self.assertNotIn("converged_at_cycle", analysis)

    def test_three_cycle_two_successes_then_failure_is_failed_after_success(
        self,
    ) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": None, "boot_outcome": "hard_fault"},
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "failed_after_success")
        self.assertEqual(analysis["failed_at_cycle"], 2)
        self.assertNotIn("converged_at_cycle", analysis)

    def test_three_cycle_success_then_two_faults_remains_converged(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": None, "boot_outcome": "hard_fault"},
                {"cycle": 2, "boot_slot": None, "boot_outcome": "hard_fault"},
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "converged")
        self.assertEqual(analysis["converged_at_cycle"], 1)
        self.assertNotIn("failed_at_cycle", analysis)

    def test_unconfirmed_revert_and_failure_to_failure_stay_changed_unconfirmed(
        self,
    ) -> None:
        cases = (
            (
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ),
            (
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "wrong_image"},
            ),
            (
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "wrong_image"},
            ),
            (
                {"cycle": 0, "boot_slot": None, "boot_outcome": "hard_fault"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "memory_checks_unmet"},
            ),
        )
        for c0, c1 in cases:
            with self.subTest(c0=c0, c1=c1):
                analysis = analyze_boot_cycles([c0, c1], requested_cycles=2)
                self.assertEqual(analysis["status"], "changed_unconfirmed")
                self.assertNotIn("failed_at_cycle", analysis)
                self.assertNotIn("recovered_at_cycle", analysis)

    def test_expected_rollback_statuses_unchanged_when_second_boot_fails(self) -> None:
        missing = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": None, "boot_outcome": "hard_fault"},
            ],
            requested_cycles=2,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(missing["status"], "rollback_missing")
        self.assertNotIn("failed_at_cycle", missing)

        already_on_target = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": None, "boot_outcome": "hard_fault"},
            ],
            requested_cycles=2,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(already_on_target["status"], "failed_after_success")
        self.assertEqual(already_on_target["failed_at_cycle"], 1)
        self.assertTrue(already_on_target["rollback_skipped"])

    def test_two_cycle_slot_switch_without_third_cycle_is_not_oscillating(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=2,
        )
        self.assertEqual(analysis["status"], "changed_unconfirmed")

        rollback_analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=2,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(rollback_analysis["status"], "rollback_observed_unconfirmed")
        self.assertEqual(rollback_analysis["rollback_cycle"], 1)

    def test_three_cycle_alternation_remains_oscillating(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": None, "boot_outcome": "hard_fault"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": None, "boot_outcome": "hard_fault"},
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "oscillating")
        self.assertNotIn("converged_at_cycle", analysis)

        slot_osc = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": "staging", "boot_outcome": "success"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "staging", "boot_outcome": "success"},
            ],
            requested_cycles=3,
            target_slot="exec",
            expected_rollback_at_cycle=1,
        )
        self.assertEqual(slot_osc["status"], "rollback_observed_oscillating")

    def test_three_cycle_failure_then_two_successes_converges(self) -> None:
        analysis = analyze_boot_cycles(
            [
                {"cycle": 0, "boot_slot": None, "boot_outcome": "hard_fault"},
                {"cycle": 1, "boot_slot": "exec", "boot_outcome": "success"},
                {"cycle": 2, "boot_slot": "exec", "boot_outcome": "success"},
            ],
            requested_cycles=3,
        )
        self.assertEqual(analysis["status"], "converged")
        self.assertEqual(analysis["converged_at_cycle"], 1)


if __name__ == "__main__":
    unittest.main()
