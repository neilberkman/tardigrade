#!/usr/bin/env python3
"""Lightweight unit tests for discovery-oriented profile/report features."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import (  # noqa: E402
    annotate_result_checks,
    calibration_completed,
    _run_batch_with_fallback,
    _run_batches_chunked,
    prepare_renode_command,
    run_batch,
    run_single_point,
    summarize_runtime_sweep,
)
from profile_loader import load_profile  # noqa: E402
from self_test import check_verdict  # noqa: E402


class DiscoveryFeaturesTest(unittest.TestCase):
    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_profile_loader_parses_discovery_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            probe = tempdir / "probe.py"
            probe.write_text(
                "def collect_state(bus=None, monitor=None, context=None):\n"
                "    return {'confirmed': True}\n",
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: discovery_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                  vector_table_offset: 0x200
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  boot_cycles: 3
                  boot_cycle_hook: {probe.as_posix()}
                  expected_rollback_at_cycle: 2
                state_probe_script: {probe.as_posix()}
                semantic_assertions:
                  control:
                    multi_boot_analysis.status: converged
                  faulted:
                    semantic_state.confirmed: false
                invariants:
                  - multi_boot_converges
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertEqual(profile.fault_sweep.boot_cycle_hook, str(probe))
            self.assertEqual(profile.fault_sweep.expected_rollback_at_cycle, 2)
            self.assertEqual(profile.invariants, ["multi_boot_converges"])
            self.assertEqual(
                profile.semantic_assertions["control"]["multi_boot_analysis.status"],
                "converged",
            )
            self.assertEqual(profile.success_criteria.vector_table_offset, 0x200)
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("BOOT_CYCLES:3", robot_vars)
            self.assertIn("BOOT_CYCLE_HOOK:{}".format(probe), robot_vars)
            self.assertIn("EXPECTED_ROLLBACK_AT_CYCLE:2", robot_vars)
            self.assertIn("STATE_PROBE_SCRIPT:{}".format(probe), robot_vars)
            self.assertIn("SUCCESS_VECTOR_OFFSET:0x00000200", robot_vars)

    def test_semantic_assertions_and_invariants_annotate_results(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: annotated_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                semantic_assertions:
                  faulted:
                    semantic_state.confirmed: false
                invariants:
                  - multi_boot_converges
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 7,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "semantic_state": {"confirmed": True},
                    "multi_boot_analysis": {"status": "oscillating", "final_slot": "staging"},
                    "is_control": False,
                }
            ]
            annotate_result_checks(results, profile)
            result = results[0]
            self.assertEqual(len(result.get("semantic_assertion_failures", [])), 1)
            self.assertEqual(len(result.get("invariant_violations", [])), 1)

            summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
            self.assertEqual(summary["bricks"], 0)
            self.assertEqual(summary["issue_points"], 1)
            self.assertEqual(summary["semantic_issue_points"], 1)
            self.assertEqual(summary["invariant_issue_points"], 1)

    def test_missing_semantic_path_records_observation_gap_not_issue(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: observation_gap_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                semantic_assertions:
                  faulted:
                    semantic_state.confirmed: false
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 3,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "semantic_state": {},
                    "is_control": False,
                }
            ]
            annotate_result_checks(results, profile)
            result = results[0]
            self.assertNotIn("semantic_assertion_failures", result)
            self.assertEqual(len(result.get("semantic_observation_failures", [])), 1)

            summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
            self.assertEqual(summary["issue_points"], 0)
            self.assertEqual(summary["semantic_observation_points"], 1)

    def test_wrong_image_is_issue_but_not_brick(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: wrong_image_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 11,
                    "fault_injected": True,
                    "boot_outcome": "wrong_image",
                    "boot_slot": "staging",
                    "signals": {"execution_observed": True, "vtor_ok": False},
                    "is_control": False,
                }
            ]

            summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
            self.assertEqual(summary["bricks"], 0)
            self.assertEqual(summary["issue_points"], 1)
            self.assertEqual(summary["failure_outcomes"], {"wrong_image": 1})
            self.assertEqual(summary["failure_classes"], {"wrong_image": 1})

    def test_rollback_converged_satisfies_generic_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: rollback_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  boot_cycles: 2
                  expected_rollback_at_cycle: 1
                invariants:
                  - multi_boot_converges
                  - successful_rollback
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 1,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "rollback_converged",
                        "expected_rollback_at_cycle": 1,
                        "rollback_cycle": 1,
                        "final_slot": "exec",
                        "final_outcome": "success",
                    },
                }
            ]
            annotate_result_checks(results, profile)
            self.assertEqual(results[0].get("invariant_violations", []), [])

    def test_successful_rollback_flags_missing_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: rollback_missing_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  boot_cycles: 2
                  expected_rollback_at_cycle: 1
                invariants:
                  - successful_rollback
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 1,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "rollback_missing",
                        "expected_rollback_at_cycle": 1,
                        "final_slot": "staging",
                        "final_outcome": "success",
                    },
                }
            ]
            annotate_result_checks(results, profile)
            self.assertEqual(len(results[0].get("invariant_violations", [])), 1)
            self.assertEqual(
                results[0]["invariant_violations"][0]["name"],
                "successful_rollback",
            )

    def test_boot_cycle_hook_with_rollback_full_pipeline(self) -> None:
        """End-to-end: profile with hook -> result with rollback cycle records -> correct invariant verdict.

        Simulates the scenario where a boot_cycle_hook acts as an
        "app confirms OTA" step. The hook writes a confirmation marker
        between cycles. Without the hook, the bootloader would roll back
        to the safe slot. With the hook confirming, the new slot sticks.

        This test proves the full pipeline:
          1. Profile parsing of boot_cycle_hook + expected_rollback_at_cycle
          2. Robot variable emission (BOOT_CYCLE_HOOK, EXPECTED_ROLLBACK_AT_CYCLE)
          3. Invariant evaluation of rollback_converged status
          4. Summary verdict (no issues when rollback succeeds)
        """
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            # Create a real hook script file (the file must exist for
            # path resolution even though we won't execute it in Renode).
            hook_script = tempdir / "confirm_ota_hook.py"
            hook_script.write_text(
                "# Boot cycle hook: simulate OTA confirmation.\n"
                "# In a real Renode run, this would write a marker to NVM:\n"
                "#   bus.WriteDoubleWord(CONFIRM_ADDR, 0xC0FFEE01)\n"
                "# Here we just need to exist for profile/path resolution.\n",
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: hook_rollback_pipeline
                description: Hook-driven rollback integration test
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  boot_cycles: 3
                  boot_cycle_hook: {hook_script.as_posix()}
                  expected_rollback_at_cycle: 2
                invariants:
                  - multi_boot_converges
                  - successful_rollback
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            # Verify profile fields parsed correctly.
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertEqual(profile.fault_sweep.boot_cycle_hook, str(hook_script))
            self.assertEqual(profile.fault_sweep.expected_rollback_at_cycle, 2)

            # Verify robot variables emitted correctly.
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("BOOT_CYCLES:3", robot_vars)
            self.assertIn(f"BOOT_CYCLE_HOOK:{hook_script}", robot_vars)
            self.assertIn("EXPECTED_ROLLBACK_AT_CYCLE:2", robot_vars)

            # Simulate a SUCCESSFUL rollback scenario:
            # Cycle 0: fault during OTA, boots to staging (wrong slot)
            # Cycle 1: hook runs, simulates "app does NOT confirm" -> boots staging again
            # Cycle 2: hook runs, bootloader rolls back -> boots exec (target slot)
            results_rollback_ok = [
                {
                    "fault_at": 5,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "rollback_converged",
                        "requested_cycles": 3,
                        "completed_cycles": 3,
                        "expected_rollback_at_cycle": 2,
                        "rollback_cycle": 2,
                        "initial_slot": "staging",
                        "initial_outcome": "success",
                        "final_slot": "exec",
                        "final_outcome": "success",
                        "slots_observed": ["staging", "staging", "exec"],
                        "outcomes_observed": ["success", "success", "success"],
                        "converged_at_cycle": 2,
                    },
                    "boot_cycles": [
                        {"cycle": 0, "boot_outcome": "success", "boot_slot": "staging"},
                        {"cycle": 1, "boot_outcome": "success", "boot_slot": "staging"},
                        {"cycle": 2, "boot_outcome": "success", "boot_slot": "exec"},
                    ],
                }
            ]
            annotate_result_checks(results_rollback_ok, profile)
            # Both invariants should pass when rollback converged.
            self.assertEqual(results_rollback_ok[0].get("invariant_violations", []), [])

            # Now simulate a FAILED rollback scenario (hook never causes rollback):
            # All 3 cycles boot to staging -- rollback never happened.
            results_rollback_missing = [
                {
                    "fault_at": 5,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "rollback_missing",
                        "requested_cycles": 3,
                        "completed_cycles": 3,
                        "expected_rollback_at_cycle": 2,
                        "initial_slot": "staging",
                        "initial_outcome": "success",
                        "final_slot": "staging",
                        "final_outcome": "success",
                        "slots_observed": ["staging", "staging", "staging"],
                        "outcomes_observed": ["success", "success", "success"],
                    },
                    "boot_cycles": [
                        {"cycle": 0, "boot_outcome": "success", "boot_slot": "staging"},
                        {"cycle": 1, "boot_outcome": "success", "boot_slot": "staging"},
                        {"cycle": 2, "boot_outcome": "success", "boot_slot": "staging"},
                    ],
                }
            ]
            annotate_result_checks(results_rollback_missing, profile)
            # successful_rollback invariant must fire.
            violations = results_rollback_missing[0].get("invariant_violations", [])
            violation_names = [v["name"] for v in violations]
            self.assertIn("successful_rollback", violation_names)

            # Verify summary correctly counts issues for the failed case.
            summary = summarize_runtime_sweep(
                results_rollback_missing, total_writes=10, profile=profile
            )
            self.assertGreater(summary["invariant_issue_points"], 0)

    def test_boot_cycle_hook_oscillating_triggers_multi_boot_invariant(self) -> None:
        """Boot path that oscillates between slots should trigger multi_boot_converges."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            hook_script = tempdir / "noop_hook.py"
            hook_script.write_text("# no-op hook\n", encoding="utf-8")
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: hook_oscillation_test
                description: Hook with oscillating boots
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  boot_cycles: 4
                  boot_cycle_hook: {hook_script.as_posix()}
                invariants:
                  - multi_boot_converges
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            # Oscillating: exec -> staging -> exec -> staging
            results = [
                {
                    "fault_at": 3,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "oscillating",
                        "requested_cycles": 4,
                        "completed_cycles": 4,
                        "initial_slot": "exec",
                        "initial_outcome": "success",
                        "final_slot": "staging",
                        "final_outcome": "success",
                        "slots_observed": ["exec", "staging", "exec", "staging"],
                        "outcomes_observed": ["success", "success", "success", "success"],
                    },
                    "boot_cycles": [
                        {"cycle": 0, "boot_outcome": "success", "boot_slot": "exec"},
                        {"cycle": 1, "boot_outcome": "success", "boot_slot": "staging"},
                        {"cycle": 2, "boot_outcome": "success", "boot_slot": "exec"},
                        {"cycle": 3, "boot_outcome": "success", "boot_slot": "staging"},
                    ],
                }
            ]
            annotate_result_checks(results, profile)
            violations = results[0].get("invariant_violations", [])
            violation_names = [v["name"] for v in violations]
            self.assertIn("multi_boot_converges", violation_names)

    def test_rollback_not_applicable_when_already_in_target_slot(self) -> None:
        """When initial boot is already in the target slot, rollback is N/A."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: rollback_na_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  boot_cycles: 3
                  expected_rollback_at_cycle: 2
                invariants:
                  - multi_boot_converges
                  - successful_rollback
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            # Already in exec (target slot) -- rollback is not applicable.
            # analyze_boot_cycles sets rollback_not_applicable=True and
            # status = converged (since all cycles are the same).
            results = [
                {
                    "fault_at": 2,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "is_control": False,
                    "multi_boot_analysis": {
                        "status": "converged",
                        "requested_cycles": 3,
                        "completed_cycles": 3,
                        "expected_rollback_at_cycle": 2,
                        "rollback_not_applicable": True,
                        "initial_slot": "exec",
                        "initial_outcome": "success",
                        "final_slot": "exec",
                        "final_outcome": "success",
                        "converged_at_cycle": 0,
                        "slots_observed": ["exec", "exec", "exec"],
                        "outcomes_observed": ["success", "success", "success"],
                    },
                    "boot_cycles": [
                        {"cycle": 0, "boot_outcome": "success", "boot_slot": "exec"},
                        {"cycle": 1, "boot_outcome": "success", "boot_slot": "exec"},
                        {"cycle": 2, "boot_outcome": "success", "boot_slot": "exec"},
                    ],
                }
            ]
            annotate_result_checks(results, profile)
            # multi_boot_converges should pass (status = converged).
            # successful_rollback should also pass: the device already
            # booted into the target slot, so rollback was not needed.
            violations = results[0].get("invariant_violations", [])
            violation_names = [v["name"] for v in violations]
            self.assertNotIn("multi_boot_converges", violation_names)
            self.assertNotIn("successful_rollback", violation_names)

    def test_control_result_derives_pre_state_for_bootable_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: derived_pre_state_profile
                description: discovery
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                invariants:
                  - at_least_one_bootable
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 7,
                    "fault_injected": True,
                    "boot_outcome": "no_boot",
                    "boot_slot": None,
                    "is_control": False,
                },
                {
                    "fault_at": 1000000,
                    "fault_injected": False,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "is_control": True,
                },
            ]
            annotate_result_checks(results, profile)
            fault_result = results[0]
            self.assertEqual(fault_result["pre_state"]["derived_from"], "control_result")
            self.assertEqual(len(fault_result.get("invariant_violations", [])), 1)

    def test_calibration_completed_rejects_incomplete_reasons(self) -> None:
        self.assertTrue(calibration_completed("vtor_captured"))
        self.assertFalse(calibration_completed("wall_timeout(600s)"))
        self.assertFalse(calibration_completed("budget"))
        self.assertFalse(calibration_completed("no_progress_stall(20.0s)"))

    def test_self_test_rejects_semantic_only_issues_by_default(self) -> None:
        passed, reason = check_verdict(
            ROOT / "profiles" / "dummy.yaml",
            {"expect": {"should_find_issues": True}},
            {
                "summary": {
                    "runtime_sweep": {
                        "bricks": 0,
                        "brick_rate": 0.0,
                        "issue_points": 1,
                        "issue_reasons": {"semantic_assertion": 1},
                    }
                }
            },
            exit_code=0,
        )
        self.assertFalse(passed)
        self.assertIn("boot-visible", reason)

    def test_self_test_allows_semantic_only_issues_when_opted_in(self) -> None:
        passed, reason = check_verdict(
            ROOT / "profiles" / "dummy.yaml",
            {
                "expect": {
                    "should_find_issues": True,
                    "allow_semantic_only_issues": True,
                }
            },
            {
                "summary": {
                    "runtime_sweep": {
                        "bricks": 0,
                        "brick_rate": 0.0,
                        "issue_points": 2,
                        "issue_reasons": {"semantic_assertion": 2},
                    }
                }
            },
            exit_code=0,
        )
        self.assertTrue(passed)
        self.assertIn("semantic/invariant", reason)

    def test_docker_renode_spec_expands_to_direct_docker_command(self) -> None:
        env = {
            "DOTNET_BUNDLE_EXTRACT_BASE_DIR": "/tmp/dotnet_bundle",
            "TMPDIR": "/tmp/renode_tmp",
            "TMP": "/tmp/renode_tmp",
            "TEMP": "/tmp/renode_tmp",
        }
        platform_repl = ROOT / "platforms" / "cortex_m4_flash_fast.repl"
        cmd = prepare_renode_command(
            "docker://renode-patched:test",
            [
                "docker://renode-patched:test",
                "--renode-config",
                "/tmp/run/renode.config",
                "tests/ota_fault_point.robot",
                "--results-dir",
                "/tmp/run/results",
                "--variable",
                "RESULT_FILE:/tmp/run/result.json",
                "--variable",
                "PLATFORM_REPL:{}".format(platform_repl),
            ],
            ROOT,
            env,
        )
        self.assertEqual(cmd[:4], ["docker", "run", "--rm", "--platform"])
        self.assertIn("renode-patched:test", cmd)
        self.assertTrue(any("renode-test" in part for part in cmd))
        self.assertIn("-w", cmd)
        self.assertIn(str(ROOT), cmd)
        self.assertTrue(
            any(part.startswith("DOTNET_BUNDLE_EXTRACT_BASE_DIR=") for part in cmd)
        )
        self.assertTrue(any(part.startswith("TMPDIR=") for part in cmd))
        self.assertTrue(any(part.startswith("TMP=") for part in cmd))
        self.assertTrue(any(part.startswith("TEMP=") for part in cmd))
        self.assertNotIn("docker://renode-patched:test", cmd[1:])

    def test_run_single_point_prunes_robot_artifacts_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: cleanup_profile
                description: cleanup
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            def fake_run(cmd, cwd, capture_output, text, check, env, timeout):
                self.assertEqual(
                    env["TMPDIR"],
                    str(tempdir / "work" / "cleanup_profile_fault_7" / ".tmp"),
                )
                self.assertEqual(env["TMP"], env["TMPDIR"])
                self.assertEqual(env["TEMP"], env["TMPDIR"])
                Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
                (Path(env["TMPDIR"]) / "renode.tmp").write_text("x", encoding="utf-8")
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                (rf_results / "snapshots").mkdir(parents=True, exist_ok=True)
                (rf_results / "snapshots" / "dummy.bin").write_text("x", encoding="utf-8")
                result_token = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("RESULT_FILE:")
                )
                result_file = Path(result_token.split(":", 1)[1])
                result_file.parent.mkdir(parents=True, exist_ok=True)
                result_file.write_text('{"boot_outcome":"success"}', encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("audit_bootloader.subprocess.run", side_effect=fake_run):
                result = run_single_point(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_at=7,
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                )

            self.assertEqual(result["boot_outcome"], "success")
            self.assertFalse((tempdir / "work" / "cleanup_profile_fault_7" / "robot").exists())
            self.assertFalse((tempdir / "work" / "cleanup_profile_fault_7" / ".tmp").exists())

    def test_run_single_point_keeps_robot_artifacts_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: keep_artifacts_profile
                description: cleanup
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            def fake_run(cmd, cwd, capture_output, text, check, env, timeout):
                self.assertEqual(
                    env["TMPDIR"],
                    str(tempdir / "work" / "keep_artifacts_profile_fault_9" / ".tmp"),
                )
                Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
                (Path(env["TMPDIR"]) / "renode.tmp").write_text("x", encoding="utf-8")
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                (rf_results / "snapshots").mkdir(parents=True, exist_ok=True)
                result_token = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("RESULT_FILE:")
                )
                result_file = Path(result_token.split(":", 1)[1])
                result_file.parent.mkdir(parents=True, exist_ok=True)
                result_file.write_text('{"boot_outcome":"success"}', encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("audit_bootloader.subprocess.run", side_effect=fake_run):
                run_single_point(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_at=9,
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    keep_run_artifacts=True,
                )

            self.assertTrue(
                (tempdir / "work" / "keep_artifacts_profile_fault_9" / "robot" / "snapshots").exists()
            )

    def test_run_single_point_uses_no_fault_control_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: control_profile
                description: cleanup
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            def fake_run(cmd, cwd, capture_output, text, check, env, timeout):
                fault_var = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("FAULT_AT:")
                )
                self.assertEqual(fault_var, "FAULT_AT:-1")
                result_token = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("RESULT_FILE:")
                )
                result_file = Path(result_token.split(":", 1)[1])
                result_file.parent.mkdir(parents=True, exist_ok=True)
                result_file.write_text('{"boot_outcome":"success","fault_injected":false}', encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("audit_bootloader.subprocess.run", side_effect=fake_run):
                result = run_single_point(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_at=1000000,
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    is_control=True,
                    keep_run_artifacts=False,
                )

            self.assertEqual(result["boot_outcome"], "success")

    def test_run_batches_chunked_emits_progress(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: progress_profile
                description: progress
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            stderr = StringIO()

            def fake_batch(*args, **kwargs):
                points = kwargs["fault_points"]
                return [{"fault_at": fp, "boot_outcome": "success"} for fp in points]

            with mock.patch(
                "audit_bootloader._run_batch_with_fallback",
                side_effect=fake_batch,
            ):
                with redirect_stderr(stderr):
                    results = _run_batches_chunked(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[1, 2, 3, 4, 5],
                        robot_vars=[],
                        work_dir=tempdir / "work",
                        renode_remote_server_dir="",
                        max_batch_points=2,
                        progress_label="worker 0",
                    )

            output = stderr.getvalue()
            self.assertEqual(len(results), 5)
            self.assertIn("[audit ", output)
            self.assertIn("worker 0 sub-batching 5 points into 3 chunks", output)
            self.assertIn("worker 0 chunk 1/3 start: 2 points (faults 1..2)", output)
            self.assertIn("worker 0 chunk 3/3 complete: 1 results", output)

    def test_run_batch_with_fallback_splits_before_singles(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: split_fallback_profile
                description: progress
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            calls = []

            def fake_run_batch(**kwargs):
                points = kwargs["fault_points"]
                calls.append(list(points))
                if len(points) > 2:
                    raise RuntimeError("batch timeout")
                return [{"fault_at": fp, "boot_outcome": "success"} for fp in points]

            with mock.patch("audit_bootloader.run_batch", side_effect=fake_run_batch):
                results = _run_batch_with_fallback(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[1, 2, 3, 4],
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                )

            self.assertEqual([1, 2, 3, 4], calls[0])
            self.assertEqual(calls[1:], [[1, 2], [3, 4]])
            self.assertEqual(len(results), 4)

    def test_run_batch_with_fallback_reaches_single_points_only_if_needed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: split_to_single_profile
                description: progress
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            calls = []

            def fake_run_batch(**kwargs):
                points = kwargs["fault_points"]
                calls.append(list(points))
                if len(points) > 1:
                    raise RuntimeError("batch timeout")
                return [{"fault_at": points[0], "boot_outcome": "success"}]

            with mock.patch("audit_bootloader.run_batch", side_effect=fake_run_batch):
                results = _run_batch_with_fallback(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[7, 8],
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                )

            self.assertEqual(calls, [[7, 8], [7], [8]])
            self.assertEqual(len(results), 2)

    def test_run_batch_prunes_robot_artifacts_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: cleanup_batch_profile
                description: cleanup
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

            def fake_run(cmd, cwd, capture_output, text, check, env, timeout):
                self.assertEqual(
                    env["TMPDIR"],
                    str(tempdir / "work" / "cleanup_batch_profile_batch" / ".tmp"),
                )
                Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
                (Path(env["TMPDIR"]) / "renode.tmp").write_text("x", encoding="utf-8")
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                (rf_results / "snapshots").mkdir(parents=True, exist_ok=True)
                (rf_results / "snapshots" / "dummy.bin").write_text("x", encoding="utf-8")
                return SimpleNamespace(returncode=1, stdout="boom", stderr="bad")

            with mock.patch("audit_bootloader.subprocess.run", side_effect=fake_run):
                with self.assertRaises(RuntimeError):
                    run_batch(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[1, 2],
                        robot_vars=[],
                        work_dir=tempdir / "work",
                        renode_remote_server_dir="",
                        keep_run_artifacts=False,
                    )

            self.assertFalse((tempdir / "work" / "cleanup_batch_profile_batch" / "robot").exists())
            self.assertFalse((tempdir / "work" / "cleanup_batch_profile_batch" / ".tmp").exists())


if __name__ == "__main__":
    unittest.main()
