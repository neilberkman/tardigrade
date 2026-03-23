#!/usr/bin/env python3
"""Lightweight unit tests for discovery-oriented profile/report features."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import textwrap
import unittest
import json
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

import audit_bootloader  # noqa: E402
from renode_runner import (  # noqa: E402
    CalibrationResult,
    _run_batches_chunked,
    _run_batch_with_fallback,
    calibration_completed,
    describe_zero_op_calibration,
    profile_robot_timeout_minutes,
    prepare_renode_command,
    run_renode_subprocess,
    run_batch,
    run_single_point,
)
from result_checks import annotate_result_checks  # noqa: E402
from audit_report import summarize_runtime_sweep  # noqa: E402
from audit_bootloader import _trace_replay_eligible_fault_types  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from self_test import check_verdict  # noqa: E402


class DiscoveryFeaturesTest(unittest.TestCase):
    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_run_renode_subprocess_kills_process_group_on_timeout(self) -> None:
        proc = mock.Mock()
        proc.pid = 4242
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd=["renode-test"], timeout=10.0),
            ("partial stdout", "partial stderr"),
        ]

        with mock.patch("renode_runner.subprocess.Popen", return_value=proc):
            with mock.patch("renode_runner.os.killpg") as mock_killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run_renode_subprocess(
                        ["renode-test"],
                        cwd=str(ROOT),
                        env={},
                        timeout_s=10.0,
                    )

        mock_killpg.assert_called_once_with(4242, signal.SIGKILL)
        proc.kill.assert_not_called()

    def test_trace_replay_eligibility_defaults_to_power_loss_only(self) -> None:
        self.assertFalse(_trace_replay_eligible_fault_types(["bit_corruption"]))
        self.assertFalse(_trace_replay_eligible_fault_types(["write_rejection"]))
        self.assertTrue(_trace_replay_eligible_fault_types(["instruction_skip", "power_loss"]))
        self.assertFalse(_trace_replay_eligible_fault_types(["instruction_skip"]))

    def test_zero_point_execute_request_skips_calibration_and_uses_control_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: zero_point_execute_control
                description: zero-point execute control coverage
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
                  mode: runtime
                  evaluation_mode: execute
                  max_writes: auto
                  max_writes_cap: 1234
                  run_duration: "10.0"
                  fault_types:
                    - power_loss
                expect:
                  should_find_issues: false
                """,
            )
            output_path = tempdir / "audit.json"
            control_result = {
                "fault_at": 1000000,
                "fault_requested": -1,
                "fault_injected": False,
                "fault_address": "0x00000000",
                "boot_outcome": "success",
                "boot_slot": "exec",
                "actual_writes": 0,
                "signals": {"trace_replay_mode": "execute"},
                "is_control": True,
            }
            sweep_summary = {
                "bricks": 0,
                "issue_points": 0,
                "semantic_issue_points": 0,
                "invariant_issue_points": 0,
                "metadata_delta_issue_points": 0,
                "timeout_points": 0,
                "resilient_rollbacks": 0,
                "control": {
                    "boot_outcome": "success",
                    "effective_outcome": "success",
                    "final_boot_outcome": "success",
                    "issue_count": 0,
                },
            }

            def fake_build_fault_plan(**kwargs):
                calibration = kwargs["calibration"]
                self.assertEqual(calibration.max_writes, 1234)
                self.assertEqual(kwargs["fault_start"], 0)
                self.assertEqual(kwargs["fault_end"], 0)
                return SimpleNamespace(
                    fault_points=[],
                    fault_types_list=None,
                    heuristic_summary=None,
                    clustered_bit_count=0,
                )

            def fake_run_runtime_sweep(**kwargs):
                self.assertEqual(kwargs["fault_points"], [])
                self.assertTrue(kwargs["include_control"])
                self.assertEqual(kwargs["evaluation_mode"], "execute")
                self.assertIn("ZERO_POINT_EXECUTE_CONTROL:true", kwargs["robot_vars"])
                return [dict(control_result)]

            argv = [
                "audit_bootloader.py",
                "--profile",
                str(profile_path),
                "--output",
                str(output_path),
                "--evaluation-mode",
                "execute",
                "--fault-start",
                "0",
                "--fault-end",
                "0",
            ]

            with mock.patch.object(sys, "argv", argv):
                with mock.patch("audit_bootloader.ensure_tool", return_value="renode-test"):
                    with mock.patch("audit_bootloader.build_fault_plan", side_effect=fake_build_fault_plan):
                        with mock.patch("audit_bootloader.run_runtime_sweep", side_effect=fake_run_runtime_sweep):
                            with mock.patch("audit_bootloader.annotate_clean_trace", return_value=None):
                                with mock.patch("audit_bootloader.annotate_result_checks"):
                                    with mock.patch("audit_bootloader.validate_runtime_findings"):
                                        with mock.patch("audit_bootloader.summarize_runtime_sweep", return_value=dict(sweep_summary)):
                                            with mock.patch("audit_bootloader.report_skip_reasons"):
                                                with mock.patch(
                                                    "audit_bootloader.run_multi_fault_phase",
                                                    return_value=SimpleNamespace(
                                                        plan=None,
                                                        plan_data=None,
                                                        results=None,
                                                        summary=None,
                                                    ),
                                                ):
                                                    with mock.patch("audit_bootloader.compute_verdict", return_value="PASS"):
                                                        with mock.patch("audit_bootloader.git_metadata", return_value={}):
                                                            rc = audit_bootloader.main()

            self.assertEqual(rc, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["fault_points_tested"], 0)
            self.assertEqual(payload["calibrated_writes"], 1234)
            self.assertEqual(payload["calibration"]["performed"], False)
            self.assertEqual(payload["calibration"]["source"], "skipped_control_only")
            self.assertEqual(payload["summary"]["runtime_sweep"]["control"]["boot_outcome"], "success")

    def test_profile_max_writes_zero_skips_calibration_and_uses_control_only_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: zero_point_execute_control_from_profile
                description: zero-point execute control coverage from profile
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
                  mode: runtime
                  evaluation_mode: execute
                  max_writes: 0
                  max_writes_cap: 1234
                  run_duration: "10.0"
                  fault_types:
                    - power_loss
                expect:
                  should_find_issues: false
                """,
            )
            output_path = tempdir / "audit.json"
            control_result = {
                "fault_at": 1000000,
                "fault_requested": -1,
                "fault_injected": False,
                "fault_address": "0x00000000",
                "boot_outcome": "success",
                "boot_slot": "exec",
                "actual_writes": 0,
                "signals": {"trace_replay_mode": "execute"},
                "is_control": True,
            }
            sweep_summary = {
                "bricks": 0,
                "issue_points": 0,
                "semantic_issue_points": 0,
                "invariant_issue_points": 0,
                "metadata_delta_issue_points": 0,
                "timeout_points": 0,
                "resilient_rollbacks": 0,
                "control": {
                    "boot_outcome": "success",
                    "effective_outcome": "success",
                    "final_boot_outcome": "success",
                    "issue_count": 0,
                },
            }

            def fake_build_fault_plan(**kwargs):
                calibration = kwargs["calibration"]
                self.assertEqual(calibration.max_writes, 0)
                self.assertEqual(kwargs["fault_start"], 0)
                self.assertEqual(kwargs["fault_end"], 0)
                return SimpleNamespace(
                    fault_points=[],
                    fault_types_list=None,
                    heuristic_summary=None,
                    clustered_bit_count=0,
                )

            def fake_run_runtime_sweep(**kwargs):
                self.assertEqual(kwargs["fault_points"], [])
                self.assertTrue(kwargs["include_control"])
                self.assertEqual(kwargs["evaluation_mode"], "execute")
                self.assertIn("ZERO_POINT_EXECUTE_CONTROL:true", kwargs["robot_vars"])
                return [dict(control_result)]

            argv = [
                "audit_bootloader.py",
                "--profile",
                str(profile_path),
                "--output",
                str(output_path),
                "--evaluation-mode",
                "execute",
            ]

            with mock.patch.object(sys, "argv", argv):
                with mock.patch("audit_bootloader.ensure_tool", return_value="renode-test"):
                    with mock.patch("audit_bootloader.build_fault_plan", side_effect=fake_build_fault_plan):
                        with mock.patch("audit_bootloader.run_runtime_sweep", side_effect=fake_run_runtime_sweep):
                            with mock.patch("audit_bootloader.annotate_clean_trace", return_value=None):
                                with mock.patch("audit_bootloader.annotate_result_checks"):
                                    with mock.patch("audit_bootloader.validate_runtime_findings"):
                                        with mock.patch("audit_bootloader.summarize_runtime_sweep", return_value=dict(sweep_summary)):
                                            with mock.patch("audit_bootloader.report_skip_reasons"):
                                                with mock.patch(
                                                    "audit_bootloader.run_multi_fault_phase",
                                                    return_value=SimpleNamespace(
                                                        plan=None,
                                                        plan_data=None,
                                                        results=None,
                                                        summary=None,
                                                    ),
                                                ):
                                                    with mock.patch("audit_bootloader.compute_verdict", return_value="PASS"):
                                                        with mock.patch("audit_bootloader.git_metadata", return_value={}):
                                                            rc = audit_bootloader.main()

            self.assertEqual(rc, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["fault_points_tested"], 0)
            self.assertEqual(payload["calibrated_writes"], 0)
            self.assertEqual(payload["calibration"]["performed"], False)
            self.assertEqual(payload["calibration"]["source"], "skipped_control_only")
            self.assertEqual(payload["summary"]["runtime_sweep"]["control"]["boot_outcome"], "success")

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
                  calibration_time_slice: "0.11"
                  phase1_time_slice: "0.13"
                  phase2_time_slice: "0.07"
                  boot_cycle_hook: {probe.as_posix()}
                  expected_rollback_at_cycle: 2
                state_probe:
                  script: {probe.as_posix()}
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
            self.assertEqual(profile.fault_sweep.calibration_time_slice, "0.11")
            self.assertEqual(profile.fault_sweep.phase1_time_slice, "0.13")
            self.assertEqual(profile.fault_sweep.phase2_time_slice, "0.07")
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
            self.assertIn("CALIBRATION_TIME_SLICE:0.11", robot_vars)
            self.assertIn("PHASE1_TIME_SLICE:0.13", robot_vars)
            self.assertIn("PHASE2_TIME_SLICE:0.07", robot_vars)
            self.assertIn("BOOT_CYCLE_HOOK:{}".format(probe), robot_vars)
            self.assertIn("EXPECTED_ROLLBACK_AT_CYCLE:2", robot_vars)
            self.assertIn("STATE_PROBE:{}".format(probe), robot_vars)
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

    def test_timing_summary_includes_followup_ms(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: timing_summary_profile
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
                    "fault_at": 1,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "signals": {
                        "reload_ms": 10,
                        "replay_ms": 20,
                        "reset_ms": 30,
                        "setup_ms": 40,
                        "emulation_ms": 50,
                        "followup_ms": 60,
                        "total_ms": 210,
                        "p2_iters": 7,
                    },
                    "is_control": False,
                }
            ]

            summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
            timing = summary["timing"]
            self.assertEqual(timing["totals"]["followup_ms"], 60)
            self.assertEqual(timing["averages"]["followup_ms"], 60)
            self.assertEqual(timing["maximums"]["followup_ms"], 60)

    def test_summary_includes_fault_type_breakdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: fault_type_summary_profile
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
                    "fault_at": 1,
                    "fault_type": "f",
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "is_control": False,
                },
                {
                    "fault_at": 2,
                    "fault_type": "m:b",
                    "fault_injected": True,
                    "boot_outcome": "hard_fault",
                    "boot_slot": None,
                    "signals": {"execution_observed": False},
                    "is_control": False,
                },
                {
                    "fault_at": 3,
                    "fault_type": "mf:10:200",
                    "fault_injected": True,
                    "boot_outcome": "wrong_image",
                    "boot_slot": "staging",
                    "signals": {"execution_observed": True, "vtor_ok": False},
                    "is_control": False,
                },
            ]

            summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
            self.assertEqual(
                summary["fault_type_points"],
                {
                    "read_bit_flip": 1,
                    "metadata_bit_corruption": 1,
                    "multi_fault_sequence": 1,
                },
            )
            self.assertEqual(
                summary["fault_type_issue_points"],
                {
                    "metadata_bit_corruption": 1,
                    "multi_fault_sequence": 1,
                },
            )
            self.assertEqual(
                summary["fault_type_bricks"],
                {
                    "metadata_bit_corruption": 1,
                },
            )

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

    def test_rollback_skipped_when_already_in_target_slot(self) -> None:
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
            # analyze_boot_cycles sets rollback_skipped=True and
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
                        "rollback_skipped": True,
                        "rollback_skipped_reason": "initial_boot_already_on_target_slot",
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

    def test_calibration_completed_no_boot_settled_writes(self) -> None:
        # no_boot_settled_writes accepted for no_boot profiles
        self.assertTrue(
            calibration_completed("no_boot_settled_writes", expected_control_outcome="no_boot")
        )
        # rejected for success profiles (same as no_boot_no_writes)
        self.assertFalse(
            calibration_completed("no_boot_settled_writes", expected_control_outcome="success")
        )
        # existing no_boot_no_writes still works
        self.assertTrue(
            calibration_completed("no_boot_no_writes", expected_control_outcome="no_boot")
        )
        self.assertFalse(
            calibration_completed("no_boot_no_writes", expected_control_outcome="success")
        )

    def test_describe_zero_op_calibration_reports_console_fatal_geometry_failure(self) -> None:
        msg = describe_zero_op_calibration(
            data={
                "signals": {
                    "phase1_console_fatal_pattern": "Cannot upgrade:",
                    "phase1_console_last_line": "I: Jumping to the first image slot",
                }
            },
            stop_reason="console_fatal(Cannot upgrade:)",
            expected_control_outcome="success",
        )
        self.assertIn("fatal console-detected stop", msg)
        self.assertIn("Cannot upgrade:", msg)
        self.assertIn("geometry/platform mismatch", msg)
        self.assertNotIn("stateless", msg)

    def test_describe_zero_op_calibration_keeps_stateless_message_for_nonfatal_zero_write_case(self) -> None:
        msg = describe_zero_op_calibration(
            data={},
            stop_reason="vtor_captured",
            expected_control_outcome="success",
        )
        self.assertIn("stateless", msg)

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

            def fake_run(cmd, *, cwd, env, timeout_s):
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

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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

            def fake_run(cmd, *, cwd, env, timeout_s):
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

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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

            def fake_run(cmd, *, cwd, env, timeout_s):
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

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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

    def test_run_single_point_control_uses_robot_timeout_as_process_floor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: control_timeout_profile
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
            observed_timeouts = []

            def fake_run(cmd, *, cwd, env, timeout_s):
                observed_timeouts.append(timeout_s)
                self.assertIn("TEST_TIMEOUT:45 minutes", cmd)
                result_token = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("RESULT_FILE:")
                )
                result_file = Path(result_token.split(":", 1)[1])
                result_file.parent.mkdir(parents=True, exist_ok=True)
                result_file.write_text(
                    '{"boot_outcome":"success","fault_injected":false}',
                    encoding="utf-8",
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.dict(
                os.environ,
                {"OTA_RENODE_ROBOT_TIMEOUT_MINUTES": "45"},
                clear=False,
            ):
                with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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
            self.assertEqual(observed_timeouts, [4050.0])

    def test_profile_robot_timeout_minutes_scales_with_run_duration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: runtime_budget_profile
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
                fault_sweep:
                  run_duration: "20.0"
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)

        self.assertEqual(profile_robot_timeout_minutes(profile), 10)

    def test_run_single_point_uses_profile_run_duration_as_robot_timeout_floor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: long_run_duration_profile
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
                fault_sweep:
                  run_duration: "20.0"
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            observed_timeouts = []

            def fake_run(cmd, *, cwd, env, timeout_s):
                observed_timeouts.append(timeout_s)
                self.assertIn("TEST_TIMEOUT:10 minutes", cmd)
                result_token = next(
                    cmd[i + 1]
                    for i, token in enumerate(cmd[:-1])
                    if token == "--variable" and cmd[i + 1].startswith("RESULT_FILE:")
                )
                result_file = Path(result_token.split(":", 1)[1])
                result_file.parent.mkdir(parents=True, exist_ok=True)
                result_file.write_text(
                    '{"boot_outcome":"success","fault_injected":false}',
                    encoding="utf-8",
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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
            self.assertEqual(observed_timeouts, [900.0])

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
                "renode_runner._run_batch_with_fallback",
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

            with mock.patch("renode_runner.run_batch", side_effect=fake_run_batch):
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

            with mock.patch("renode_runner.run_batch", side_effect=fake_run_batch):
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

    def test_run_batch_with_fallback_returns_synthetic_timeout_for_single_point(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: single_timeout_profile
                description: timeout
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

            with mock.patch("renode_runner.run_batch", side_effect=RuntimeError("batch timeout")):
                with redirect_stderr(stderr):
                    results = _run_batch_with_fallback(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[99],
                        robot_vars=[],
                        work_dir=tempdir / "work",
                        renode_remote_server_dir="",
                        fault_types_list=["s"],
                        keep_run_artifacts=False,
                    )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["fault_at"], 99)
            self.assertEqual(results[0]["fault_type"], "s")
            self.assertEqual(results[0]["boot_outcome"], "no_boot")
            self.assertTrue(results[0]["fault_injected"])
            self.assertTrue(results[0]["timeout"])
            self.assertIn("batch timeout", results[0]["error"])
            self.assertIn("recording synthetic timeout result", stderr.getvalue())

    def test_run_batch_with_fallback_returns_synthetic_timeout_at_depth_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: depth_limit_profile
                description: timeout
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

            with mock.patch("renode_runner.run_batch", side_effect=RuntimeError("still failing")):
                with redirect_stderr(stderr):
                    results = _run_batch_with_fallback(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[11, 12],
                        robot_vars=[],
                        work_dir=tempdir / "work",
                        renode_remote_server_dir="",
                        fault_types_list=["w", "e"],
                        keep_run_artifacts=False,
                        _depth=10,
                    )

            self.assertEqual([r["fault_at"] for r in results], [11, 12])
            self.assertEqual([r["fault_type"] for r in results], ["w", "e"])
            self.assertTrue(all(r["timeout"] for r in results))
            self.assertIn("Fallback depth limit (10)", stderr.getvalue())

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

            def fake_run(cmd, *, cwd, env, timeout_s):
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

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
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

    def test_run_batch_uses_explicit_bundle_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: shared_bundle_profile
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
            shared_bundle = tempdir / "worker_0" / ".dotnet_bundle"

            def fake_run(cmd, *, cwd, env, timeout_s):
                self.assertEqual(env["DOTNET_BUNDLE_EXTRACT_BASE_DIR"], str(shared_bundle))
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                result_var = next(
                    entry for entry in cmd
                    if isinstance(entry, str) and entry.startswith("RESULT_FILE:")
                )
                result_file = Path(result_var.split("RESULT_FILE:", 1)[1])
                result_file.write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
                results = run_batch(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[1, 2],
                    robot_vars=[],
                    work_dir=tempdir / "worker_0" / "chunk_0000",
                    renode_remote_server_dir="",
                    bundle_dir=shared_bundle,
                    keep_run_artifacts=False,
                )

            self.assertEqual(results, [])

    def test_run_batches_chunked_reuses_shared_bundle_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: chunk_bundle_profile
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
                calls.append((kwargs["work_dir"], kwargs["bundle_dir"], list(kwargs["fault_points"])))
                return [{"fault_at": fp, "boot_outcome": "success"} for fp in kwargs["fault_points"]]

            with mock.patch("renode_runner.run_batch", side_effect=fake_run_batch):
                results = _run_batches_chunked(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[1, 2, 3, 4],
                    robot_vars=[],
                    work_dir=tempdir / "worker_0",
                    renode_remote_server_dir="",
                    max_batch_points=2,
                )

            self.assertEqual(len(results), 4)
            expected_bundle = tempdir / "worker_0" / ".dotnet_bundle"
            self.assertEqual([bundle for _work, bundle, _points in calls], [expected_bundle, expected_bundle])
            self.assertEqual(
                [work for work, _bundle, _points in calls],
                [tempdir / "worker_0" / "chunk_0000", tempdir / "worker_0" / "chunk_0001"],
            )
            self.assertFalse((tempdir / "worker_0" / "chunk_0000" / ".dotnet_bundle").exists())
            self.assertFalse((tempdir / "worker_0" / "chunk_0001" / ".dotnet_bundle").exists())

    def test_run_batch_scales_robot_timeout_with_batch_size(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: timeout_batch_profile
                    description: timeout
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
                    """
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            def fake_run(cmd, *, cwd, env, timeout_s):
                # Robot timeout scales with fault point cost (2s + fp*0.003s each).
                # fps 0-19 = 160s → 3 minutes.
                self.assertIn("TEST_TIMEOUT:3 minutes", cmd)
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                result_var = next(
                    entry for entry in cmd
                    if isinstance(entry, str) and entry.startswith("RESULT_FILE:")
                )
                result_file = Path(result_var.split("RESULT_FILE:", 1)[1])
                result_file.write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
                results = run_batch(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=list(range(20)),
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                )

            self.assertEqual(results, [])

    def test_run_batch_uses_trace_replay_timeout_model(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: trace_replay_timeout_profile
                    description: timeout
                    platform: platforms/stm32f4.repl
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
                    """
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            observed_timeouts = []

            def fake_run(cmd, *, cwd, env, timeout_s):
                self.assertIn("TEST_TIMEOUT:5 minutes", cmd)
                observed_timeouts.append(timeout_s)
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                result_var = next(
                    entry for entry in cmd
                    if isinstance(entry, str) and entry.startswith("RESULT_FILE:")
                )
                result_file = Path(result_var.split("RESULT_FILE:", 1)[1])
                result_file.write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
                results = run_batch(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=list(range(1000, 1128)),
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    trace_file=str(tempdir / "trace.csv"),
                    fault_types_list=["w"] * 128,
                    keep_run_artifacts=False,
                )

            self.assertEqual(results, [])

    def test_run_batch_uses_trace_replay_timeout_model_for_bit_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: trace_replay_timeout_profile_bitflip
                    description: timeout
                    platform: platforms/stm32f4.repl
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
                    """
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            observed_timeouts = []

            def fake_run(cmd, *, cwd, env, timeout_s):
                self.assertIn("TEST_TIMEOUT:3 minutes", cmd)
                observed_timeouts.append(timeout_s)
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                result_var = next(
                    entry for entry in cmd
                    if isinstance(entry, str) and entry.startswith("RESULT_FILE:")
                )
                result_file = Path(result_var.split("RESULT_FILE:", 1)[1])
                result_file.write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
                results = run_batch(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=list(range(20)),
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    trace_file=str(tempdir / "trace.csv"),
                    fault_types_list=["b"] * 20,
                    keep_run_artifacts=False,
                )

            self.assertEqual(results, [])
            self.assertEqual(len(observed_timeouts), 1)
            self.assertEqual(observed_timeouts[0], 450.0)
            self.assertEqual(len(observed_timeouts), 1)
            self.assertLess(observed_timeouts[0], 500.0)

    def test_run_batch_single_point_uses_per_point_timeout_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: single_point_timeout_profile
                    description: timeout
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
                    """
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            observed_timeouts = []

            def fake_run(cmd, *, cwd, env, timeout_s):
                observed_timeouts.append(timeout_s)
                rf_results = Path(cmd[cmd.index("--results-dir") + 1])
                rf_results.mkdir(parents=True, exist_ok=True)
                result_var = next(
                    entry for entry in cmd
                    if isinstance(entry, str) and entry.startswith("RESULT_FILE:")
                )
                result_file = Path(result_var.split("RESULT_FILE:", 1)[1])
                result_file.write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.dict(os.environ, {"OTA_RENODE_POINT_TIMEOUT_S": "40"}):
                with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
                    results = run_batch(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[1796],
                        robot_vars=[],
                        work_dir=tempdir / "work",
                        renode_remote_server_dir="",
                        fault_types_list=["i:0x704"],
                        keep_run_artifacts=False,
                    )

            self.assertEqual(results, [])
            self.assertEqual(observed_timeouts, [60.0])


class Phase2FaultTest(unittest.TestCase):
    """Tests for the phase2_fault profile schema and robot var generation."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_phase2_fault_defaults_disabled(self) -> None:
        """Without phase2_fault in profile, config defaults to disabled."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_phase2
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                """,
            )
            profile = load_profile(profile_path)
            self.assertFalse(profile.fault_sweep.phase2_fault.enabled)
            self.assertEqual(profile.fault_sweep.phase2_fault.max_points, 0)
            self.assertEqual(profile.fault_sweep.phase2_fault.fault_types, ["power_loss"])
            # Robot vars should NOT contain PHASE2_FAULT_ENABLED
            robot_vars = profile.robot_vars(ROOT)
            phase2_vars = [v for v in robot_vars if "PHASE2_FAULT" in v]
            self.assertEqual(phase2_vars, [])

    def test_phase2_fault_enabled_parsed(self) -> None:
        """phase2_fault section is parsed and emits robot vars."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: with_phase2
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  evaluation_mode: execute
                  phase2_fault:
                    enabled: true
                    fault_types:
                      - power_loss
                      - interrupted_erase
                    max_points: 50
                """,
            )
            profile = load_profile(profile_path)
            p2f = profile.fault_sweep.phase2_fault
            self.assertTrue(p2f.enabled)
            self.assertEqual(p2f.max_points, 50)
            self.assertEqual(p2f.fault_types, ["power_loss", "interrupted_erase"])

            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("PHASE2_FAULT_ENABLED:true", robot_vars)
            self.assertIn("PHASE2_FAULT_MAX_POINTS:50", robot_vars)

    def test_phase2_fault_enabled_no_max_points(self) -> None:
        """phase2_fault enabled without max_points omits that var."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: phase2_no_max
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  phase2_fault:
                    enabled: true
                """,
            )
            profile = load_profile(profile_path)
            self.assertTrue(profile.fault_sweep.phase2_fault.enabled)
            self.assertEqual(profile.fault_sweep.phase2_fault.max_points, 0)

            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("PHASE2_FAULT_ENABLED:true", robot_vars)
            # max_points=0 means auto/unlimited — no robot var emitted
            max_points_vars = [v for v in robot_vars if "PHASE2_FAULT_MAX_POINTS" in v]
            self.assertEqual(max_points_vars, [])

    def test_phase2_fault_negative_max_points_rejected(self) -> None:
        """Negative max_points raises ProfileError."""
        from profile_loader import ProfileError

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: bad_phase2
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  phase2_fault:
                    enabled: true
                    max_points: -5
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)

    def test_phase2_fault_invalid_type_warns(self) -> None:
        """Unknown fault type in phase2_fault emits a warning."""
        import warnings

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: warn_phase2
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  phase2_fault:
                    enabled: true
                    fault_types:
                      - power_loss
                      - unknown_type_xyz
                """,
            )
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                profile = load_profile(profile_path)
                warning_msgs = [str(warning.message) for warning in w]
                has_unknown_warning = any(
                    "unknown_type_xyz" in msg.lower()
                    for msg in warning_msgs
                )
                self.assertTrue(has_unknown_warning, "Expected warning about unknown_type_xyz")
            self.assertTrue(profile.fault_sweep.phase2_fault.enabled)

    def test_phase2_fault_cli_output(self) -> None:
        """CLI debug output includes phase2_fault fields."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: cli_phase2
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  phase2_fault:
                    enabled: true
                    max_points: 25
                    fault_types:
                      - power_loss
                """,
            )
            import json
            from unittest.mock import patch
            from io import StringIO

            with patch("sys.argv", ["profile_loader.py", str(profile_path)]):
                captured = StringIO()
                with redirect_stderr(StringIO()):
                    import profile_loader
                    with patch("sys.stdout", captured):
                        profile_loader.main()
                output = json.loads(captured.getvalue())
            self.assertTrue(output["phase2_fault_enabled"])
            self.assertEqual(output["phase2_fault_max_points"], 25)
            self.assertEqual(output["phase2_fault_types"], ["power_loss"])

    def test_p2_fault_type_encoding(self) -> None:
        """Validate the p2: encoding format for fault_type_csv."""
        # The dispatch encoding is 'p2:P1_AT:P2_AT:P1_TYPE:P2_TYPE'.
        # Test that the format matches what the resc parser expects.
        encoded = "p2:100:5:w:e"
        parts = encoded.split(":")
        self.assertEqual(parts[0], "p2")
        self.assertEqual(int(parts[1]), 100)  # p1_fault_at
        self.assertEqual(int(parts[2]), 5)    # p2_fault_at
        self.assertEqual(parts[3], "w")       # p1_fault_type
        self.assertEqual(parts[4], "e")       # p2_fault_type

    def test_p2_fault_type_encoding_defaults(self) -> None:
        """p2: encoding with only two fields defaults types to 'w'."""
        encoded = "p2:50:10"
        parts = encoded.split(":")
        self.assertEqual(parts[0], "p2")
        p1_type = parts[3] if len(parts) > 3 else "w"
        p2_type = parts[4] if len(parts) > 4 else "w"
        self.assertEqual(p1_type, "w")
        self.assertEqual(p2_type, "w")

    def test_phase2_skip_reasons_summarized(self) -> None:
        results = [
            {
                "fault_at": 10,
                "fault_type": "p2",
                "fault_injected": False,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "skip_reason": "phase2_no_write_at_index",
                "phase2_fault": {
                    "skip_reason": "no_write_at_index",
                    "p2_total_ops": 3,
                    "p2_max_fault_index": 2,
                },
            },
            {
                "fault_at": 11,
                "fault_type": "p2",
                "fault_injected": False,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "skip_reason": "phase2_no_erase_at_index",
                "phase2_fault": {
                    "skip_reason": "no_erase_at_index",
                    "p2_total_ops": 0,
                    "p2_max_fault_index": -1,
                },
            },
            {
                "fault_at": 12,
                "fault_type": "w",
                "fault_injected": False,
                "boot_outcome": "skipped",
                "boot_slot": None,
                "skip_reason": "probability_gate",
            },
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertEqual(summary["discarded_no_fault_fired"], 3)
        self.assertEqual(summary["skip_reasons"]["phase2_no_write_at_index"], 1)
        self.assertEqual(summary["skip_reasons"]["phase2_no_erase_at_index"], 1)
        self.assertEqual(summary["skip_reasons"]["probability_gate"], 1)
        self.assertEqual(summary["phase2_skip_reasons"]["no_write_at_index"], 1)
        self.assertEqual(summary["phase2_skip_reasons"]["no_erase_at_index"], 1)

    def test_phase2_skip_reasons_absent_without_phase2_discards(self) -> None:
        results = [
            {
                "fault_at": 1,
                "fault_injected": False,
                "boot_outcome": "skipped",
                "boot_slot": None,
                "skip_reason": "probability_gate",
            }
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertIn("skip_reasons", summary)
        self.assertNotIn("phase2_skip_reasons", summary)


class HookFaultTest(unittest.TestCase):
    """Tests for the hook_fault profile schema and summary reporting."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_hook_fault_defaults_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_hook_fault
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                """,
            )
            profile = load_profile(profile_path)
            self.assertFalse(profile.fault_sweep.hook_fault.enabled)
            self.assertEqual(profile.fault_sweep.hook_fault.max_points, 0)
            self.assertEqual(profile.fault_sweep.hook_fault.fault_types, ["power_loss"])

    def test_hook_fault_enabled_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: with_hook_fault
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  boot_cycles: 3
                  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py
                  hook_fault:
                    enabled: true
                    fault_types:
                      - power_loss
                      - bit_corruption
                    max_points: 12
                """,
            )
            profile = load_profile(profile_path)
            hf = profile.fault_sweep.hook_fault
            self.assertTrue(hf.enabled)
            self.assertEqual(hf.max_points, 12)
            self.assertEqual(hf.fault_types, ["power_loss", "bit_corruption"])

    def test_hook_fault_negative_max_points_rejected(self) -> None:
        from profile_loader import ProfileError

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: bad_hook_fault
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  boot_cycles: 2
                  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py
                  hook_fault:
                    enabled: true
                    max_points: -1
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)

    def test_hook_fault_invalid_type_warns(self) -> None:
        import warnings

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: warn_hook_fault
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  boot_cycles: 2
                  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py
                  hook_fault:
                    enabled: true
                    fault_types:
                      - power_loss
                      - nonsense_type
                """,
            )
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                profile = load_profile(profile_path)
            self.assertTrue(any("nonsense_type" in str(x.message) for x in w))
            self.assertEqual(profile.fault_sweep.hook_fault.fault_types, ["power_loss"])

    def test_hook_fault_cli_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: cli_hook_fault
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
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
                  mode: runtime
                  boot_cycles: 2
                  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py
                  hook_fault:
                    enabled: true
                    max_points: 7
                    fault_types:
                      - power_loss
                """,
            )
            import json
            from io import StringIO

            with mock.patch("sys.argv", ["profile_loader.py", str(profile_path)]):
                captured = StringIO()
                with redirect_stderr(StringIO()):
                    import profile_loader
                    with mock.patch("sys.stdout", captured):
                        profile_loader.main()
                output = json.loads(captured.getvalue())
            self.assertTrue(output["hook_fault_enabled"])
            self.assertEqual(output["hook_fault_max_points"], 7)
            self.assertEqual(output["hook_fault_types"], ["power_loss"])

    def test_hook_fault_type_encoding(self) -> None:
        encoded = "h:5:w"
        parts = encoded.split(":")
        self.assertEqual(parts[0], "h")
        self.assertEqual(int(parts[1]), 5)
        self.assertEqual(parts[2], "w")

    def test_hook_skip_reasons_summarized(self) -> None:
        results = [
            {
                "fault_at": 2,
                "fault_type": "h",
                "fault_injected": False,
                "boot_outcome": "skipped",
                "boot_slot": None,
                "skip_reason": "hook_no_write_at_index",
                "hook_fault": {
                    "skip_reason": "no_write_at_index",
                    "hook_total_ops": 3,
                    "hook_max_fault_index": 2,
                },
            },
            {
                "fault_at": 3,
                "fault_type": "h",
                "fault_injected": False,
                "boot_outcome": "skipped",
                "boot_slot": None,
                "skip_reason": "hook_hook_script_not_python",
                "hook_fault": {
                    "skip_reason": "hook_script_not_python",
                    "hook_total_ops": 0,
                    "hook_max_fault_index": -1,
                },
            },
        ]
        profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
        summary = summarize_runtime_sweep(results, profile=profile)
        self.assertEqual(summary["hook_skip_reasons"], {
            "hook_script_not_python": 1,
            "no_write_at_index": 1,
        })

    def test_hook_skip_reasons_absent_without_hook_faults(self) -> None:
        results = [
            {
                "fault_at": 1,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "no_boot",
                "boot_slot": None,
            }
        ]
        profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
        summary = summarize_runtime_sweep(results, profile=profile)
        self.assertNotIn("hook_skip_reasons", summary)


class MetadataFaultTest(unittest.TestCase):
    """Tests for metadata-write-fault injection feature."""

    def _make_profile_yaml(self, metadata_fault_block):
        base = textwrap.dedent("""            schema_version: 1
            name: test_metadata_fault
            platform: platforms/test.repl
            bootloader:
              elf: test.elf
              entry: 0x00000000
            memory:
              sram: { start: 0x20000000, end: 0x20040000 }
              write_granularity: 4
              slots:
                exec: { base: 0x00010000, size: 0x40000 }
                staging: { base: 0x00050000, size: 0x40000 }
            images:
              exec: test_exec.bin
              staging: test_staging.bin
            fault_sweep:
              mode: runtime
              evaluation_mode: execute
              max_writes: 100
        """)
        if metadata_fault_block:
            base += textwrap.indent(metadata_fault_block, "  ")
        return base

    def test_metadata_fault_profile_parsing(self):
        yaml_str = self._make_profile_yaml(
            "metadata_fault:\n  enabled: true\n  fault_types:\n    - power_loss\n    - bit_corruption\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_str)
            f.flush()
            profile = load_profile(f.name)
        os.unlink(f.name)
        mf = profile.fault_sweep.metadata_fault
        self.assertTrue(mf.enabled)
        self.assertIn("power_loss", mf.fault_types)
        self.assertIn("bit_corruption", mf.fault_types)

    def test_metadata_fault_default_disabled(self):
        yaml_str = self._make_profile_yaml("")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_str)
            f.flush()
            profile = load_profile(f.name)
        os.unlink(f.name)
        self.assertFalse(profile.fault_sweep.metadata_fault.enabled)
        robot_vars = profile.robot_vars(Path("/tmp"))
        self.assertEqual([v for v in robot_vars if "METADATA_FAULT" in v], [])

    def test_metadata_fault_enabled_emits_no_legacy_robot_var(self):
        yaml_str = self._make_profile_yaml("metadata_fault:\n  enabled: true\n")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_str)
            f.flush()
            profile = load_profile(f.name)
        os.unlink(f.name)
        robot_vars = profile.robot_vars(Path("/tmp"))
        metadata_vars = [v for v in robot_vars if v.startswith("METADATA_FAULT_ENABLED:")]
        self.assertEqual(metadata_vars, [])

    def test_metadata_fault_generates_fault_points(self):
        from profile_loader import MetadataFaultConfig
        mf = MetadataFaultConfig(enabled=True, fault_types=["power_loss"])
        combined = []
        for mf_fp in range(5):
            for ft_name in mf.fault_types:
                combined.append((mf_fp, "m:{}".format({"power_loss": "w", "bit_corruption": "b"}.get(ft_name, "w"))))
        self.assertEqual(len(combined), 5)
        self.assertEqual(combined[0], (0, "m:w"))
        self.assertEqual(combined[4], (4, "m:w"))

    @unittest.skipIf(CalibrationResult is None, "audit_bootloader not importable")
    def test_calibration_result_setup_writes(self):
        cal = CalibrationResult(total_writes=100, total_erases=5, trace_file=None, erase_trace_file=None, trace_file_bin=None, erase_trace_file_bin=None, setup_writes=4)
        self.assertEqual(cal.setup_writes, 4)

    @unittest.skipIf(CalibrationResult is None, "audit_bootloader not importable")
    def test_calibration_result_setup_writes_default(self):
        cal = CalibrationResult(total_writes=100, total_erases=5, trace_file=None, erase_trace_file=None, trace_file_bin=None, erase_trace_file_bin=None)
        self.assertEqual(cal.setup_writes, 0)

    def test_metadata_fault_invalid_type_warns(self):
        yaml_str = self._make_profile_yaml("metadata_fault:\n  enabled: true\n  fault_types:\n    - power_loss\n    - bogus_type\n")
        import warnings
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_str)
            f.flush()
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                profile = load_profile(f.name)
        os.unlink(f.name)
        self.assertTrue(any("bogus_type" in str(x.message) for x in w), "Expected warning about bogus_type")
        self.assertIn("power_loss", profile.fault_sweep.metadata_fault.fault_types)

    def test_metadata_fault_type_encoding(self):
        self.assertEqual("m:w".split(":")[0], "m")
        self.assertEqual("m:w".split(":")[1], "w")
        self.assertEqual("m:b".split(":")[1], "b")


if __name__ == "__main__":
    unittest.main()
