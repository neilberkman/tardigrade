#!/usr/bin/env python3
"""Lightweight unit tests for discovery-oriented profile/report features."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import (  # noqa: E402
    annotate_result_checks,
    calibration_completed,
    prepare_renode_command,
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
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  boot_cycles: 3
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
            self.assertEqual(profile.invariants, ["multi_boot_converges"])
            self.assertEqual(
                profile.semantic_assertions["control"]["multi_boot_analysis.status"],
                "converged",
            )
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("BOOT_CYCLES:3", robot_vars)
            self.assertIn("STATE_PROBE_SCRIPT:{}".format(probe), robot_vars)

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
        env = {"DOTNET_BUNDLE_EXTRACT_BASE_DIR": "/tmp/dotnet_bundle"}
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
        self.assertIn("DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/dotnet_bundle", cmd)
        self.assertNotIn("docker://renode-patched:test", cmd[1:])


if __name__ == "__main__":
    unittest.main()
