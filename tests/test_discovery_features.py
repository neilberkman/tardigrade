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
    prepare_renode_command,
    summarize_runtime_sweep,
)
from profile_loader import load_profile  # noqa: E402


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
