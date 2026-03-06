#!/usr/bin/env python3
"""Unit tests for generic discovery-framework boundaries."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import annotate_result_checks  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from run_scenario import (  # noqa: E402
    _deep_merge,
    apply_replay_to_profile,
    evaluate_assertions,
    load_replay_spec,
)


class GenericFrameworkTest(unittest.TestCase):
    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_profile_loader_parses_structured_state_probe_and_provider(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            probe = tempdir / "probe.py"
            probe.write_text(
                "def collect_state(bus=None, monitor=None, context=None):\n"
                "    return {'confirmed': True}\n",
                encoding="utf-8",
            )
            provider = tempdir / "provider.py"
            provider.write_text(
                "from invariants import InvariantViolation\n"
                "def check_external(result, **_):\n"
                "    pass\n"
                "INVARIANTS = {'external_ok': check_external}\n",
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: generic_profile
                description: generic
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
                state_probe:
                  script: {probe.as_posix()}
                  format: tardigrade.semantic-state/v1
                  contract_version: 2
                  required_paths:
                    - semantic_state.confirmed
                invariant_providers:
                  - {provider.as_posix()}
                invariants:
                  - external_ok
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertIsNotNone(profile.state_probe)
            self.assertEqual(profile.state_probe_script, str(probe))
            self.assertEqual(profile.state_probe.contract_version, 2)
            self.assertEqual(
                profile.state_probe.required_paths,
                ["semantic_state.confirmed"],
            )
            self.assertEqual(profile.invariant_providers, [str(provider)])
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("STATE_PROBE_SCRIPT:{}".format(probe), robot_vars)

    def test_external_invariant_provider_participates_in_annotation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            provider = tempdir / "provider.py"
            provider.write_text(
                textwrap.dedent(
                    """
                    from invariants import InvariantViolation

                    def check_external_probe(result, **_):
                        state = result.nvm_state or {}
                        if state.get("status") != "ok":
                            raise InvariantViolation(
                                invariant_name="external_probe_ok",
                                description="external provider detected bad status",
                                result=result,
                                details={"status": state.get("status")},
                            )

                    INVARIANTS = {"external_probe_ok": check_external_probe}
                    """
                ),
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: provider_profile
                description: provider
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
                invariant_providers:
                  - {provider.as_posix()}
                invariants:
                  - external_probe_ok
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
                    "semantic_state": {"status": "bad"},
                    "is_control": False,
                }
            ]
            annotate_result_checks(results, profile)
            self.assertEqual(len(results[0].get("invariant_violations", [])), 1)
            self.assertEqual(
                results[0]["invariant_violations"][0]["name"],
                "external_probe_ok",
            )

    def test_state_probe_required_paths_become_observation_failures(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            probe = tempdir / "probe.py"
            probe.write_text(
                "def collect_state(bus=None, monitor=None, context=None):\n"
                "    return {'status': 'ok'}\n",
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: probe_contract_profile
                description: probe contract
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
                state_probe:
                  script: {probe.as_posix()}
                  required_paths:
                    - semantic_state.confirmed
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [
                {
                    "fault_at": 2,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "semantic_state": {"status": "ok"},
                    "is_control": False,
                }
            ]
            annotate_result_checks(results, profile)
            self.assertEqual(len(results[0].get("semantic_observation_failures", [])), 1)
            self.assertEqual(
                results[0]["semantic_observation_failures"][0]["contract"],
                "state_probe.required_paths",
            )

    def test_replay_spec_merges_profile_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            replay_path = tempdir / "replay.yaml"
            replay_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    kind: replay
                    name: example_replay
                    profile_overrides:
                      pre_boot_state:
                        - { address: 0x10000000, u32: 0x00000001 }
                      expect:
                        should_find_issues: true
                    """
                ),
                encoding="utf-8",
            )
            replay = load_replay_spec(replay_path)
            base_profile = {
                "schema_version": 1,
                "name": "base",
                "expect": {"should_find_issues": False, "control_outcome": "success"},
            }
            merged = apply_replay_to_profile(
                base_profile,
                replay,
                inline_overrides={"expect": {"required_issue_reasons": ["boot_outcome"]}},
            )
            self.assertTrue(merged["expect"]["should_find_issues"])
            self.assertEqual(merged["expect"]["control_outcome"], "success")
            self.assertEqual(merged["expect"]["required_issue_reasons"], ["boot_outcome"])
            self.assertEqual(len(merged["pre_boot_state"]), 1)

    def test_evaluate_assertions_handles_nested_paths(self) -> None:
        failures = evaluate_assertions(
            {
                "steps": {
                    "case1": {
                        "report": {
                            "summary": {
                                "runtime_sweep": {
                                    "issue_points": 2,
                                    "control": {"boot_outcome": "success"},
                                }
                            }
                        }
                    }
                }
            },
            [
                {
                    "path": "steps.case1.report.summary.runtime_sweep.issue_points",
                    "op": "ge",
                    "value": 1,
                },
                {
                    "path": "steps.case1.report.summary.runtime_sweep.control.boot_outcome",
                    "op": "equals",
                    "value": "success",
                },
            ],
        )
        self.assertEqual(failures, [])

    def test_deep_merge_keeps_unrelated_nested_keys(self) -> None:
        merged = _deep_merge(
            {"expect": {"should_find_issues": False, "control_outcome": "success"}},
            {"expect": {"required_issue_reasons": ["boot_outcome"]}},
        )
        self.assertEqual(merged["expect"]["control_outcome"], "success")
        self.assertEqual(merged["expect"]["required_issue_reasons"], ["boot_outcome"])


if __name__ == "__main__":
    unittest.main()
