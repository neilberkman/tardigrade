#!/usr/bin/env python3
"""Unit tests for generic discovery-framework boundaries."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from unittest import mock
from types import SimpleNamespace
from pathlib import Path
import sys as pysys

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from result_checks import annotate_result_checks  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from invariants import resolve_invariants  # noqa: E402
from run_scenario import (  # noqa: E402
    _deep_merge,
    _scenario_asserts_step_verdict,
    apply_replay_to_profile,
    evaluate_assertions,
    load_replay_spec,
    run_audit_step,
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
                invariant_config:
                  rollback_window: 3
                  mode: strict
                invariants:
                  - external_ok
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertIsNotNone(profile.state_probe)
            self.assertEqual(profile.state_probe.script, str(probe))
            self.assertEqual(profile.state_probe.contract_version, 2)
            self.assertEqual(
                profile.state_probe.required_paths,
                ["semantic_state.confirmed"],
            )
            self.assertEqual(profile.invariant_providers, [str(provider)])
            self.assertEqual(
                profile.invariant_config,
                {"rollback_window": 3, "mode": "strict"},
            )
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("STATE_PROBE:{}".format(probe), robot_vars)

    def test_profile_loader_emits_optional_slot_and_image_vars(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            tertiary = tempdir / "tertiary.bin"
            recovery = tempdir / "recovery.bin"
            tertiary.write_bytes(b"\xAA" * 32)
            recovery.write_bytes(b"\xBB" * 32)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: optional_slot_profile
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
                    tertiary: {{ base: 0x10010000, size: 0x1000 }}
                    recovery: {{ base: 0x10011000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                  tertiary: {tertiary.as_posix()}
                  recovery: {recovery.as_posix()}
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn("SLOT_TERTIARY_BASE:0x10010000", robot_vars)
            self.assertIn("SLOT_RECOVERY_BASE:0x10011000", robot_vars)
            self.assertIn("IMAGE_TERTIARY:{}".format(tertiary), robot_vars)
            self.assertIn("IMAGE_RECOVERY:{}".format(recovery), robot_vars)

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

    def test_invariant_config_is_forwarded_to_provider(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            provider = tempdir / "provider.py"
            provider.write_text(
                textwrap.dedent(
                    """
                    from invariants import InvariantViolation

                    def check_external_probe(result, **context):
                        cfg = context.get("invariant_config") or {}
                        if cfg.get("expected_status") != "ok":
                            raise InvariantViolation(
                                invariant_name="external_probe_ok",
                                description="unexpected invariant config",
                                result=result,
                                details={"config": cfg},
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
                invariant_config:
                  expected_status: ok
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
            self.assertEqual(results[0].get("invariant_violations", []), [])

    def test_invariant_semantic_stage_selects_fault_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            provider = tempdir / "provider.py"
            provider.write_text(
                textwrap.dedent(
                    """
                    from invariants import InvariantViolation

                    def check_stage(result, result_signals=None, **_):
                        if (result.nvm_state or {}).get("stage") != "fault":
                            raise InvariantViolation(
                                invariant_name="wrong_stage",
                                description="invariant did not receive fault state",
                                result=result,
                            )
                        if (result_signals or {}).get("semantic_state", {}).get("stage") != "fault":
                            raise InvariantViolation(
                                invariant_name="wrong_signal_stage",
                                description="signals did not receive fault state",
                                result=result,
                            )

                    INVARIANTS = {"check_stage": check_stage}
                    """
                ),
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: staged_profile
                description: generic
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                invariant_providers:
                  - {provider.as_posix()}
                invariants:
                  - check_stage
                invariant_config:
                  semantic_state_stage: fault_snapshot
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            results = [{
                "fault_at": 1,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "semantic_state": {"stage": "recovery"},
                "fault_semantic_state": {"stage": "fault"},
                "signals": {"semantic_state": {"stage": "recovery"}},
                "is_control": False,
            }]
            annotate_result_checks(results, profile)
            self.assertEqual(results[0].get("invariant_violations", []), [])

            missing = dict(results[0])
            missing.pop("fault_semantic_state", None)
            missing.pop("semantic_observation_failures", None)
            annotate_result_checks([missing], profile)
            self.assertEqual(
                missing["semantic_observation_failures"][0]["path"],
                "fault_semantic_state",
            )

    def test_invariant_provider_sees_elapsed_virtual_time(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            provider = tempdir / "provider.py"
            provider.write_text(
                textwrap.dedent(
                    """
                    from invariants import InvariantViolation

                    def check_boot_timing(result, **context):
                        cfg = context.get("invariant_config") or {}
                        limit = cfg.get("max_boot_seconds")
                        if limit is None:
                            return
                        elapsed = getattr(result, "elapsed_virtual_time_s", None)
                        if elapsed is None:
                            raise InvariantViolation(
                                invariant_name="boot_timing",
                                description="missing elapsed virtual time",
                                result=result,
                            )
                        if elapsed > limit:
                            raise InvariantViolation(
                                invariant_name="boot_timing",
                                description="boot exceeded configured limit",
                                result=result,
                                details={"elapsed": elapsed, "limit": limit},
                            )

                    INVARIANTS = {"boot_timing": check_boot_timing}
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
                invariant_config:
                  max_boot_seconds: 1.0
                invariants:
                  - boot_timing
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
                    "signals": {"phase2_emulated_s": 0.75},
                    "is_control": False,
                }
            ]
            annotate_result_checks(results, profile)
            self.assertEqual(results[0].get("invariant_violations", []), [])

    def test_external_invariant_provider_loads_without_scripts_dir_on_sys_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            provider = tempdir / "provider.py"
            provider.write_text(
                textwrap.dedent(
                    """
                    from invariants import InvariantViolation

                    def check_external_probe(result, **_):
                        return None

                    INVARIANTS = {"external_probe_ok": check_external_probe}
                    """
                ),
                encoding="utf-8",
            )

            original_path = list(pysys.path)
            try:
                pysys.path[:] = [entry for entry in pysys.path if entry != str(SCRIPTS)]
                resolved = resolve_invariants(
                    ["external_probe_ok"],
                    provider_paths=[str(provider)],
                )
            finally:
                pysys.path[:] = original_path

            self.assertEqual(len(resolved), 1)

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

    def test_state_probe_required_paths_use_final_boot_cycle_semantic_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            probe = tempdir / "probe.py"
            probe.write_text(
                "def collect_state(bus=None, monitor=None, context=None):\n"
                "    return {'confirmed': False}\n",
                encoding="utf-8",
            )
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: settled_probe_contract_profile
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
                    "fault_at": 4,
                    "fault_injected": False,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "semantic_state": {},
                    "boot_cycles": [
                        {"cycle": 0, "semantic_state": {}},
                        {"cycle": 1, "semantic_state": {"confirmed": False}},
                    ],
                    "is_control": True,
                }
            ]
            annotate_result_checks(results, profile)
            self.assertNotIn("semantic_observation_failures", results[0])

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

    def test_audit_step_honors_failed_json_verdict_with_zero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            base_profile = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: scenario_verdict_fixture
                """,
            )

            def fake_run(cmd, cwd):
                output_path = Path(cmd[cmd.index("--output") + 1])
                output_path.write_text('{"verdict":"FAIL"}', encoding="utf-8")
                return 0, "", ""

            with mock.patch("run_scenario._run_command_streamed", side_effect=fake_run):
                step_result = run_audit_step(
                    repo_root=ROOT,
                    scenario_dir=tempdir,
                    default_base_profile_path=base_profile,
                    step={"id": "failed_audit", "kind": "audit"},
                    tempdir=tempdir,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                )

        self.assertEqual(step_result["exit_code"], 0)
        self.assertEqual(step_result["status"], "FAIL")
        self.assertEqual(step_result["verdict_policy"], "require_pass")

    def test_explicit_scenario_verdict_assertion_owns_expected_failure(self) -> None:
        steps = [
            {"id": "audit_case", "kind": "audit"},
            {
                "id": "verdict_policy",
                "kind": "assert",
                "assertions": [
                    {
                        "path": "steps.audit_case.report.verdict",
                        "op": "equals",
                        "value": "FAIL",
                    }
                ],
            },
        ]
        self.assertTrue(_scenario_asserts_step_verdict(steps, "audit_case"))
        self.assertFalse(
            _scenario_asserts_step_verdict(
                [
                    {
                        "id": "weak_policy",
                        "kind": "assert",
                        "assertions": [
                            {
                                "path": "steps.audit_case.report.verdict",
                                "op": "exists",
                            }
                        ],
                    }
                ],
                "audit_case",
            )
        )

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            base_profile = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: expected_failure_fixture
                """,
            )

            def fake_run(cmd, cwd):
                output_path = Path(cmd[cmd.index("--output") + 1])
                output_path.write_text('{"verdict":"FAIL"}', encoding="utf-8")
                return 0, "", ""

            with mock.patch("run_scenario._run_command_streamed", side_effect=fake_run):
                step_result = run_audit_step(
                    repo_root=ROOT,
                    scenario_dir=tempdir,
                    default_base_profile_path=base_profile,
                    step=steps[0],
                    tempdir=tempdir,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                    defer_verdict_to_assertion=True,
                )

        self.assertEqual(step_result["status"], "PASS")
        self.assertEqual(step_result["verdict_policy"], "scenario_assertion")

    def test_scenario_assertion_cannot_accept_missing_child_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            base_profile = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: missing_report_fixture
                """,
            )

            with mock.patch(
                "run_scenario._run_command_streamed",
                return_value=(0, "", ""),
            ):
                step_result = run_audit_step(
                    repo_root=ROOT,
                    scenario_dir=tempdir,
                    default_base_profile_path=base_profile,
                    step={"id": "missing_report", "kind": "audit"},
                    tempdir=tempdir,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                    defer_verdict_to_assertion=True,
                )

        self.assertEqual(step_result["exit_code"], 0)
        self.assertEqual(step_result["status"], "FAIL")
        self.assertIsNone(step_result["report"])

    def test_deep_merge_keeps_unrelated_nested_keys(self) -> None:
        merged = _deep_merge(
            {"expect": {"should_find_issues": False, "control_outcome": "success"}},
            {"expect": {"required_issue_reasons": ["boot_outcome"]}},
        )
        self.assertEqual(merged["expect"]["control_outcome"], "success")
        self.assertEqual(merged["expect"]["required_issue_reasons"], ["boot_outcome"])

    def test_run_audit_step_honors_step_base_profile_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            base1 = tempdir / "base1.yaml"
            base2 = tempdir / "base2.yaml"
            base1.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: base_one
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader: { elf: examples/vulnerable_ota/firmware.elf, entry: 0x10000000 }
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x10000000, size: 0x1000 }
                        staging: { base: 0x10001000, size: 0x1000 }
                    images: { staging: examples/vulnerable_ota/firmware.bin }
                    success_criteria: { vtor_in_slot: exec }
                    expect: { should_find_issues: false }
                    """
                ),
                encoding="utf-8",
            )
            base2.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: base_two
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader: { elf: examples/vulnerable_ota/firmware.elf, entry: 0x10000000 }
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x20000000, size: 0x1000 }
                        staging: { base: 0x20001000, size: 0x1000 }
                    images: { staging: examples/vulnerable_ota/firmware.bin }
                    success_criteria: { vtor_in_slot: exec }
                    expect: { should_find_issues: false }
                    """
                ),
                encoding="utf-8",
            )

            def fake_run(cmd, cwd):
                profile_path = Path(cmd[cmd.index("--profile") + 1])
                output_path = Path(cmd[cmd.index("--output") + 1])
                rendered = profile_path.read_text(encoding="utf-8")
                self.assertIn("name: base_two", rendered)
                output_path.write_text(
                    '{"summary": {"runtime_sweep": {"issue_points": 0}}}',
                    encoding="utf-8",
                )
                return 0, "", ""

            with mock.patch("run_scenario._run_command_streamed", side_effect=fake_run):
                step_result = run_audit_step(
                    repo_root=ROOT,
                    scenario_dir=tempdir,
                    default_base_profile_path=base1,
                    step={
                        "id": "override_case",
                        "kind": "audit",
                        "base_profile": base2.name,
                        "profile_overrides": {"expect": {"required_issue_reasons": ["boot_outcome"]}},
                    },
                    tempdir=tempdir,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                )
            self.assertEqual(step_result["base_profile"], str(base2.resolve()))

    def test_run_audit_step_materializes_inherited_profile_before_temp_copy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profiles = root / "profiles"
            run_temp = root / "run"
            profiles.mkdir()
            run_temp.mkdir()
            base = profiles / "base.yaml"
            child = profiles / "child.yaml"
            base.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: inherited_base
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader: { elf: examples/vulnerable_ota/firmware.elf, entry: 0x10000000 }
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x10000000, size: 0x1000 }
                        staging: { base: 0x10001000, size: 0x1000 }
                    images: { staging: examples/vulnerable_ota/firmware.bin }
                    success_criteria: { vtor_in_slot: exec }
                    fault_sweep: { mode: runtime, max_writes: 1 }
                    expect: { should_find_issues: false }
                    """
                ),
                encoding="utf-8",
            )
            child.write_text(
                "base_profile: base.yaml\nname: inherited_child\n",
                encoding="utf-8",
            )

            def fake_run(cmd, cwd):
                rendered_path = Path(cmd[cmd.index("--profile") + 1])
                rendered = yaml.safe_load(rendered_path.read_text(encoding="utf-8"))
                self.assertNotIn("base_profile", rendered)
                self.assertEqual(rendered["name"], "inherited_child")
                self.assertIn("memory", rendered)
                output_path = Path(cmd[cmd.index("--output") + 1])
                output_path.write_text('{"verdict":"PASS"}', encoding="utf-8")
                return 0, "", ""

            with mock.patch("run_scenario._run_command_streamed", side_effect=fake_run):
                step_result = run_audit_step(
                    repo_root=ROOT,
                    scenario_dir=profiles,
                    default_base_profile_path=child,
                    step={"id": "inherited", "kind": "audit"},
                    tempdir=run_temp,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                )
            self.assertEqual(step_result["status"], "PASS")

    def test_run_audit_step_resolves_repo_root_relative_base_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profiles_dir = tempdir / "profiles"
            scenarios_dir = tempdir / "scenarios"
            profiles_dir.mkdir()
            scenarios_dir.mkdir()
            base1 = profiles_dir / "base1.yaml"
            base2 = profiles_dir / "base2.yaml"
            base1.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: base_one
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader: { elf: examples/vulnerable_ota/firmware.elf, entry: 0x10000000 }
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x10000000, size: 0x1000 }
                        staging: { base: 0x10001000, size: 0x1000 }
                    images: { staging: examples/vulnerable_ota/firmware.bin }
                    success_criteria: { vtor_in_slot: exec }
                    expect: { should_find_issues: false }
                    """
                ),
                encoding="utf-8",
            )
            base2.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: base_two
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader: { elf: examples/vulnerable_ota/firmware.elf, entry: 0x10000000 }
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x20000000, size: 0x1000 }
                        staging: { base: 0x20001000, size: 0x1000 }
                    images: { staging: examples/vulnerable_ota/firmware.bin }
                    success_criteria: { vtor_in_slot: exec }
                    expect: { should_find_issues: false }
                    """
                ),
                encoding="utf-8",
            )

            def fake_run(cmd, cwd):
                profile_path = Path(cmd[cmd.index("--profile") + 1])
                output_path = Path(cmd[cmd.index("--output") + 1])
                rendered = profile_path.read_text(encoding="utf-8")
                self.assertIn("name: base_two", rendered)
                output_path.write_text(
                    '{"summary": {"runtime_sweep": {"issue_points": 0}}}',
                    encoding="utf-8",
                )
                return 0, "", ""

            with mock.patch("run_scenario._run_command_streamed", side_effect=fake_run):
                step_result = run_audit_step(
                    repo_root=tempdir,
                    scenario_dir=scenarios_dir,
                    default_base_profile_path=base1,
                    step={
                        "id": "repo_root_override",
                        "kind": "audit",
                        "base_profile": "profiles/base2.yaml",
                    },
                    tempdir=tempdir,
                    args=SimpleNamespace(
                        renode_test="",
                        renode_remote_server_dir="",
                        robot_var=[],
                        keep_run_artifacts=False,
                        workers=0,
                    ),
                )
            self.assertEqual(step_result["base_profile"], str(base2.resolve()))


if __name__ == "__main__":
    unittest.main()
