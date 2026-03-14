#!/usr/bin/env python3
"""WS3 regression tests for real MCUboot HEAD phase2/multi-fault profiles."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_plan import CalibrationInputs, build_fault_plan
from profile_loader import load_profile, load_profile_raw
from self_test import discover_profiles
from sweep import run_multi_fault_phase


MOVE_P2 = ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_phase2fault.yaml"
OFFSET_P2 = ROOT / "profiles" / "mcuboot_head_offset_nrf52_revert_phase2fault.yaml"
MOVE_P2_SELFTEST = (
    ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_phase2fault_selftest.yaml"
)
MOVE_MF = ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade_multifault.yaml"
MOVE_MF_SELFTEST = (
    ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade_multifault_selftest.yaml"
)


class WS3ProfileConfigTests(unittest.TestCase):
    def test_main_profiles_load_and_skip_self_test(self) -> None:
        for path in (MOVE_P2, OFFSET_P2, MOVE_MF):
            profile = load_profile(path)
            raw = load_profile_raw(path)
            self.assertTrue(raw.get("skip_self_test", False), path.name)
            if "phase2fault" in path.name:
                self.assertTrue(profile.fault_sweep.phase2_fault.enabled)
                self.assertEqual(profile.fault_sweep.phase2_fault.max_points, 12)
            if "multifault" in path.name:
                self.assertTrue(profile.fault_sweep.multi_fault.enabled)
                self.assertEqual(
                    profile.fault_sweep.multi_fault.strategy,
                    "pairwise_interesting",
                )
                self.assertEqual(profile.fault_sweep.multi_fault.max_pairs, 100)

    def test_selftest_profiles_are_discoverable(self) -> None:
        discovered = {path.name for path in discover_profiles(ROOT)}
        self.assertIn(MOVE_P2_SELFTEST.name, discovered)
        self.assertIn(MOVE_MF_SELFTEST.name, discovered)
        self.assertNotIn(MOVE_P2.name, discovered)
        self.assertNotIn(MOVE_MF.name, discovered)

    def test_phase2fault_selftest_generates_phase2_entries(self) -> None:
        profile = load_profile(MOVE_P2_SELFTEST)
        plan = build_fault_plan(profile, CalibrationInputs(max_writes=256), quick=False)
        phase2_entries = [ft for ft in plan.fault_types_list if ft.startswith("p2:")]
        self.assertEqual(len(phase2_entries), 3 * 6)
        self.assertIn("p2:0:0:w:w", phase2_entries)
        self.assertIn("p2:128:5:w:w", phase2_entries)


class WS3MultiFaultPhaseTests(unittest.TestCase):
    def _interesting_sweep_results(self):
        return [
            {
                "fault_at": 5,
                "fault_requested": 5,
                "fault_type": "w",
                "fault_injected": True,
                "fault_address": "0x00001000",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "signals": {},
            },
            {
                "fault_at": 30,
                "fault_requested": 30,
                "fault_type": "w",
                "fault_injected": True,
                "fault_address": "0x00002000",
                "boot_outcome": "wrong_image",
                "boot_slot": "staging",
                "signals": {},
            },
            {
                "fault_at": 90,
                "fault_requested": 90,
                "fault_type": "w",
                "fault_injected": True,
                "fault_address": "0x00003000",
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "signals": {},
            },
            {
                "fault_at": 999999,
                "fault_requested": 999999,
                "fault_type": "control",
                "fault_injected": False,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {},
                "is_control": True,
            },
        ]

    def test_multifault_explain_only_includes_rationale(self) -> None:
        profile = load_profile(MOVE_MF_SELFTEST)
        with tempfile.TemporaryDirectory(prefix="ws3_mf_") as td:
            out = run_multi_fault_phase(
                profile=profile,
                sweep_results=self._interesting_sweep_results(),
                repo_root=ROOT,
                renode_test="renode-test",
                robot_suite="tests/ota_fault_point.robot",
                robot_vars=[],
                work_dir=Path(td),
                renode_remote_server_dir="",
                num_workers=1,
                max_batch_points=0,
                max_writes=256,
                explain_only=True,
            )
        self.assertIsNotNone(out.plan)
        self.assertIsNotNone(out.plan_data)
        self.assertTrue(out.plan_data["execution_skipped"])
        self.assertEqual(out.plan_data["interesting_points"], 3)
        self.assertIn("interesting_point_provenance", out.plan_data)
        sample = out.plan_data["sample_sequences"][0]
        self.assertIn("rationale", sample)
        self.assertIn("point", sample["rationale"])

    def test_multifault_execution_path_uses_encoded_sequences(self) -> None:
        profile = load_profile(MOVE_MF_SELFTEST)
        captured = {}

        def fake_run_runtime_sweep(**kwargs):
            captured["fault_points"] = list(kwargs["fault_points"])
            captured["fault_types_list"] = list(kwargs["fault_types_list"])
            results = []
            for idx, fault_type in enumerate(kwargs["fault_types_list"]):
                results.append(
                    {
                        "fault_at": kwargs["fault_points"][idx],
                        "fault_requested": kwargs["fault_points"][idx],
                        "fault_type": fault_type,
                        "fault_injected": True,
                        "fault_address": "0x00000000",
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "actual_writes": 64,
                        "signals": {},
                    }
                )
            return results

        with tempfile.TemporaryDirectory(prefix="ws3_mf_exec_") as td:
            with mock.patch("sweep.run_runtime_sweep", side_effect=fake_run_runtime_sweep):
                out = run_multi_fault_phase(
                    profile=profile,
                    sweep_results=self._interesting_sweep_results(),
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    robot_vars=[],
                    work_dir=Path(td),
                    renode_remote_server_dir="",
                    num_workers=1,
                    max_batch_points=0,
                    max_writes=256,
                    explain_only=False,
                )

        self.assertTrue(captured["fault_points"])
        self.assertTrue(all(ft.startswith("mf:") for ft in captured["fault_types_list"]))
        self.assertIsNotNone(out.summary)
        self.assertEqual(len(out.results), len(captured["fault_types_list"]))
        self.assertIn("fault_sequence", out.results[0])
        self.assertIn("sequence_rationale", out.results[0])


if __name__ == "__main__":
    unittest.main()
