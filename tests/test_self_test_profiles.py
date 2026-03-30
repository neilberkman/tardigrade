#!/usr/bin/env python3
"""Regression tests for generic self-test profile discovery."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock
import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from self_test import build_detailed_result, discover_profiles, run_audit, write_summary


class SelfTestProfileDiscoveryTests(unittest.TestCase):
    def test_benchmark_and_execute_only_profiles_are_skipped(self):
        repo_root = ROOT
        discovered = {p.name for p in discover_profiles(repo_root)}

        self.assertNotIn("nuttx_nxboot_128.yaml", discovered)
        self.assertNotIn("security_toctou_no_protection.yaml", discovered)
        self.assertNotIn("security_toctou_with_protection.yaml", discovered)
        self.assertNotIn("fault_copy_before_validate.yaml", discovered)
        self.assertNotIn("fault_staging_overlap.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_extended.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults_long.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_rc_injection.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_nohashbypass.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_upgrade_extended_selftest.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_verify_instruction_skip.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_fixed.yaml", discovered)
        self.assertNotIn("mcuboot_pr2206_scratch_geom_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2206_scratch_geom_fixed.yaml", discovered)
        self.assertNotIn("tfm_an521_verify_instruction_skip.yaml", discovered)
        self.assertNotIn("fault_no_crc.yaml", discovered)
        self.assertNotIn("fault_single_replica.yaml", discovered)
        self.assertNotIn("fault_wrong_slot_order.yaml", discovered)
        self.assertNotIn("fault_no_fallback.yaml", discovered)
        self.assertNotIn("fault_no_meta_replication.yaml", discovered)
        self.assertNotIn("fault_no_vector_check.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_stm32f4_fast_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_offset_stm32f4_fast_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_scratch_stm32f4_fast_upgrade.yaml", discovered)
        self.assertIn("fault_copy_before_validate_selftest.yaml", discovered)
        self.assertIn("fault_staging_overlap_selftest.yaml", discovered)
        self.assertIn("mcuboot_head_move_nrf52_revert_extended_selftest.yaml", discovered)
        self.assertIn("mcuboot_head_move_nrf52_revert_rc_injection_selftest.yaml", discovered)
        self.assertIn("mcuboot_head_move_nrf52_revert_write_faults_selftest.yaml", discovered)
        self.assertIn("fault_no_crc_selftest.yaml", discovered)
        self.assertIn("fault_single_replica_selftest.yaml", discovered)
        self.assertIn("fault_wrong_slot_order_selftest.yaml", discovered)
        self.assertIn("fault_no_fallback_selftest.yaml", discovered)
        self.assertIn("fault_no_meta_replication_selftest.yaml", discovered)
        self.assertIn("fault_no_vector_check_selftest.yaml", discovered)

    def test_retroactive_negative_controls_expect_no_issues(self):
        negative_controls = [
            "mcuboot_head_move_nrf52_revert_rc_injection.yaml",
            "mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_head_move_nrf52_revert_write_faults.yaml",
            "mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml",
            "mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml",
            "mcuboot_head_move_stm32f4_revert_driver_error.yaml",
            "mcuboot_head_offset_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_head_scratch_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_pr2109_scratch_fixed_silent.yaml",
        ]
        for relpath in negative_controls:
            with self.subTest(profile=relpath):
                raw = yaml.safe_load((ROOT / "profiles" / relpath).read_text(encoding="utf-8"))
                expect = raw.get("expect", {}) or {}
                self.assertFalse(expect.get("should_find_issues", False), relpath)

    def test_generic_stm32f4_offset_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_offset_stm32f4_upgrade.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(
            raw.get("fault_sweep", {}).get("fault_types"),
            ["power_loss", "swap_progress"],
        )
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x08020014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertNotIn("page_size", raw.get("memory", {}))

    def test_generic_nrf52_move_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(
            raw.get("fault_sweep", {}).get("fault_types"),
            ["power_loss", "swap_progress"],
        )
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertTrue(raw.get("expect", {}).get("should_find_issues"))
        self.assertNotIn("page_size", raw.get("memory", {}))

    def test_extended_nrf52_move_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade_extended.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_move_upgrade_followon_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_move_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_move_nrf52_upgrade_multifault.yaml",
            "mcuboot_head_move_nrf52_upgrade_multifault_selftest.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_offset_upgrade_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_offset_nrf52_upgrade.yaml",
            "mcuboot_head_offset_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_offset_nrf52_upgrade_multifault.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_scratch_upgrade_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_scratch_nrf52_upgrade.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_extended.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_multifault.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_remaining_generic_mcuboot_upgrades_use_discovery(self):
        expected = {
            "mcuboot_head_upgrade.yaml": (0x0000C014, 0x00010001),
            "mcuboot_offset_upgrade.yaml": (0x0000C014, 0x00010001),
            "mcuboot_head_move_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_offset_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_scratch_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_move_stm32f4_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_offset_stm32f4_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_move_stm32f4_fast_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_offset_stm32f4_fast_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_scratch_stm32f4_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_scratch_stm32f4_fast_upgrade.yaml": (0x08020014, 0x00000101),
        }
        for name, (marker_address, marker_value) in expected.items():
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), marker_address)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), marker_value)
                self.assertNotIn("image_hash", raw.get("success_criteria", {}))
                self.assertNotIn("expected_image", raw.get("success_criteria", {}))
                fault_types = raw.get("fault_sweep", {}).get("fault_types", [])
                self.assertIn("power_loss", fault_types)
                self.assertIn("swap_progress", fault_types)

    def test_run_audit_forwards_extra_args(self):
        repo_root = ROOT
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        output_path = ROOT / "tmp_self_test_result.json"

        with mock.patch("self_test.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            run_audit(
                repo_root=repo_root,
                profile_path=profile_path,
                output_path=output_path,
                quick=False,
                renode_test="renode-test",
                extra_args=["--workers", "8"],
            )

        cmd = mock_run.call_args.kwargs["args"] if "args" in mock_run.call_args.kwargs else mock_run.call_args.args[0]
        self.assertIn("--workers", cmd)
        self.assertIn("8", cmd)

    def test_write_summary_records_partial_progress(self):
        output_path = ROOT / "tmp_self_test_summary.json"
        try:
            write_summary(
                str(output_path),
                total=5,
                detailed_results=[
                    {"profile": "one", "passed": True},
                    {"profile": "two", "passed": False},
                ],
            )
            payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_profiles"], 5)
            self.assertEqual(payload["completed_profiles"], 2)
            self.assertEqual(payload["passed"], 1)
            self.assertEqual(payload["failed"], 1)
        finally:
            output_path.unlink(missing_ok=True)

    def test_build_detailed_result_keeps_raw_audit_verdict_separate(self):
        result = build_detailed_result(
            profile="mcuboot_head_move_nrf52_revert_phase2fault_selftest",
            passed=True,
            reason="No issues found, as expected",
            exit_code=1,
            report={
                "verdict": "FAIL — found 1042 issue points",
                "summary": {"runtime_sweep": {"bricks": 1042, "brick_rate": 0.97}},
            },
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["audit_verdict"], "FAIL — found 1042 issue points")
        self.assertEqual(result["bricks"], 1042)
        self.assertEqual(result["brick_rate"], 0.97)


if __name__ == "__main__":
    unittest.main()
