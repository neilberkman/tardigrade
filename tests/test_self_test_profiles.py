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

from self_test import discover_profiles, run_audit, write_summary


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
        self.assertNotIn("mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_fixed.yaml", discovered)
        self.assertNotIn("fault_no_crc.yaml", discovered)
        self.assertNotIn("fault_single_replica.yaml", discovered)
        self.assertNotIn("fault_wrong_slot_order.yaml", discovered)
        self.assertNotIn("fault_no_fallback.yaml", discovered)
        self.assertNotIn("fault_no_meta_replication.yaml", discovered)
        self.assertNotIn("fault_no_vector_check.yaml", discovered)
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
        self.assertNotIn("page_size", raw.get("memory", {}))

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


if __name__ == "__main__":
    unittest.main()
