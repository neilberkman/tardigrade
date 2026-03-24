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

from self_test import discover_profiles, run_audit


class SelfTestProfileDiscoveryTests(unittest.TestCase):
    def test_benchmark_and_execute_only_profiles_are_skipped(self):
        repo_root = ROOT
        discovered = {p.name for p in discover_profiles(repo_root)}

        self.assertNotIn("nuttx_nxboot_128.yaml", discovered)
        self.assertNotIn("security_toctou_no_protection.yaml", discovered)
        self.assertNotIn("security_toctou_with_protection.yaml", discovered)

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


if __name__ == "__main__":
    unittest.main()
