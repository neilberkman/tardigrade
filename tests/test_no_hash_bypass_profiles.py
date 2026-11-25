#!/usr/bin/env python3
"""Regression coverage for no-hash-bypass profile variants."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile, load_profile_raw  # noqa: E402


class NoHashBypassProfileTests(unittest.TestCase):
    def test_full_fault_coverage_nohashbypass_matches_bypass_canary_plus_payload_faults(self) -> None:
        source = load_profile(
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_power_and_controller_faults.yaml"
        )
        variant = load_profile(
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml"
        )

        # The bypass canary leaves out the payload-corrupting types; this
        # profile runs them with validation on. On NRF52NVMC,
        # write_rejection keeps the old word and reports success.
        payload_corrupting = [
            "bit_corruption",
            "silent_write_failure",
            "write_disturb",
            "wear_leveling_corruption",
            "write_rejection",
        ]
        for fault_type in payload_corrupting:
            with self.subTest(fault_type=fault_type):
                self.assertNotIn(fault_type, source.fault_sweep.fault_types)
                self.assertIn(fault_type, variant.fault_sweep.fault_types)
        self.assertEqual(
            [t for t in variant.fault_sweep.fault_types if t not in payload_corrupting],
            source.fault_sweep.fault_types,
        )
        self.assertEqual(variant.bootloader_elf, source.bootloader_elf)
        self.assertEqual(variant.images["exec"], source.images["exec"])
        self.assertEqual(variant.images["staging"], source.images["staging"])
        self.assertEqual(
            [(w.address, w.u32) for w in variant.pre_boot_state],
            [(w.address, w.u32) for w in source.pre_boot_state],
        )
        self.assertEqual(variant.fault_sweep.run_duration, source.fault_sweep.run_duration)
        self.assertEqual(variant.fault_sweep.max_step_limit, source.fault_sweep.max_step_limit)
        self.assertEqual(variant.fault_sweep.sweep_hash_bypass_symbols, [])
        self.assertTrue(
            load_profile_raw(
                ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml"
            ).get("skip_self_test", False)
        )


if __name__ == "__main__":
    unittest.main()
