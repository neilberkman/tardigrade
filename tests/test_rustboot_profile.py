#!/usr/bin/env python3
"""Regression coverage for the checked-in rustBoot runtime profile."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile


class RustbootProfileTests(unittest.TestCase):
    def test_update_profile_uses_semantic_checks_and_erase_faults(self):
        profile = load_profile(ROOT / "profiles" / "rustboot_nrf52840_update.yaml")

        self.assertEqual(profile.memory.slots["exec"].base, 0x0002F000)
        self.assertEqual(profile.memory.slots["staging"].base, 0x00058000)
        self.assertEqual(profile.fault_sweep.fault_types, ["interrupted_erase"])
        self.assertTrue(profile.success_criteria.image_hash)
        self.assertEqual(profile.success_criteria.image_hash_slot, "exec")
        self.assertEqual(profile.success_criteria.expected_image, "staging")
        self.assertIsNotNone(profile.state_probe)
        self.assertEqual(profile.state_probe.script, "targets/rustboot/probe.py")
        self.assertEqual(
            profile.invariant_providers, ["targets/rustboot/invariants.py"]
        )
        self.assertEqual(
            profile.invariants,
            [
                "rustboot_boot_not_empty",
                "rustboot_swap_flags_consistent",
                "rustboot_no_packed_flag_corruption",
            ],
        )
        self.assertTrue(profile.expect.should_find_issues)


if __name__ == "__main__":
    unittest.main()
