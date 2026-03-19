#!/usr/bin/env python3
"""Registration and planner coverage for the driver_error fault type."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from fault_types import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from profile_loader import IMPLEMENTED_FAULT_TYPES, KNOWN_FAULT_TYPES, load_profile  # noqa: E402


_BASE_PROFILE = textwrap.dedent("""\
    schema_version: 1
    name: driver_error_test
    description: driver_error planner test
    platform: platforms/cortex_m4_flash_fast.repl
    bootloader:
      elf: examples/vulnerable_ota/firmware.elf
      entry: 0x00000000
    memory:
      sram: { start: 0x20000000, end: 0x20020000 }
      write_granularity: 4
      slots:
        exec: { base: 0x00000000, size: 0x40000 }
        staging: { base: 0x00040000, size: 0x40000 }
    images:
      staging: examples/vulnerable_ota/firmware.bin
    success_criteria:
      vtor_in_slot: exec
    expect:
      should_find_issues: true
    fault_sweep:
      mode: runtime
      max_writes: 8
      fault_types: [driver_error]
""")


class DriverErrorFaultTypeTest(unittest.TestCase):
    def test_driver_error_registered_everywhere(self) -> None:
        self.assertIn("driver_error", KNOWN_FAULT_TYPES)
        self.assertIn("driver_error", IMPLEMENTED_FAULT_TYPES)
        self.assertIn("driver_error", EXECUTE_ONLY_FAULT_TYPES)
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["driver_error"], "g")
        self.assertEqual(_fault_type_label("g"), "driver_error")

    def test_profile_parses_driver_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        self.assertEqual(profile.fault_sweep.fault_types, ["driver_error"])

    def test_fault_plan_emits_driver_error_points(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=4),
            quick=False,
        )
        self.assertEqual(plan.fault_points, [0, 1, 2, 3])
        self.assertEqual(plan.fault_types_list, ["g", "g", "g", "g"])

    def test_existing_mcuboot_revert_profiles_include_driver_error(self) -> None:
        profile_paths = [
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml",
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml",
        ]
        for profile_path in profile_paths:
            with self.subTest(profile=profile_path.name):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    profile = load_profile(profile_path)
                self.assertIn("driver_error", profile.fault_sweep.fault_types)


if __name__ == "__main__":
    unittest.main()
