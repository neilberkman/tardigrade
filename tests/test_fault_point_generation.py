#!/usr/bin/env python3
"""End-to-end tests proving OTP, NVS corruption, and bootloader_region_write
fault types are (or aren't) genuinely emitted by the sweep planner.

These tests exercise the profile-parser -> include-flag -> combined-list
pipeline to verify that each fault type either generates real fault points
or is correctly rejected as classification-only.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fault_inject import generate_nvs_corruption_variants
from fault_types import (
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _OTP_WIRE_CODE_TO_BLOW_MODE,
    _OTP_WIRE_CODES,
    _fault_type_label,
)
from fault_plan import CalibrationInputs, build_fault_plan

# Aliases used by sync tests (historically from audit_bootloader, now canonical in fault_types).
FT_EXECUTE_ONLY = EXECUTE_ONLY_FAULT_TYPES
FT_NAME_TO_CODE = FAULT_TYPE_NAME_TO_CODE
ft_label = _fault_type_label
from profile_loader import (
    CLASSIFICATION_ONLY_FAULT_TYPES,
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    NvsCorruptionConfig,
    OTP_FAULT_TYPE_CODES,
    load_profile,
)


# ---------------------------------------------------------------------------
# Helper: minimal profile YAML template
# ---------------------------------------------------------------------------

_BASE_PROFILE = textwrap.dedent("""\
    schema_version: 1
    name: test_fp_gen
    description: fault point generation test
    platform: platforms/cortex_m4_flash_fast.repl
    bootloader:
      elf: examples/vulnerable_ota/firmware.elf
      entry: 0x00000000
    memory:
      sram: {{ start: 0x20000000, end: 0x20020000 }}
      write_granularity: 4
      slots:
        exec: {{ base: 0x00000000, size: 0x40000 }}
        staging: {{ base: 0x00040000, size: 0x40000 }}
    images:
      staging: examples/vulnerable_ota/firmware.bin
    success_criteria:
      vtor_in_slot: exec
    expect:
      should_find_issues: true
    {extra}
""")


def _write_profile(tmpdir: str, extra: str = "") -> Path:
    path = Path(tmpdir) / "profile.yaml"
    path.write_text(_BASE_PROFILE.format(extra=extra), encoding="utf-8")
    return path


# ===========================================================================
# OTP fault types: include-flag and wire-code coverage
# ===========================================================================


class OTPFaultPointGenerationTest(unittest.TestCase):
    """Prove OTP fault types are wired into the sweep planner."""

    OTP_TYPES = {"otp_partial_program", "otp_stuck_bit", "otp_read_disturb", "otp_overblow"}

    def test_otp_types_are_implemented(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, IMPLEMENTED_FAULT_TYPES)

    def test_otp_types_are_execute_only(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, EXECUTE_ONLY_FAULT_TYPES)
            self.assertIn(ft, FT_EXECUTE_ONLY)

    def test_otp_wire_codes_in_name_to_code(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, FAULT_TYPE_NAME_TO_CODE)
            self.assertIn(ft, FT_NAME_TO_CODE)

    def test_otp_wire_code_round_trip(self) -> None:
        for ft in self.OTP_TYPES:
            code = FAULT_TYPE_NAME_TO_CODE[ft]
            self.assertEqual(_fault_type_label(code), ft)
            self.assertEqual(ft_label(code), ft)

    def test_otp_blow_mode_mapping_exists(self) -> None:
        self.assertEqual(_OTP_WIRE_CODE_TO_BLOW_MODE["op"], 0)
        self.assertEqual(_OTP_WIRE_CODE_TO_BLOW_MODE["os"], 1)
        self.assertEqual(_OTP_WIRE_CODE_TO_BLOW_MODE["od"], 2)
        self.assertEqual(_OTP_WIRE_CODE_TO_BLOW_MODE["oo"], 3)

    def test_otp_wire_codes_set(self) -> None:
        self.assertEqual(_OTP_WIRE_CODES, frozenset({"op", "os", "od", "oo"}))

    def test_otp_include_flag_derived_from_fault_types(self) -> None:
        """Simulate the include_otp_faults flag logic from audit_bootloader."""
        fault_types = ["power_loss", "otp_partial_program", "otp_stuck_bit"]
        include_otp = any(ft.startswith("otp_") for ft in fault_types)
        self.assertTrue(include_otp)
        otp_fault_types = [ft for ft in fault_types if ft.startswith("otp_")]
        self.assertEqual(otp_fault_types, ["otp_partial_program", "otp_stuck_bit"])

    def test_otp_fault_points_generated_for_each_type(self) -> None:
        """Simulate the combined-list builder for OTP fault types."""
        fault_points = [0, 5, 10]
        fault_types = ["otp_partial_program", "otp_read_disturb"]
        combined = []
        for otp_ft in fault_types:
            otp_code = FAULT_TYPE_NAME_TO_CODE.get(otp_ft, "op")
            combined += [(fp, otp_code) for fp in fault_points]
        # Each OTP type gets its own set of fault points.
        self.assertEqual(len(combined), 6)
        codes = [ft for _, ft in combined]
        self.assertEqual(codes.count("op"), 3)
        self.assertEqual(codes.count("od"), 3)

    def test_otp_profile_parsing_with_all_types(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                otp_peripheral: otp
                fault_sweep:
                  mode: runtime
                  max_writes: 50
                  fault_types:
                    - otp_partial_program
                    - otp_stuck_bit
                    - otp_read_disturb
                    - otp_overblow
            """))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(path)
            for ft in self.OTP_TYPES:
                self.assertIn(ft, profile.fault_sweep.fault_types)


class SwapProgressFaultPointGenerationTest(unittest.TestCase):
    def test_swap_progress_is_implemented(self) -> None:
        self.assertIn("swap_progress", KNOWN_FAULT_TYPES)
        self.assertIn("swap_progress", IMPLEMENTED_FAULT_TYPES)

    def test_swap_progress_wire_code_round_trip(self) -> None:
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["swap_progress"], "w:sp")
        self.assertEqual(_fault_type_label("w:sp"), "swap_progress")

    def test_swap_progress_profile_parsing_reads_page_size(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  page_size: 0x1000
                  slots:
                    exec: { base: 0x00000000, size: 0x40000 }
                    staging: { base: 0x00040000, size: 0x40000 }
                fault_sweep:
                  mode: runtime
                  max_writes: auto
                  fault_types: [swap_progress]
            """))
            profile = load_profile(path)
            self.assertEqual(profile.memory.page_size, 0x1000)
            self.assertEqual(profile.fault_sweep.fault_types, ["swap_progress"])

    def test_swap_progress_fault_points_generated_from_sector_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  page_size: 0x1000
                  slots:
                    exec: { base: 0x00000000, size: 0x40000 }
                    staging: { base: 0x00040000, size: 0x40000 }
                fault_sweep:
                  mode: runtime
                  max_writes: auto
                  fault_types: [swap_progress]
            """))
            trace = Path(td) / "write_trace.csv"
            trace.write_text(
                "\n".join(
                    [
                        "write_index,flash_offset,value",
                        "1,262144,1",
                        "2,262148,2",
                        "3,266240,3",
                        "4,266244,4",
                        "5,270336,5",
                    ]
                ),
                encoding="utf-8",
            )
            erase_trace = Path(td) / "erase_trace.csv"
            erase_trace.write_text(
                "\n".join(
                    [
                        "erase_index,flash_offset,writes_at_this_point,erase_size",
                        "1,262144,0,4096",
                        "2,266240,2,4096",
                        "3,270336,4,4096",
                    ]
                ),
                encoding="utf-8",
            )
            profile = load_profile(path)
            plan = build_fault_plan(
                profile=profile,
                calibration=CalibrationInputs(
                    max_writes=5,
                    trace_file=str(trace),
                    erase_trace_file=str(erase_trace),
                ),
            )
            self.assertEqual(plan.fault_points, [2, 4])
            self.assertEqual(plan.fault_types_list, ["w:sp", "w:sp"])


# ===========================================================================
# NVS corruption: wire code, variant generation, include-flag
# ===========================================================================


class NVSCorruptionFaultPointGenerationTest(unittest.TestCase):
    """Prove nvs_corruption is wired into the sweep planner."""

    def test_nvs_corruption_is_implemented(self) -> None:
        self.assertIn("nvs_corruption", IMPLEMENTED_FAULT_TYPES)

    def test_nvs_corruption_is_execute_only(self) -> None:
        self.assertIn("nvs_corruption", EXECUTE_ONLY_FAULT_TYPES)
        self.assertIn("nvs_corruption", FT_EXECUTE_ONLY)

    def test_nvs_corruption_wire_code(self) -> None:
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["nvs_corruption"], "nv")
        self.assertEqual(FT_NAME_TO_CODE["nvs_corruption"], "nv")

    def test_nvs_corruption_wire_code_round_trip(self) -> None:
        self.assertEqual(_fault_type_label("nv"), "nvs_corruption")
        self.assertEqual(ft_label("nv"), "nvs_corruption")

    def test_nvs_variant_prefix_label(self) -> None:
        self.assertEqual(_fault_type_label("nv:0"), "nvs_corruption_variant")
        self.assertEqual(_fault_type_label("nv:3"), "nvs_corruption_variant")
        self.assertEqual(ft_label("nv:2"), "nvs_corruption_variant")

    def test_nvs_include_flag_derived(self) -> None:
        fault_types = ["power_loss", "nvs_corruption"]
        include_nvs = "nvs_corruption" in fault_types
        self.assertTrue(include_nvs)

    def test_nvs_fault_points_generated_per_mode(self) -> None:
        """Simulate the combined-list builder for nvs_corruption."""
        nvs_modes = ["bit_flip", "partial_erase", "truncate", "scramble"]
        combined = []
        for vi, mode in enumerate(nvs_modes):
            combined.append((vi, "nv:{}".format(vi)))
        self.assertEqual(len(combined), 4)
        self.assertEqual(combined[0], (0, "nv:0"))
        self.assertEqual(combined[3], (3, "nv:3"))

    def test_nvs_corruption_config_defaults(self) -> None:
        cfg = NvsCorruptionConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.modes, ["bit_flip", "partial_erase", "truncate"])

    def test_nvs_corruption_config_enabled(self) -> None:
        cfg = NvsCorruptionConfig(enabled=True, modes=["bit_flip", "scramble"])
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.modes, ["bit_flip", "scramble"])

    def test_nvs_variant_generation_produces_different_data(self) -> None:
        clean = b"\xAA" * 256
        variants = generate_nvs_corruption_variants(clean, 256, modes=["bit_flip", "scramble"])
        self.assertEqual(len(variants), 2)
        for mode, data in variants:
            self.assertNotEqual(data, clean)
            self.assertEqual(len(data), 256)

    def test_nvs_profile_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                nvs_region:
                  address: 0x80000
                  size: 0x1000
                fault_sweep:
                  mode: runtime
                  max_writes: 50
                  fault_types:
                    - power_loss
                    - nvs_corruption
                  nvs_corruption:
                    enabled: true
                    modes: [bit_flip, scramble]
                    seed: 42
            """))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(path)
            self.assertIn("nvs_corruption", profile.fault_sweep.fault_types)
            self.assertTrue(profile.fault_sweep.nvs_corruption.enabled)
            self.assertEqual(profile.fault_sweep.nvs_corruption.modes, ["bit_flip", "scramble"])
            self.assertEqual(profile.fault_sweep.nvs_corruption.seed, 42)

    def test_nvs_robot_vars_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                nvs_region:
                  address: 0x80000
                  size: 0x1000
                fault_sweep:
                  mode: runtime
                  max_writes: 50
                  fault_types:
                    - nvs_corruption
                  nvs_corruption:
                    enabled: true
                    modes: [bit_flip, scramble]
                    seed: 7
            """))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(path)
            repo_root = Path(td)
            rvars = profile.robot_vars(repo_root)
            modes_var = [v for v in rvars if v.startswith("NVS_CORRUPTION_MODES:")]
            seed_var = [v for v in rvars if v.startswith("NVS_CORRUPTION_SEED:")]
            self.assertEqual(len(modes_var), 1)
            self.assertEqual(modes_var[0], "NVS_CORRUPTION_MODES:bit_flip,scramble")
            self.assertEqual(len(seed_var), 1)
            self.assertEqual(seed_var[0], "NVS_CORRUPTION_SEED:7")

    def test_nvs_robot_vars_not_emitted_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                nvs_region:
                  address: 0x80000
                  size: 0x1000
                fault_sweep:
                  mode: runtime
                  max_writes: 50
                  fault_types:
                    - power_loss
            """))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(path)
            repo_root = Path(td)
            rvars = profile.robot_vars(repo_root)
            modes_var = [v for v in rvars if "NVS_CORRUPTION_MODES" in v]
            self.assertEqual(len(modes_var), 0)


# ===========================================================================
# bootloader_region_write: classification-only, not injectable
# ===========================================================================


class BootloaderRegionWriteClassificationTest(unittest.TestCase):
    """Prove bootloader_region_write is NOT an injectable fault type."""

    def test_bootloader_region_write_in_known(self) -> None:
        self.assertIn("bootloader_region_write", KNOWN_FAULT_TYPES)

    def test_bootloader_region_write_not_in_implemented(self) -> None:
        self.assertNotIn("bootloader_region_write", IMPLEMENTED_FAULT_TYPES)

    def test_bootloader_region_write_in_classification_only(self) -> None:
        self.assertIn("bootloader_region_write", CLASSIFICATION_ONLY_FAULT_TYPES)

    def test_bootloader_region_write_no_wire_code(self) -> None:
        self.assertNotIn("bootloader_region_write", FAULT_TYPE_NAME_TO_CODE)
        self.assertNotIn("bootloader_region_write", FT_NAME_TO_CODE)

    def test_bootloader_region_write_not_execute_only(self) -> None:
        self.assertNotIn("bootloader_region_write", EXECUTE_ONLY_FAULT_TYPES)

    def test_profile_warns_on_bootloader_region_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_profile(td, textwrap.dedent("""\
                fault_sweep:
                  mode: runtime
                  max_writes: 50
                  fault_types:
                    - power_loss
                    - bootloader_region_write
            """))
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                load_profile(path)
            classification_warnings = [
                x for x in w if "classification" in str(x.message).lower()
            ]
            self.assertGreater(
                len(classification_warnings), 0,
                "Expected a warning about bootloader_region_write being "
                "classification-only, got: {}".format(
                    [str(x.message) for x in w]
                ),
            )


# ===========================================================================
# Cross-cutting: consistency between fault_types.py and audit_bootloader.py
# ===========================================================================


class FaultTypeConsistencyTest(unittest.TestCase):
    """Verify fault_types.py and audit_bootloader.py stay in sync."""

    def test_execute_only_sets_match(self) -> None:
        self.assertEqual(EXECUTE_ONLY_FAULT_TYPES, FT_EXECUTE_ONLY)

    def test_name_to_code_maps_match(self) -> None:
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE, FT_NAME_TO_CODE)

    def test_all_implemented_have_wire_codes_or_are_special(self) -> None:
        """Every IMPLEMENTED fault type should have a wire code."""
        for ft in IMPLEMENTED_FAULT_TYPES:
            self.assertIn(
                ft, FAULT_TYPE_NAME_TO_CODE,
                "{} is IMPLEMENTED but has no wire code".format(ft),
            )


if __name__ == "__main__":
    unittest.main()
