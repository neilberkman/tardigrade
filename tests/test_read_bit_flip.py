#!/usr/bin/env python3
"""Unit tests for read-time bit-flip fault injection support."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import ReadFaultResult, ReadFaultSpec  # noqa: E402
from profile_loader import (  # noqa: E402
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    FaultSweepConfig,
    ProfileError,
    ReadFaultConfig,
    _warn_fault_backend_compat,
    load_profile,
)


# ---------------------------------------------------------------------------
# ReadFaultSpec validation
# ---------------------------------------------------------------------------


class ReadFaultSpecTest(unittest.TestCase):
    """Tests for the ReadFaultSpec dataclass in fault_inject.py."""

    def test_valid_spec(self) -> None:
        spec = ReadFaultSpec(
            region_start=0x10000000,
            region_end=0x10010000,
            bit_flip_count=2,
            probability=0.5,
            seed=42,
        )
        self.assertEqual(spec.region_start, 0x10000000)
        self.assertEqual(spec.region_end, 0x10010000)
        self.assertEqual(spec.bit_flip_count, 2)
        self.assertAlmostEqual(spec.probability, 0.5)
        self.assertEqual(spec.seed, 42)
        self.assertEqual(spec.region_size, 0x10000)

    def test_defaults(self) -> None:
        spec = ReadFaultSpec(region_start=0x1000, region_end=0x2000)
        self.assertEqual(spec.bit_flip_count, 1)
        self.assertAlmostEqual(spec.probability, 1.0)
        self.assertEqual(spec.seed, 0)

    def test_region_end_must_be_greater_than_start(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ReadFaultSpec(region_start=0x2000, region_end=0x1000)
        self.assertIn("must be greater than", str(ctx.exception))

    def test_region_end_equal_to_start_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ReadFaultSpec(region_start=0x1000, region_end=0x1000)

    def test_bit_flip_count_must_be_positive(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ReadFaultSpec(region_start=0x1000, region_end=0x2000, bit_flip_count=0)
        self.assertIn("bit_flip_count", str(ctx.exception))

    def test_probability_out_of_range_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ReadFaultSpec(region_start=0x1000, region_end=0x2000, probability=1.5)
        with self.assertRaises(ValueError):
            ReadFaultSpec(region_start=0x1000, region_end=0x2000, probability=-0.1)

    def test_probability_boundary_values(self) -> None:
        spec_zero = ReadFaultSpec(
            region_start=0x1000, region_end=0x2000, probability=0.0
        )
        self.assertAlmostEqual(spec_zero.probability, 0.0)
        spec_one = ReadFaultSpec(
            region_start=0x1000, region_end=0x2000, probability=1.0
        )
        self.assertAlmostEqual(spec_one.probability, 1.0)


# ---------------------------------------------------------------------------
# ReadFaultResult
# ---------------------------------------------------------------------------


class ReadFaultResultTest(unittest.TestCase):
    """Tests for the ReadFaultResult dataclass."""

    def test_basic_construction(self) -> None:
        result = ReadFaultResult(
            fault_at=5,
            boot_outcome="success",
            boot_slot="exec",
            nvm_state=None,
            raw_log="log output",
            reads_corrupted=3,
            total_reads=100,
        )
        self.assertEqual(result.fault_at, 5)
        self.assertEqual(result.boot_outcome, "success")
        self.assertEqual(result.boot_slot, "exec")
        self.assertEqual(result.reads_corrupted, 3)
        self.assertEqual(result.total_reads, 100)
        self.assertFalse(result.is_control)

    def test_control_flag(self) -> None:
        result = ReadFaultResult(
            fault_at=0,
            boot_outcome="success",
            boot_slot="exec",
            nvm_state=None,
            raw_log="",
            reads_corrupted=0,
            total_reads=0,
            is_control=True,
        )
        self.assertTrue(result.is_control)


# ---------------------------------------------------------------------------
# ReadFaultConfig (profile_loader)
# ---------------------------------------------------------------------------


class ReadFaultConfigTest(unittest.TestCase):
    """Tests for ReadFaultConfig in profile_loader.py."""

    def test_default_config(self) -> None:
        cfg = ReadFaultConfig()
        self.assertEqual(cfg.target_regions, [])
        self.assertEqual(cfg.bit_flip_count, 1)
        self.assertAlmostEqual(cfg.fault_probability, 1.0)
        self.assertEqual(cfg.seed, 0)

    def test_custom_config(self) -> None:
        cfg = ReadFaultConfig(
            target_regions=[(0x10000, 0x20000), (0x30000, 0x40000)],
            bit_flip_count=3,
            fault_probability=0.75,
            seed=99,
        )
        self.assertEqual(len(cfg.target_regions), 2)
        self.assertEqual(cfg.bit_flip_count, 3)
        self.assertAlmostEqual(cfg.fault_probability, 0.75)
        self.assertEqual(cfg.seed, 99)

    def test_invalid_probability_rejected(self) -> None:
        with self.assertRaises(ProfileError):
            ReadFaultConfig(fault_probability=2.0)
        with self.assertRaises(ProfileError):
            ReadFaultConfig(fault_probability=-0.5)

    def test_invalid_region_rejected(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            ReadFaultConfig(target_regions=[(0x2000, 0x1000)])
        self.assertIn("must be >", str(ctx.exception))

    def test_bit_flip_count_clamped_to_minimum_1(self) -> None:
        cfg = ReadFaultConfig(bit_flip_count=0)
        self.assertEqual(cfg.bit_flip_count, 1)


# ---------------------------------------------------------------------------
# Fault type registration
# ---------------------------------------------------------------------------


class FaultTypeRegistrationTest(unittest.TestCase):
    """Tests that read_bit_flip is registered in the type sets."""

    def test_read_bit_flip_in_known_types(self) -> None:
        self.assertIn("read_bit_flip", KNOWN_FAULT_TYPES)

    def test_read_bit_flip_in_implemented_types(self) -> None:
        self.assertIn("read_bit_flip", IMPLEMENTED_FAULT_TYPES)


# ---------------------------------------------------------------------------
# Profile YAML parsing
# ---------------------------------------------------------------------------


class ProfileReadFaultParsingTest(unittest.TestCase):
    """Tests for parsing read_fault_config from YAML profiles."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_profile_with_read_bit_flip_fault_type(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: read_fault_test
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                  read_fault_config:
                    target_regions:
                      - { start: 0x10000000, end: 0x10001000 }
                      - { start: 0x10001000, end: 0x10002000 }
                    bit_flip_count: 2
                    fault_probability: 0.8
                    seed: 42
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertIn("read_bit_flip", profile.fault_sweep.fault_types)
            rfc = profile.fault_sweep.read_fault_config
            self.assertIsNotNone(rfc)
            self.assertEqual(len(rfc.target_regions), 2)
            self.assertEqual(rfc.target_regions[0], (0x10000000, 0x10001000))
            self.assertEqual(rfc.target_regions[1], (0x10001000, 0x10002000))
            self.assertEqual(rfc.bit_flip_count, 2)
            self.assertAlmostEqual(rfc.fault_probability, 0.8)
            self.assertEqual(rfc.seed, 42)

    def test_profile_without_read_fault_config_defaults_to_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_read_fault
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertIsNone(profile.fault_sweep.read_fault_config)

    def test_invalid_read_fault_region_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: bad_region
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                  read_fault_config:
                    target_regions:
                      - { start: 0x20000, end: 0x10000 }
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError) as ctx:
                load_profile(profile_path)
            self.assertIn("must be >", str(ctx.exception))

    def test_invalid_read_fault_probability_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: bad_prob
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                  read_fault_config:
                    fault_probability: 2.0
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)


# ---------------------------------------------------------------------------
# Robot variable emission
# ---------------------------------------------------------------------------


class RobotVarEmissionTest(unittest.TestCase):
    """Tests for robot variable emission with read fault config."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_read_fault_robot_vars_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: robot_var_test
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                  read_fault_config:
                    target_regions:
                      - { start: 0x10000000, end: 0x10001000 }
                    bit_flip_count: 3
                    fault_probability: 0.5
                    seed: 77
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn(
                "READ_FAULT_REGIONS:0x10000000-0x10001000", robot_vars
            )
            self.assertIn("READ_FAULT_BIT_FLIPS:3", robot_vars)
            self.assertIn("READ_FAULT_PROBABILITY:0.5", robot_vars)
            self.assertIn("READ_FAULT_SEED:77", robot_vars)

    def test_read_fault_vars_not_emitted_without_fault_type(self) -> None:
        """When read_bit_flip is not in fault_types, no read fault vars."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_read_vars
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [power_loss]
                  read_fault_config:
                    target_regions:
                      - { start: 0x10000000, end: 0x10001000 }
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            read_vars = [v for v in robot_vars if v.startswith("READ_FAULT_")]
            self.assertEqual(read_vars, [])

    def test_multiple_regions_comma_separated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: multi_region
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                  read_fault_config:
                    target_regions:
                      - { start: 0x10000000, end: 0x10001000 }
                      - { start: 0x20000000, end: 0x20010000 }
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            regions_var = [v for v in robot_vars if v.startswith("READ_FAULT_REGIONS:")]
            self.assertEqual(len(regions_var), 1)
            self.assertEqual(
                regions_var[0],
                "READ_FAULT_REGIONS:0x10000000-0x10001000,0x20000000-0x20010000",
            )

    def test_read_fault_vars_not_emitted_without_config(self) -> None:
        """When read_bit_flip is in fault_types but no config, no vars."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_config
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  fault_types: [read_bit_flip]
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            read_vars = [v for v in robot_vars if v.startswith("READ_FAULT_")]
            self.assertEqual(read_vars, [])


# ---------------------------------------------------------------------------
# Backend-compat warnings
# ---------------------------------------------------------------------------


class BackendCompatWarningTest(unittest.TestCase):
    """Tests that _warn_fault_backend_compat correctly identifies which
    backends support read_bit_flip and which do not.

    Supported: NVMemory (slow-path), MRAMMemory.
    Unsupported: MappedMemory+NVMC (fast-path), STM32 controllers.
    """

    def _make_fs(self, fault_types: list) -> FaultSweepConfig:
        return FaultSweepConfig(fault_types=fault_types)

    # -- NVMemory (slow-path) should NOT warn --

    def test_no_warning_nvm_ctrl_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "platforms/nvm_slow.repl", "nvm_ctrl")
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(read_warnings, [])

    def test_no_warning_nvm_platform_no_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "platforms/nvm_slow.repl", None)
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(read_warnings, [])

    # -- MRAMMemory should NOT warn --

    def test_no_warning_mram_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "platforms/mram_full.repl", "mram")
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(read_warnings, [])

    def test_no_warning_mram_platform_no_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(
                fs, "platforms/cortex_m0_mram_endpoint.repl", None
            )
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(read_warnings, [])

    # -- Fast-path (NVMC) SHOULD warn --

    def test_warning_nvmc_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(
                fs, "platforms/cortex_m4_flash_fast.repl", "faultFlash"
            )
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(len(read_warnings), 1)
        self.assertIn("NVMemory or MRAMMemory", str(read_warnings[0].message))

    def test_warning_nvmc_platform_no_backend(self) -> None:
        fs = self._make_fs(["read_bit_flip"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(
                fs, "platforms/cortex_m4_flash_fast.repl", None
            )
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(len(read_warnings), 1)

    # -- No warning when read_bit_flip not in fault_types --

    def test_no_warning_without_read_bit_flip(self) -> None:
        fs = self._make_fs(["power_loss"])
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(
                fs, "platforms/cortex_m4_flash_fast.repl", "faultFlash"
            )
        read_warnings = [x for x in w if "read_bit_flip" in str(x.message)]
        self.assertEqual(read_warnings, [])


if __name__ == "__main__":
    unittest.main()
