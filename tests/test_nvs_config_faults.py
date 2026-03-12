#!/usr/bin/env python3
"""Unit tests for NVS/config region fault injection feature."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fault_inject import (  # noqa: E402
    NVS_CORRUPTION_MODES,
    NvsCorruptionSpec,
    generate_nvs_corruption_variants,
)
from profile_loader import (  # noqa: E402
    ConfigCheck,
    NvsRegionConfig,
    ProfileError,
    load_profile,
)


# ---------------------------------------------------------------------------
# NvsCorruptionSpec dataclass tests
# ---------------------------------------------------------------------------


class TestNvsCorruptionSpec(unittest.TestCase):
    def test_valid_spec(self) -> None:
        spec = NvsCorruptionSpec(
            region_start=0x3E000,
            region_end=0x40000,
            corruption_mode="bit_flip",
        )
        self.assertEqual(spec.region_size, 0x2000)

    def test_invalid_region_range(self) -> None:
        with self.assertRaises(ValueError):
            NvsCorruptionSpec(
                region_start=0x40000,
                region_end=0x3E000,
                corruption_mode="bit_flip",
            )

    def test_equal_region_range(self) -> None:
        with self.assertRaises(ValueError):
            NvsCorruptionSpec(
                region_start=0x3E000,
                region_end=0x3E000,
                corruption_mode="bit_flip",
            )

    def test_invalid_corruption_mode(self) -> None:
        with self.assertRaises(ValueError):
            NvsCorruptionSpec(
                region_start=0x3E000,
                region_end=0x40000,
                corruption_mode="invalid_mode",
            )

    def test_all_modes_accepted(self) -> None:
        for mode in sorted(NVS_CORRUPTION_MODES):
            spec = NvsCorruptionSpec(
                region_start=0x1000,
                region_end=0x2000,
                corruption_mode=mode,
            )
            self.assertEqual(spec.corruption_mode, mode)


# ---------------------------------------------------------------------------
# generate_nvs_corruption_variants tests
# ---------------------------------------------------------------------------


class TestGenerateNvsCorruptionVariants(unittest.TestCase):
    def setUp(self) -> None:
        self.region_size = 256
        self.region_data = bytes([0xAA] * self.region_size)

    def test_all_modes_generated_by_default(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size
        )
        mode_names = [name for name, _ in variants]
        self.assertEqual(sorted(mode_names), sorted(NVS_CORRUPTION_MODES))

    def test_single_mode(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["bit_flip"]
        )
        self.assertEqual(len(variants), 1)
        self.assertEqual(variants[0][0], "bit_flip")

    def test_bit_flip_modifies_data(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["bit_flip"], seed=42
        )
        _, corrupted = variants[0]
        self.assertEqual(len(corrupted), self.region_size)
        self.assertNotEqual(corrupted, self.region_data)
        diffs = sum(1 for a, b in zip(self.region_data, corrupted) if a != b)
        self.assertGreater(diffs, 0)

    def test_partial_erase_second_half_is_ff(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["partial_erase"]
        )
        _, corrupted = variants[0]
        half = self.region_size // 2
        self.assertEqual(corrupted[:half], self.region_data[:half])
        self.assertEqual(corrupted[half:], bytes([0xFF] * (self.region_size - half)))

    def test_truncate_zeroes_after_16_bytes(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["truncate"]
        )
        _, corrupted = variants[0]
        self.assertEqual(corrupted[:16], self.region_data[:16])
        self.assertEqual(corrupted[16:], bytes([0x00] * (self.region_size - 16)))

    def test_scramble_fully_randomized(self) -> None:
        variants = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["scramble"], seed=123
        )
        _, corrupted = variants[0]
        self.assertEqual(len(corrupted), self.region_size)
        self.assertNotEqual(corrupted, self.region_data)

    def test_deterministic_with_same_seed(self) -> None:
        v1 = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["bit_flip"], seed=99
        )
        v2 = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["bit_flip"], seed=99
        )
        self.assertEqual(v1[0][1], v2[0][1])

    def test_different_seeds_produce_different_output(self) -> None:
        v1 = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["scramble"], seed=1
        )
        v2 = generate_nvs_corruption_variants(
            self.region_data, self.region_size, modes=["scramble"], seed=2
        )
        self.assertNotEqual(v1[0][1], v2[0][1])

    def test_short_data_padded_with_ff(self) -> None:
        short_data = bytes([0xBB] * 32)
        variants = generate_nvs_corruption_variants(
            short_data, self.region_size, modes=["partial_erase"]
        )
        _, corrupted = variants[0]
        self.assertEqual(len(corrupted), self.region_size)
        half = self.region_size // 2
        expected_first_half = short_data + bytes([0xFF] * (half - len(short_data)))
        self.assertEqual(corrupted[:half], expected_first_half)

    def test_invalid_mode_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_nvs_corruption_variants(
                self.region_data, self.region_size, modes=["bogus"]
            )

    def test_output_length_matches_region_size(self) -> None:
        for mode in sorted(NVS_CORRUPTION_MODES):
            variants = generate_nvs_corruption_variants(
                self.region_data, self.region_size, modes=[mode]
            )
            _, corrupted = variants[0]
            self.assertEqual(
                len(corrupted),
                self.region_size,
                "mode {} produced wrong length".format(mode),
            )


# ---------------------------------------------------------------------------
# ConfigCheck evaluation tests
# ---------------------------------------------------------------------------


class TestConfigCheck(unittest.TestCase):
    def test_expected_match(self) -> None:
        check = ConfigCheck(address=0x3E010, expected=0x01)
        self.assertTrue(check.evaluate(0x01))
        self.assertFalse(check.evaluate(0x02))

    def test_nonzero(self) -> None:
        check = ConfigCheck(address=0x3E100, nonzero=True)
        self.assertTrue(check.evaluate(0x42))
        self.assertTrue(check.evaluate(1))
        self.assertFalse(check.evaluate(0))

    def test_range_check(self) -> None:
        check = ConfigCheck(address=0x3E200, range_min=10, range_max=100)
        self.assertTrue(check.evaluate(50))
        self.assertTrue(check.evaluate(10))
        self.assertTrue(check.evaluate(100))
        self.assertFalse(check.evaluate(9))
        self.assertFalse(check.evaluate(101))

    def test_range_min_only(self) -> None:
        check = ConfigCheck(address=0x1000, range_min=5)
        self.assertTrue(check.evaluate(5))
        self.assertTrue(check.evaluate(1000))
        self.assertFalse(check.evaluate(4))

    def test_range_max_only(self) -> None:
        check = ConfigCheck(address=0x1000, range_max=200)
        self.assertTrue(check.evaluate(0))
        self.assertTrue(check.evaluate(200))
        self.assertFalse(check.evaluate(201))

    def test_combined_expected_and_nonzero(self) -> None:
        check = ConfigCheck(address=0x1000, expected=0x42, nonzero=True)
        self.assertTrue(check.evaluate(0x42))
        self.assertFalse(check.evaluate(0x00))
        self.assertFalse(check.evaluate(0x43))

    def test_describe_failure(self) -> None:
        check = ConfigCheck(address=0x3E010, expected=0x01)
        desc = check.describe_failure(0xFF)
        self.assertIn("0x3E010", desc)
        self.assertIn("0xFF", desc)
        self.assertIn("0x1", desc)

    def test_no_constraints_always_passes(self) -> None:
        check = ConfigCheck(address=0x1000)
        self.assertTrue(check.evaluate(0))
        self.assertTrue(check.evaluate(0xFFFFFFFF))


# ---------------------------------------------------------------------------
# Profile parsing tests
# ---------------------------------------------------------------------------


class TestNvsRegionProfileParsing(unittest.TestCase):
    def _write_profile(self, tmpdir: Path, body: str) -> Path:
        path = tmpdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def _base_profile(self, extra: str = "") -> str:
        return """
        schema_version: 1
        name: test_nvs
        description: test
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
        {}
        """.format(extra)

    def test_profile_without_nvs_region_works(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile())
            profile = load_profile(p)
            self.assertIsNone(profile.nvs_region)
            self.assertEqual(profile.success_criteria.config_checks, [])

    def test_nvs_region_parsed(self) -> None:
        extra = "\n        nvs_region:\n          address: 0x0003E000\n          size: 0x2000\n        "
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile(extra))
            profile = load_profile(p)
            self.assertIsNotNone(profile.nvs_region)
            self.assertEqual(profile.nvs_region.address, 0x3E000)
            self.assertEqual(profile.nvs_region.size, 0x2000)
            self.assertIsNone(profile.nvs_region.snapshot)

    def test_nvs_region_with_snapshot(self) -> None:
        extra = "\n        nvs_region:\n          address: 0x0003E000\n          size: 0x2000\n          snapshot: old_firmware_nvs.bin\n        "
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile(extra))
            profile = load_profile(p)
            self.assertEqual(profile.nvs_region.snapshot, "old_firmware_nvs.bin")

    def test_nvs_region_missing_address_raises(self) -> None:
        extra = "\n        nvs_region:\n          size: 0x2000\n        "
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile(extra))
            with self.assertRaises(ProfileError):
                load_profile(p)

    def test_nvs_region_missing_size_raises(self) -> None:
        extra = "\n        nvs_region:\n          address: 0x0003E000\n        "
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile(extra))
            with self.assertRaises(ProfileError):
                load_profile(p)

    def test_nvs_region_zero_size_raises(self) -> None:
        extra = "\n        nvs_region:\n          address: 0x0003E000\n          size: 0\n        "
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), self._base_profile(extra))
            with self.assertRaises(ProfileError):
                load_profile(p)

    def test_config_checks_parsed(self) -> None:
        body = """
        schema_version: 1
        name: test_nvs_checks
        description: test
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
          config_checks:
            - { address: 0x0003E010, expected: 0x01 }
            - { address: 0x0003E100, nonzero: true }
            - address: 0x0003E200
              range: { min: 10, max: 100 }
        """
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), body)
            profile = load_profile(p)
            checks = profile.success_criteria.config_checks
            self.assertEqual(len(checks), 3)
            self.assertEqual(checks[0].address, 0x3E010)
            self.assertEqual(checks[0].expected, 0x01)
            self.assertFalse(checks[0].nonzero)
            self.assertEqual(checks[1].address, 0x3E100)
            self.assertTrue(checks[1].nonzero)
            self.assertIsNone(checks[1].expected)
            self.assertEqual(checks[2].address, 0x3E200)
            self.assertEqual(checks[2].range_min, 10)
            self.assertEqual(checks[2].range_max, 100)

    def test_nvs_corruption_fault_type_accepted(self) -> None:
        body = """
        schema_version: 1
        name: test_nvs_fault_type
        description: test
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
          fault_types: [power_loss, nvs_corruption]
        """
        with tempfile.TemporaryDirectory() as td:
            p = self._write_profile(Path(td), body)
            profile = load_profile(p)
            self.assertIn("nvs_corruption", profile.fault_sweep.fault_types)


# ---------------------------------------------------------------------------
# Config check classification tests (config_lost / config_crash)
# ---------------------------------------------------------------------------


class TestNvsConfigClassification(unittest.TestCase):
    def setUp(self) -> None:
        from audit_bootloader import evaluate_config_checks
        from fault_classification import classify_failure_class, result_is_brick

        self.classify_failure_class = classify_failure_class
        self.evaluate_config_checks = evaluate_config_checks
        self.result_is_brick = result_is_brick

    def _make_profile_with_checks(self):
        from profile_loader import (
            ConfigCheck,
            ExpectConfig,
            FaultSweepConfig,
            MemoryConfig,
            ProfileConfig,
            SlotConfig,
            StateFuzzerConfig,
            SuccessCriteria,
        )

        return ProfileConfig(
            schema_version=1,
            name="test",
            description="test",
            platform="test.repl",
            bootloader_elf="test.elf",
            bootloader_entry=0x10000000,
            memory=MemoryConfig(
                sram_start=0x20000000,
                sram_end=0x20020000,
                write_granularity=4,
                slots={"exec": SlotConfig(0x10000000, 0x1000)},
            ),
            images={},
            pre_boot_state=[],
            setup_script=None,
            extra_peripherals=None,
            success_criteria=SuccessCriteria(
                vtor_in_slot="exec",
                config_checks=[
                    ConfigCheck(address=0x3E010, expected=0x01),
                    ConfigCheck(address=0x3E100, nonzero=True),
                ],
            ),
            fault_sweep=FaultSweepConfig(),
            state_fuzzer=StateFuzzerConfig(),
            expect=ExpectConfig(),
        )

    def test_config_lost_when_boot_succeeds_but_checks_fail(self) -> None:
        profile = self._make_profile_with_checks()
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "config_values": {"0x3E010": 0xFF, "0x3E100": 0x42},
        }
        self.assertEqual(self.evaluate_config_checks(result, profile), "config_lost")

    def test_config_checks_pass(self) -> None:
        profile = self._make_profile_with_checks()
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "config_values": {"0x3E010": 0x01, "0x3E100": 0x42},
        }
        self.assertIsNone(self.evaluate_config_checks(result, profile))

    def test_config_crash_when_no_boot_with_nvs_corruption(self) -> None:
        profile = self._make_profile_with_checks()
        result = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "nvs_corruption_mode": "scramble",
        }
        self.assertEqual(self.evaluate_config_checks(result, profile), "config_crash")

    def test_no_classification_without_nvs_corruption_on_no_boot(self) -> None:
        profile = self._make_profile_with_checks()
        result = {"boot_outcome": "no_boot", "boot_slot": None}
        self.assertIsNone(self.evaluate_config_checks(result, profile))

    def test_config_lost_missing_address_in_values(self) -> None:
        profile = self._make_profile_with_checks()
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "config_values": {"0x3E010": 0x01},
        }
        self.assertEqual(self.evaluate_config_checks(result, profile), "config_lost")

    def test_no_checks_returns_none(self) -> None:
        from profile_loader import (
            ExpectConfig,
            FaultSweepConfig,
            MemoryConfig,
            ProfileConfig,
            SlotConfig,
            StateFuzzerConfig,
            SuccessCriteria,
        )

        profile = ProfileConfig(
            schema_version=1,
            name="test",
            description="test",
            platform="test.repl",
            bootloader_elf="test.elf",
            bootloader_entry=0x10000000,
            memory=MemoryConfig(
                sram_start=0x20000000,
                sram_end=0x20020000,
                write_granularity=4,
                slots={"exec": SlotConfig(0x10000000, 0x1000)},
            ),
            images={},
            pre_boot_state=[],
            setup_script=None,
            extra_peripherals=None,
            success_criteria=SuccessCriteria(vtor_in_slot="exec"),
            fault_sweep=FaultSweepConfig(),
            state_fuzzer=StateFuzzerConfig(),
            expect=ExpectConfig(),
        )
        result = {"boot_outcome": "success", "boot_slot": "exec"}
        self.assertIsNone(self.evaluate_config_checks(result, profile))

    def test_classify_failure_class_config_lost(self) -> None:
        result = {"boot_outcome": "config_lost", "boot_slot": "exec"}
        self.assertEqual(self.classify_failure_class(result), "config_lost")

    def test_classify_failure_class_config_crash(self) -> None:
        result = {"boot_outcome": "config_crash", "boot_slot": None}
        self.assertEqual(self.classify_failure_class(result), "config_crash")

    def test_config_crash_is_brick(self) -> None:
        result = {"boot_outcome": "config_crash", "boot_slot": None}
        self.assertTrue(self.result_is_brick(result))

    def test_config_lost_is_not_brick(self) -> None:
        result = {"boot_outcome": "config_lost", "boot_slot": "exec"}
        self.assertFalse(self.result_is_brick(result))


if __name__ == "__main__":
    unittest.main()
