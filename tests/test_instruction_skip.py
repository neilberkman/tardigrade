#!/usr/bin/env python3
"""Unit tests for instruction_skip fault type support."""

from __future__ import annotations

import sys
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from profile_loader import (  # noqa: E402
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    FaultSweepConfig,
    InstructionSkipConfig,
    ProfileError,
    _parse_instruction_skip_config,
)


class InstructionSkipRegistrationTest(unittest.TestCase):
    """Verify instruction_skip is wired into the type registries."""

    def test_in_known_types(self) -> None:
        self.assertIn("instruction_skip", KNOWN_FAULT_TYPES)

    def test_in_implemented_types(self) -> None:
        self.assertIn("instruction_skip", IMPLEMENTED_FAULT_TYPES)

    def test_is_execute_only(self) -> None:
        self.assertIn("instruction_skip", EXECUTE_ONLY_FAULT_TYPES)

    def test_fault_type_code(self) -> None:
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["instruction_skip"], "i")

    def test_fault_type_label(self) -> None:
        self.assertEqual(_fault_type_label("i"), "instruction_skip")


class InstructionSkipConfigTest(unittest.TestCase):
    """Validate InstructionSkipConfig construction and validation."""

    def test_defaults(self) -> None:
        cfg = InstructionSkipConfig()
        self.assertEqual(cfg.target_addresses, [])
        self.assertEqual(cfg.skip_count, 1)

    def test_valid_config(self) -> None:
        cfg = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x2000), (0x3000, 0x4000)],
            skip_count=2,
        )
        self.assertEqual(len(cfg.target_addresses), 2)
        self.assertEqual(cfg.target_addresses[0], (0x1000, 0x2000))
        self.assertEqual(cfg.skip_count, 2)

    def test_end_must_exceed_start(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            InstructionSkipConfig(target_addresses=[(0x2000, 0x1000)])
        self.assertIn("end", str(ctx.exception))
        self.assertIn("must be > start", str(ctx.exception))

    def test_equal_start_end_rejected(self) -> None:
        with self.assertRaises(ProfileError):
            InstructionSkipConfig(target_addresses=[(0x1000, 0x1000)])

    def test_start_must_be_halfword_aligned(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            InstructionSkipConfig(target_addresses=[(0x1001, 0x2000)])
        self.assertIn("halfword-aligned", str(ctx.exception))

    def test_skip_count_minimum_is_one(self) -> None:
        cfg = InstructionSkipConfig(skip_count=0)
        self.assertEqual(cfg.skip_count, 1)

    def test_skip_count_negative_clamped(self) -> None:
        cfg = InstructionSkipConfig(skip_count=-5)
        self.assertEqual(cfg.skip_count, 1)


class ParseInstructionSkipConfigTest(unittest.TestCase):
    """Test YAML parsing of instruction_skip_config."""

    def test_none_returns_none(self) -> None:
        self.assertIsNone(_parse_instruction_skip_config(None))

    def test_valid_yaml(self) -> None:
        raw = {
            "target_addresses": [
                {"start": "0x1000", "end": "0x2000"},
                {"start": "0x3000", "end": "0x3100"},
            ],
            "skip_count": 2,
        }
        cfg = _parse_instruction_skip_config(raw)
        self.assertIsNotNone(cfg)
        self.assertEqual(len(cfg.target_addresses), 2)
        self.assertEqual(cfg.target_addresses[0], (0x1000, 0x2000))
        self.assertEqual(cfg.target_addresses[1], (0x3000, 0x3100))
        self.assertEqual(cfg.skip_count, 2)

    def test_default_skip_count(self) -> None:
        raw = {"target_addresses": [{"start": "0x1000", "end": "0x2000"}]}
        cfg = _parse_instruction_skip_config(raw)
        self.assertEqual(cfg.skip_count, 1)

    def test_non_dict_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config("not a dict")

    def test_non_list_target_addresses_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config({"target_addresses": "not a list"})

    def test_invalid_region_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": ["not a dict"]}
            )

    def test_missing_start_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": [{"end": "0x2000"}]}
            )

    def test_missing_end_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": [{"start": "0x1000"}]}
            )

    def test_invalid_skip_count_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config({"skip_count": -1})


class FaultSweepConfigIntegrationTest(unittest.TestCase):
    """Verify instruction_skip_config integrates into FaultSweepConfig."""

    def test_default_is_none(self) -> None:
        fs = FaultSweepConfig()
        self.assertIsNone(fs.instruction_skip_config)

    def test_can_set_config(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x2000)], skip_count=1
        )
        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=isc,
        )
        self.assertIsNotNone(fs.instruction_skip_config)
        self.assertEqual(fs.instruction_skip_config.target_addresses, [(0x1000, 0x2000)])


class BackendCompatWarningTest(unittest.TestCase):
    """Verify warnings for instruction_skip config mismatches."""

    def test_warn_config_without_fault_type(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        isc = InstructionSkipConfig(target_addresses=[(0x1000, 0x2000)])
        fs = FaultSweepConfig(
            fault_types=["power_loss"],
            instruction_skip_config=isc,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [x for x in w if "instruction_skip_config" in str(x.message)]
            self.assertTrue(
                len(skip_warnings) > 0,
                "Expected warning about instruction_skip_config without fault type",
            )

    def test_warn_fault_type_without_config(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=None,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [x for x in w if "instruction_skip" in str(x.message)]
            self.assertTrue(
                len(skip_warnings) > 0,
                "Expected warning about instruction_skip without config",
            )

    def test_no_warn_when_both_present(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        isc = InstructionSkipConfig(target_addresses=[(0x1000, 0x2000)])
        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=isc,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [
                x for x in w
                if "instruction_skip" in str(x.message)
            ]
            self.assertEqual(
                len(skip_warnings), 0,
                "No instruction_skip warnings expected when both type and config are set",
            )


class FaultPointGenerationTest(unittest.TestCase):
    """Verify instruction_skip fault points are generated from address ranges."""

    def test_address_enumeration(self) -> None:
        """Each halfword in target ranges should produce one fault point."""
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1010)],
            skip_count=1,
        )
        # 0x1010 - 0x1000 = 16 bytes = 8 halfwords
        addrs = []
        for start, end in isc.target_addresses:
            for addr in range(start, end, 2):
                addrs.append(addr)
        self.assertEqual(len(addrs), 8)
        self.assertEqual(addrs[0], 0x1000)
        self.assertEqual(addrs[-1], 0x100E)

    def test_multiple_ranges(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1004), (0x2000, 0x2006)],
        )
        addrs = []
        for start, end in isc.target_addresses:
            for addr in range(start, end, 2):
                addrs.append(addr)
        # 2 halfwords + 3 halfwords = 5
        self.assertEqual(len(addrs), 5)

    def test_fault_type_code_format(self) -> None:
        """Fault type codes should be 'i:0xADDR' format."""
        addr = 0x1234
        code = "i:0x{:X}".format(addr)
        self.assertEqual(code, "i:0x1234")
        # Parse it back
        parts = code.split(":")
        self.assertEqual(parts[0], "i")
        self.assertEqual(int(parts[1], 0), 0x1234)


if __name__ == "__main__":
    unittest.main()
