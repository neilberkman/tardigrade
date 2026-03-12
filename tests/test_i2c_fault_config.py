#!/usr/bin/env python3
"""Unit tests for I2C bus fault injection profile configuration."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import (
    I2C_FAULT_TYPE_CODES,
    I2CFaultConfig,
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    ProfileError,
    load_profile,
)

from fault_types import (
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)


# ---------------------------------------------------------------------------
# I2CFaultConfig direct construction tests
# ---------------------------------------------------------------------------


class I2CFaultConfigConstructionTest(unittest.TestCase):
    def test_defaults(self):
        cfg = I2CFaultConfig()
        self.assertEqual(cfg.peripheral_name, "i2cProxy")
        self.assertEqual(cfg.target_address, 0)
        self.assertEqual(cfg.fault_types, ["i2c_nack"])
        self.assertEqual(cfg.fault_at_transaction, 0)
        self.assertEqual(cfg.fault_seed, 0)

    def test_custom_values(self):
        cfg = I2CFaultConfig(
            peripheral_name="secureI2C",
            target_address=0x50,
            fault_types=["i2c_timeout", "i2c_bit_flip"],
            fault_at_transaction=5,
            fault_seed=42,
        )
        self.assertEqual(cfg.peripheral_name, "secureI2C")
        self.assertEqual(cfg.target_address, 0x50)
        self.assertEqual(cfg.fault_types, ["i2c_timeout", "i2c_bit_flip"])
        self.assertEqual(cfg.fault_at_transaction, 5)
        self.assertEqual(cfg.fault_seed, 42)

    def test_target_address_zero_means_all(self):
        cfg = I2CFaultConfig(target_address=0)
        self.assertEqual(cfg.target_address, 0)

    def test_target_address_max_7bit(self):
        cfg = I2CFaultConfig(target_address=127)
        self.assertEqual(cfg.target_address, 127)

    def test_target_address_too_high_rejected(self):
        with self.assertRaises(ProfileError):
            I2CFaultConfig(target_address=128)

    def test_target_address_negative_rejected(self):
        with self.assertRaises(ProfileError):
            I2CFaultConfig(target_address=-1)

    def test_unknown_fault_type_rejected(self):
        with self.assertRaises(ProfileError):
            I2CFaultConfig(fault_types=["i2c_explode"])

    def test_all_fault_types_accepted(self):
        all_types = [
            "i2c_nack",
            "i2c_timeout",
            "i2c_bit_flip",
            "i2c_truncated",
            "i2c_wrong_address",
        ]
        cfg = I2CFaultConfig(fault_types=all_types)
        self.assertEqual(cfg.fault_types, all_types)

    def test_negative_fault_at_transaction_clamped(self):
        cfg = I2CFaultConfig(fault_at_transaction=-5)
        self.assertEqual(cfg.fault_at_transaction, 0)


# ---------------------------------------------------------------------------
# I2C fault type registration tests
# ---------------------------------------------------------------------------


class I2CFaultTypeRegistrationTest(unittest.TestCase):
    """Verify I2C fault types are properly registered in all type sets."""

    I2C_TYPES = [
        "i2c_nack",
        "i2c_timeout",
        "i2c_bit_flip",
        "i2c_truncated",
        "i2c_wrong_address",
    ]

    def test_all_in_known_types(self):
        for ft in self.I2C_TYPES:
            self.assertIn(ft, KNOWN_FAULT_TYPES, f"{ft} missing from KNOWN_FAULT_TYPES")

    def test_all_in_implemented_types(self):
        for ft in self.I2C_TYPES:
            self.assertIn(
                ft, IMPLEMENTED_FAULT_TYPES, f"{ft} missing from IMPLEMENTED_FAULT_TYPES"
            )

    def test_all_in_execute_only_types(self):
        for ft in self.I2C_TYPES:
            self.assertIn(
                ft, EXECUTE_ONLY_FAULT_TYPES, f"{ft} missing from EXECUTE_ONLY_FAULT_TYPES"
            )

    def test_all_have_wire_codes(self):
        for ft in self.I2C_TYPES:
            self.assertIn(
                ft, FAULT_TYPE_NAME_TO_CODE, f"{ft} missing from FAULT_TYPE_NAME_TO_CODE"
            )

    def test_wire_code_round_trip(self):
        for ft in self.I2C_TYPES:
            code = FAULT_TYPE_NAME_TO_CODE[ft]
            label = _fault_type_label(code)
            self.assertEqual(label, ft, f"round-trip failed for {ft}: code={code}, label={label}")

    def test_i2c_fault_type_codes_map(self):
        self.assertEqual(I2C_FAULT_TYPE_CODES["i2c_nack"], 1)
        self.assertEqual(I2C_FAULT_TYPE_CODES["i2c_timeout"], 2)
        self.assertEqual(I2C_FAULT_TYPE_CODES["i2c_bit_flip"], 3)
        self.assertEqual(I2C_FAULT_TYPE_CODES["i2c_truncated"], 4)
        self.assertEqual(I2C_FAULT_TYPE_CODES["i2c_wrong_address"], 5)


# ---------------------------------------------------------------------------
# Profile YAML parsing tests
# ---------------------------------------------------------------------------


class I2CFaultProfileParsingTest(unittest.TestCase):
    """Profile YAML parsing of i2c_fault_config block."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_i2c
                description: test i2c fault config
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 8
                  slots:
                    exec: {{ base: 0x10000000, size: 0x38000 }}
                    staging: {{ base: 0x10038000, size: 0x38000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_no_i2c_config_default_none(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            self.assertIsNone(profile.fault_sweep.i2c_fault_config)

    def test_i2c_config_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      evaluation_mode: execute
                      i2c_fault_config:
                        peripheral_name: myI2CProxy
                        target_address: 0x50
                        fault_types: [i2c_nack, i2c_timeout]
                        fault_at_transaction: 3
                        fault_seed: 99
                """),
            )
            profile = load_profile(path)
            ifc = profile.fault_sweep.i2c_fault_config
            self.assertIsNotNone(ifc)
            self.assertEqual(ifc.peripheral_name, "myI2CProxy")
            self.assertEqual(ifc.target_address, 0x50)
            self.assertEqual(ifc.fault_types, ["i2c_nack", "i2c_timeout"])
            self.assertEqual(ifc.fault_at_transaction, 3)
            self.assertEqual(ifc.fault_seed, 99)

    def test_i2c_config_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      evaluation_mode: execute
                      i2c_fault_config: {}
                """),
            )
            profile = load_profile(path)
            ifc = profile.fault_sweep.i2c_fault_config
            self.assertIsNotNone(ifc)
            self.assertEqual(ifc.peripheral_name, "i2cProxy")
            self.assertEqual(ifc.target_address, 0)
            self.assertEqual(ifc.fault_types, ["i2c_nack"])
            self.assertEqual(ifc.fault_at_transaction, 0)
            self.assertEqual(ifc.fault_seed, 0)

    def test_i2c_config_invalid_address_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      evaluation_mode: execute
                      i2c_fault_config:
                        target_address: 200
                """),
            )
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_i2c_config_invalid_fault_type_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      evaluation_mode: execute
                      i2c_fault_config:
                        fault_types: [i2c_explode]
                """),
            )
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_i2c_config_non_mapping_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      i2c_fault_config: true
                """),
            )
            with self.assertRaises(ProfileError):
                load_profile(path)


# ---------------------------------------------------------------------------
# Robot variable emission tests
# ---------------------------------------------------------------------------


class I2CFaultRobotVarsTest(unittest.TestCase):
    """Verify robot variable emission for I2C fault config."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_i2c_vars
                description: test
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 8
                  slots:
                    exec: {{ base: 0x10000000, size: 0x38000 }}
                    staging: {{ base: 0x10038000, size: 0x38000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_no_i2c_no_robot_vars(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            i2c_vars = [v for v in vars_list if v.startswith("I2C_")]
            self.assertEqual(i2c_vars, [])

    def test_i2c_emits_robot_vars(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack, i2c_timeout]
                      evaluation_mode: execute
                      i2c_fault_config:
                        peripheral_name: secureI2C
                        target_address: 80
                        fault_types: [i2c_nack, i2c_timeout]
                        fault_at_transaction: 5
                        fault_seed: 12345
                """),
            )
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            self.assertIn("I2C_FAULT_PERIPHERAL:secureI2C", vars_list)
            self.assertIn("I2C_FAULT_TARGET_ADDRESS:80", vars_list)
            self.assertIn("I2C_FAULT_TYPES:i2c_nack,i2c_timeout", vars_list)
            self.assertIn("I2C_FAULT_TYPE_CODES:1,2", vars_list)
            self.assertIn("I2C_FAULT_AT_TRANSACTION:5", vars_list)
            self.assertIn("I2C_FAULT_SEED:12345", vars_list)

    def test_i2c_no_vars_when_config_missing(self):
        """I2C fault types in fault_types but no i2c_fault_config -> no I2C vars."""
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      fault_types: [i2c_nack]
                      evaluation_mode: execute
                """),
            )
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            i2c_vars = [v for v in vars_list if v.startswith("I2C_")]
            self.assertEqual(i2c_vars, [])


if __name__ == "__main__":
    unittest.main()
