#!/usr/bin/env python3
"""Unit tests for OTP/eFuse backend: schema registration, profile parsing, and fault type wiring."""

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

from audit_bootloader import (
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from profile_loader import (
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    OTP_FAULT_TYPE_CODES,
    ProfileError,
    load_profile,
)


class OTPFaultTypeRegistrationTest(unittest.TestCase):
    """Verify OTP fault types are registered in all the right places."""

    OTP_TYPES = {"otp_partial_program", "otp_stuck_bit", "otp_read_disturb"}

    def test_otp_types_in_known(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, KNOWN_FAULT_TYPES, f"{ft} missing from KNOWN_FAULT_TYPES")

    def test_otp_types_in_implemented(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, IMPLEMENTED_FAULT_TYPES, f"{ft} missing from IMPLEMENTED_FAULT_TYPES")

    def test_otp_types_are_execute_only(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, EXECUTE_ONLY_FAULT_TYPES, f"{ft} missing from EXECUTE_ONLY_FAULT_TYPES")

    def test_otp_types_have_wire_codes(self) -> None:
        for ft in self.OTP_TYPES:
            self.assertIn(ft, FAULT_TYPE_NAME_TO_CODE, f"{ft} missing from FAULT_TYPE_NAME_TO_CODE")

    def test_otp_wire_codes_unique(self) -> None:
        otp_codes = {FAULT_TYPE_NAME_TO_CODE[ft] for ft in self.OTP_TYPES}
        self.assertEqual(len(otp_codes), len(self.OTP_TYPES), "OTP wire codes are not unique")

    def test_otp_fault_type_codes_map(self) -> None:
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_partial_program"], 0)
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_stuck_bit"], 1)
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_read_disturb"], 2)


class OTPFaultTypeLabelTest(unittest.TestCase):
    """Verify round-trip from wire code to human label."""

    def test_otp_partial_program_label(self) -> None:
        code = FAULT_TYPE_NAME_TO_CODE["otp_partial_program"]
        self.assertEqual(_fault_type_label(code), "otp_partial_program")

    def test_otp_stuck_bit_label(self) -> None:
        code = FAULT_TYPE_NAME_TO_CODE["otp_stuck_bit"]
        self.assertEqual(_fault_type_label(code), "otp_stuck_bit")

    def test_otp_read_disturb_label(self) -> None:
        code = FAULT_TYPE_NAME_TO_CODE["otp_read_disturb"]
        self.assertEqual(_fault_type_label(code), "otp_read_disturb")


class OTPProfileParsingTest(unittest.TestCase):
    """Verify profile YAML parsing with otp_peripheral field."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_otp
                description: test
                platform: platforms/cortex_m0_otp.repl
                flash_backend: nvm_ctrl
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
                expect:
                  should_find_issues: true
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_otp_peripheral_not_set(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            self.assertIsNone(profile.otp_peripheral)

    def test_otp_peripheral_set(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td, "otp_peripheral: otp")
            profile = load_profile(path)
            self.assertEqual(profile.otp_peripheral, "otp")

    def test_otp_fault_types_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    otp_peripheral: otp
                    fault_sweep:
                      mode: runtime
                      max_writes: 100
                      fault_types:
                        - power_loss
                        - otp_partial_program
                        - otp_stuck_bit
                        - otp_read_disturb
                """),
            )
            profile = load_profile(path)
            self.assertIn("otp_partial_program", profile.fault_sweep.fault_types)
            self.assertIn("otp_stuck_bit", profile.fault_sweep.fault_types)
            self.assertIn("otp_read_disturb", profile.fault_sweep.fault_types)

    def test_otp_robot_vars_include_peripheral(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td, "otp_peripheral: otp")
            profile = load_profile(path)
            repo_root = Path(td)
            vars_list = profile.robot_vars(repo_root)
            otp_vars = [v for v in vars_list if v.startswith("OTP_PERIPHERAL:")]
            self.assertEqual(len(otp_vars), 1)
            self.assertEqual(otp_vars[0], "OTP_PERIPHERAL:otp")


class OTPBackendCompatWarningTest(unittest.TestCase):
    """Verify warnings when OTP fault types are used without OTP peripheral."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_otp_compat
                description: test
                platform: platforms/cortex_m0_nvm.repl
                flash_backend: nvm_ctrl
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
                expect:
                  should_find_issues: true
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_otp_fault_without_otp_peripheral_warns(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      mode: runtime
                      max_writes: 100
                      fault_types:
                        - otp_partial_program
                """),
            )
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                load_profile(path)
                otp_warnings = [x for x in w if "OTP" in str(x.message)]
                self.assertGreater(len(otp_warnings), 0,
                                   "Expected warning about OTP fault type without OTP peripheral")

    def test_otp_fault_with_otp_peripheral_no_warn(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    otp_peripheral: otp
                    fault_sweep:
                      mode: runtime
                      max_writes: 100
                      fault_types:
                        - otp_partial_program
                """),
            )
            # Use the OTP platform so the heuristic matches
            content = path.read_text().replace(
                "platforms/cortex_m0_nvm.repl",
                "platforms/cortex_m0_otp.repl",
            )
            path.write_text(content)
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                load_profile(path)
                otp_warnings = [x for x in w if "OTP" in str(x.message)]
                self.assertEqual(len(otp_warnings), 0,
                                 "Unexpected OTP warning when otp_peripheral is set")


if __name__ == "__main__":
    unittest.main()
