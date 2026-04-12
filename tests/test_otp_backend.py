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

from fault_types import (
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

    OTP_TYPES = {"otp_partial_program", "otp_stuck_bit", "otp_read_disturb", "otp_overblow", "otp_blow_nop"}

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
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_overblow"], 3)


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

    def test_otp_overblow_label(self) -> None:
        code = FAULT_TYPE_NAME_TO_CODE["otp_overblow"]
        self.assertEqual(_fault_type_label(code), "otp_overblow")


class OTPOverblowProfileParsingTest(unittest.TestCase):
    """Verify otp_overblow is accepted in profile YAML."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_otp_overblow
                description: test overblow fault mode
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

    def test_otp_overblow_accepted_in_fault_types(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    otp_peripheral: otp
                    fault_sweep:
                      mode: runtime
                      max_writes: 100
                      fault_types:
                        - otp_overblow
                """),
            )
            profile = load_profile(path)
            self.assertIn("otp_overblow", profile.fault_sweep.fault_types)

    def test_otp_overblow_code_is_3(self):
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_overblow"], 3)

    def test_otp_overblow_wire_code_round_trip(self):
        code = FAULT_TYPE_NAME_TO_CODE["otp_overblow"]
        self.assertEqual(code, "oo")
        self.assertEqual(_fault_type_label(code), "otp_overblow")


class OTPBlowNopRegistrationTest(unittest.TestCase):
    """Verify otp_blow_nop is registered and wired correctly."""

    def test_blow_nop_in_known_fault_types(self):
        self.assertIn("otp_blow_nop", KNOWN_FAULT_TYPES)

    def test_blow_nop_code_is_4(self):
        self.assertEqual(OTP_FAULT_TYPE_CODES["otp_blow_nop"], 4)

    def test_blow_nop_wire_code_round_trip(self):
        code = FAULT_TYPE_NAME_TO_CODE["otp_blow_nop"]
        self.assertEqual(code, "on")
        self.assertEqual(_fault_type_label(code), "otp_blow_nop")

    def test_blow_nop_in_execute_only(self):
        from scripts.fault_types import EXECUTE_ONLY_FAULT_TYPES
        self.assertIn("otp_blow_nop", EXECUTE_ONLY_FAULT_TYPES)

    def test_blow_nop_accepted_in_profile(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(
                textwrap.dedent("""\
                    schema_version: 1
                    name: test_otp_blow_nop
                    description: test blow-nop fault mode
                    platform: platforms/cortex_m0_otp.repl
                    flash_backend: nvm_ctrl
                    otp_peripheral: otp
                    bootloader:
                      elf: examples/vulnerable_ota/firmware.elf
                      entry: 0x10000000
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 8
                      slots:
                        exec: { base: 0x10000000, size: 0x38000 }
                        staging: { base: 0x10038000, size: 0x38000 }
                    images:
                      staging: examples/vulnerable_ota/firmware.bin
                    success_criteria:
                      vtor_in_slot: exec
                    fault_sweep:
                      mode: runtime
                      max_writes: 100
                      fault_types:
                        - otp_blow_nop
                    expect:
                      should_find_issues: false
                """),
                encoding="utf-8",
            )
            profile = load_profile(path)
            self.assertIn("otp_blow_nop", profile.fault_sweep.fault_types)


# ---------------------------------------------------------------------------
# Python mirror of OTPMemory C# logic for behavioral testing.
# This mirrors the *fixed* C# code, validating the bug fixes in-process.
# ---------------------------------------------------------------------------


def _popcount(b: int) -> int:
    c = 0
    while b:
        c += b & 1
        b >>= 1
    return c


class OTPSim:
    """Minimal Python model of the fixed OTPMemory peripheral."""

    def __init__(self, size: int = 256, granularity: int = 32):
        self.size = size
        self.granularity = granularity
        self.storage = bytearray(size)
        self.total_blows: int = 0
        self.fault_at_blow: int = 0  # 0 = disabled
        self.blow_fault_fired: bool = False
        self.last_fault_address: int = 0
        self.fault_snapshot: bytes | None = None
        self.fault_mode: int = 0
        self.permanent_stuck_bits: bool = False
        self.stuck_bit_mask = bytearray(size)

    def reset(self):
        # Storage survives (non-volatile). Counters/diagnostics reset.
        self.total_blows = 0
        self.blow_fault_fired = False
        self.last_fault_address = 0
        self.fault_snapshot = None

    def test_clear_all(self):
        self.storage = bytearray(self.size)
        self.stuck_bit_mask = bytearray(self.size)
        self.total_blows = 0
        self.blow_fault_fired = False
        self.last_fault_address = 0
        self.fault_snapshot = None

    def write_byte(self, offset: int, value: int):
        self._blow_bits(offset, bytes([value & 0xFF]))

    def write_word(self, offset: int, value: int):
        self._blow_bits(offset, bytes([
            value & 0xFF,
            (value >> 8) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 24) & 0xFF,
        ]))

    def read_byte(self, offset: int) -> int:
        return self.storage[offset]

    # -- internal --

    def _count_new_bits(self, offset: int, data: bytes) -> int:
        c = 0
        for i, b in enumerate(data):
            c += _popcount(b & ~self.storage[offset + i])
        return c

    def _count_new_bytes(self, offset: int, data: bytes) -> int:
        c = 0
        for i, b in enumerate(data):
            if (b & ~self.storage[offset + i]) != 0:
                c += 1
        return c

    def _count_new_words(self, offset: int, data: bytes) -> int:
        c = 0
        for w in range(0, len(data), 4):
            w_end = min(w + 4, len(data))
            for i in range(w, w_end):
                if (data[i] & ~self.storage[offset + i]) != 0:
                    c += 1
                    break
        return c

    def _blow_bits(self, offset: int, data: bytes):
        if not data:
            return
        g = self.granularity
        if g == 1:
            blows = self._count_new_bits(offset, data)
        elif g == 8:
            blows = self._count_new_bytes(offset, data)
        elif g == 32:
            blows = self._count_new_words(offset, data)
        else:
            blows = self._count_new_bytes(offset, data)

        if blows == 0:
            return

        for blow_idx in range(blows):
            self.total_blows += 1
            if self.fault_at_blow > 0 and self.total_blows == self.fault_at_blow and not self.blow_fault_fired:
                self.blow_fault_fired = True
                self.last_fault_address = offset
                if g == 1:
                    self._apply_bit_level_fault(offset, data, blow_idx)
                else:
                    # Apply prior windows normally.
                    for prior in range(blow_idx):
                        s, e = self._compute_blow_window(offset, data, prior)
                        self._apply_normal(offset, data, s, e)
                    s, e = self._compute_blow_window(offset, data, blow_idx)
                    # Faulted: just skip the faulted window (power_loss = nothing written).
                self.fault_snapshot = bytes(self.storage)
                return

        # No fault: apply all normally.
        if not self.blow_fault_fired:
            self._apply_normal(offset, data, 0, len(data))

    def _apply_normal(self, offset: int, data: bytes, start: int, end: int):
        for i in range(start, min(end, len(data))):
            mask = self.stuck_bit_mask[offset + i] if self.permanent_stuck_bits else 0
            self.storage[offset + i] |= (data[i] & ~mask)

    def _apply_bit_level_fault(self, offset: int, data: bytes, fault_bit_idx: int):
        bits_seen = 0
        for i in range(len(data)):
            new_bits = data[i] & ~self.storage[offset + i]
            if new_bits == 0:
                continue
            for bit in range(8):
                if not (new_bits & (1 << bit)):
                    continue
                if bits_seen < fault_bit_idx:
                    mask = self.stuck_bit_mask[offset + i] if self.permanent_stuck_bits else 0
                    self.storage[offset + i] |= ((1 << bit) & ~mask)
                    bits_seen += 1
                else:
                    # Faulted bit: power_loss = skip.
                    return

    def _compute_blow_window(self, offset: int, data: bytes, blow_idx: int):
        g = self.granularity
        if g == 8:
            found = 0
            for i in range(len(data)):
                if (data[i] & ~self.storage[offset + i]) != 0:
                    if found == blow_idx:
                        return (i, i + 1)
                    found += 1
            return (0, len(data))
        elif g == 32:
            found = 0
            for w in range(0, len(data), 4):
                w_end = min(w + 4, len(data))
                has_new = any(
                    (data[i] & ~self.storage[offset + i]) != 0
                    for i in range(w, w_end)
                )
                if not has_new:
                    continue
                if found == blow_idx:
                    return (w, w_end)
                found += 1
            return (0, len(data))
        return (0, len(data))


class OTPNoOpWriteTest(unittest.TestCase):
    """Bug 1: No-op writes must not consume FaultAtBlow."""

    def test_noop_byte_write_does_not_increment_blows(self):
        otp = OTPSim(size=16, granularity=8)
        otp.write_byte(0, 0xFF)
        self.assertEqual(otp.total_blows, 1)
        # Writing the same value again: no new bits.
        otp.write_byte(0, 0xFF)
        self.assertEqual(otp.total_blows, 1, "No-op write should not increment TotalBlows")

    def test_noop_does_not_consume_fault_at_blow(self):
        otp = OTPSim(size=16, granularity=8)
        otp.fault_at_blow = 2
        # First real write: blow 1.
        otp.write_byte(0, 0x01)
        self.assertEqual(otp.total_blows, 1)
        self.assertFalse(otp.blow_fault_fired)
        # No-op write (0x01 already set): should NOT consume blow 2.
        otp.write_byte(0, 0x01)
        self.assertEqual(otp.total_blows, 1)
        self.assertFalse(otp.blow_fault_fired)
        # Second real write: blow 2 -> fault fires.
        otp.write_byte(1, 0x02)
        self.assertEqual(otp.total_blows, 2)
        self.assertTrue(otp.blow_fault_fired)

    def test_noop_word_write_does_not_increment_blows(self):
        otp = OTPSim(size=16, granularity=32)
        otp.write_word(0, 0xDEADBEEF)
        blows_after_first = otp.total_blows
        otp.write_word(0, 0xDEADBEEF)
        self.assertEqual(otp.total_blows, blows_after_first,
                         "No-op word write should not increment TotalBlows")

    def test_partial_noop_only_counts_changed_bytes(self):
        """Write 4 bytes where 2 are already set: only 2 blows at granularity=8."""
        otp = OTPSim(size=16, granularity=8)
        otp.write_byte(0, 0xFF)
        otp.write_byte(1, 0xFF)
        otp.total_blows = 0  # reset counter for clarity
        # Write 4 bytes: bytes 0,1 are no-ops, bytes 2,3 are new.
        otp._blow_bits(0, bytes([0xFF, 0xFF, 0xAA, 0xBB]))
        self.assertEqual(otp.total_blows, 2)


class OTPBitGranularityFaultTest(unittest.TestCase):
    """Bug 2: Bit-level blow counting must apply individual bits correctly."""

    def test_bit_granularity_counts_individual_bits(self):
        otp = OTPSim(size=16, granularity=1)
        otp.write_byte(0, 0x07)  # 3 bits set
        self.assertEqual(otp.total_blows, 3)

    def test_bit_granularity_fault_at_exact_bit(self):
        otp = OTPSim(size=16, granularity=1)
        otp.fault_at_blow = 2
        # Writing 0x07 (bits 0,1,2). Fault at blow 2 means:
        #   blow 1 = bit 0 -> applied
        #   blow 2 = bit 1 -> fault fires, bit 1 skipped (power loss)
        otp.write_byte(0, 0x07)
        self.assertTrue(otp.blow_fault_fired)
        self.assertEqual(otp.total_blows, 2)
        # Only bit 0 should be applied (bit 1 was the faulted one).
        self.assertEqual(otp.read_byte(0), 0x01)

    def test_bit_granularity_fault_at_first_bit(self):
        otp = OTPSim(size=16, granularity=1)
        otp.fault_at_blow = 1
        otp.write_byte(0, 0x0F)  # 4 bits
        self.assertTrue(otp.blow_fault_fired)
        # Fault at first bit: nothing applied.
        self.assertEqual(otp.read_byte(0), 0x00)

    def test_bit_granularity_no_fault_all_bits_applied(self):
        otp = OTPSim(size=16, granularity=1)
        otp.fault_at_blow = 999  # won't fire
        otp.write_byte(0, 0xF0)
        self.assertFalse(otp.blow_fault_fired)
        self.assertEqual(otp.read_byte(0), 0xF0)


class OTPResetTest(unittest.TestCase):
    """Bug 3: Reset must clear transient counters but preserve storage."""

    def test_reset_clears_total_blows(self):
        otp = OTPSim(size=16, granularity=8)
        otp.write_byte(0, 0xFF)
        self.assertGreater(otp.total_blows, 0)
        otp.reset()
        self.assertEqual(otp.total_blows, 0)

    def test_reset_clears_last_fault_address(self):
        otp = OTPSim(size=16, granularity=8)
        otp.fault_at_blow = 1
        otp.write_byte(4, 0x01)
        self.assertEqual(otp.last_fault_address, 4)
        otp.reset()
        self.assertEqual(otp.last_fault_address, 0)

    def test_reset_clears_fault_snapshot(self):
        otp = OTPSim(size=16, granularity=8)
        otp.fault_at_blow = 1
        otp.write_byte(0, 0x01)
        self.assertIsNotNone(otp.fault_snapshot)
        otp.reset()
        self.assertIsNone(otp.fault_snapshot)

    def test_reset_clears_blow_fault_fired(self):
        otp = OTPSim(size=16, granularity=8)
        otp.fault_at_blow = 1
        otp.write_byte(0, 0x01)
        self.assertTrue(otp.blow_fault_fired)
        otp.reset()
        self.assertFalse(otp.blow_fault_fired)

    def test_reset_preserves_storage(self):
        otp = OTPSim(size=16, granularity=8)
        otp.write_byte(0, 0xAB)
        otp.reset()
        self.assertEqual(otp.read_byte(0), 0xAB, "OTP storage must survive reset")


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
