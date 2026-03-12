#!/usr/bin/env python3
"""Unit tests for boot_registers and write_order_constraints features."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import FaultResult  # noqa: E402
from invariants import (  # noqa: E402
    InvariantViolation,
    check_boot_registers_match,
    run_invariants,
)
from profile_loader import (  # noqa: E402
    BootRegisterDef,
    BootRegisterPreWrite,
    ProfileError,
    WriteOrderConstraint,
    load_profile,
)

# Inline import of audit function
from result_checks import check_write_order_constraints  # noqa: E402


class BootRegistersProfileParsingTest(unittest.TestCase):
    """Test YAML parsing of boot_registers and boot_register_values."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_boot_registers_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_boot_regs
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
                boot_registers:
                  - { address: 0xE000ED94, name: "MPU_CTRL" }
                  - { address: 0xE000ED98, name: "MPU_RNR" }
                success_criteria:
                  vtor_in_slot: exec
                  boot_register_values:
                    MPU_CTRL: 0x00000005
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.boot_registers), 2)
            self.assertEqual(profile.boot_registers[0].name, "MPU_CTRL")
            self.assertEqual(profile.boot_registers[0].address, 0xE000ED94)
            self.assertEqual(profile.boot_registers[1].name, "MPU_RNR")
            self.assertEqual(profile.boot_registers[1].address, 0xE000ED98)
            self.assertEqual(
                profile.success_criteria.boot_register_values,
                {"MPU_CTRL": 0x00000005},
            )

    def test_boot_registers_empty_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_no_boot_regs
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
            self.assertEqual(profile.boot_registers, [])
            self.assertEqual(profile.success_criteria.boot_register_values, {})

    def test_boot_registers_robot_vars(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_robot_vars
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
                boot_registers:
                  - { address: 0xE000ED94, name: "MPU_CTRL" }
                  - { address: 0xE000EDA0, name: "MPU_RASR" }
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            boot_reg_var = [v for v in robot_vars if v.startswith("BOOT_REGISTERS:")]
            self.assertEqual(len(boot_reg_var), 1)
            self.assertIn("0xE000ED94=MPU_CTRL", boot_reg_var[0])
            self.assertIn("0xE000EDA0=MPU_RASR", boot_reg_var[0])

    def test_boot_registers_invalid_type_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_bad_regs
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
                boot_registers: "not_a_list"
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)


class BootRegistersInvariantTest(unittest.TestCase):
    """Test the check_boot_registers_match invariant."""

    def _make_result(self, boot_outcome: str = "success") -> FaultResult:
        return FaultResult(
            fault_at=42,
            boot_outcome=boot_outcome,
            boot_slot="exec",
            nvm_state={},
            raw_log="",
        )

    def test_matching_registers_passes(self) -> None:
        result = self._make_result()
        signals = {
            "boot_register_snapshot": {
                "MPU_CTRL": "0x00000005",
                "MPU_RASR": "0x1700003F",
            },
        }
        expected = {"MPU_CTRL": 0x00000005, "MPU_RASR": 0x1700003F}
        # Should not raise.
        check_boot_registers_match(
            result,
            boot_register_values=expected,
            result_signals=signals,
        )

    def test_mismatched_register_raises(self) -> None:
        result = self._make_result()
        signals = {
            "boot_register_snapshot": {
                "MPU_CTRL": "0x00000000",
            },
        }
        expected = {"MPU_CTRL": 0x00000005}
        with self.assertRaises(InvariantViolation) as ctx:
            check_boot_registers_match(
                result,
                boot_register_values=expected,
                result_signals=signals,
            )
        self.assertEqual(ctx.exception.invariant_name, "boot_registers_match")
        self.assertIn("MPU_CTRL", ctx.exception.description)

    def test_missing_register_raises(self) -> None:
        result = self._make_result()
        signals = {"boot_register_snapshot": {}}
        expected = {"MPU_CTRL": 0x00000005}
        with self.assertRaises(InvariantViolation):
            check_boot_registers_match(
                result,
                boot_register_values=expected,
                result_signals=signals,
            )

    def test_no_snapshot_skips(self) -> None:
        result = self._make_result()
        signals = {}
        expected = {"MPU_CTRL": 0x00000005}
        # Should not raise -- no snapshot means nothing to check.
        check_boot_registers_match(
            result,
            boot_register_values=expected,
            result_signals=signals,
        )

    def test_no_boot_skips(self) -> None:
        result = self._make_result(boot_outcome="no_boot")
        signals = {
            "boot_register_snapshot": {"MPU_CTRL": "0x00000000"},
        }
        expected = {"MPU_CTRL": 0x00000005}
        # Should not raise -- device didn't boot.
        check_boot_registers_match(
            result,
            boot_register_values=expected,
            result_signals=signals,
        )

    def test_no_expected_values_skips(self) -> None:
        result = self._make_result()
        signals = {
            "boot_register_snapshot": {"MPU_CTRL": "0x00000000"},
        }
        # Should not raise -- no expected values configured.
        check_boot_registers_match(result, result_signals=signals)

    def test_invariant_via_run_invariants(self) -> None:
        result = self._make_result()
        signals = {
            "boot_register_snapshot": {"MPU_CTRL": "0x00000000"},
        }
        expected = {"MPU_CTRL": 0x00000005}
        violations = run_invariants(
            result,
            [check_boot_registers_match],
            boot_register_values=expected,
            result_signals=signals,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].invariant_name, "boot_registers_match")


class WriteOrderConstraintsProfileParsingTest(unittest.TestCase):
    """Test YAML parsing of write_order_constraints."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_write_order_constraints_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_woc
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
                write_order_constraints:
                  - first: { start: 0x70100, size: 256 }
                    then: { start: 0x70000, size: 256 }
                    label: inactive_before_active
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.write_order_constraints), 1)
            c = profile.write_order_constraints[0]
            self.assertEqual(c.first_start, 0x70100)
            self.assertEqual(c.first_size, 256)
            self.assertEqual(c.then_start, 0x70000)
            self.assertEqual(c.then_size, 256)
            self.assertEqual(c.label, "inactive_before_active")

    def test_no_constraints_defaults_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_no_woc
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
            self.assertEqual(profile.write_order_constraints, [])


class WriteOrderConstraintsCheckTest(unittest.TestCase):
    """Test check_write_order_constraints with synthetic trace data."""

    def _constraint(
        self,
        first_start: int,
        first_size: int,
        then_start: int,
        then_size: int,
        label: str = "test",
    ) -> WriteOrderConstraint:
        return WriteOrderConstraint(
            first_start=first_start,
            first_size=first_size,
            then_start=then_start,
            then_size=then_size,
            label=label,
        )

    def test_correct_order_passes(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70100, "value": 1},
            {"write_index": 1, "flash_offset": 0x70108, "value": 2},
            {"write_index": 2, "flash_offset": 0x70000, "value": 3},
            {"write_index": 3, "flash_offset": 0x70008, "value": 4},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "inactive_first"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_wrong_order_violates(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
            {"write_index": 1, "flash_offset": 0x70100, "value": 2},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "inactive_first"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["label"], "inactive_first")
        self.assertEqual(violations[0]["status"], "violated")
        self.assertEqual(violations[0]["first_write_index"], 1)
        self.assertEqual(violations[0]["then_write_index"], 0)

    def test_only_first_written_passes(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70100, "value": 1},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "test"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_only_then_written_violates(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "test"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(len(violations), 1)
        self.assertIn("never written", violations[0]["reason"])

    def test_neither_written_passes(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x90000, "value": 1},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "test"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_same_index_passes(self) -> None:
        """When first and then are at the same write_index, treat as satisfied."""
        trace = [
            {"write_index": 5, "flash_offset": 0x70100, "value": 1},
            {"write_index": 5, "flash_offset": 0x70000, "value": 2},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "test"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_multiple_constraints(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70100, "value": 1},
            {"write_index": 1, "flash_offset": 0x70000, "value": 2},
            {"write_index": 2, "flash_offset": 0x80000, "value": 3},
            {"write_index": 3, "flash_offset": 0x80100, "value": 4},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "first_ok"),
            self._constraint(0x80100, 256, 0x80000, 256, "second_bad"),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["label"], "second_bad")

    def test_empty_trace_passes(self) -> None:
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "test"),
        ]
        violations = check_write_order_constraints([], constraints)
        self.assertEqual(violations, [])

    def test_empty_constraints_passes(self) -> None:
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
        ]
        violations = check_write_order_constraints(trace, [])
        self.assertEqual(violations, [])


class BootRegisterPreWritesProfileParsingTest(unittest.TestCase):
    """Test YAML parsing of boot_register_pre_writes."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_pre_writes_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_pre_writes
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
                boot_register_pre_writes:
                  - { address: 0xE000ED98, value: 0x00000000 }
                  - { address: 0xE000ED00, value: 0x00000001 }
                boot_registers:
                  - { address: 0xE000ED94, name: "MPU_CTRL" }
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.boot_register_pre_writes), 2)
            self.assertEqual(profile.boot_register_pre_writes[0].address, 0xE000ED98)
            self.assertEqual(profile.boot_register_pre_writes[0].value, 0x00000000)
            self.assertEqual(profile.boot_register_pre_writes[1].address, 0xE000ED00)
            self.assertEqual(profile.boot_register_pre_writes[1].value, 0x00000001)

    def test_no_pre_writes_defaults_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_no_pre_writes
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
            self.assertEqual(profile.boot_register_pre_writes, [])

    def test_pre_writes_robot_vars(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_pre_writes_rv
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
                boot_register_pre_writes:
                  - { address: 0xE000ED98, value: 0x00000000 }
                boot_registers:
                  - { address: 0xE000ED94, name: "MPU_CTRL" }
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
            pw_var = [v for v in robot_vars if v.startswith("BOOT_REGISTER_PRE_WRITES:")]
            self.assertEqual(len(pw_var), 1)
            self.assertIn("0xE000ED98=0x00000000", pw_var[0])

    def test_pre_writes_invalid_type_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_bad_pre_writes
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
                boot_register_pre_writes: "not_a_list"
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)

    def test_pre_writes_missing_value_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_bad_pre_writes2
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
                boot_register_pre_writes:
                  - { address: 0xE000ED98 }
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)


class BidirectionalWriteOrderConstraintParsingTest(unittest.TestCase):
    """Test YAML parsing of bidirectional write_order_constraints."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_bidirectional_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_bidir_woc
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
                write_order_constraints:
                  - first: { start: 0x70100, size: 256 }
                    then: { start: 0x70000, size: 256 }
                    bidirectional: true
                    label: "no_interleave"
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.write_order_constraints), 1)
            c = profile.write_order_constraints[0]
            self.assertTrue(c.bidirectional)
            self.assertEqual(c.label, "no_interleave")

    def test_bidirectional_defaults_false(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_default_bidir
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
                write_order_constraints:
                  - first: { start: 0x70100, size: 256 }
                    then: { start: 0x70000, size: 256 }
                    label: "strict"
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            c = profile.write_order_constraints[0]
            self.assertFalse(c.bidirectional)


class BidirectionalWriteOrderCheckTest(unittest.TestCase):
    """Test check_write_order_constraints with bidirectional mode."""

    def _constraint(
        self,
        first_start: int,
        first_size: int,
        then_start: int,
        then_size: int,
        label: str = "test",
        bidirectional: bool = False,
    ) -> WriteOrderConstraint:
        return WriteOrderConstraint(
            first_start=first_start,
            first_size=first_size,
            then_start=then_start,
            then_size=then_size,
            label=label,
            bidirectional=bidirectional,
        )

    def test_bidir_first_before_then_passes(self) -> None:
        """Normal order passes in bidirectional mode."""
        trace = [
            {"write_index": 0, "flash_offset": 0x70100, "value": 1},
            {"write_index": 1, "flash_offset": 0x70108, "value": 2},
            {"write_index": 2, "flash_offset": 0x70000, "value": 3},
            {"write_index": 3, "flash_offset": 0x70008, "value": 4},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "bidir", bidirectional=True),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_bidir_then_before_first_passes(self) -> None:
        """Reverse order passes in bidirectional mode."""
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
            {"write_index": 1, "flash_offset": 0x70008, "value": 2},
            {"write_index": 2, "flash_offset": 0x70100, "value": 3},
            {"write_index": 3, "flash_offset": 0x70108, "value": 4},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "bidir", bidirectional=True),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_bidir_interleaved_violates(self) -> None:
        """Interleaved writes violate in bidirectional mode."""
        trace = [
            {"write_index": 0, "flash_offset": 0x70100, "value": 1},
            {"write_index": 1, "flash_offset": 0x70000, "value": 2},
            {"write_index": 2, "flash_offset": 0x70108, "value": 3},
            {"write_index": 3, "flash_offset": 0x70008, "value": 4},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "bidir", bidirectional=True),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(len(violations), 1)
        self.assertIn("interleaved", violations[0]["reason"])

    def test_bidir_only_one_region_passes(self) -> None:
        """Only one region written -- no interleaving possible."""
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "bidir", bidirectional=True),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(violations, [])

    def test_non_bidir_reverse_order_still_violates(self) -> None:
        """Non-bidirectional constraint still violates on reverse order."""
        trace = [
            {"write_index": 0, "flash_offset": 0x70000, "value": 1},
            {"write_index": 1, "flash_offset": 0x70008, "value": 2},
            {"write_index": 2, "flash_offset": 0x70100, "value": 3},
        ]
        constraints = [
            self._constraint(0x70100, 256, 0x70000, 256, "strict", bidirectional=False),
        ]
        violations = check_write_order_constraints(trace, constraints)
        self.assertEqual(len(violations), 1)


class HookFaultCommandDropTest(unittest.TestCase):
    """Test that command_drop is accepted in hook_fault.fault_types."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_command_drop_accepted_in_hook_fault(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_hook_cmd_drop
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
                fault_sweep:
                  boot_cycles: 2
                  boot_cycle_hook: scripts/run_runtime_fault_sweep.resc
                  hook_fault:
                    enabled: true
                    fault_types: [command_drop]
                """,
            )
            profile = load_profile(profile_path)
            self.assertIn("command_drop", profile.fault_sweep.hook_fault.fault_types)


class HookFaultMultiFaultWarningTest(unittest.TestCase):
    """Test that enabling both hook_fault and multi_fault produces a warning."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_hook_and_multi_fault_warns(self) -> None:
        import warnings as _warnings

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_hook_multi_warn
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
                fault_sweep:
                  boot_cycles: 2
                  boot_cycle_hook: scripts/run_runtime_fault_sweep.resc
                  hook_fault:
                    enabled: true
                    fault_types: [power_loss]
                  multi_fault:
                    enabled: true
                """,
            )
            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                load_profile(profile_path)
            msgs = [str(w.message) for w in caught]
            self.assertTrue(
                any("hook_fault and multi_fault" in m for m in msgs),
                "Expected warning about hook_fault + multi_fault interaction, "
                "got: {}".format(msgs),
            )

    def test_hook_only_no_warning(self) -> None:
        import warnings as _warnings

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_hook_only
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
                fault_sweep:
                  boot_cycles: 2
                  boot_cycle_hook: scripts/run_runtime_fault_sweep.resc
                  hook_fault:
                    enabled: true
                    fault_types: [power_loss]
                """,
            )
            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                load_profile(profile_path)
            msgs = [str(w.message) for w in caught]
            self.assertFalse(
                any("hook_fault and multi_fault" in m for m in msgs),
                "Should not warn when multi_fault is not enabled, "
                "got: {}".format(msgs),
            )


if __name__ == "__main__":
    unittest.main()
