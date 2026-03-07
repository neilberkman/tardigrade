#!/usr/bin/env python3
"""Unit tests for the real NuttX nxboot target-side adapter scaffold."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from examples.nxboot_style.gen_nxboot_images import make_nxboot_image  # noqa: E402
from targets.nuttx_nxboot.invariants import (  # noqa: E402
    check_nuttx_nxboot_confirmed_has_recovery,
    check_nuttx_nxboot_duplicate_update_consumed,
    check_nuttx_nxboot_roles_distinct,
    check_nuttx_nxboot_unconfirmed_internal_requires_revert,
)
from targets.nuttx_nxboot.probe import (  # noqa: E402
    NXBOOT_HEADER_MAGIC_INT,
    _crc32_update,
    collect_state,
)


class _FakeBus:
    def __init__(self) -> None:
        self._bytes = {}

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, byte in enumerate(data):
            self._bytes[addr + i] = byte

    def ReadByte(self, addr: int) -> int:
        return self._bytes.get(addr, 0xFF)


class _FakeMonitor:
    def __init__(self, variables):
        self._variables = dict(variables)

    def GetVariable(self, name: str):
        return self._variables[name]


class NuttxNxbootTargetPackageTest(unittest.TestCase):
    @staticmethod
    def _monitor(primary_base: int, secondary_base: int, slot_size: int) -> _FakeMonitor:
        return _FakeMonitor(
            {
                "slot_exec_base": hex(primary_base),
                "slot_exec_size": hex(slot_size),
                "slot_staging_base": hex(secondary_base),
                "slot_staging_size": hex(slot_size),
            }
        )

    def test_crc_helper_accepts_legacy_char_iteration(self) -> None:
        expected = _crc32_update(0xFFFFFFFF, b"ABC") ^ 0xFFFFFFFF
        legacy = _crc32_update(0xFFFFFFFF, "ABC") ^ 0xFFFFFFFF
        self.assertEqual(legacy, expected)

    def test_probe_models_pending_update_roles(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000
        tertiary_base = secondary_base + slot_size

        bus = _FakeBus()
        monitor = self._monitor(primary_base, secondary_base, slot_size)

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        update = make_nxboot_image(primary_base, 0x4000, (2, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, update)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["target"], "nuttx_nxboot")
        self.assertEqual(state["slots"]["primary"]["magic_kind"], "external")
        self.assertTrue(state["slots"]["primary"]["crc_valid"])
        self.assertEqual(state["slots"]["secondary"]["magic_kind"], "external")
        self.assertEqual(state["roles"]["update_slot"], "secondary")
        self.assertEqual(state["roles"]["recovery_slot"], "tertiary")
        self.assertTrue(state["roles"]["primary_valid"])
        self.assertTrue(state["roles"]["primary_confirmed"])
        self.assertEqual(state["roles"]["next_boot"], "update")
        self.assertEqual(state["slots"]["tertiary"]["magic_kind"], "erased")

    def test_probe_models_internal_primary_confirmed_via_secondary_recovery(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000

        bus = _FakeBus()
        monitor = self._monitor(primary_base, secondary_base, slot_size)

        primary = make_nxboot_image(
            primary_base,
            0x4000,
            (2, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT | 0x1,
        )
        recovery = make_nxboot_image(
            primary_base,
            0x4000,
            (2, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT,
        )
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, recovery)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["roles"]["update_slot"], "tertiary")
        self.assertEqual(state["roles"]["recovery_slot"], "secondary")
        self.assertTrue(state["roles"]["primary_valid"])
        self.assertTrue(state["roles"]["primary_confirmed"])
        self.assertTrue(state["roles"]["recovery_valid"])
        self.assertTrue(state["roles"]["recovery_present"])
        self.assertEqual(state["roles"]["next_boot"], "none")

    def test_probe_switches_update_role_to_tertiary(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000
        tertiary_base = secondary_base + slot_size

        bus = _FakeBus()
        monitor = self._monitor(primary_base, secondary_base, slot_size)

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        recovery = make_nxboot_image(
            primary_base,
            0x4000,
            (1, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT,
        )
        update = make_nxboot_image(primary_base, 0x4000, (2, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, recovery)
        bus.write_bytes(tertiary_base, update)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["roles"]["update_slot"], "tertiary")
        self.assertEqual(state["roles"]["recovery_slot"], "secondary")
        self.assertEqual(state["roles"]["next_boot"], "update")
        self.assertTrue(state["roles"]["recovery_valid"])
        self.assertTrue(state["flags"]["same_primary_recovery_crc"])

    def test_probe_honors_explicit_tertiary_layout(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000
        tertiary_base = 0x10100000

        bus = _FakeBus()
        monitor = _FakeMonitor(
            {
                "slot_exec_base": hex(primary_base),
                "slot_exec_size": hex(slot_size),
                "slot_staging_base": hex(secondary_base),
                "slot_staging_size": hex(slot_size),
                "slot_tertiary_base": hex(tertiary_base),
                "slot_tertiary_size": hex(slot_size),
            }
        )

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        recovery = make_nxboot_image(
            primary_base,
            0x4000,
            (1, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT,
        )
        update = make_nxboot_image(primary_base, 0x4000, (3, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, recovery)
        bus.write_bytes(tertiary_base, update)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["slots"]["tertiary"]["base"], "0x10100000")
        self.assertEqual(state["roles"]["update_slot"], "tertiary")
        self.assertEqual(state["roles"]["recovery_slot"], "secondary")
        self.assertEqual(state["roles"]["next_boot"], "update")

    def test_probe_accepts_recovery_slot_alias(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000
        recovery_base = 0x10100000

        bus = _FakeBus()
        monitor = _FakeMonitor(
            {
                "slot_exec_base": hex(primary_base),
                "slot_exec_size": hex(slot_size),
                "slot_staging_base": hex(secondary_base),
                "slot_staging_size": hex(slot_size),
                "slot_recovery_base": hex(recovery_base),
                "slot_recovery_size": hex(slot_size),
            }
        )

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        recovery = make_nxboot_image(
            primary_base,
            0x4000,
            (1, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT,
        )
        update = make_nxboot_image(primary_base, 0x4000, (3, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, recovery)
        bus.write_bytes(recovery_base, update)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["slots"]["tertiary"]["base"], "0x10100000")
        self.assertEqual(state["roles"]["update_slot"], "tertiary")
        self.assertEqual(state["roles"]["recovery_slot"], "secondary")
        self.assertEqual(state["roles"]["next_boot"], "update")

    def test_probe_models_revert_for_unconfirmed_internal_primary(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000

        bus = _FakeBus()
        monitor = self._monitor(primary_base, secondary_base, slot_size)

        primary = make_nxboot_image(
            primary_base,
            0x4000,
            (2, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT | 0x1,
        )
        recovery = make_nxboot_image(
            primary_base,
            0x4000,
            (1, 0, 0),
            magic=NXBOOT_HEADER_MAGIC_INT,
        )
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, recovery)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertFalse(state["roles"]["primary_confirmed"])
        self.assertTrue(state["roles"]["recovery_valid"])
        self.assertEqual(state["roles"]["next_boot"], "revert")

    def test_probe_consumes_duplicate_update(self) -> None:
        slot_size = 0x23000
        primary_base = 0x10002000
        secondary_base = 0x10025000

        bus = _FakeBus()
        monitor = self._monitor(primary_base, secondary_base, slot_size)

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        duplicate = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, duplicate)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["roles"]["update_slot"], "secondary")
        self.assertTrue(state["flags"]["same_primary_update_crc"])
        self.assertEqual(state["roles"]["next_boot"], "none")

    def test_invariant_rejects_confirmed_internal_without_recovery(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "slots": {"primary": {"magic_kind": "internal"}},
                "roles": {
                    "primary_confirmed": True,
                    "recovery_valid": False,
                    "recovery_present": False,
                },
            }
        )
        with self.assertRaises(InvariantViolation):
            check_nuttx_nxboot_confirmed_has_recovery(result)

    def test_invariant_rejects_duplicate_update_loop(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "slots": {
                    "secondary": {"magic_kind": "external", "crc_valid": True},
                },
                "roles": {
                    "primary_valid": True,
                    "update_slot": "secondary",
                    "next_boot": "update",
                },
                "flags": {
                    "same_primary_update_crc": True,
                },
            }
        )
        with self.assertRaises(InvariantViolation):
            check_nuttx_nxboot_duplicate_update_consumed(result)

    def test_invariant_rejects_collapsed_roles(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "roles": {
                    "update_slot": "secondary",
                    "recovery_slot": "secondary",
                }
            }
        )
        with self.assertRaises(InvariantViolation):
            check_nuttx_nxboot_roles_distinct(result)

    def test_invariant_requires_revert_for_unconfirmed_internal_primary(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "slots": {
                    "primary": {"magic_kind": "internal"},
                },
                "roles": {
                    "primary_confirmed": False,
                    "recovery_valid": True,
                    "next_boot": "none",
                },
            }
        )
        with self.assertRaises(InvariantViolation):
            check_nuttx_nxboot_unconfirmed_internal_requires_revert(result)


if __name__ == "__main__":
    unittest.main()
