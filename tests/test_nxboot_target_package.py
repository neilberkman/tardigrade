#!/usr/bin/env python3
"""Unit tests for the public nxboot-style target-side adapter."""

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
from targets.nxboot.invariants import (  # noqa: E402
    check_nxboot_confirmed_has_recovery,
    check_nxboot_duplicate_update_consumed,
)
from targets.nxboot.probe import _crc32_update, collect_state  # noqa: E402


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


class NxbootTargetPackageTest(unittest.TestCase):
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
        monitor = _FakeMonitor(
            {
                "slot_exec_base": hex(primary_base),
                "slot_exec_size": hex(slot_size),
                "slot_staging_base": hex(secondary_base),
                "slot_staging_size": hex(slot_size),
            }
        )

        primary = make_nxboot_image(primary_base, 0x4000, (1, 0, 0))
        update = make_nxboot_image(primary_base, 0x4000, (2, 0, 0))
        bus.write_bytes(primary_base, primary)
        bus.write_bytes(secondary_base, update)

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["slots"]["primary"]["magic_kind"], "external")
        self.assertTrue(state["slots"]["primary"]["crc_valid"])
        self.assertEqual(state["slots"]["secondary"]["magic_kind"], "external")
        self.assertEqual(state["roles"]["update_slot"], "secondary")
        self.assertEqual(state["roles"]["recovery_slot"], "tertiary")
        self.assertTrue(state["roles"]["primary_valid"])
        self.assertTrue(state["roles"]["primary_confirmed"])
        self.assertEqual(state["roles"]["next_boot"], "update")
        self.assertEqual(state["slots"]["tertiary"]["magic_kind"], "erased")

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
            check_nxboot_confirmed_has_recovery(result)

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
            check_nxboot_duplicate_update_consumed(result)


if __name__ == "__main__":
    unittest.main()
