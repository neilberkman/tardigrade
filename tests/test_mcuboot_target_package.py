#!/usr/bin/env python3
"""Unit tests for the public MCUboot target-side adapter."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from targets.mcuboot.invariants import check_mcuboot_no_partial_magic  # noqa: E402
from targets.mcuboot.probe import collect_state  # noqa: E402


GOOD_MAGIC = struct.pack(
    "<IIII",
    0xF395C277,
    0x7FEFD260,
    0x0F505235,
    0x8079B62C,
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


class McubootTargetPackageTest(unittest.TestCase):
    def test_probe_reads_trailer_flags(self) -> None:
        exec_base = 0x0000C000
        exec_size = 0x1000
        staging_base = 0x0000D000
        staging_size = 0x1000
        align = 8
        bus = _FakeBus()
        monitor = _FakeMonitor(
            {
                "slot_exec_base": hex(exec_base),
                "slot_exec_size": hex(exec_size),
                "slot_staging_base": hex(staging_base),
                "slot_staging_size": hex(staging_size),
                "mcuboot_trailer_align": str(align),
            }
        )

        exec_end = exec_base + exec_size
        bus.write_bytes(exec_end - 16, GOOD_MAGIC)
        bus.write_bytes(exec_end - 16 - align, b"\x01")
        bus.write_bytes(exec_end - 16 - (2 * align), b"\x01")

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "post_boot", "boot_slot": "exec", "fault_injected": False},
        )
        self.assertEqual(state["slots"]["exec"]["magic_state"], "good")
        self.assertEqual(state["slots"]["exec"]["image_ok"]["state"], "set")
        self.assertEqual(state["slots"]["exec"]["copy_done"]["state"], "set")
        self.assertEqual(state["slots"]["staging"]["magic_state"], "unset")
        self.assertFalse(state["flags"]["any_partial_magic"])

    def test_invariant_rejects_partial_magic(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "slots": {
                    "exec": {"magic_state": "partial"},
                    "staging": {"magic_state": "unset"},
                }
            }
        )
        with self.assertRaises(InvariantViolation):
            check_mcuboot_no_partial_magic(result)


if __name__ == "__main__":
    unittest.main()
