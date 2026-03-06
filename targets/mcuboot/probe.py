#!/usr/bin/env python3
"""MCUboot trailer-state probe for tardigrade semantic-state collection."""

from __future__ import annotations

import struct
from typing import Any, Dict


MCUBOOT_GOOD_MAGIC = struct.pack(
    "<IIII",
    0xF395C277,
    0x7FEFD260,
    0x0F505235,
    0x8079B62C,
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value), 0)
    except Exception:
        return int(default)


def _read_byte(bus: Any, addr: int) -> int:
    return int(bus.ReadByte(addr)) & 0xFF


def _read_bytes(bus: Any, addr: int, size: int) -> bytes:
    return bytes(_read_byte(bus, addr + i) for i in range(size))


def _read_flag(bus: Any, addr: int) -> Dict[str, Any]:
    raw = _read_byte(bus, addr)
    if raw == 0xFF:
        state = "unset"
    elif raw == 0x01:
        state = "set"
    else:
        state = "other"
    return {
        "raw": "0x{:02X}".format(raw),
        "state": state,
    }


def _magic_state(raw: bytes) -> str:
    if raw == MCUBOOT_GOOD_MAGIC:
        return "good"
    if raw == (b"\xFF" * 16):
        return "unset"
    if raw[:8] == MCUBOOT_GOOD_MAGIC[:8] and raw[8:] == (b"\xFF" * 8):
        return "partial"
    return "other"


def _slot_probe(bus: Any, base: int, size: int, align: int) -> Dict[str, Any]:
    slot_end = base + size
    magic_addr = slot_end - 16
    image_ok_addr = slot_end - 16 - align
    copy_done_addr = slot_end - 16 - (2 * align)
    magic = _read_bytes(bus, magic_addr, 16)
    return {
        "base": "0x{:08X}".format(base),
        "size": "0x{:08X}".format(size),
        "magic_addr": "0x{:08X}".format(magic_addr),
        "image_ok_addr": "0x{:08X}".format(image_ok_addr),
        "copy_done_addr": "0x{:08X}".format(copy_done_addr),
        "magic": magic.hex(),
        "magic_state": _magic_state(magic),
        "image_ok": _read_flag(bus, image_ok_addr),
        "copy_done": _read_flag(bus, copy_done_addr),
    }


def collect_state(bus: Any = None, monitor: Any = None, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if bus is None or monitor is None:
        return {}
    context = context or {}
    exec_base = _as_int(monitor.GetVariable("slot_exec_base"))
    exec_size = _as_int(monitor.GetVariable("slot_exec_size"))
    staging_base = _as_int(monitor.GetVariable("slot_staging_base"))
    staging_size = _as_int(monitor.GetVariable("slot_staging_size"))
    align = _as_int(monitor.GetVariable("mcuboot_trailer_align"), 8)
    if align <= 0:
        align = 8

    exec_slot = _slot_probe(bus, exec_base, exec_size, align)
    staging_slot = _slot_probe(bus, staging_base, staging_size, align)
    return {
        "target": "mcuboot",
        "stage": context.get("stage"),
        "boot_slot": context.get("boot_slot"),
        "fault_injected": bool(context.get("fault_injected", False)),
        "trailer_align": align,
        "slots": {
            "exec": exec_slot,
            "staging": staging_slot,
        },
        "flags": {
            "any_partial_magic": (
                exec_slot["magic_state"] == "partial"
                or staging_slot["magic_state"] == "partial"
            ),
            "both_good_magic": (
                exec_slot["magic_state"] == "good"
                and staging_slot["magic_state"] == "good"
            ),
        },
    }
