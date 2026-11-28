#!/usr/bin/env python3
"""MCUboot trailer-state probe for tardigrade semantic-state collection."""

import struct


MCUBOOT_GOOD_MAGIC = struct.pack(
    "<IIII",
    0xF395C277,
    0x7FEFD260,
    0x0F505235,
    0x8079B62C,
)


def _as_int(value, default=0):
    try:
        return int(str(value), 0)
    except Exception:
        return int(default)


def _read_bytes(bus, addr, size):
    size = int(size)
    addr = int(addr)
    raw = bus.ReadBytes(addr, size)
    return bytearray(int(b) & 0xFF for b in raw)


def _read_flag(bus, addr):
    raw = _read_bytes(bus, addr, 1)[0]
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


def _magic_state(raw):
    if raw == MCUBOOT_GOOD_MAGIC:
        return "good"
    if raw == (b"\xFF" * 16):
        return "unset"
    if raw[:8] == MCUBOOT_GOOD_MAGIC[:8] and raw[8:] == (b"\xFF" * 8):
        return "partial"
    return "other"


def _slot_probe(bus, base, size, align):
    slot_end = base + size
    magic_addr = slot_end - 16
    image_ok_addr = slot_end - 16 - align
    copy_done_addr = slot_end - 16 - (2 * align)
    magic = _read_bytes(bus, magic_addr, 16)
    return {
        "magic_state": _magic_state(magic),
        "image_ok": _read_flag(bus, image_ok_addr),
        "copy_done": _read_flag(bus, copy_done_addr),
    }


def describe_ranges(context=None):
    """Return named persistent address ranges for MCUboot slot trailers and headers."""
    context = context or {}
    geometry = context.get("slot_geometry") or context.get("slots") or {}
    align = _as_int(context.get("trailer_align", 8), 8)
    if align <= 0:
        align = 8
    page_size = _as_int(context.get("page_size", 4096), 4096)
    if page_size <= 0:
        page_size = 4096
    magic_align_size = ((16 + align - 1) // align) * align if align > 16 else 16
    ranges = []
    for slot_name, slot_info in sorted(geometry.items()):
        if not isinstance(slot_info, dict):
            continue
        base = _as_int(slot_info.get("base"), -1)
        size = _as_int(slot_info.get("size"), 0)
        if base < 0 or size <= 0:
            continue
        slot_end = base + size
        magic_start = slot_end - 16
        image_ok_start = slot_end - magic_align_size - align
        copy_done_start = slot_end - magic_align_size - (2 * align)
        swap_info_start = slot_end - magic_align_size - (3 * align)
        swap_size_start = slot_end - magic_align_size - (4 * align)
        status_start = max(base, slot_end - page_size)
        if magic_start >= base:
            ranges.append({
                "start": magic_start,
                "end": slot_end,
                "name": "MCUboot trailer magic",
                "slot": slot_name,
                "field": "magic",
            })
        if image_ok_start >= base:
            ranges.append({
                "start": image_ok_start,
                "end": slot_end - magic_align_size,
                "name": "MCUboot image_ok",
                "slot": slot_name,
                "field": "image_ok",
            })
        if copy_done_start >= base:
            ranges.append({
                "start": copy_done_start,
                "end": image_ok_start,
                "name": "MCUboot copy_done",
                "slot": slot_name,
                "field": "copy_done",
            })
        if swap_info_start >= base:
            ranges.append({
                "start": swap_info_start,
                "end": copy_done_start,
                "name": "MCUboot swap_info",
                "slot": slot_name,
                "field": "swap_info",
            })
        if swap_size_start >= base:
            ranges.append({
                "start": swap_size_start,
                "end": swap_info_start,
                "name": "MCUboot swap_size",
                "slot": slot_name,
                "field": "swap_size",
            })
        if swap_size_start > status_start:
            ranges.append({
                "start": status_start,
                "end": swap_size_start,
                "name": "MCUboot swap status",
                "slot": slot_name,
                "field": "swap_status",
            })
    return ranges


def collect_state(bus=None, monitor=None, context=None):
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
