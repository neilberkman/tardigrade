#!/usr/bin/env python3
"""Temporary PR2206 post-boot probe.

Reads the staging header and trailer words after the boot attempt so we can
distinguish "swap never engaged" from "secondary validation erased the image".
"""


def _as_int(value):
    try:
        return int(value)
    except Exception:
        return 0


def _read_u32(bus, addr):
    try:
        return _as_int(bus.ReadDoubleWord(int(addr))) & 0xFFFFFFFF
    except Exception:
        return None


def _fmt_u32(value):
    if value is None:
        return None
    return "0x{:08X}".format(int(value) & 0xFFFFFFFF)


def _derive_staging_bounds(context):
    signals = (context or {}).get("signals") or {}
    header_debug = signals.get("staging_header_debug") or {}
    pre_boot = signals.get("pre_boot_state_debug") or []

    base = None
    if isinstance(header_debug, dict):
        base_raw = header_debug.get("base")
        if isinstance(base_raw, str):
            try:
                base = int(base_raw, 0)
            except Exception:
                base = None

    slot_end = None
    if pre_boot:
        try:
            last_addr = max(int(str(entry.get("address")), 0) for entry in pre_boot)
            slot_end = last_addr + 4
        except Exception:
            slot_end = None

    if base is None:
        base = 0x08108000
    if slot_end is None:
        slot_end = base + 0x18000
    return base, slot_end


def collect_state(bus, monitor, context):
    staging_base, slot_end = _derive_staging_bounds(context)
    header_words = {
        "magic": _fmt_u32(_read_u32(bus, staging_base + 0x0)),
        "load_addr": _fmt_u32(_read_u32(bus, staging_base + 0x4)),
        "hdr_plus_prot": _fmt_u32(_read_u32(bus, staging_base + 0x8)),
        "img_size": _fmt_u32(_read_u32(bus, staging_base + 0xC)),
        "flags": _fmt_u32(_read_u32(bus, staging_base + 0x10)),
        "tlv_magic": _fmt_u32(_read_u32(bus, staging_base + 0x9000)),
    }

    align = 32
    trailer_words = {
        "swap_size_off": {
            "addr": _fmt_u32(slot_end - 0xA0),
            "value": _fmt_u32(_read_u32(bus, slot_end - 0xA0)),
        },
        "swap_info_off": {
            "addr": _fmt_u32(slot_end - 0x80),
            "value": _fmt_u32(_read_u32(bus, slot_end - 0x80)),
        },
        "copy_done_off": {
            "addr": _fmt_u32(slot_end - 16 - (2 * align)),
            "value": _fmt_u32(_read_u32(bus, slot_end - 16 - (2 * align))),
        },
        "image_ok_off": {
            "addr": _fmt_u32(slot_end - 16 - align),
            "value": _fmt_u32(_read_u32(bus, slot_end - 16 - align)),
        },
        "magic_0": {
            "addr": _fmt_u32(slot_end - 16),
            "value": _fmt_u32(_read_u32(bus, slot_end - 16)),
        },
        "magic_1": {
            "addr": _fmt_u32(slot_end - 12),
            "value": _fmt_u32(_read_u32(bus, slot_end - 12)),
        },
        "magic_2": {
            "addr": _fmt_u32(slot_end - 8),
            "value": _fmt_u32(_read_u32(bus, slot_end - 8)),
        },
        "magic_3": {
            "addr": _fmt_u32(slot_end - 4),
            "value": _fmt_u32(_read_u32(bus, slot_end - 4)),
        },
    }

    return {
        "probe": "pr2206_post_boot_state_probe",
        "stage": (context or {}).get("stage"),
        "boot_outcome": (context or {}).get("boot_outcome"),
        "boot_slot": (context or {}).get("boot_slot"),
        "staging_base": _fmt_u32(staging_base),
        "staging_end": _fmt_u32(slot_end),
        "header_words": header_words,
        "trailer_words": trailer_words,
    }
