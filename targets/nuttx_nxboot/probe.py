#!/usr/bin/env python3
"""NuttX nxboot state probe for tardigrade semantic-state collection.

This models the public nxboot slot-role and confirm/recovery semantics from
apache/nuttx-apps/boot/nxboot. It is an adapter scaffold, not a surfaced
workflow yet.
"""

import struct


NXBOOT_HEADER_MAGIC = 0x534F584E
NXBOOT_HEADER_MAGIC_INT = 0xACA0ABB0
HEADER_SIZE_FALLBACK = 0x200
SRAM_START = 0x20000000
SRAM_END = 0x20020000


def _as_int(value, default=0):
    try:
        return int(str(value), 0)
    except Exception:
        return int(default)


def _get_monitor_int(monitor, names, default=None):
    for name in names:
        try:
            return _as_int(monitor.GetVariable(name))
        except Exception:
            continue
    return default


def _read_byte(bus, addr):
    return int(bus.ReadByte(addr)) & 0xFF


def _read_bytes(bus, addr, size):
    raw = []
    for offset in range(int(size)):
        raw.append(_read_byte(bus, addr + offset))
    return struct.pack("{}B".format(len(raw)), *raw)


def _read_u32(bus, addr):
    return struct.unpack("<I", _read_bytes(bus, addr, 4))[0]


def _crc32_update(crc, raw):
    for byte in raw:
        if not isinstance(byte, int):
            byte = ord(byte)
        crc ^= int(byte) & 0xFF
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
            crc &= 0xFFFFFFFF
    return crc


def _magic_kind(magic):
    if magic == NXBOOT_HEADER_MAGIC:
        return "external"
    if magic == 0xFFFFFFFF:
        return "erased"
    if (magic & 0xFFFFFFF0) == NXBOOT_HEADER_MAGIC_INT:
        return "internal"
    return "other"


def _vector_valid(bus, base, header_size, slot_size):
    img_base = int(base) + int(header_size)
    sp = _read_u32(bus, img_base)
    rv = _read_u32(bus, img_base + 4)
    pc = rv & (~1)
    return (
        sp >= SRAM_START
        and sp <= SRAM_END
        and (rv & 1) == 1
        and pc >= img_base
        and pc < (int(base) + int(slot_size))
    )


def _hex_u32(value):
    return "0x{:08X}".format(int(value) & 0xFFFFFFFF)


def _hex_u64(value):
    return "0x{:016X}".format(int(value) & 0xFFFFFFFFFFFFFFFF)


def _slot_probe(bus, base, slot_size):
    header = _read_bytes(bus, base, 40)
    magic = struct.unpack_from("<I", header, 0)[0]
    header_size = struct.unpack_from("<H", header, 6)[0]
    image_crc = struct.unpack_from("<I", header, 8)[0]
    image_size = struct.unpack_from("<I", header, 12)[0]
    identifier = struct.unpack_from("<Q", header, 16)[0]
    version = struct.unpack_from("<HHH", header, 28)
    magic_kind = _magic_kind(magic)
    if header_size <= 0:
        header_size = HEADER_SIZE_FALLBACK
    total_image_size = int(header_size) + int(image_size)
    crc_valid = False
    if (
        magic_kind in ("external", "internal")
        and total_image_size > 12
        and total_image_size <= int(slot_size)
    ):
        crc_data = _read_bytes(bus, int(base) + 12, total_image_size - 12)
        computed_crc = _crc32_update(0xFFFFFFFF, crc_data) ^ 0xFFFFFFFF
        crc_valid = computed_crc == image_crc
    image_valid = bool(magic_kind in ("external", "internal") and crc_valid)
    vector_valid = False
    if total_image_size <= int(slot_size) and header_size <= int(slot_size):
        vector_valid = _vector_valid(bus, base, header_size, slot_size)
    return {
        "base": _hex_u32(base),
        "size": _hex_u32(slot_size),
        "magic": _hex_u32(magic),
        "magic_kind": magic_kind,
        "internal_recovery_ptr": int(magic & 0x3) if magic_kind == "internal" else None,
        "header_size": int(header_size),
        "image_size": int(image_size),
        "image_crc": _hex_u32(image_crc),
        "identifier": _hex_u64(identifier),
        "version": "{}.{}.{}".format(version[0], version[1], version[2]),
        "crc_valid": bool(crc_valid),
        "image_valid": image_valid,
        "vector_valid": bool(vector_valid),
        "bootable": bool(image_valid and vector_valid),
    }


def _determine_roles(primary, secondary, tertiary):
    update_slot = "secondary"
    recovery_slot = "tertiary"

    if tertiary.get("magic_kind") == "external":
        update_slot = "tertiary"
        recovery_slot = "secondary"
    elif (
        secondary.get("magic_kind") == "internal"
        and tertiary.get("magic_kind") == "internal"
    ):
        if primary.get("magic_kind") == "internal":
            recovery_ptr = primary.get("internal_recovery_ptr")
            if recovery_ptr == 1 and primary.get("image_crc") == secondary.get("image_crc"):
                update_slot = "tertiary"
                recovery_slot = "secondary"
        elif primary.get("magic_kind") == "external":
            if primary.get("image_crc") == secondary.get("image_crc"):
                update_slot = "tertiary"
                recovery_slot = "secondary"
    elif secondary.get("magic_kind") == "internal":
        update_slot = "tertiary"
        recovery_slot = "secondary"

    return update_slot, recovery_slot


def collect_state(bus=None, monitor=None, context=None):
    if bus is None or monitor is None:
        return {}

    context = context or {}
    primary_base = _as_int(monitor.GetVariable("slot_exec_base"))
    primary_size = _as_int(monitor.GetVariable("slot_exec_size"))
    secondary_base = _as_int(monitor.GetVariable("slot_staging_base"))
    secondary_size = _as_int(monitor.GetVariable("slot_staging_size"), primary_size)
    tertiary_base = _get_monitor_int(
        monitor,
        ("slot_tertiary_base", "slot_recovery_base"),
        secondary_base + secondary_size,
    )
    tertiary_size = _get_monitor_int(
        monitor,
        ("slot_tertiary_size", "slot_recovery_size"),
        secondary_size,
    )

    primary = _slot_probe(bus, primary_base, primary_size)
    secondary = _slot_probe(bus, secondary_base, secondary_size)
    tertiary = _slot_probe(bus, tertiary_base, tertiary_size)

    update_slot, recovery_slot = _determine_roles(primary, secondary, tertiary)
    update = secondary if update_slot == "secondary" else tertiary
    recovery = secondary if recovery_slot == "secondary" else tertiary

    primary_valid = bool(primary.get("image_valid"))
    recovery_valid = bool(recovery.get("image_valid"))
    recovery_present = primary.get("image_crc") == recovery.get("image_crc")

    primary_confirmed = False
    if primary.get("magic_kind") == "external":
        primary_confirmed = True
    elif primary.get("magic_kind") == "internal":
        ptr = primary.get("internal_recovery_ptr")
        if ptr == 1 and secondary.get("magic_kind") == "internal":
            primary_confirmed = primary.get("image_crc") == secondary.get("image_crc")
        elif ptr == 2 and tertiary.get("magic_kind") == "internal":
            primary_confirmed = primary.get("image_crc") == tertiary.get("image_crc")

    next_boot = "none"
    if update.get("magic_kind") == "external" and update.get("crc_valid"):
        if (not primary_valid) or primary.get("image_crc") != update.get("image_crc"):
            next_boot = "update"
        else:
            next_boot = "none"
    elif (
        recovery.get("magic_kind") == "internal"
        and recovery_valid
        and ((primary.get("magic_kind") == "internal" and not primary_confirmed) or (not primary_valid))
    ):
        next_boot = "revert"

    return {
        "target": "nuttx_nxboot",
        "stage": context.get("stage"),
        "boot_slot": context.get("boot_slot"),
        "fault_injected": bool(context.get("fault_injected", False)),
        "slots": {
            "primary": primary,
            "secondary": secondary,
            "tertiary": tertiary,
        },
        "roles": {
            "update_slot": update_slot,
            "recovery_slot": recovery_slot,
            "primary_valid": primary_valid,
            "primary_confirmed": primary_confirmed,
            "recovery_valid": recovery_valid,
            "recovery_present": recovery_present,
            "next_boot": next_boot,
        },
        "flags": {
            "same_primary_update_crc": primary.get("image_crc") == update.get("image_crc"),
            "same_primary_recovery_crc": recovery_present,
        },
    }
