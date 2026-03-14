#!/usr/bin/env python3
"""ESP-IDF otadata state probe for tardigrade semantic-state collection.

Reads the dual otadata sectors and produces structured state describing:
- Per-sector entry validity (CRC check, sequence number, OTA state)
- Which entry is active (highest valid ota_seq wins)
- Which slot the active entry maps to
- Rollback-relevant state (PENDING_VERIFY detection)

otadata entry format (esp_ota_select_entry_t, 32 bytes):
    uint32_t ota_seq       offset 0   (1-based, 0xFFFFFFFF = erased)
    uint8_t  seq_label[20] offset 4   (unused, 0xFF)
    uint32_t ota_state     offset 24  state enum
    uint32_t crc           offset 28  CRC-32 of ota_seq only

OTA state values:
    0x00000000  NEW
    0x00000001  PENDING_VERIFY
    0x00000002  VALID
    0x00000003  INVALID
    0x00000004  ABORTED
    0xFFFFFFFF  UNDEFINED (erased)

Reference: ESP-IDF bootloader_utility.c (Apache 2.0)
This is a clean-room reimplementation, not ESP-IDF code.
"""

import struct

# OTA state enum
_OTA_STATE_NAMES = {
    0x00000000: "new",
    0x00000001: "pending_verify",
    0x00000002: "valid",
    0x00000003: "invalid",
    0x00000004: "aborted",
    0xFFFFFFFF: "undefined",
}

# Default addresses matching the esp_idf_ota.c model
_DEFAULT_OTADATA_BASE = 0x000F8000
_DEFAULT_OTADATA_SECTOR_SIZE = 0x1000
_DEFAULT_NUM_SLOTS = 2


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


def _read_u32(bus, addr):
    return struct.unpack("<I", _read_bytes(bus, addr, 4))[0]


def _crc32_table():
    """Build CRC-32 table with polynomial 0xEDB88320."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        table.append(c)
    return table


_CRC_TABLE = _crc32_table()


def _esp_otadata_crc(ota_seq):
    """Compute CRC-32 of ota_seq matching ESP-IDF ROM convention.

    esp_rom_crc32_le(0xFFFFFFFF, &ota_seq, 4):
      ROM internally does crc = ~init = 0, process bytes, return ~crc.
    """
    data = struct.pack("<I", ota_seq)
    crc = 0x00000000
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _ota_state_name(state_val):
    return _OTA_STATE_NAMES.get(state_val, "unknown_0x{:08X}".format(state_val))


def _probe_otadata_entry(bus, sector_addr):
    """Read and validate a single otadata entry from a sector."""
    raw = _read_bytes(bus, sector_addr, 32)
    ota_seq = struct.unpack_from("<I", raw, 0)[0]
    ota_state = struct.unpack_from("<I", raw, 24)[0]
    crc_stored = struct.unpack_from("<I", raw, 28)[0]

    # Check if entry is erased
    erased = (ota_seq == 0xFFFFFFFF)

    # CRC validity
    if erased:
        crc_valid = False
        crc_expected = None
    else:
        crc_expected = _esp_otadata_crc(ota_seq)
        crc_valid = (crc_stored == crc_expected)

    # Entry is valid for selection if: not erased, CRC matches,
    # and state is not INVALID or ABORTED
    selectable = (
        not erased
        and crc_valid
        and ota_state not in (0x00000003, 0x00000004)  # INVALID, ABORTED
    )

    return {
        "sector_addr": "0x{:08X}".format(sector_addr),
        "ota_seq": ota_seq,
        "ota_seq_hex": "0x{:08X}".format(ota_seq),
        "ota_state": _ota_state_name(ota_state),
        "ota_state_raw": ota_state,
        "crc_stored": "0x{:08X}".format(crc_stored),
        "crc_expected": "0x{:08X}".format(crc_expected) if crc_expected is not None else None,
        "crc_valid": crc_valid,
        "erased": erased,
        "selectable": selectable,
    }


def _select_active(entries):
    """Select the active otadata entry (highest valid ota_seq wins).

    Returns the index (0 or 1) of the active entry, or -1 if neither is valid.
    """
    valid = [e["selectable"] for e in entries]

    if valid[0] and valid[1]:
        return 0 if entries[0]["ota_seq"] >= entries[1]["ota_seq"] else 1
    if valid[0]:
        return 0
    if valid[1]:
        return 1
    return -1


def _seq_to_slot(ota_seq, num_slots=2):
    """Map ota_seq to slot index: slot = (ota_seq - 1) % num_slots."""
    if ota_seq == 0xFFFFFFFF or ota_seq == 0:
        return None
    return (ota_seq - 1) % num_slots


def collect_state(bus=None, monitor=None, context=None):
    """Collect ESP-IDF otadata semantic state from emulated memory.

    Returns a structured dict describing both otadata entries, which one
    is active, which slot maps to, and rollback-relevant flags.
    """
    if bus is None or monitor is None:
        return {}

    context = context or {}

    # Read otadata base from monitor variables if available, else use defaults
    try:
        otadata_base = _as_int(monitor.GetVariable("otadata_base"))
    except Exception:
        otadata_base = _DEFAULT_OTADATA_BASE

    try:
        otadata_sector_size = _as_int(monitor.GetVariable("otadata_sector_size"))
    except Exception:
        otadata_sector_size = _DEFAULT_OTADATA_SECTOR_SIZE

    try:
        num_slots = _as_int(monitor.GetVariable("num_ota_slots"))
    except Exception:
        num_slots = _DEFAULT_NUM_SLOTS

    # Probe both otadata entries
    entry0 = _probe_otadata_entry(bus, otadata_base)
    entry1 = _probe_otadata_entry(bus, otadata_base + otadata_sector_size)

    entries = [entry0, entry1]
    active_idx = _select_active(entries)

    # Derive slot mapping
    if active_idx >= 0:
        active_entry = entries[active_idx]
        target_slot_idx = _seq_to_slot(active_entry["ota_seq"], num_slots)
        target_slot = "exec" if target_slot_idx == 0 else "staging"
        active_seq = active_entry["ota_seq"]
        active_state = active_entry["ota_state"]
    else:
        target_slot = None
        active_seq = None
        active_state = None

    # Detect rollback-relevant conditions
    has_pending_verify = any(
        e["ota_state"] == "pending_verify" and not e["erased"]
        for e in entries
    )
    has_valid_fallback = any(
        e["selectable"] and e["ota_state"] == "valid"
        for e in entries
    )
    both_erased = all(e["erased"] for e in entries)

    return {
        "target": "esp_idf",
        "stage": context.get("stage"),
        "boot_slot": context.get("boot_slot"),
        "fault_injected": bool(context.get("fault_injected", False)),
        "entries": {
            "sector0": entry0,
            "sector1": entry1,
        },
        "active_entry": active_idx,
        "active_seq": active_seq,
        "active_state": active_state,
        "target_slot": target_slot,
        # Expose replica-level validity for the built-in
        # metadata_single_fault_consistency invariant
        "replica0_valid": entry0["selectable"],
        "replica1_valid": entry1["selectable"],
        "replica0_seq": entry0["ota_seq"],
        "replica1_seq": entry1["ota_seq"],
        "flags": {
            "has_pending_verify": has_pending_verify,
            "has_valid_fallback": has_valid_fallback,
            "both_erased": both_erased,
            "both_selectable": entry0["selectable"] and entry1["selectable"],
            "neither_selectable": not entry0["selectable"] and not entry1["selectable"],
            "crc_mismatch_any": (
                (not entry0["erased"] and not entry0["crc_valid"])
                or (not entry1["erased"] and not entry1["crc_valid"])
            ),
        },
    }
