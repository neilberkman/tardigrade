#!/usr/bin/env python3
"""rustBoot state probe for tardigrade semantic-state collection.

Reads the BOOT and UPDATE partition trailers, plus SWAP partition
occupancy, and produces structured state describing:

- Per-partition state byte and magic validity
- Per-sector swap progress flags (packed as 4-bit nibbles)
- SWAP partition occupancy (non-erased content)

rustBoot trailer layout (at end of BOOT and UPDATE partitions):

  offset from partition end:
    -4   magic: "BOOT" = 0x544F4F42 (little-endian)
    -5   state byte:
           0xFF = New
           0x70 = Updating
           0x10 = Testing
           0x00 = Success
    -5-N per-sector flags (packed, 2 nibbles per byte, low nibble first):
           0x0F = New
           0x07 = Swapping
           0x03 = Backup
           0x00 = Updated

The SWAP partition has no trailer -- it is scratch space for sector-level
swap operations. Occupancy is inferred from non-0xFF content.

Reference: rustBoot (MIT license)
This is a clean-room reimplementation, not rustBoot code.
"""

import struct


# State byte values
_STATE_NAMES = {
    0xFF: "new",
    0x70: "updating",
    0x10: "testing",
    0x00: "success",
}

# Per-sector flag nibble values
_FLAG_NAMES = {
    0x0F: "new",
    0x07: "swapping",
    0x03: "backup",
    0x00: "updated",
}

# Magic value: ASCII "BOOT" as little-endian uint32
RUSTBOOT_MAGIC = 0x544F4F42

# Flag nibble ordering for monotonicity checks
_FLAG_ORDER = {0x0F: 0, 0x07: 1, 0x03: 2, 0x00: 3}

# Default reference partition layout for an nRF52840 rustBoot integration.
# These defaults match the public assets under results/oss_validation/assets/.
_DEFAULT_BOOT_BASE = 0x0002F000
_DEFAULT_BOOT_SIZE = 0x00028000    # 160KB
_DEFAULT_UPDATE_BASE = 0x00058000
_DEFAULT_UPDATE_SIZE = 0x00028000  # 160KB
_DEFAULT_SWAP_BASE = 0x00057000
_DEFAULT_SWAP_SIZE = 0x00001000    # 4KB (one sector)
_DEFAULT_SECTOR_SIZE = 0x00001000  # 4KB


def _as_int(value, default=0):
    try:
        return int(str(value), 0)
    except Exception:
        return int(default)


def _get_monitor_var(monitor, name, default=None):
    """Safely read a Renode monitor variable, returning default on failure."""
    try:
        value = monitor.GetVariable(name)
    except Exception:
        return default
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        return default
    return _as_int(value, default)


def _read_bytes(bus, addr, size):
    size = int(size)
    addr = int(addr)
    raw = bus.ReadBytes(addr, size)
    return bytearray(int(b) & 0xFF for b in raw)


def _read_u32(bus, addr):
    return struct.unpack("<I", _read_bytes(bus, addr, 4))[0]


def _state_name(state_val):
    return _STATE_NAMES.get(state_val, "unknown_0x{:02X}".format(state_val))


def _flag_name(nibble):
    return _FLAG_NAMES.get(nibble, "unknown_0x{:01X}".format(nibble))


def _probe_partition_trailer(bus, part_base, part_size, sector_size):
    """Read and validate a rustBoot partition trailer.

    Returns a dict with magic validity, state byte, and per-sector flags.
    """
    part_end = part_base + part_size

    # Read magic at offset -4 from partition end
    magic_addr = part_end - 4
    magic = _read_u32(bus, magic_addr)
    magic_valid = (magic == RUSTBOOT_MAGIC)

    # Read state byte at offset -5
    state_addr = part_end - 5
    state_raw = _read_bytes(bus, state_addr, 1)[0]
    state = _state_name(state_raw)

    # Read per-sector flags: one nibble per sector, packed 2 per byte,
    # low nibble = even-indexed sector, high nibble = odd-indexed sector.
    # Flags occupy bytes from offset -(5 + flag_bytes) to offset -5.
    num_sectors = part_size // sector_size
    flag_bytes_count = (num_sectors + 1) // 2  # ceil(num_sectors / 2)

    flags_start_addr = part_end - 5 - flag_bytes_count
    flag_data = _read_bytes(bus, flags_start_addr, flag_bytes_count)

    sector_flags = []
    for i in range(num_sectors):
        byte_idx = i // 2
        if byte_idx < len(flag_data):
            raw_byte = flag_data[byte_idx]
            if i % 2 == 0:
                nibble = raw_byte & 0x0F
            else:
                nibble = (raw_byte >> 4) & 0x0F
        else:
            nibble = 0x0F  # default to New if out of range
        sector_flags.append({
            "sector": i,
            "nibble": nibble,
            "nibble_hex": "0x{:01X}".format(nibble),
            "state": _flag_name(nibble),
        })

    return {
        "base": "0x{:08X}".format(part_base),
        "size": "0x{:08X}".format(part_size),
        "magic": "0x{:08X}".format(magic),
        "magic_valid": magic_valid,
        "state_raw": state_raw,
        "state_hex": "0x{:02X}".format(state_raw),
        "state": state,
        "num_sectors": num_sectors,
        "sector_flags": sector_flags,
    }


def _probe_swap(bus, swap_base, swap_size):
    """Check whether the SWAP partition has non-erased content.

    Samples the first 64 bytes and the last 64 bytes. If all are 0xFF,
    the swap area is considered empty.
    """
    sample_size = min(64, swap_size)
    head = _read_bytes(bus, swap_base, sample_size)
    tail = _read_bytes(bus, swap_base + swap_size - sample_size, sample_size)

    head_erased = all(b == 0xFF for b in head)
    tail_erased = all(b == 0xFF for b in tail)
    occupied = not (head_erased and tail_erased)

    return {
        "base": "0x{:08X}".format(swap_base),
        "size": "0x{:08X}".format(swap_size),
        "occupied": occupied,
    }


def _flags_monotonic(sector_flags):
    """Check that sector flags are monotonic (no flag regression).

    During a swap, sector flags should progress: New -> Swapping -> Backup
    -> Updated. A regression (e.g., sector N is Updated but sector N+1 is
    Backup with sector N+2 back to Swapping) indicates a corrupted flag
    write that repeated or reverted a state transition.

    Returns True if flags are monotonic (ordered from most-progressed to
    least-progressed or all the same).
    """
    if not sector_flags:
        return True

    # Sectors are swapped in order: sector 0 first, then 1, etc.
    # So earlier sectors should be MORE progressed (higher order value)
    # than later sectors. Flags must be non-increasing.
    min_order_seen = 999
    for flag in sector_flags:
        nibble = flag.get("nibble", 0x0F)
        order = _FLAG_ORDER.get(nibble, -1)
        if order < 0:
            # Unknown flag value -- not monotonic
            return False
        if order > min_order_seen:
            return False
        min_order_seen = order
    return True


def collect_state(bus=None, monitor=None, context=None):
    """Collect rustBoot semantic state from emulated memory.

    Returns a structured dict describing BOOT and UPDATE partition trailers,
    SWAP occupancy, and derived safety flags.
    """
    if bus is None or monitor is None:
        return {}

    context = context or {}

    # Read partition layout from monitor variables, with defaults
    boot_base = _get_monitor_var(monitor, "rustboot_boot_base", _DEFAULT_BOOT_BASE)
    boot_size = _get_monitor_var(monitor, "rustboot_boot_size", _DEFAULT_BOOT_SIZE)
    update_base = _get_monitor_var(monitor, "rustboot_update_base", _DEFAULT_UPDATE_BASE)
    update_size = _get_monitor_var(monitor, "rustboot_update_size", _DEFAULT_UPDATE_SIZE)
    swap_base = _get_monitor_var(monitor, "rustboot_swap_base", _DEFAULT_SWAP_BASE)
    swap_size = _get_monitor_var(monitor, "rustboot_swap_size", _DEFAULT_SWAP_SIZE)
    sector_size = _get_monitor_var(monitor, "rustboot_sector_size", _DEFAULT_SECTOR_SIZE)

    # Probe partitions
    boot = _probe_partition_trailer(bus, boot_base, boot_size, sector_size)
    update = _probe_partition_trailer(bus, update_base, update_size, sector_size)
    swap = _probe_swap(bus, swap_base, swap_size)

    # Derive safety-relevant flags
    boot_flags_monotonic = _flags_monotonic(boot["sector_flags"])
    update_flags_monotonic = _flags_monotonic(update["sector_flags"])

    # Check if any adjacent nibbles in packed bytes show corruption
    # (one nibble modified while its neighbor was not properly preserved)
    packed_corruption = False
    for part in (boot, update):
        for flag in part["sector_flags"]:
            nibble = flag.get("nibble", 0x0F)
            if nibble not in _FLAG_ORDER:
                packed_corruption = True
                break

    return {
        "target": "rustboot",
        "stage": context.get("stage"),
        "boot_slot": context.get("boot_slot"),
        "fault_injected": bool(context.get("fault_injected", False)),
        "boot": boot,
        "update": update,
        "swap": swap,
        "sector_size": sector_size,
        "flags": {
            "boot_magic_valid": boot["magic_valid"],
            "update_magic_valid": update["magic_valid"],
            "boot_flags_monotonic": boot_flags_monotonic,
            "update_flags_monotonic": update_flags_monotonic,
            "swap_occupied": swap["occupied"],
            "packed_flag_corruption": packed_corruption,
            "boot_has_firmware": boot["magic_valid"] and boot["state"] != "new",
            "update_has_firmware": update["magic_valid"] and update["state"] != "new",
        },
    }
