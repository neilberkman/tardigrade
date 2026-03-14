#!/usr/bin/env python3
"""TF-M BL2 state probe for tardigrade semantic-state collection.

TF-M BL2 is ARM's Trusted Firmware-M second-stage bootloader, which wraps
MCUboot with ARM-specific extensions for TrustZone-enabled Cortex-M devices.

Key differences from vanilla MCUboot that this probe must handle:

1. Multi-image boot: TF-M manages separate secure (SPE) and non-secure (NSPE)
   images, each with their own slots and trailers. MCUBOOT_IMAGE_NUMBER=2
   means 4 slots total (2 primary + 2 secondary).

2. Single-image boot: SPE+NSPE concatenated and signed as one blob. This mode
   is structurally identical to vanilla MCUboot (2 slots).

3. Fault Injection Hardening (FIH): TF-M adds software countermeasures
   (control flow integrity, complex constants, redundant checks, random
   delays) that affect the boot path but not the trailer format.

4. SAU/MPC configuration: The bootloader configures Security Attribution Unit
   and Memory Protection Controller before jumping to the secure image. A
   fault during this window could leave the NS world with access to secure
   memory.

The trailer format is standard MCUboot (magic + image_ok + copy_done at the
end of each slot), but there are potentially 4 slots to probe instead of 2.
"""

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


def _read_u32(bus, addr):
    return struct.unpack("<I", _read_bytes(bus, addr, 4))[0]


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
    """Probe a single MCUboot slot trailer for magic, image_ok, copy_done."""
    slot_end = base + size
    magic_addr = slot_end - 16
    image_ok_addr = slot_end - 16 - align
    copy_done_addr = slot_end - 16 - (2 * align)
    magic = _read_bytes(bus, magic_addr, 16)
    return {
        "base": "0x{:08X}".format(base),
        "size": "0x{:08X}".format(size),
        "magic_state": _magic_state(magic),
        "image_ok": _read_flag(bus, image_ok_addr),
        "copy_done": _read_flag(bus, copy_done_addr),
    }


def _get_monitor_var(monitor, name, default=None):
    """Safely read a Renode monitor variable, returning default on failure."""
    try:
        return _as_int(monitor.GetVariable(name))
    except Exception:
        return default


# TODO: Read SAU region configuration registers.
# On Cortex-M33, SAU_RNR (0xE000EDD8), SAU_RBAR (0xE000EDDC),
# SAU_RLAR (0xE000EDE0) define secure/non-secure memory boundaries.
# After a fault, SAU misconfiguration could expose secure memory to NS world.
def _sau_probe(bus):
    """Probe SAU configuration registers. Returns SAU region info.

    TODO: Implement SAU register reads once Renode Cortex-M33 platform
    is available with SAU emulation support.
    """
    return {"status": "not_implemented"}


# TODO: Read MPC (Memory Protection Controller) status.
# MPC defines per-block secure/non-secure attribution for SRAM and flash.
# On AN521, MPC is at platform-specific addresses.
def _mpc_probe(bus):
    """Probe MPC block security attribution.

    TODO: Implement MPC register reads once platform-specific addresses
    are known for the target board.
    """
    return {"status": "not_implemented"}


def collect_state(bus=None, monitor=None, context=None):
    """Collect TF-M BL2 semantic state from emulated memory.

    Supports both single-image (2-slot) and multi-image (4-slot) TF-M
    configurations. In multi-image mode, slots are organized as:
      - secure_exec / secure_staging (SPE image pair)
      - ns_exec / ns_staging (NSPE image pair)

    In single-image mode, falls back to standard exec/staging layout.
    """
    if bus is None or monitor is None:
        return {}

    context = context or {}
    align = _as_int(
        _get_monitor_var(monitor, "mcuboot_trailer_align", 8) or 8,
    )
    if align <= 0:
        align = 8

    # Check for multi-image mode (MCUBOOT_IMAGE_NUMBER=2).
    # In multi-image mode, TF-M has separate slot pairs for S and NS images.
    s_exec_base = _get_monitor_var(monitor, "slot_s_exec_base")
    multi_image = s_exec_base is not None

    if multi_image:
        # Multi-image: 4 slots (secure primary/secondary + NS primary/secondary)
        s_exec_size = _get_monitor_var(monitor, "slot_s_exec_size", 0)
        s_staging_base = _get_monitor_var(monitor, "slot_s_staging_base", 0)
        s_staging_size = _get_monitor_var(monitor, "slot_s_staging_size", 0)
        ns_exec_base = _get_monitor_var(monitor, "slot_ns_exec_base", 0)
        ns_exec_size = _get_monitor_var(monitor, "slot_ns_exec_size", 0)
        ns_staging_base = _get_monitor_var(monitor, "slot_ns_staging_base", 0)
        ns_staging_size = _get_monitor_var(monitor, "slot_ns_staging_size", 0)

        slots = {
            "secure_exec": _slot_probe(bus, s_exec_base, s_exec_size, align),
            "secure_staging": _slot_probe(bus, s_staging_base, s_staging_size, align),
            "ns_exec": _slot_probe(bus, ns_exec_base, ns_exec_size, align),
            "ns_staging": _slot_probe(bus, ns_staging_base, ns_staging_size, align),
        }
        flags = {
            "multi_image": True,
            "any_partial_magic": any(
                s["magic_state"] == "partial" for s in slots.values()
            ),
            "secure_exec_good": slots["secure_exec"]["magic_state"] == "good",
            "ns_exec_good": slots["ns_exec"]["magic_state"] == "good",
        }
    else:
        # Single-image: standard 2-slot MCUboot layout
        exec_base = _as_int(_get_monitor_var(monitor, "slot_exec_base", 0))
        exec_size = _as_int(_get_monitor_var(monitor, "slot_exec_size", 0))
        staging_base = _as_int(_get_monitor_var(monitor, "slot_staging_base", 0))
        staging_size = _as_int(_get_monitor_var(monitor, "slot_staging_size", 0))

        slots = {
            "exec": _slot_probe(bus, exec_base, exec_size, align),
            "staging": _slot_probe(bus, staging_base, staging_size, align),
        }
        flags = {
            "multi_image": False,
            "any_partial_magic": any(
                s["magic_state"] == "partial" for s in slots.values()
            ),
            "both_good_magic": all(
                s["magic_state"] == "good" for s in slots.values()
            ),
        }

    # TODO: Add SAU/MPC probing once Renode Cortex-M33 TrustZone
    # emulation is confirmed working.
    # sau = _sau_probe(bus)
    # mpc = _mpc_probe(bus)

    return {
        "target": "tf_m_bl2",
        "stage": context.get("stage"),
        "boot_slot": context.get("boot_slot"),
        "fault_injected": bool(context.get("fault_injected", False)),
        "trailer_align": align,
        "slots": slots,
        "flags": flags,
        # "sau": sau,
        # "mpc": mpc,
    }
