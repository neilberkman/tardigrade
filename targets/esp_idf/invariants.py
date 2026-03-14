#!/usr/bin/env python3
"""ESP-IDF-specific invariants for tardigrade fault-injection testing.

These invariants validate the safety properties of the ESP-IDF otadata
dual-sector OTA slot selection algorithm.  They consume the structured
state produced by targets/esp_idf/probe.py.

Reference: ESP-IDF bootloader_utility.c (Apache 2.0)
This is a clean-room analysis, not ESP-IDF code.
"""

from invariants import InvariantViolation


def _root(result):
    state = result.nvm_state or {}
    return state if isinstance(state, dict) else {}


def _entries(root):
    entries = root.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def _flags(root):
    flags = root.get("flags", {})
    return flags if isinstance(flags, dict) else {}


def check_esp_idf_otadata_crc_integrity(result, **_):
    """After a fault, at least one otadata entry must have a valid CRC.

    The dual-sector design ensures that a single fault during an otadata
    rewrite cannot corrupt both entries simultaneously.  If both entries
    have CRC mismatches (and neither is erased), the bootloader cannot
    determine which slot to boot -- indicating a sequencing bug where
    both sectors were in a writable state at the same time.
    """
    if getattr(result, "is_control", False):
        return

    root = _root(result)
    entries = _entries(root)
    sector0 = entries.get("sector0", {})
    sector1 = entries.get("sector1", {})

    if not isinstance(sector0, dict) or not isinstance(sector1, dict):
        return

    # Skip if either entry is erased (erased = no data to validate)
    if sector0.get("erased") or sector1.get("erased"):
        return

    # Both entries have data -- at least one must have valid CRC
    s0_crc_ok = sector0.get("crc_valid", True)
    s1_crc_ok = sector1.get("crc_valid", True)

    if not s0_crc_ok and not s1_crc_ok:
        raise InvariantViolation(
            invariant_name="esp_idf_otadata_crc_integrity",
            description=(
                "Both otadata sectors have CRC mismatches after a single fault. "
                "Sector 0: seq={}, crc_stored={}, crc_expected={}. "
                "Sector 1: seq={}, crc_stored={}, crc_expected={}. "
                "The dual-sector design should prevent simultaneous corruption.".format(
                    sector0.get("ota_seq_hex"),
                    sector0.get("crc_stored"),
                    sector0.get("crc_expected"),
                    sector1.get("ota_seq_hex"),
                    sector1.get("crc_stored"),
                    sector1.get("crc_expected"),
                )
            ),
            result=result,
            details={
                "sector0_seq": sector0.get("ota_seq"),
                "sector0_crc_stored": sector0.get("crc_stored"),
                "sector0_crc_expected": sector0.get("crc_expected"),
                "sector1_seq": sector1.get("ota_seq"),
                "sector1_crc_stored": sector1.get("crc_stored"),
                "sector1_crc_expected": sector1.get("crc_expected"),
                "fault_at": getattr(result, "fault_at", None),
            },
        )


def check_esp_idf_pending_verify_gets_aborted(result, **_):
    """A PENDING_VERIFY entry should not survive a reboot without confirmation.

    In ESP-IDF, the bootloader ABORTs any PENDING_VERIFY entry before slot
    selection.  If an entry is still PENDING_VERIFY after the recovery boot
    completed, the abort logic was skipped or corrupted by the fault.  This
    would cause the unconfirmed image to be selected again on the next boot
    instead of rolling back.

    Only checked when the device booted successfully (if it bricked, the
    state is moot).
    """
    if getattr(result, "boot_outcome", None) != "success":
        return

    root = _root(result)
    entries = _entries(root)

    pending_sectors = []
    for sector_name in ("sector0", "sector1"):
        sector = entries.get(sector_name, {})
        if not isinstance(sector, dict):
            continue
        if sector.get("ota_state") == "pending_verify" and not sector.get("erased"):
            pending_sectors.append(sector_name)

    if not pending_sectors:
        return

    raise InvariantViolation(
        invariant_name="esp_idf_pending_verify_gets_aborted",
        description=(
            "otadata entry in {} still has state PENDING_VERIFY after recovery "
            "boot completed. The bootloader should have ABORTed it before "
            "slot selection. An unconfirmed image may be re-selected on "
            "subsequent boots instead of rolling back.".format(
                ", ".join(pending_sectors)
            )
        ),
        result=result,
        details={
            "pending_sectors": pending_sectors,
            "boot_outcome": getattr(result, "boot_outcome", None),
            "fault_at": getattr(result, "fault_at", None),
        },
    )


def check_esp_idf_active_entry_maps_to_valid_slot(result, **_):
    """The active otadata entry must map to a slot with valid ARM vectors.

    After recovery boot, if the device booted successfully, the active
    otadata entry's ota_seq should map to the slot that was actually booted.
    A mismatch indicates the bootloader's fallback path was needed --
    acceptable for resilience, but if the active entry maps to a slot
    whose vectors are corrupted AND the bootloader doesn't have fallback
    logic, this is a brick.

    This invariant checks that when boot succeeded, the active entry's
    target slot is consistent with the boot outcome.  If neither entry
    is selectable but the device still booted, the bootloader used its
    exhaustive fallback sweep (expected behavior for the correct
    implementation).
    """
    if getattr(result, "boot_outcome", None) != "success":
        return

    root = _root(result)
    flags = _flags(root)
    target_slot = root.get("target_slot")

    # If neither entry is selectable, the bootloader must have used
    # exhaustive fallback -- that's acceptable
    if flags.get("neither_selectable"):
        return

    # If we have a target slot and a boot slot, check consistency
    boot_slot = root.get("boot_slot") or getattr(result, "boot_slot", None)
    if target_slot is None or boot_slot is None:
        return

    # Normalize boot_slot: numeric 0/1 -> "exec"/"staging"
    boot_slot_str = str(boot_slot)
    if boot_slot_str == "0":
        boot_slot_str = "exec"
    elif boot_slot_str == "1":
        boot_slot_str = "staging"

    if target_slot != boot_slot_str:
        # Mismatch is not necessarily a violation -- the bootloader may
        # have fallen back because the target slot's image was corrupt.
        # But we flag it as informational state for downstream analysis.
        # Only raise if the device booted but the metadata disagrees
        # AND both entries are selectable (meaning fallback wasn't needed).
        if flags.get("both_selectable"):
            raise InvariantViolation(
                invariant_name="esp_idf_active_entry_maps_to_valid_slot",
                description=(
                    "Both otadata entries are selectable, active entry maps to "
                    "slot '{}' (ota_seq={}), but device booted from slot '{}'. "
                    "The slot selection algorithm may have a bug.".format(
                        target_slot,
                        root.get("active_seq"),
                        boot_slot_str,
                    )
                ),
                result=result,
                details={
                    "target_slot": target_slot,
                    "boot_slot": boot_slot_str,
                    "active_entry": root.get("active_entry"),
                    "active_seq": root.get("active_seq"),
                    "active_state": root.get("active_state"),
                    "fault_at": getattr(result, "fault_at", None),
                },
            )


def check_esp_idf_seq_not_zero(result, **_):
    """A non-erased otadata entry must never have ota_seq == 0.

    ESP-IDF uses 1-based sequence numbers. ota_seq=0 is not a valid value
    and would cause (0 - 1) % 2 = 1 in the slot mapping, silently
    selecting the wrong slot. A fault that zeroes ota_seq without
    invalidating the CRC could cause this.

    Only checked for entries that pass CRC validation (otherwise the
    bootloader would already reject them).
    """
    root = _root(result)
    entries = _entries(root)

    zero_seq_sectors = []
    for sector_name in ("sector0", "sector1"):
        sector = entries.get(sector_name, {})
        if not isinstance(sector, dict):
            continue
        if sector.get("erased"):
            continue
        if sector.get("crc_valid") and sector.get("ota_seq") == 0:
            zero_seq_sectors.append(sector_name)

    if not zero_seq_sectors:
        return

    raise InvariantViolation(
        invariant_name="esp_idf_seq_not_zero",
        description=(
            "otadata entry in {} has ota_seq=0 with valid CRC. "
            "ESP-IDF uses 1-based sequence numbers; ota_seq=0 would map to "
            "slot index (0-1) %% 2 = 1, silently selecting the wrong slot.".format(
                ", ".join(zero_seq_sectors)
            )
        ),
        result=result,
        details={
            "zero_seq_sectors": zero_seq_sectors,
            "fault_at": getattr(result, "fault_at", None),
        },
    )


INVARIANTS = {
    "esp_idf_otadata_crc_integrity": check_esp_idf_otadata_crc_integrity,
    "esp_idf_pending_verify_gets_aborted": check_esp_idf_pending_verify_gets_aborted,
    "esp_idf_active_entry_maps_to_valid_slot": check_esp_idf_active_entry_maps_to_valid_slot,
    "esp_idf_seq_not_zero": check_esp_idf_seq_not_zero,
}
