#!/usr/bin/env python3
"""rustBoot-specific invariants for tardigrade fault-injection testing.

These invariants validate safety properties of the rustBoot swap-scratch
OTA update algorithm. They consume the structured state produced by
targets/rustboot/probe.py.

rustBoot uses a 3-partition layout (BOOT, UPDATE, SWAP) with per-sector
swap flags packed as 4-bit nibbles and a state machine driven by a single
state byte per partition.

Known bugs targeted:
  #77 - Interrupted swap leaves device bricked (no valid BOOT image)
  #79 - Corrupted boot image runs without validation
  #80 - Damaged update image bricks during swap

Reference: rustBoot (MIT license)
This is a clean-room analysis, not rustBoot code.
"""

from invariants import InvariantViolation


# Flag nibble ordering for monotonicity
_FLAG_ORDER = {0x0F: 0, 0x07: 1, 0x03: 2, 0x00: 3}


def _root(result):
    state = result.nvm_state or {}
    return state if isinstance(state, dict) else {}


def _partition(root, name):
    part = root.get(name, {})
    return part if isinstance(part, dict) else {}


def _flags(root):
    flags = root.get("flags", {})
    return flags if isinstance(flags, dict) else {}


def check_rustboot_boot_not_empty(result, **_):
    """BOOT partition must have valid magic after recovery boot.

    rustBoot's swap-scratch algorithm copies sectors between BOOT, UPDATE,
    and SWAP partitions. If a power loss interrupts the swap mid-way and
    the bootloader cannot resume, the BOOT partition may be left without
    valid firmware -- the magic "BOOT" (0x544F4F42) is missing or the
    partition state indicates no bootable image.

    This catches bug #77: an interrupted swap sequence that leaves BOOT
    in a state where no firmware can be loaded on the next boot.
    """
    if getattr(result, "boot_outcome", None) == "success":
        # Boot succeeded, so BOOT partition was clearly usable.
        return

    root = _root(result)
    boot = _partition(root, "boot")

    if not boot:
        return

    magic_valid = boot.get("magic_valid", True)
    state = boot.get("state")

    # If magic is missing entirely, BOOT is empty/corrupted.
    if not magic_valid:
        raise InvariantViolation(
            invariant_name="rustboot_boot_not_empty",
            description=(
                "BOOT partition magic is invalid after fault recovery. "
                "Magic={}. The swap was interrupted and the bootloader "
                "could not restore a valid image to BOOT.".format(
                    boot.get("magic")
                )
            ),
            result=result,
            details={
                "boot_magic": boot.get("magic"),
                "boot_state": state,
                "boot_outcome": getattr(result, "boot_outcome", None),
                "fault_at": getattr(result, "fault_at", None),
            },
        )


def check_rustboot_swap_flags_consistent(result, **_):
    """Sector swap flags must be monotonic -- no flag regression.

    During a swap, sectors progress through states in order:
    New (0x0F) -> Swapping (0x07) -> Backup (0x03) -> Updated (0x00).

    Sector flags are written sequentially: sector 0 first, then sector 1,
    etc. After an interrupted swap resumes, all sectors up to some index K
    should be at a later state than sectors after K. A regression (sector N
    at Updated but sector N+1 at New with sector N+2 at Swapping) indicates
    a corrupted flag write or an incorrect swap resume that re-processed
    sectors out of order.

    This catches corruption from the packed nibble storage: two sector
    flags share a byte, and a partial byte write can corrupt the neighbor.
    """
    root = _root(result)
    flags = _flags(root)

    if not flags:
        return

    violations = []
    for part_name in ("boot", "update"):
        key = "{}_flags_monotonic".format(part_name)
        if flags.get(key) is False:
            part = _partition(root, part_name)
            sector_flags = part.get("sector_flags", [])
            # Find the specific regression point
            regression_desc = _find_regression(sector_flags)
            violations.append((part_name, regression_desc))

    if not violations:
        return

    parts = ", ".join(v[0] for v in violations)
    details_list = "; ".join(
        "{}: {}".format(v[0], v[1]) for v in violations
    )

    raise InvariantViolation(
        invariant_name="rustboot_swap_flags_consistent",
        description=(
            "Sector swap flags are not monotonic in partition(s): {}. "
            "{}. This indicates a corrupted flag write or incorrect "
            "swap resume logic.".format(parts, details_list)
        ),
        result=result,
        details={
            "violating_partitions": [v[0] for v in violations],
            "fault_at": getattr(result, "fault_at", None),
        },
    )


def _find_regression(sector_flags):
    """Find where monotonicity breaks in sector flag list."""
    if not sector_flags:
        return "empty flags"
    max_order = -1
    for flag in sector_flags:
        nibble = flag.get("nibble", 0x0F)
        order = _FLAG_ORDER.get(nibble, -1)
        if order < 0:
            return "sector {} has unknown flag 0x{:01X}".format(
                flag.get("sector", "?"), nibble
            )
        if order < max_order:
            return "sector {} regressed to {} after a more-progressed sector".format(
                flag.get("sector", "?"), flag.get("state", "?")
            )
        max_order = order
    return "no regression found"


def check_rustboot_testing_has_rollback_path(result, **_):
    """If BOOT is in Testing state, UPDATE must be in Updating state.

    rustBoot's state machine: when a new image is swapped into BOOT, BOOT
    is marked Testing (0x10) and UPDATE is marked Updating (0x70). If the
    new image fails to confirm (mark Success), the bootloader should roll
    back by swapping again.

    If BOOT is Testing but UPDATE is NOT Updating, the rollback path is
    broken: the bootloader has no record that a swap occurred and cannot
    restore the previous firmware. This catches bug #79's precondition:
    a corrupted state byte that puts BOOT in Testing without the
    corresponding UPDATE state.
    """
    root = _root(result)
    boot = _partition(root, "boot")
    update = _partition(root, "update")

    if not boot or not update:
        return

    boot_state = boot.get("state")
    update_state = update.get("state")

    if boot_state != "testing":
        return

    if update_state == "updating":
        return

    raise InvariantViolation(
        invariant_name="rustboot_testing_has_rollback_path",
        description=(
            "BOOT partition is in Testing state but UPDATE is '{}' "
            "(expected Updating). Without UPDATE in Updating state, "
            "the bootloader cannot roll back to the previous firmware "
            "if the new image fails to confirm.".format(update_state)
        ),
        result=result,
        details={
            "boot_state": boot_state,
            "boot_state_raw": boot.get("state_raw"),
            "update_state": update_state,
            "update_state_raw": update.get("state_raw"),
            "fault_at": getattr(result, "fault_at", None),
        },
    )


def check_rustboot_no_packed_flag_corruption(result, **_):
    """Adjacent nibbles in a packed flag byte must not corrupt each other.

    rustBoot packs two sector flags per byte (low nibble = even sector,
    high nibble = odd sector). A partial byte write during power loss can
    modify one nibble while corrupting its neighbor. This is especially
    dangerous because the corrupted nibble might become a valid but
    incorrect flag value, silently changing the swap progress for a sector
    that was not being updated.

    This invariant checks for nibble values that are not in the valid set
    {0x0F, 0x07, 0x03, 0x00}, which indicates cross-nibble corruption
    from a partial packed-byte write.
    """
    root = _root(result)

    corrupt_sectors = []
    for part_name in ("boot", "update"):
        part = _partition(root, part_name)
        sector_flags = part.get("sector_flags", [])
        for flag in sector_flags:
            nibble = flag.get("nibble", 0x0F)
            if nibble not in _FLAG_ORDER:
                corrupt_sectors.append({
                    "partition": part_name,
                    "sector": flag.get("sector"),
                    "nibble": nibble,
                    "nibble_hex": flag.get("nibble_hex"),
                })

    if not corrupt_sectors:
        return

    desc_parts = []
    for cs in corrupt_sectors:
        desc_parts.append(
            "{}[sector {}]={}".format(
                cs["partition"], cs["sector"], cs["nibble_hex"]
            )
        )

    raise InvariantViolation(
        invariant_name="rustboot_no_packed_flag_corruption",
        description=(
            "Sector flags contain invalid nibble values indicating "
            "packed-byte corruption: {}. Valid nibbles are 0x0F (New), "
            "0x07 (Swapping), 0x03 (Backup), 0x00 (Updated). A partial "
            "byte write corrupted the adjacent nibble.".format(
                ", ".join(desc_parts)
            )
        ),
        result=result,
        details={
            "corrupt_sectors": corrupt_sectors,
            "fault_at": getattr(result, "fault_at", None),
        },
    )


INVARIANTS = {
    "rustboot_boot_not_empty": check_rustboot_boot_not_empty,
    "rustboot_swap_flags_consistent": check_rustboot_swap_flags_consistent,
    "rustboot_testing_has_rollback_path": check_rustboot_testing_has_rollback_path,
    "rustboot_no_packed_flag_corruption": check_rustboot_no_packed_flag_corruption,
}
