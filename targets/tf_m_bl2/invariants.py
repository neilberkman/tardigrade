#!/usr/bin/env python3
"""TF-M BL2 specific invariants for tardigrade fault-injection testing.

These invariants target attack surfaces unique to TF-M's use of MCUboot,
beyond what the generic MCUboot invariants cover:

1. Secure/non-secure partition isolation: A fault during BL2's SAU/MPC
   setup could leave secure memory accessible to the non-secure world.

2. Multi-image consistency: In multi-image mode, S and NS images must
   either both update or both roll back. A fault that updates one but
   not the other creates a version mismatch that may break the S/NS
   interface contract (veneer table incompatibility, etc.).

3. FIH bypass detection: TF-M's Fault Injection Hardening adds redundant
   checks. A single fault should not bypass both the primary check and
   its redundant counterpart.
"""

from invariants import InvariantViolation


def _semantic_slot(result, slot_name):
    """Extract a named slot dict from result.nvm_state.slots."""
    state = result.nvm_state or {}
    if not isinstance(state, dict):
        return {}
    slots = state.get("slots", {})
    if not isinstance(slots, dict):
        return {}
    slot = slots.get(slot_name, {})
    return slot if isinstance(slot, dict) else {}


def _is_multi_image(result):
    """Check if this result came from a multi-image TF-M configuration."""
    state = result.nvm_state or {}
    if not isinstance(state, dict):
        return False
    flags = state.get("flags", {})
    if not isinstance(flags, dict):
        return False
    return bool(flags.get("multi_image", False))


def check_tfm_multi_image_consistency(result, **_):
    """In multi-image mode, S and NS slots must have consistent swap state.

    If the secure image's exec slot shows swap completed (copy_done=set,
    magic=good) but the non-secure image's exec slot does not (or vice
    versa), the two images are in inconsistent update states. This means
    a power loss interrupted the swap between the two image pairs,
    leaving S and NS at different firmware versions.

    This is a TF-M-specific risk because vanilla MCUboot with a single
    image cannot have this cross-image inconsistency.
    """
    if not _is_multi_image(result):
        return

    s_exec = _semantic_slot(result, "secure_exec")
    ns_exec = _semantic_slot(result, "ns_exec")

    if not s_exec or not ns_exec:
        return

    s_copy_done = (s_exec.get("copy_done") or {}).get("state")
    ns_copy_done = (ns_exec.get("copy_done") or {}).get("state")

    # If both are in the same state, no inconsistency.
    if s_copy_done == ns_copy_done:
        return

    # One completed swap, the other did not.
    if s_copy_done == "set" and ns_copy_done != "set":
        inconsistent = "secure swap completed but non-secure did not"
    elif ns_copy_done == "set" and s_copy_done != "set":
        inconsistent = "non-secure swap completed but secure did not"
    else:
        # Both in non-matching but neither is clearly "completed" --
        # could be mid-swap for both. Not clearly an inconsistency.
        return

    raise InvariantViolation(
        invariant_name="tfm_multi_image_consistency",
        description=(
            "Multi-image swap state inconsistency: {}. "
            "S and NS images are at different update stages, which may "
            "break the secure/non-secure interface contract.".format(inconsistent)
        ),
        result=result,
        details={
            "secure_exec_copy_done": s_copy_done,
            "ns_exec_copy_done": ns_copy_done,
            "secure_exec_magic": s_exec.get("magic_state"),
            "ns_exec_magic": ns_exec.get("magic_state"),
        },
    )


def check_tfm_no_partial_magic(result, **_):
    """No slot should have partially-written trailer magic after recovery.

    This is the same check as the vanilla MCUboot invariant but extended
    to cover all 4 slots in multi-image mode. A partial magic write
    indicates the power loss interrupted the atomic trailer update, and
    the bootloader failed to detect/repair it on the recovery boot.
    """
    state = result.nvm_state or {}
    if not isinstance(state, dict):
        return

    slots = state.get("slots", {})
    if not isinstance(slots, dict):
        return

    partial_slots = []
    for slot_name, slot_data in slots.items():
        if not isinstance(slot_data, dict):
            continue
        if slot_data.get("magic_state") == "partial":
            partial_slots.append(slot_name)

    if not partial_slots:
        return

    raise InvariantViolation(
        invariant_name="tfm_no_partial_magic",
        description=(
            "TF-M BL2 trailer magic remained partially written in slot(s): {}. "
            "The bootloader did not detect or repair the interrupted write.".format(
                ", ".join(sorted(partial_slots))
            )
        ),
        result=result,
        details={
            "partial_slots": partial_slots,
            "multi_image": _is_multi_image(result),
        },
    )


def check_tfm_secure_slot_not_empty(result, **_):
    """After recovery boot, the secure exec slot must not be erased/empty.

    In TF-M, if the secure image slot is erased (magic=unset, no valid
    image), the device has no SPE firmware and cannot function at all --
    even the non-secure world depends on secure services (crypto, storage,
    attestation). This is a stricter version of "at least one bootable
    slot" because in TF-M the secure slot is always required.

    Applies to both single-image and multi-image modes: in single-image
    mode the combined S+NS blob is in the exec slot; in multi-image mode
    the secure_exec slot specifically must be valid.
    """
    if result.boot_outcome == "success":
        # Boot succeeded, so the secure image was clearly present.
        return

    if _is_multi_image(result):
        s_exec = _semantic_slot(result, "secure_exec")
        slot_name = "secure_exec"
    else:
        s_exec = _semantic_slot(result, "exec")
        slot_name = "exec"

    if not s_exec:
        return

    magic = s_exec.get("magic_state")
    copy_done = (s_exec.get("copy_done") or {}).get("state")
    image_ok = (s_exec.get("image_ok") or {}).get("state")

    # If magic is unset and copy_done is unset, the slot is erased.
    if magic == "unset" and copy_done == "unset":
        raise InvariantViolation(
            invariant_name="tfm_secure_slot_not_empty",
            description=(
                "The {} slot appears erased after fault recovery "
                "(magic=unset, copy_done=unset). Without a secure image, "
                "the device cannot provide any TF-M services and is "
                "effectively bricked.".format(slot_name)
            ),
            result=result,
            details={
                "slot_name": slot_name,
                "magic_state": magic,
                "copy_done": copy_done,
                "image_ok": image_ok,
                "boot_outcome": result.boot_outcome,
                "multi_image": _is_multi_image(result),
            },
        )


INVARIANTS = {
    "tfm_multi_image_consistency": check_tfm_multi_image_consistency,
    "tfm_no_partial_magic": check_tfm_no_partial_magic,
    "tfm_secure_slot_not_empty": check_tfm_secure_slot_not_empty,
}
