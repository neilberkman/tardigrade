#!/usr/bin/env python3
"""NuttX nxboot invariants for tardigrade replay and audit runs."""

from invariants import InvariantViolation


def _semantic_root(result):
    state = result.nvm_state or {}
    return state if isinstance(state, dict) else {}


def _slot(root, slot_name):
    slots = root.get("slots", {})
    if not isinstance(slots, dict):
        return {}
    value = slots.get(slot_name, {})
    return value if isinstance(value, dict) else {}


def _roles(root):
    roles = root.get("roles", {})
    return roles if isinstance(roles, dict) else {}


def _flags(root):
    flags = root.get("flags", {})
    return flags if isinstance(flags, dict) else {}


def check_nuttx_nxboot_roles_distinct(result, **_):
    root = _semantic_root(result)
    roles = _roles(root)
    update_slot = roles.get("update_slot")
    recovery_slot = roles.get("recovery_slot")
    if not update_slot or not recovery_slot or update_slot != recovery_slot:
        return
    raise InvariantViolation(
        invariant_name="nuttx_nxboot_roles_distinct",
        description="NuttX nxboot update and recovery roles collapsed onto the same slot.",
        result=result,
        details={"update_slot": update_slot, "recovery_slot": recovery_slot},
    )


def check_nuttx_nxboot_confirmed_has_recovery(result, **_):
    root = _semantic_root(result)
    roles = _roles(root)
    primary = _slot(root, "primary")
    if primary.get("magic_kind") != "internal" or not roles.get("primary_confirmed"):
        return
    if roles.get("recovery_valid") and roles.get("recovery_present"):
        return
    raise InvariantViolation(
        invariant_name="nuttx_nxboot_confirmed_has_recovery",
        description=(
            "Internal primary image was treated as confirmed without a matching valid recovery image."
        ),
        result=result,
        details={
            "primary_magic_kind": primary.get("magic_kind"),
            "primary_confirmed": roles.get("primary_confirmed"),
            "recovery_valid": roles.get("recovery_valid"),
            "recovery_present": roles.get("recovery_present"),
        },
    )


def check_nuttx_nxboot_duplicate_update_consumed(result, **_):
    root = _semantic_root(result)
    roles = _roles(root)
    flags = _flags(root)
    update = _slot(root, roles.get("update_slot", ""))
    if not (
        roles.get("primary_valid")
        and flags.get("same_primary_update_crc")
        and update.get("magic_kind") == "external"
        and update.get("crc_valid")
    ):
        return
    if roles.get("next_boot") == "none":
        return
    raise InvariantViolation(
        invariant_name="nuttx_nxboot_duplicate_update_consumed",
        description=(
            "Duplicate nxboot update remained actionable instead of being consumed."
        ),
        result=result,
        details={
            "next_boot": roles.get("next_boot"),
            "update_slot": roles.get("update_slot"),
        },
    )


INVARIANTS = {
    "nuttx_nxboot_roles_distinct": check_nuttx_nxboot_roles_distinct,
    "nuttx_nxboot_confirmed_has_recovery": check_nuttx_nxboot_confirmed_has_recovery,
    "nuttx_nxboot_duplicate_update_consumed": check_nuttx_nxboot_duplicate_update_consumed,
}
