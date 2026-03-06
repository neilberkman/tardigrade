#!/usr/bin/env python3
"""MCUboot-specific invariants for tardigrade replay and audit runs."""

from __future__ import annotations

from typing import Any, Dict

from invariants import InvariantViolation


def _semantic_slot(result: Any, slot_name: str) -> Dict[str, Any]:
    state = result.nvm_state or {}
    if not isinstance(state, dict):
        return {}
    slots = state.get("slots", {})
    if not isinstance(slots, dict):
        return {}
    slot = slots.get(slot_name, {})
    return slot if isinstance(slot, dict) else {}


def check_mcuboot_no_partial_magic(result: Any, **_: Any) -> None:
    exec_slot = _semantic_slot(result, "exec")
    staging_slot = _semantic_slot(result, "staging")
    partial_slots = []
    if exec_slot.get("magic_state") == "partial":
        partial_slots.append("exec")
    if staging_slot.get("magic_state") == "partial":
        partial_slots.append("staging")
    if not partial_slots:
        return
    raise InvariantViolation(
        invariant_name="mcuboot_no_partial_magic",
        description=(
            "MCUboot trailer magic remained partially written in slot(s): {}.".format(
                ", ".join(partial_slots)
            )
        ),
        result=result,
        details={
            "partial_slots": partial_slots,
            "exec_magic_state": exec_slot.get("magic_state"),
            "staging_magic_state": staging_slot.get("magic_state"),
        },
    )


INVARIANTS = {
    "mcuboot_no_partial_magic": check_mcuboot_no_partial_magic,
}
