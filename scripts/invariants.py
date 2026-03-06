"""Postcondition invariant framework for OTA fault-injection testing.

After each fault-injection run produces a FaultResult, invariant checks
validate that the firmware update protocol upheld its safety guarantees.
Violations indicate real bugs in the update logic — not expected bricks
from known-vulnerable code paths.

Usage from a campaign runner::

    from invariants import run_invariants, default_invariants

    violations = run_invariants(result, invariants=default_invariants("strict"),
                                pre_state=pre_state, write_log=write_log,
                                partition_ranges=ranges)
    if violations:
        for v in violations:
            print(f"VIOLATION: {v.invariant_name}: {v.description}")
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from fault_inject import FaultResult


# ---------------------------------------------------------------------------
# Violation type
# ---------------------------------------------------------------------------

class InvariantViolation(Exception):
    """Raised (or collected) when a postcondition invariant is violated.

    Attributes:
        invariant_name: Machine-readable name of the invariant that failed.
        description: Human-readable explanation of why it failed.
        result: The FaultResult under test.
        details: Arbitrary context dict for tooling / reports.
    """

    def __init__(
        self,
        invariant_name: str,
        description: str,
        result: FaultResult,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.invariant_name = invariant_name
        self.description = description
        self.result = result
        self.details = details or {}
        super().__init__(f"{invariant_name}: {description}")


# Type alias for an invariant check function.  Every check takes a
# FaultResult as its first positional argument and arbitrary keyword
# context (pre_state, write_log, partition_ranges, etc.).
InvariantFn = Callable[..., None]


# ---------------------------------------------------------------------------
# Individual invariant checks
# ---------------------------------------------------------------------------

def check_at_least_one_bootable(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """If the pre-fault state had at least one valid slot, the device must boot.

    A single fault should never brick *both* slots when one was not being
    written to.  If ``pre_state`` is ``None`` the check is skipped (we
    cannot reason about the precondition without it).
    """
    if pre_state is None:
        return

    # Determine whether the pre-state had at least one valid slot.
    # IMPORTANT: use slot_a_valid/slot_b_valid (vector table checks), NOT
    # replica0_valid/replica1_valid (metadata CRC checks). These are different:
    # a valid metadata replica does NOT mean the corresponding slot has valid vectors.
    pre_slot_a_valid = pre_state.get("slot_a_valid", False)
    pre_slot_b_valid = pre_state.get("slot_b_valid", False)

    if not (pre_slot_a_valid or pre_slot_b_valid):
        # Pre-state already had no valid slots — nothing to assert.
        return

    if result.boot_outcome != "success":
        raise InvariantViolation(
            invariant_name="at_least_one_bootable",
            description=(
                "Device failed to boot (outcome={!r}) after a single fault, "
                "but the pre-fault state had at least one valid slot "
                "(A={}, B={}).".format(
                    result.boot_outcome, pre_slot_a_valid, pre_slot_b_valid
                )
            ),
            result=result,
            details={
                "pre_slot_a_valid": pre_slot_a_valid,
                "pre_slot_b_valid": pre_slot_b_valid,
                "boot_outcome": result.boot_outcome,
                "fault_at": result.fault_at,
            },
        )


def check_boot_matches_metadata(result: FaultResult, **_: Any) -> None:
    """If metadata says active slot is X and both slots are valid, boot must go to X.

    Only applicable when ``nvm_state`` provides ``requested_slot`` and
    ``chosen_slot`` (or ``active_slot``) together with per-slot validity.
    """
    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    requested = nvm.get("requested_slot") or nvm.get("active_slot")
    chosen = nvm.get("chosen_slot")
    if requested is None or chosen is None:
        return

    slot_a_valid = nvm.get("replica0_valid", nvm.get("slot_a_valid"))
    slot_b_valid = nvm.get("replica1_valid", nvm.get("slot_b_valid"))

    # Only meaningful when both slots are valid — if one is corrupt the
    # bootloader is free to fall back.
    if not (slot_a_valid and slot_b_valid):
        return

    if result.boot_outcome != "success":
        # Boot failed entirely — check_at_least_one_bootable covers that.
        return

    if chosen != requested:
        raise InvariantViolation(
            invariant_name="boot_matches_metadata",
            description=(
                "Metadata requested slot {!r} but bootloader chose slot {!r} "
                "with both slots valid. This indicates a metadata-interpretation bug.".format(
                    requested, chosen
                )
            ),
            result=result,
            details={
                "requested_slot": requested,
                "chosen_slot": chosen,
                "slot_a_valid": slot_a_valid,
                "slot_b_valid": slot_b_valid,
            },
        )


def check_metadata_single_fault_consistency(result: FaultResult, **_: Any) -> None:
    """After a single fault at least one metadata replica must remain valid.

    If both replicas are invalid after one fault the update protocol has a
    sequencing bug — it wrote both replicas in a window where a single
    interruption could corrupt both.

    Only checked for non-control runs (control runs have no fault).
    """
    if result.is_control:
        return

    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    replica0_valid = nvm.get("replica0_valid")
    replica1_valid = nvm.get("replica1_valid")

    # Skip if the state dict doesn't carry replica validity.
    if replica0_valid is None or replica1_valid is None:
        return

    if not replica0_valid and not replica1_valid:
        raise InvariantViolation(
            invariant_name="metadata_single_fault_consistency",
            description=(
                "Both metadata replicas are invalid after a single fault "
                "(fault_at={}). The update protocol must never leave both "
                "replicas in a corruptible window simultaneously.".format(
                    result.fault_at
                )
            ),
            result=result,
            details={
                "replica0_valid": replica0_valid,
                "replica1_valid": replica1_valid,
                "replica0_seq": nvm.get("replica0_seq"),
                "replica1_seq": nvm.get("replica1_seq"),
                "fault_at": result.fault_at,
            },
        )


def check_no_oob_writes(
    result: FaultResult,
    write_log: Optional[List[int]] = None,
    partition_ranges: Optional[List[Tuple[int, int]]] = None,
    **_: Any,
) -> None:
    """Flag any NVM write outside the allowed partition ranges.

    Parameters:
        write_log: List of write addresses observed during the run.
        partition_ranges: List of ``(start_inclusive, end_exclusive)`` tuples
            defining valid write regions.

    Skipped when either argument is ``None``.
    """
    if write_log is None or partition_ranges is None:
        return

    if not partition_ranges:
        return

    oob_addresses: List[int] = []
    for addr in write_log:
        if not any(start <= addr < end for start, end in partition_ranges):
            oob_addresses.append(addr)

    if oob_addresses:
        raise InvariantViolation(
            invariant_name="no_oob_writes",
            description=(
                "{} write(s) landed outside allowed partition ranges. "
                "First offender: 0x{:08X}.".format(len(oob_addresses), oob_addresses[0])
            ),
            result=result,
            details={
                "oob_addresses": oob_addresses,
                "oob_count": len(oob_addresses),
                "partition_ranges": [
                    {"start": "0x{:08X}".format(s), "end": "0x{:08X}".format(e)}
                    for s, e in partition_ranges
                ],
            },
        )


# SRAM range for Cortex-M0+ vector table validation.
_SRAM_START = 0x20000000
_SRAM_END = 0x20100000  # 1 MB — generous upper bound.


def check_slot_integrity(result: FaultResult, **_: Any) -> None:
    """If boot succeeded, the chosen slot must have plausible ARM vectors.

    Validates (when derivable from nvm_state):
      - Initial SP is in SRAM range.
      - Reset vector is within the slot's address range.
      - Reset vector has the Thumb bit set (bit 0 = 1).
    """
    if result.boot_outcome != "success":
        return

    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    initial_sp = nvm.get("initial_sp")
    reset_vector = nvm.get("reset_vector")
    slot_start = nvm.get("slot_start")
    slot_end = nvm.get("slot_end")

    # Nothing to validate if the state doesn't carry vector info.
    if initial_sp is None or reset_vector is None:
        return

    problems: List[str] = []

    # SP must point into SRAM.
    if not (_SRAM_START <= initial_sp < _SRAM_END):
        problems.append(
            "Initial SP 0x{:08X} is outside SRAM range "
            "[0x{:08X}, 0x{:08X}).".format(initial_sp, _SRAM_START, _SRAM_END)
        )

    # Thumb bit must be set.
    if not (reset_vector & 1):
        problems.append(
            "Reset vector 0x{:08X} does not have Thumb bit set.".format(reset_vector)
        )

    # Reset vector (ignoring Thumb bit) must be within the slot.
    if slot_start is not None and slot_end is not None:
        rv_addr = reset_vector & ~1  # mask off Thumb bit
        if not (slot_start <= rv_addr < slot_end):
            problems.append(
                "Reset vector address 0x{:08X} is outside slot range "
                "[0x{:08X}, 0x{:08X}).".format(rv_addr, slot_start, slot_end)
            )

    if problems:
        raise InvariantViolation(
            invariant_name="slot_integrity",
            description=(
                "Boot reported success on slot {!r} but vector table looks "
                "invalid: {}".format(result.boot_slot, "; ".join(problems))
            ),
            result=result,
            details={
                "initial_sp": "0x{:08X}".format(initial_sp) if initial_sp is not None else None,
                "reset_vector": "0x{:08X}".format(reset_vector) if reset_vector is not None else None,
                "slot_start": "0x{:08X}".format(slot_start) if slot_start is not None else None,
                "slot_end": "0x{:08X}".format(slot_end) if slot_end is not None else None,
                "problems": problems,
                "boot_slot": result.boot_slot,
            },
        )


def check_multi_boot_converges(
    result: FaultResult,
    multi_boot_analysis: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """When multi-boot analysis is present, the boot path should converge.

    This catches stuck revert / oscillation bugs that only become visible
    across repeated clean boots after the initial recovery boot.
    """
    if not isinstance(multi_boot_analysis, dict):
        return

    status = multi_boot_analysis.get("status")
    if status in (None, "not_run", "single_boot"):
        return
    if status == "unsupported_fast_path_required":
        return
    if status != "converged":
        raise InvariantViolation(
            invariant_name="multi_boot_converges",
            description=(
                "Boot path did not converge across follow-up boots "
                "(status={!r}, final_slot={!r}, final_outcome={!r}).".format(
                    status,
                    multi_boot_analysis.get("final_slot"),
                    multi_boot_analysis.get("final_outcome"),
                )
            ),
            result=result,
            details=dict(multi_boot_analysis),
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_ALL_INVARIANTS: List[InvariantFn] = [
    check_at_least_one_bootable,
    check_boot_matches_metadata,
    check_metadata_single_fault_consistency,
    check_no_oob_writes,
    check_slot_integrity,
    check_multi_boot_converges,
]

_INVARIANT_REGISTRY: Dict[str, InvariantFn] = {
    "at_least_one_bootable": check_at_least_one_bootable,
    "boot_matches_metadata": check_boot_matches_metadata,
    "metadata_single_fault_consistency": check_metadata_single_fault_consistency,
    "no_oob_writes": check_no_oob_writes,
    "slot_integrity": check_slot_integrity,
    "multi_boot_converges": check_multi_boot_converges,
}


def run_invariants(
    result: FaultResult,
    invariants: Optional[Sequence[InvariantFn]] = None,
    **context: Any,
) -> List[InvariantViolation]:
    """Run invariant checks against a single FaultResult.

    Args:
        result: The fault-injection result to validate.
        invariants: Which checks to run.  ``None`` means all registered
            invariants.
        **context: Extra keyword arguments forwarded to each check function
            (e.g. ``pre_state``, ``write_log``, ``partition_ranges``).

    Returns:
        A list of :class:`InvariantViolation` objects.  Empty means all
        checks passed.  Does **not** raise — violations are collected.
    """
    if invariants is None:
        invariants = _ALL_INVARIANTS

    violations: List[InvariantViolation] = []
    for check_fn in invariants:
        try:
            check_fn(result, **context)
        except InvariantViolation as v:
            violations.append(v)
    return violations


# ---------------------------------------------------------------------------
# Scenario presets
# ---------------------------------------------------------------------------

def default_invariants(scenario: str) -> List[InvariantFn]:
    """Return the default invariant list for a named scenario.

    Presets:
        ``"strict"``:  All invariants.  Intended for update protocols that
            should survive every single-fault scenario.
        ``"vulnerable"``: Only ``check_slot_integrity``.  Vulnerable OTA
            is *expected* to brick; we only verify that a boot-success
            claim is genuine.
        Anything else:    ``check_at_least_one_bootable`` +
            ``check_slot_integrity`` — a conservative baseline.
    """
    if scenario == "strict":
        return list(_ALL_INVARIANTS)
    if scenario == "vulnerable":
        return [check_slot_integrity]
    return [check_at_least_one_bootable, check_slot_integrity]


def resolve_invariants(spec: Sequence[str]) -> List[InvariantFn]:
    """Resolve invariant names/presets into callable checks."""
    resolved: List[InvariantFn] = []
    seen: set[str] = set()
    for entry in spec:
        name = str(entry).strip()
        if not name:
            continue
        if name in ("strict", "vulnerable", "default"):
            preset = default_invariants(name)
            for fn in preset:
                fn_name = fn.__name__
                if fn_name not in seen:
                    resolved.append(fn)
                    seen.add(fn_name)
            continue
        fn = _INVARIANT_REGISTRY.get(name)
        if fn is None:
            raise ValueError("unknown invariant '{}'".format(name))
        if fn.__name__ not in seen:
            resolved.append(fn)
            seen.add(fn.__name__)
    return resolved
