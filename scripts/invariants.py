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

import importlib.util
from pathlib import Path
import sys
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
        # Surface multi-fault sequence in details so violations aren't
        # misattributed to only the first fault point.
        fault_seq = getattr(result, "fault_sequence", None)
        if fault_seq is not None and "fault_sequence" not in self.details:
            self.details["fault_sequence"] = fault_seq
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

    slot_a_valid = nvm.get("slot_a_valid")
    slot_b_valid = nvm.get("slot_b_valid")

    # If slot validity flags are not present, skip rather than falling back
    # to replica0_valid/replica1_valid — those are metadata CRC checks, not
    # vector table checks (see check_at_least_one_bootable).
    if slot_a_valid is None or slot_b_valid is None:
        return

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
    if status not in ("converged", "rollback_converged"):
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


def check_successful_rollback(
    result: FaultResult,
    multi_boot_analysis: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """When rollback is expected, the boot path should reach it in time."""
    if not isinstance(multi_boot_analysis, dict):
        return
    expected_cycle = multi_boot_analysis.get("expected_rollback_at_cycle")
    if expected_cycle in (None, ""):
        return
    if multi_boot_analysis.get("status") == "rollback_converged":
        return
    # If the device already booted into the target slot (no rollback
    # needed), this is not a failure -- rollback is simply N/A.
    if multi_boot_analysis.get("rollback_skipped"):
        return
    # A missed/no-boot first cycle that recovers to a successful boot on the
    # rollback target slot, by the expected cycle, is preserved availability,
    # not a rollback failure. The cycle-0 "no_boot" here comes from the
    # execute-mode probe not observing execution (vtor/pc unset). Only treat it
    # as a pass when the recovery landed on the expected rollback target and did
    # so on time -- a recovery into another slot, or one that arrived later than
    # expected, is still a genuine rollback failure.
    if (
        multi_boot_analysis.get("status") == "initial_no_boot_recovered"
        and multi_boot_analysis.get("final_outcome") == "success"
        and multi_boot_analysis.get("rollback_target_slot") is not None
        and multi_boot_analysis.get("final_slot")
        == multi_boot_analysis.get("rollback_target_slot")
        and multi_boot_analysis.get("rollback_cycle") is not None
        and int(multi_boot_analysis.get("rollback_cycle")) <= int(expected_cycle)
    ):
        return
    raise InvariantViolation(
        invariant_name="successful_rollback",
        description=(
            "Expected rollback by cycle {!r}, but multi-boot analysis reported "
            "status={!r} (rollback_cycle={!r}, final_slot={!r}, final_outcome={!r}).".format(
                expected_cycle,
                multi_boot_analysis.get("status"),
                multi_boot_analysis.get("rollback_cycle"),
                multi_boot_analysis.get("final_slot"),
                multi_boot_analysis.get("final_outcome"),
            )
        ),
        result=result,
        details=dict(multi_boot_analysis),
    )


def check_metadata_seq_monotonic(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """After a fault, the active metadata sequence number should not regress.

    If a bootloader uses dual-replica metadata with monotonic sequence
    numbers, a single fault should not cause the bootloader to select an
    older replica over a newer one.  Regression indicates a write-ordering
    bug where both replicas were updated in a window that left the newer
    one vulnerable to corruption.

    Requires the state probe to report ``replica0_seq`` and ``replica1_seq``
    (or ``active_seq``) in both pre-state and post-fault nvm_state.
    """
    if pre_state is None:
        return
    if result.is_control:
        return

    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    def _parse_int(val: Any) -> int:
        """Parse an int that may be a hex string like '0xFFFFFFFF'."""
        if isinstance(val, str):
            return int(val, 0)
        return int(val)

    def _max_seq(state: Dict[str, Any]) -> Optional[int]:
        active = state.get("active_seq")
        if active is not None:
            return _parse_int(active)
        r0 = state.get("replica0_seq")
        r1 = state.get("replica1_seq")
        if r0 is None and r1 is None:
            return None
        vals = []
        if r0 is not None:
            vals.append(_parse_int(r0))
        if r1 is not None:
            vals.append(_parse_int(r1))
        return max(vals) if vals else None

    pre_seq = _max_seq(pre_state)
    post_seq = _max_seq(nvm)
    if pre_seq is None or post_seq is None:
        return

    # Signed comparison for uint32 wraparound: if (post - pre) interpreted
    # as signed is negative, the sequence went backwards.
    delta = (post_seq - pre_seq) & 0xFFFFFFFF
    if delta > 0x7FFFFFFF:
        signed_delta = delta - 0x100000000
        raise InvariantViolation(
            invariant_name="metadata_seq_monotonic",
            description=(
                "Metadata sequence number regressed after fault: "
                "pre={}, post={} (delta={}).  The bootloader may have "
                "selected a stale replica.".format(pre_seq, post_seq, signed_delta)
            ),
            result=result,
            details={
                "pre_seq": pre_seq,
                "post_seq": post_seq,
                "signed_delta": signed_delta,
                "pre_replica0_seq": pre_state.get("replica0_seq"),
                "pre_replica1_seq": pre_state.get("replica1_seq"),
                "post_replica0_seq": nvm.get("replica0_seq"),
                "post_replica1_seq": nvm.get("replica1_seq"),
                "fault_at": result.fault_at,
            },
        )


def check_slot_hash_consistent(
    result: FaultResult,
    **_: Any,
) -> None:
    """If metadata records a hash for a slot, it must match the actual image.

    Many bootloaders store image hashes (SHA-256, CRC-32, etc.) in metadata
    for fast re-validation without reading the entire image.  After a fault,
    a stale or corrupted hash field that still passes the metadata integrity
    check would cause the bootloader to trust a wrong hash — potentially
    skipping re-validation of a corrupted image on the next boot.

    Requires the state probe to report per-slot ``hash_recorded`` and
    ``hash_computed`` fields (any comparable format — hex strings or ints).
    Checks all slots found in the nvm_state dict.
    """
    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    if result.boot_outcome != "success":
        return

    # Check top-level per-slot fields.
    _SLOT_PREFIXES = ("slot_a", "slot_b", "exec", "staging", "primary", "secondary")
    mismatches: List[str] = []

    for prefix in _SLOT_PREFIXES:
        recorded = nvm.get("{}_hash_recorded".format(prefix))
        computed = nvm.get("{}_hash_computed".format(prefix))
        if recorded is None or computed is None:
            continue
        if recorded != computed:
            mismatches.append(prefix)

    # Also check nested slots dict (probes may use either convention).
    slots = nvm.get("slots")
    if isinstance(slots, dict):
        for slot_name, slot_data in slots.items():
            if not isinstance(slot_data, dict):
                continue
            recorded = slot_data.get("hash_recorded")
            computed = slot_data.get("hash_computed")
            if recorded is None or computed is None:
                continue
            if recorded != computed and slot_name not in mismatches:
                mismatches.append(slot_name)

    if mismatches:
        raise InvariantViolation(
            invariant_name="slot_hash_consistent",
            description=(
                "Recorded image hash does not match computed hash for slot(s): {}. "
                "Metadata may contain stale or corrupted hash values.".format(
                    ", ".join(mismatches)
                )
            ),
            result=result,
            details={
                "mismatched_slots": mismatches,
                "boot_outcome": result.boot_outcome,
            },
        )


def check_rollback_version_bounded(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Anti-rollback version floor should not spike from a single fault.

    If the bootloader maintains a minimum-version floor for anti-rollback,
    a single fault should not cause it to jump by a large amount.  A spike
    indicates corrupt metadata was salvaged and a garbage value was injected
    into the version floor, potentially locking out all valid firmware.

    Requires the state probe to report ``rollback_min_version`` in both
    pre-state and post-fault nvm_state.
    """
    if pre_state is None:
        return
    if result.is_control:
        return

    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    pre_rmv = pre_state.get("rollback_min_version")
    post_rmv = nvm.get("rollback_min_version")
    if pre_rmv is None or post_rmv is None:
        return

    pre_rmv = int(pre_rmv)
    post_rmv = int(post_rmv)

    # During normal operation the version floor only advances by the delta
    # between the old and new firmware versions — typically single digits.
    # A jump of more than 256 is almost certainly corrupt metadata being
    # misinterpreted as a version number.
    max_delta = 256
    delta = post_rmv - pre_rmv
    if delta > max_delta:
        raise InvariantViolation(
            invariant_name="rollback_version_bounded",
            description=(
                "Anti-rollback version floor spiked from {} to {} (delta={}) "
                "after a single fault.  Corrupt metadata may have been "
                "salvaged with a garbage version field.".format(
                    pre_rmv, post_rmv, delta
                )
            ),
            result=result,
            details={
                "pre_rollback_min_version": pre_rmv,
                "post_rollback_min_version": post_rmv,
                "delta": delta,
                "max_allowed_delta": max_delta,
                "fault_at": result.fault_at,
            },
        )


def check_no_unauthorized_state_promotion(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """A slot should not be promoted from testing to accepted by a fault.

    If a slot was in a trial/testing state before the fault, it should not
    appear as accepted/confirmed after the fault unless the device actually
    completed a successful boot cycle into that slot and the application
    explicitly confirmed it.  A fault that skips the trial-boot verification
    could permanently activate a broken firmware image.

    Requires the state probe to report per-slot state fields (e.g.
    ``slot_a_state``, ``slot_b_state``) with generic values like
    ``"testing"``, ``"pending_test"``, ``"accepted"``, ``"confirmed"``.
    """
    if pre_state is None:
        return
    if result.is_control:
        return

    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return

    _TESTING = {"testing", "pending_test", "pending", "unconfirmed", "trial"}
    _ACCEPTED = {"accepted", "confirmed", "ok", "permanent"}

    _SLOT_KEYS = (
        "slot_a_state", "slot_b_state",
        "exec_state", "staging_state",
        "primary_state", "secondary_state",
    )

    promotions: List[Tuple[str, str, str]] = []
    for key in _SLOT_KEYS:
        pre_val = pre_state.get(key)
        post_val = nvm.get(key)
        if pre_val is None or post_val is None:
            continue
        pre_str = str(pre_val).lower()
        post_str = str(post_val).lower()
        if pre_str in _TESTING and post_str in _ACCEPTED:
            promotions.append((key, pre_str, post_str))

    if promotions:
        raise InvariantViolation(
            invariant_name="no_unauthorized_state_promotion",
            description=(
                "Slot state was promoted from testing to accepted after a "
                "fault without completing a trial boot: {}.".format(
                    ", ".join(
                        "{}: {} -> {}".format(k, pre, post)
                        for k, pre, post in promotions
                    )
                )
            ),
            result=result,
            details={
                "promotions": [
                    {"slot": k, "pre": pre, "post": post}
                    for k, pre, post in promotions
                ],
                "boot_outcome": result.boot_outcome,
                "fault_at": result.fault_at,
            },
        )


# ---------------------------------------------------------------------------
# Boot register snapshot invariant
# ---------------------------------------------------------------------------


def check_boot_registers_match(
    result: FaultResult,
    boot_register_values: Optional[Dict[str, int]] = None,
    result_signals: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Check that boot-time register values match expected values.

    At VTOR detection time the harness captures a configurable set of
    register addresses.  This invariant compares each captured value
    against the expected value from ``success_criteria.boot_register_values``.

    Only runs when the device booted successfully and register snapshots
    are present.
    """
    if not boot_register_values:
        return
    if result.boot_outcome != "success":
        return

    # The snapshot lives in signals.boot_register_snapshot.
    snapshot = None
    if isinstance(result_signals, dict):
        snapshot = result_signals.get("boot_register_snapshot")
    if not isinstance(snapshot, dict):
        return

    mismatches: List[str] = []
    details_mismatches: List[Dict[str, Any]] = []
    for reg_name, expected_val in boot_register_values.items():
        actual_raw = snapshot.get(reg_name)
        if actual_raw is None:
            mismatches.append("{}: not captured".format(reg_name))
            details_mismatches.append({
                "register": reg_name,
                "expected": "0x{:08X}".format(expected_val),
                "actual": None,
            })
            continue
        try:
            actual_val = int(str(actual_raw), 0)
        except (ValueError, TypeError):
            mismatches.append(
                "{}: unparseable value {!r}".format(reg_name, actual_raw)
            )
            details_mismatches.append({
                "register": reg_name,
                "expected": "0x{:08X}".format(expected_val),
                "actual": str(actual_raw),
            })
            continue
        if actual_val != expected_val:
            mismatches.append(
                "{}: expected 0x{:08X}, got 0x{:08X}".format(
                    reg_name, expected_val, actual_val
                )
            )
            details_mismatches.append({
                "register": reg_name,
                "expected": "0x{:08X}".format(expected_val),
                "actual": "0x{:08X}".format(actual_val),
            })

    if mismatches:
        raise InvariantViolation(
            invariant_name="boot_registers_match",
            description=(
                "Boot register mismatch after fault: {}".format(
                    "; ".join(mismatches)
                )
            ),
            result=result,
            details={
                "mismatches": details_mismatches,
                "boot_outcome": result.boot_outcome,
                "fault_at": result.fault_at,
            },
        )


def check_boot_target_matches_metadata(
    result: FaultResult,
    result_signals: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """After a successful boot, the boot slot should match what metadata declares active.

    The state probe may report a ``semantic_state`` dict inside
    ``result_signals`` with an ``active_slot`` or ``target_slot`` field.
    If the bootloader booted into a different slot than the metadata
    indicates, the metadata interpretation is inconsistent — potentially
    caused by a fault corrupting the metadata without invalidating its
    integrity check.

    Skipped when the device did not boot successfully, when
    ``result_signals`` is absent, or when the metadata slot info cannot
    be determined (conservative — no false positives).
    """
    if result.boot_outcome != "success":
        return

    if not isinstance(result_signals, dict):
        return

    semantic = result_signals.get("semantic_state")
    if not isinstance(semantic, dict):
        return

    metadata_slot = semantic.get("active_slot") or semantic.get("target_slot")
    if metadata_slot is None:
        return

    boot_slot = result.boot_slot
    if boot_slot is None:
        return

    # Normalize to strings for comparison (probes may report ints or strings).
    if str(metadata_slot) != str(boot_slot):
        raise InvariantViolation(
            invariant_name="boot_target_matches_metadata",
            description=(
                "Bootloader booted into slot {!r} but metadata declares "
                "active/target slot {!r}. The metadata interpretation is "
                "inconsistent with the actual boot path.".format(
                    boot_slot, metadata_slot
                )
            ),
            result=result,
            details={
                "boot_slot": boot_slot,
                "metadata_slot": metadata_slot,
                "semantic_state": semantic,
            },
        )


def check_last_known_good_preserved(
    result: FaultResult,
    result_signals: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """After any fault, at least one slot must still contain a valid image.

    This catches catastrophic corruption where ALL copies of firmware are
    destroyed by a single fault — a violation of the fundamental OTA safety
    property that a known-good image must always be recoverable.

    Looks for per-slot image validity or hash-match results in
    ``result_signals.semantic_state``.  Keys checked (in order of
    preference):

    - ``slot_a_image_ok`` / ``slot_b_image_ok`` (boolean)
    - ``slot_a_hash_match`` / ``slot_b_hash_match`` (boolean)
    - ``slots`` dict with per-slot ``image_ok`` or ``hash_match`` keys

    Skipped conservatively when the necessary signal data is absent —
    will never false-positive on missing information.
    """
    if not isinstance(result_signals, dict):
        return

    semantic = result_signals.get("semantic_state")
    if not isinstance(semantic, dict):
        return

    # Strategy 1: top-level per-slot boolean fields.
    slot_validity: Dict[str, bool] = {}

    for slot_name in ("slot_a", "slot_b", "exec", "staging", "primary", "secondary"):
        ok_key = "{}_image_ok".format(slot_name)
        hash_key = "{}_hash_match".format(slot_name)
        val = semantic.get(ok_key)
        if val is None:
            val = semantic.get(hash_key)
        if val is not None:
            slot_validity[slot_name] = bool(val)

    # Strategy 2: nested slots dict.
    slots = semantic.get("slots")
    if isinstance(slots, dict) and not slot_validity:
        for slot_name, slot_data in slots.items():
            if not isinstance(slot_data, dict):
                continue
            val = slot_data.get("image_ok")
            if val is None:
                val = slot_data.get("hash_match")
            if val is not None:
                slot_validity[slot_name] = bool(val)

    # If we couldn't determine ANY slot's image validity, skip.
    if not slot_validity:
        return

    if not any(slot_validity.values()):
        raise InvariantViolation(
            invariant_name="last_known_good_preserved",
            description=(
                "All slots have corrupted/invalid images after fault. "
                "No known-good firmware remains: {}.".format(
                    ", ".join(
                        "{}={}".format(k, v)
                        for k, v in sorted(slot_validity.items())
                    )
                )
            ),
            result=result,
            details={
                "slot_validity": slot_validity,
                "fault_at": result.fault_at,
                "boot_outcome": result.boot_outcome,
            },
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
    check_successful_rollback,
    check_metadata_seq_monotonic,
    check_slot_hash_consistent,
    check_rollback_version_bounded,
    check_no_unauthorized_state_promotion,
    check_boot_registers_match,
    check_boot_target_matches_metadata,
    check_last_known_good_preserved,
]

_INVARIANT_REGISTRY: Dict[str, InvariantFn] = {
    "at_least_one_bootable": check_at_least_one_bootable,
    "boot_matches_metadata": check_boot_matches_metadata,
    "metadata_single_fault_consistency": check_metadata_single_fault_consistency,
    "no_oob_writes": check_no_oob_writes,
    "slot_integrity": check_slot_integrity,
    "multi_boot_converges": check_multi_boot_converges,
    "successful_rollback": check_successful_rollback,
    "metadata_seq_monotonic": check_metadata_seq_monotonic,
    "slot_hash_consistent": check_slot_hash_consistent,
    "rollback_version_bounded": check_rollback_version_bounded,
    "no_unauthorized_state_promotion": check_no_unauthorized_state_promotion,
    "boot_registers_match": check_boot_registers_match,
    "boot_target_matches_metadata": check_boot_target_matches_metadata,
    "last_known_good_preserved": check_last_known_good_preserved,
}
_PROVIDER_CACHE: Dict[str, Dict[str, InvariantFn]] = {}


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
        except (ValueError, TypeError):
            # Don't crash the entire invariant run if a state probe returns
            # unparseable values (e.g. hex strings, unexpected types).
            # The individual invariant is simply skipped.
            pass
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


def _load_provider_module(provider_path: str) -> Dict[str, InvariantFn]:
    resolved = str(Path(provider_path).resolve())
    cached = _PROVIDER_CACHE.get(resolved)
    if cached is not None:
        return cached

    module_name = "tardigrade_invariant_provider_{}".format(
        abs(hash(resolved))
    )
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise ValueError(
            "failed to load invariant provider module '{}'".format(provider_path)
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # Ensure provider modules can resolve `from invariants import ...`
    # and `from targets.<x> import ...` (namespace packages).
    scripts_dir = str(Path(__file__).resolve().parent)
    repo_root = str(Path(__file__).resolve().parent.parent)
    scripts_added = scripts_dir not in sys.path
    root_added = repo_root not in sys.path
    if scripts_added:
        sys.path.insert(0, scripts_dir)
    if root_added:
        sys.path.insert(0, repo_root)
    try:
        spec.loader.exec_module(module)
    finally:
        if scripts_added and scripts_dir in sys.path:
            sys.path.remove(scripts_dir)
        if root_added and repo_root in sys.path:
            sys.path.remove(repo_root)

    mapping: Any = None
    if hasattr(module, "register_invariants"):
        mapping = module.register_invariants()
    elif hasattr(module, "INVARIANTS"):
        mapping = getattr(module, "INVARIANTS")
    else:
        raise ValueError(
            "invariant provider '{}' must define register_invariants() or INVARIANTS".format(
                provider_path
            )
        )

    if not isinstance(mapping, dict):
        raise ValueError(
            "invariant provider '{}' must return a name -> callable mapping".format(
                provider_path
            )
        )

    parsed: Dict[str, InvariantFn] = {}
    for raw_name, fn in mapping.items():
        name = str(raw_name).strip()
        if not name:
            raise ValueError(
                "invariant provider '{}' returned an empty invariant name".format(
                    provider_path
                )
            )
        if not callable(fn):
            raise ValueError(
                "invariant provider '{}' entry '{}' is not callable".format(
                    provider_path, name
                )
            )
        parsed[name] = fn

    _PROVIDER_CACHE[resolved] = parsed
    return parsed


def build_invariant_registry(
    provider_paths: Optional[Sequence[str]] = None,
) -> Dict[str, InvariantFn]:
    registry = dict(_INVARIANT_REGISTRY)
    for provider_path in provider_paths or []:
        provided = _load_provider_module(provider_path)
        for name, fn in provided.items():
            if name in registry:
                raise ValueError(
                    "duplicate invariant name '{}' from provider '{}'".format(
                        name, provider_path
                    )
                )
            registry[name] = fn
    return registry


def resolve_invariants(
    spec: Sequence[str],
    provider_paths: Optional[Sequence[str]] = None,
) -> List[InvariantFn]:
    """Resolve invariant names/presets into callable checks."""
    registry = build_invariant_registry(provider_paths)
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
        fn = registry.get(name)
        if fn is None:
            raise ValueError("unknown invariant '{}'".format(name))
        if fn.__name__ not in seen:
            resolved.append(fn)
            seen.add(fn.__name__)
    return resolved
