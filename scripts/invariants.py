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
import math
import numbers
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

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


_SUCCESS_EFFECT_OPS = {
    "eq", "ne", "lt", "le", "gt", "ge", "gt_pre", "ge_pre",
    "lt_pre", "le_pre", "changed", "unchanged",
}
_MISSING = object()


def _contract_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a numeric contract value")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 10)


def _contract_path(state: Any, path: str) -> Any:
    current = state
    for component in str(path).split("."):
        if not component or not isinstance(current, dict) or component not in current:
            return _MISSING
        current = current[component]
    return current


def _success_effect_condition(
    condition: Dict[str, Any],
    pre_state: Optional[Dict[str, Any]],
    post_state: Optional[Dict[str, Any]],
) -> Tuple[bool, Dict[str, Any]]:
    source = condition.get("source")
    path = str(condition.get("path") or "")
    op = str(condition.get("op") or "").strip().lower()
    state = pre_state if source == "pre" else post_state if source == "post" else None
    if state is None:
        raise ValueError("semantic {} state is missing".format(source))
    actual = _contract_path(state, path)
    if actual is _MISSING:
        raise ValueError("semantic {} path {!r} is missing".format(source, path))
    comparison = None
    if op in {"changed", "unchanged", "gt_pre", "ge_pre", "lt_pre", "le_pre"}:
        if source != "post" or pre_state is None:
            raise ValueError("{} requires a post source and semantic pre-state".format(op))
        before = _contract_path(pre_state, path)
        if before is _MISSING:
            raise ValueError("semantic pre path {!r} is missing".format(path))
        if op in {"changed", "unchanged"}:
            comparison = actual != before if op == "changed" else actual == before
        else:
            left, right = _contract_int(actual), _contract_int(before)
            comparison = {
                "gt_pre": left > right, "ge_pre": left >= right,
                "lt_pre": left < right, "le_pre": left <= right,
            }[op]
        before_serialized = before
    else:
        expected = condition.get("value")
        if expected is None:
            raise ValueError("operator {} requires value".format(op))
        if op in {"eq", "ne"}:
            try:
                left, right = _contract_int(actual), _contract_int(expected)
            except (TypeError, ValueError):
                left, right = actual, expected
        else:
            left, right = _contract_int(actual), _contract_int(expected)
        comparison = {
            "eq": left == right, "ne": left != right,
            "lt": left < right, "le": left <= right,
            "gt": left > right, "ge": left >= right,
        }.get(op)
        if comparison is None:
            raise ValueError("unsupported operator {!r}".format(op))
        before_serialized = None
    return bool(comparison), {
        "source": source,
        "path": path,
        "op": op,
        "actual": actual,
        "pre_value": (
            _contract_path(pre_state, path)
            if isinstance(pre_state, dict) and _contract_path(pre_state, path) is not _MISSING
            else None
        ),
        "post_value": (
            _contract_path(post_state, path)
            if source == "pre" and isinstance(post_state, dict)
            else actual if source == "post" else None
        ),
        "expected": condition.get("value"),
        "passed": bool(comparison),
    }


def _success_effect_group(
    group: Dict[str, Any],
    pre_state: Optional[Dict[str, Any]],
    post_state: Optional[Dict[str, Any]],
) -> Tuple[bool, List[Dict[str, Any]]]:
    if not isinstance(group, dict) or set(group) not in ({"all"}, {"any"}):
        raise ValueError("require must contain exactly one of all or any")
    kind = next(iter(group))
    conditions = group[kind]
    if not isinstance(conditions, list) or not conditions:
        raise ValueError("{} condition group must be a non-empty list".format(kind))
    evaluated = []
    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError("condition must be a mapping")
        passed, detail = _success_effect_condition(condition, pre_state, post_state)
        evaluated.append(detail)
    return (all(item["passed"] for item in evaluated) if kind == "all" else any(item["passed"] for item in evaluated)), evaluated


def check_success_implies_effect(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    invariant_config: Optional[Dict[str, Any]] = None,
    result_signals: Optional[Dict[str, Any]] = None,
    result_dict: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Require a durable semantic postcondition after a successful API return."""
    config = (invariant_config or {}).get("success_implies_effect")
    if not config:
        return
    result_signals = result_signals or {}
    result_dict = result_dict or {}
    if result.is_control:
        contracts = [c for c in config if isinstance(c, dict) and c.get("evaluate_control")]
    else:
        contracts = list(config)
    if not contracts:
        return
    probes = result_signals.get("function_return_probes")
    if not isinstance(probes, dict):
        raise ValueError("function return probe telemetry is missing")
    post_state = result_signals.get("semantic_state")
    if not isinstance(post_state, dict):
        post_state = result.nvm_state
    if not isinstance(post_state, dict):
        raise ValueError("semantic post-state is missing")
    for contract in contracts:
        if not isinstance(contract, dict):
            raise ValueError("success_implies_effect contract must be a mapping")
        name = str(contract.get("name") or "").strip()
        label = str(contract.get("probe") or "").strip()
        telemetry = probes.get(label)
        if not isinstance(telemetry, dict):
            raise ValueError("probe {!r} telemetry is missing".format(label))
        call_count = int(telemetry.get("call_count", 0) or 0)
        capture = str(telemetry.get("capture") or "last").lower()
        selector = contract.get("call")
        if selector is None:
            if capture not in {"first", "last"}:
                raise ValueError("contract {!r} must set call for capture=all".format(name))
            selector = capture
        if isinstance(selector, bool):
            raise ValueError("contract {!r} has invalid call selector".format(name))
        if isinstance(selector, str) and selector.strip().lower() in {"first", "last"}:
            selected_index = 0 if selector.strip().lower() == "first" else call_count - 1
        else:
            try:
                selected_index = _contract_int(selector)
            except (TypeError, ValueError) as exc:
                raise ValueError("contract {!r} has invalid call selector".format(name)) from exc
        if selected_index < 0 or selected_index >= call_count:
            raise ValueError("contract {!r} selected call {} is absent".format(name, selected_index))
        raw_values = telemetry.get("raw_values") or telemetry.get("return_values") or []
        calls = telemetry.get("calls") or []
        selected = next(
            (item for item in calls if int(item.get("call_index", -1)) == selected_index),
            None,
        ) if calls else None
        if selected is not None:
            if selected.get("register_read_error"):
                raise ValueError(
                    "probe {!r} return register read failed: {}".format(
                        label, selected.get("register_read_error")
                    )
                )
            return_value = selected.get("raw_value", selected.get("return_value"))
        elif len(raw_values) == call_count:
            return_value = raw_values[selected_index]
        elif len(raw_values) == 1 and selected_index == 0:
            return_value = raw_values[0]
        else:
            raise ValueError("probe {!r} does not contain selected return telemetry".format(label))
        return_value_int = _contract_int(return_value) & 0xFFFFFFFF
        success_values = [_contract_int(value) & 0xFFFFFFFF for value in (contract.get("success_values") or [])]
        if return_value_int not in success_values:
            continue
        passed, condition_details = _success_effect_group(
            contract.get("require"), pre_state, post_state
        )
        if not passed:
            details = {
                "finding_code": "SUCCESS_WITHOUT_REQUIRED_EFFECT",
                "contract": name,
                "probe": label,
                "return_value": return_value_int & 0xFFFFFFFF,
                "return_value_text": "0x{:08X}".format(return_value_int & 0xFFFFFFFF),
                "fault_at": result_dict.get("fault_at", result.fault_at),
                "fault_point": result_dict.get("fault_address"),
                "conditions": condition_details,
            }
            raise InvariantViolation(
                "success_implies_effect",
                "contract {!r} observed a success return without the required effect".format(name),
                result,
                details=details,
            )


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


def _lookup_dotted_state_path(
    state: Dict[str, Any], path: str, invariant_name: str
) -> Any:
    """Resolve a dotted path within nested invariant state."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("{} path must be a non-empty string".format(invariant_name))

    current: Any = state
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(
                "{} path {!r} is missing component {!r}".format(
                    invariant_name, path, part
                )
            )
        current = current[part]
    return current


def _lookup_atomic_state_path(state: Dict[str, Any], path: str) -> Any:
    """Resolve a dotted path within semantic NVM state."""
    return _lookup_dotted_state_path(state, path, "atomic_state_groups member")


def check_atomic_state_groups(
    result: FaultResult,
    invariant_config: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Jointly committed persistent state must not remain partially updated.

    Profiles declare the members of each durable transition and the stable
    value for each member before and after that transition.  At the observation
    boundary after fault handling or recovery, every member must describe the
    same boundary state: either all ``before`` or all ``after``.  A mixture
    means an interruption or reset exposed a partial commit across storage
    objects.

    The contract is opt-in because independently updatable components may
    legitimately carry different values.  Configure it under
    ``invariant_config.atomic_state_groups``.
    """
    config = invariant_config or {}
    groups = config.get("atomic_state_groups")
    if groups is None:
        return
    if not isinstance(groups, list):
        raise ValueError("atomic_state_groups must be a list")

    state = result.nvm_state
    if not isinstance(state, dict):
        raise ValueError("atomic_state_groups requires dictionary nvm_state")

    for group_index, group in enumerate(groups):
        if not isinstance(group, dict):
            raise ValueError(
                "atomic_state_groups[{}] must be a mapping".format(group_index)
            )
        name = group.get("name", "group_{}".format(group_index))
        members = group.get("members")
        if not isinstance(members, list) or len(members) < 2:
            raise ValueError(
                "atomic_state_groups {!r} must contain at least two members".format(
                    name
                )
            )

        observations: List[Dict[str, Any]] = []
        phases = set()
        for member_index, member in enumerate(members):
            if not isinstance(member, dict):
                raise ValueError(
                    "atomic_state_groups {!r} member {} must be a mapping".format(
                        name, member_index
                    )
                )
            path = member.get("path")
            if "before" not in member or "after" not in member:
                raise ValueError(
                    "atomic_state_groups {!r} member {!r} requires before and after".format(
                        name, path
                    )
                )
            before = member["before"]
            after = member["after"]
            if before == after:
                raise ValueError(
                    "atomic_state_groups {!r} member {!r} has identical before and after".format(
                        name, path
                    )
                )

            actual = _lookup_atomic_state_path(state, path)
            if actual == before:
                phase = "before"
            elif actual == after:
                phase = "after"
            else:
                phase = "unexpected"
            phases.add(phase)
            observations.append(
                {
                    "path": path,
                    "before": before,
                    "after": after,
                    "actual": actual,
                    "phase": phase,
                }
            )

        if phases == {"before"} or phases == {"after"}:
            continue

        raise InvariantViolation(
            invariant_name="atomic_state_groups",
            description=(
                "Persistent transition {!r} did not recover to a single commit "
                "boundary; observed phases: {}.".format(
                    name, ", ".join(sorted(phases))
                )
            ),
            result=result,
            details={
                "group": name,
                "observations": observations,
                "phases": sorted(phases),
                "fault_at": result.fault_at,
            },
        )


def _parse_monotonic_state_fields(
    raw: Any,
) -> List[Tuple[str, str]]:
    """Normalize monotonic-state configuration to ``(path, direction)`` pairs."""
    if isinstance(raw, dict):
        paths = raw.get("paths", raw.get("fields"))
        direction = raw.get("direction", "nondecreasing")
        if paths is None:
            # Also accept a compact mapping of dotted path -> direction.
            # A mapping containing only ``direction`` remains malformed.
            direct_paths = [
                {"path": path, "direction": value}
                for path, value in raw.items()
                if path != "direction"
            ]
            if direct_paths and len(direct_paths) == len(raw) - (
                1 if "direction" in raw else 0
            ):
                paths = direct_paths
            else:
                raise ValueError(
                    "monotonic_state_fields requires a paths list"
                )
    elif isinstance(raw, list):
        paths = raw
        direction = "nondecreasing"
    else:
        raise ValueError("monotonic_state_fields must be a mapping or list")

    if not isinstance(paths, list) or not paths:
        raise ValueError("monotonic_state_fields paths must be a non-empty list")
    if not isinstance(direction, str) or direction not in (
        "nondecreasing",
        "nonincreasing",
    ):
        raise ValueError(
            "monotonic_state_fields direction must be 'nondecreasing' or "
            "'nonincreasing'"
        )

    parsed: List[Tuple[str, str]] = []
    for index, entry in enumerate(paths):
        entry_direction = direction
        if isinstance(entry, dict):
            path = entry.get("path")
            entry_direction = entry.get("direction", direction)
        else:
            path = entry
        if not isinstance(path, str) or not path.strip():
            raise ValueError(
                "monotonic_state_fields paths[{}] must be a non-empty string "
                "or mapping with path".format(index)
            )
        if not isinstance(entry_direction, str) or entry_direction not in (
            "nondecreasing",
            "nonincreasing",
        ):
            raise ValueError(
                "monotonic_state_fields path {!r} has invalid direction {!r}".format(
                    path, entry_direction
                )
            )
        parsed.append((path, entry_direction))
    return parsed


def _monotonic_numeric(value: Any, path: str) -> Union[int, float]:
    """Validate a state value for safe numeric comparison."""
    if isinstance(value, bool):
        raise ValueError(
            "monotonic_state_fields path {!r} must contain a numeric value, got {!r}".format(
                path, type(value).__name__
            )
        )
    if isinstance(value, numbers.Real):
        numeric: Union[int, float] = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            # Probes commonly expose register values as decimal or hex text.
            numeric = int(text, 0)
        except ValueError:
            try:
                numeric = float(text)
            except ValueError:
                raise ValueError(
                    "monotonic_state_fields path {!r} must contain a numeric value, got {!r}".format(
                        path, type(value).__name__
                    )
                )
    else:
        raise ValueError(
            "monotonic_state_fields path {!r} must contain a numeric value, got {!r}".format(
                path, type(value).__name__
            )
        )
    if isinstance(numeric, float) and not math.isfinite(numeric):
        raise ValueError(
            "monotonic_state_fields path {!r} must contain a finite numeric value".format(
                path
            )
        )
    return numeric


def check_monotonic_state_fields(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    invariant_config: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Persistent numeric state fields must not move backwards after a fault.

    Configure ``invariant_config.monotonic_state_fields`` with either a list
    of dotted paths (implicitly nondecreasing), or a mapping containing a
    ``paths`` list and a ``direction``.  Each path is resolved independently
    in both ``pre_state`` and ``result.nvm_state``.  A configured observation
    that is malformed or missing is an evaluation error rather than a pass.
    Control runs are excluded because they are the source of the pre-state.
    """
    if result.is_control:
        return

    if invariant_config is None:
        config: Dict[str, Any] = {}
    elif not isinstance(invariant_config, dict):
        raise ValueError("invariant_config must be a mapping")
    else:
        config = invariant_config
    if "monotonic_state_fields" not in config:
        return
    fields = _parse_monotonic_state_fields(config["monotonic_state_fields"])

    if not isinstance(pre_state, dict):
        raise ValueError("monotonic_state_fields requires dictionary pre_state")
    nvm_state = result.nvm_state
    if not isinstance(nvm_state, dict):
        raise ValueError("monotonic_state_fields requires dictionary nvm_state")

    regressions: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    for path, direction in fields:
        pre_value = _lookup_dotted_state_path(
            pre_state, path, "monotonic_state_fields"
        )
        post_value = _lookup_dotted_state_path(
            nvm_state, path, "monotonic_state_fields"
        )
        pre_numeric = _monotonic_numeric(pre_value, path)
        post_numeric = _monotonic_numeric(post_value, path)
        delta = post_numeric - pre_numeric
        observations.append(
            {
                "path": path,
                "direction": direction,
                "pre_value": pre_value,
                "post_value": post_value,
                "delta": delta,
            }
        )
        regressed = (
            post_numeric < pre_numeric
            if direction == "nondecreasing"
            else post_numeric > pre_numeric
        )
        if regressed:
            regressions.append(observations[-1])

    if not regressions:
        return

    details: Dict[str, Any] = {
        "regressions": regressions,
        "observations": observations,
        "fault_at": result.fault_at,
    }
    if len(regressions) == 1:
        details.update(regressions[0])

    raise InvariantViolation(
        invariant_name="monotonic_state_fields",
        description=(
            "Monotonic persistent state moved in the forbidden direction "
            "after a fault: {}.  "
            "Check recovery defaults and interrupted writes for the affected "
            "security state.".format(
                ", ".join(
                    "{} ({} -> {})".format(
                        item["path"], item["pre_value"], item["post_value"]
                    )
                    for item in regressions
                )
            )
        ),
        result=result,
        details=details,
    )


# ---------------------------------------------------------------------------
# Cross-field state relations
# ---------------------------------------------------------------------------

_STATE_RELATION_OPS = frozenset({"eq", "ne", "lt", "le", "gt", "ge"})


def _relation_type(value: Any) -> str:
    """Return the strict comparison category used by state relations."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, numbers.Real):
        return "number"
    if value is None:
        return "null"
    return type(value).__name__


def _relation_numeric(value: Any, label: str) -> Union[int, float]:
    """Use the same strict numeric conversion as monotonic state fields."""
    try:
        return _monotonic_numeric(value, label)
    except ValueError as exc:
        raise ValueError(
            "state_relations {} must contain a numeric value, got {!r}".format(
                label, type(value).__name__
            )
        ) from exc


def _relation_equal(left: Any, right: Any, label: str) -> bool:
    """Compare values without silently coercing strings, booleans, or numbers."""
    left_type = _relation_type(left)
    right_type = _relation_type(right)
    if left_type != right_type:
        raise ValueError(
            "state_relations {} equality requires compatible types, got {} and {}".format(
                label, left_type, right_type
            )
        )
    if left_type == "number":
        # Reject non-finite values even though Python can compare them.
        return _relation_numeric(left, label) == _relation_numeric(right, label)
    if left_type in {"boolean", "string", "null"}:
        return left == right
    raise ValueError(
        "state_relations {} has unsupported value type {!r}".format(
            label, type(left).__name__
        )
    )


def _relation_compare(left: Any, op: str, right: Any, label: str) -> bool:
    """Evaluate one relation comparison, rejecting incompatible operands."""
    normalized = str(op or "").strip().lower()
    if normalized not in _STATE_RELATION_OPS:
        raise ValueError("state_relations {} has unsupported operator {!r}".format(label, op))
    if normalized in {"eq", "ne"}:
        equal = _relation_equal(left, right, label)
        return equal if normalized == "eq" else not equal
    left_numeric = _relation_numeric(left, label)
    right_numeric = _relation_numeric(right, label)
    return {
        "lt": left_numeric < right_numeric,
        "le": left_numeric <= right_numeric,
        "gt": left_numeric > right_numeric,
        "ge": left_numeric >= right_numeric,
    }[normalized]


def _relation_operand(
    operand: Any,
    *,
    pre_state: Optional[Dict[str, Any]],
    post_state: Optional[Dict[str, Any]],
    label: str,
) -> Tuple[Any, Dict[str, Any]]:
    """Resolve one declarative relation operand and return value plus evidence."""
    if not isinstance(operand, dict):
        raise ValueError("state_relations {} operand must be a mapping".format(label))
    has_path = "path" in operand
    has_value = "value" in operand
    if has_path == has_value:
        raise ValueError(
            "state_relations {} operand must contain exactly one of path or value".format(label)
        )
    if has_path:
        if set(operand) != {"source", "path"}:
            raise ValueError(
                "state_relations {} path operand must contain only source and path".format(label)
            )
        source = operand.get("source")
        if source not in {"pre", "post"}:
            raise ValueError(
                "state_relations {} path operand source must be pre or post".format(label)
            )
        path = operand.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("state_relations {} path must be a non-empty string".format(label))
        state = pre_state if source == "pre" else post_state
        if not isinstance(state, dict):
            raise ValueError("state_relations {} {} state is missing".format(label, source))
        value = _lookup_dotted_state_path(state, path, "state_relations")
        return value, {"source": source, "path": path, "value": value}
    if set(operand) != {"value"}:
        raise ValueError(
            "state_relations {} literal operand must contain only value".format(label)
        )
    return operand["value"], {"value": operand["value"]}


def _relation_rule_evidence(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Return a JSON-safe copy of a validated relation rule."""
    # Rules consist only of mappings/lists/scalars after profile validation.
    return dict(rule)


def check_state_relations(
    result: FaultResult,
    pre_state: Optional[Dict[str, Any]] = None,
    invariant_config: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> None:
    """Enforce declarative compatibility relations between state fields.

    Relations run for both clean controls and faulted results.  A relation's
    optional ``when`` condition is resolved first; a false condition skips the
    relation.  Missing paths and incompatible values raise evaluation errors,
    which ``run_invariants`` records as fail-closed violations.
    """
    config = invariant_config or {}
    relations = config.get("state_relations")
    if relations is None:
        return
    if not isinstance(relations, list):
        raise ValueError("state_relations must be a list")
    post_state = result.nvm_state
    if not isinstance(post_state, dict):
        raise ValueError("state_relations requires dictionary post state")
    phase = "control" if result.is_control else "faulted"
    relation_names: set[str] = set()

    for index, relation in enumerate(relations):
        label = "state_relations[{}]".format(index)
        if not isinstance(relation, dict):
            raise ValueError("{} must be a mapping".format(label))
        unknown = set(relation) - {"name", "compare", "allowed_tuples", "when"}
        if unknown:
            raise ValueError(
                "{} has unknown field(s): {}".format(label, ", ".join(map(str, sorted(unknown))))
            )
        name = str(relation.get("name") or "").strip()
        if not name:
            raise ValueError("{}.name must be a non-empty string".format(label))
        if name in relation_names:
            raise ValueError("{}.name is duplicated".format(label))
        relation_names.add(name)
        has_compare = "compare" in relation
        has_tuples = "allowed_tuples" in relation
        if has_compare == has_tuples:
            raise ValueError("{} must contain exactly one of compare or allowed_tuples".format(label))

        when = relation.get("when")
        if when is not None:
            if not isinstance(when, dict) or set(when) != {"left", "op", "right"}:
                raise ValueError("{}.when must contain left, op, and right".format(label))
            when_left, _ = _relation_operand(
                when["left"], pre_state=pre_state, post_state=post_state,
                label=label + ".when.left",
            )
            when_right, _ = _relation_operand(
                when["right"], pre_state=pre_state, post_state=post_state,
                label=label + ".when.right",
            )
            if not _relation_compare(when_left, when["op"], when_right, label + ".when"):
                continue

        component_ids: List[str] = []

        def add_component_id(operand: Any) -> None:
            if isinstance(operand, dict) and "path" in operand:
                path = str(operand.get("path") or "")
                parts = path.split(".")
                if len(parts) >= 2 and parts[0] == "components" and parts[1] not in component_ids:
                    component_ids.append(parts[1])

        if has_compare:
            compare = relation["compare"]
            if not isinstance(compare, dict) or set(compare) != {"left", "op", "right"}:
                raise ValueError("{}.compare must contain left, op, and right".format(label))
            left, left_evidence = _relation_operand(
                compare["left"], pre_state=pre_state, post_state=post_state,
                label=label + ".compare.left",
            )
            right, right_evidence = _relation_operand(
                compare["right"], pre_state=pre_state, post_state=post_state,
                label=label + ".compare.right",
            )
            add_component_id(compare["left"])
            add_component_id(compare["right"])
            passed = _relation_compare(left, compare["op"], right, label + ".compare")
            observed: Any = {"left": left_evidence, "right": right_evidence}
            details: Dict[str, Any] = {
                "finding_code": "STATE_RELATION_VIOLATION",
                "relation": name,
                "relation_name": name,
                "phase": phase,
                "run_phase": phase,
                "component_identifiers": component_ids,
                "resolved_operands": observed,
                "operands": observed,
                "observed_operands": {"left": left, "right": right},
                "resolved_left": left,
                "resolved_right": right,
                "expected_rule": _relation_rule_evidence(compare),
                "expected": _relation_rule_evidence(compare),
            }
        else:
            tuples = relation["allowed_tuples"]
            if not isinstance(tuples, dict) or set(tuples) != {"fields", "values"}:
                raise ValueError("{}.allowed_tuples must contain fields and values".format(label))
            fields = tuples["fields"]
            allowed = tuples["values"]
            if not isinstance(fields, list) or len(fields) < 2:
                raise ValueError("{}.allowed_tuples.fields requires at least two fields".format(label))
            if not isinstance(allowed, list) or not allowed:
                raise ValueError("{}.allowed_tuples.values requires at least one tuple".format(label))
            observed_values: List[Any] = []
            field_evidence: List[Dict[str, Any]] = []
            for field_index, field in enumerate(fields):
                value, evidence = _relation_operand(
                    field, pre_state=pre_state, post_state=post_state,
                    label="{}.allowed_tuples.fields[{}]".format(label, field_index),
                )
                observed_values.append(value)
                field_evidence.append(evidence)
                add_component_id(field)
            matched = False
            for tuple_index, allowed_tuple in enumerate(allowed):
                if not isinstance(allowed_tuple, (list, tuple)) or len(allowed_tuple) != len(fields):
                    raise ValueError(
                        "{}.allowed_tuples.values[{}] must match field count {}".format(
                            label, tuple_index, len(fields)
                        )
                    )
                for field_index, expected in enumerate(allowed_tuple):
                    actual_type = _relation_type(observed_values[field_index])
                    expected_type = _relation_type(expected)
                    if actual_type != expected_type:
                        # A listed tuple with the wrong runtime type is an
                        # invalid observation, not simply a disallowed pair.
                        raise ValueError(
                            "{}.allowed_tuples field {} expected type {}, got {}".format(
                                label, field_index, expected_type, actual_type
                            )
                        )
                if all(
                    _relation_equal(actual, expected, "{}.allowed_tuples".format(label))
                    for actual, expected in zip(observed_values, allowed_tuple)
                ):
                    matched = True
                    break
            if not matched:
                observed = {"fields": field_evidence, "tuple": observed_values}
                details = {
                    "finding_code": "STATE_RELATION_VIOLATION",
                    "relation": name,
                    "relation_name": name,
                    "phase": phase,
                    "run_phase": phase,
                    "component_identifiers": component_ids,
                    "resolved_tuple": observed_values,
                    "observed_tuple": observed_values,
                    "observed_values": observed_values,
                    "tuple": observed_values,
                    "resolved_operands": field_evidence,
                    "expected_rule": _relation_rule_evidence(tuples),
                    "expected": _relation_rule_evidence(tuples),
                }
                raise InvariantViolation(
                    invariant_name="state_relations",
                    description=(
                        "State relation {!r} rejected observed tuple {}.".format(
                            name, observed_values
                        )
                    ),
                    result=result,
                    details=details,
                )
            continue

        if passed:
            continue
        raise InvariantViolation(
            invariant_name="state_relations",
            description=(
                "State relation {!r} rejected resolved operands.".format(name)
            ),
            result=result,
            details=details,
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
    check_atomic_state_groups,
    check_monotonic_state_fields,
    check_state_relations,
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
    "atomic_state_groups": check_atomic_state_groups,
    "monotonic_state_fields": check_monotonic_state_fields,
    "state_relations": check_state_relations,
    "success_implies_effect": check_success_implies_effect,
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
        except (ValueError, TypeError) as exc:
            # A configured invariant that cannot evaluate is not evidence
            # that the invariant held.  Preserve the error as a violation so
            # the campaign cannot silently pass with a broken observation.
            check_name = getattr(check_fn, "__name__", "unknown_invariant")
            violations.append(
                InvariantViolation(
                    "invariant_evaluation_error",
                    "{} could not evaluate: {}".format(check_name, exc),
                    result,
                    details={
                        "check": check_name,
                        "error_type": type(exc).__name__,
                    },
                )
            )
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
