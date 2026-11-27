"""Result classification: boot outcome promotion, brick/issue detection, failure classes.

Extracted from audit_bootloader.py to reduce its size and provide a
focused module for result classification logic.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional, Tuple

from boot_cycle_analysis import (
    _FAILURE_BOOT_OUTCOMES,
    cycle_has_unresolved_timeout,
)
from fault_types import FAULT_TYPE_NAME_TO_CODE, multi_fault_stage_code


# Multi-boot statuses that promote the final cycle's outcome/slot as the
# effective boot result.
_MULTI_BOOT_SUCCESS_STATUSES = frozenset(
    {"converged", "rollback_converged", "recovered_after_failure"}
)
_MULTI_BOOT_FAILURE_STATUSES = frozenset({"failed_after_success"})
_MULTI_BOOT_PROMOTED_STATUSES = (
    _MULTI_BOOT_SUCCESS_STATUSES | _MULTI_BOOT_FAILURE_STATUSES
)
_RECOVERED_AFTER_FAILURE_STATUSES = frozenset({"recovered_after_failure"})
_INITIAL_FAILURE_OUTCOMES = frozenset(
    {
        "no_boot",
        "hard_fault",
        "wrong_pc",
        "misaligned_vtor",
        "config_crash",
        "config_lost",
        "memory_checks_unmet",
        "rollback_accepted",
        "toctou_corruption",
    }
)
_BOOT_MISMATCH_ISSUE_REASONS = frozenset(
    {
        "boot_outcome",
        "content_criteria",
        "otadata_expect",
        "anti_rollback",
        "reset_vector_offset",
        "memory_check",
        "config_check",
        "bootloader_integrity",
        "vtor_expectation",
        "vtor_alignment",
        "pc_expectation",
    }
)
_CONFIRM_CYCLE_ISSUE_REASONS = frozenset(
    {
        "confirm_incomplete",
        "rollback_not_ratcheted",
        "metadata_inconsistent_after_confirm",
    }
)
_NON_REPORTABLE_VALIDATION_DISPOSITIONS = frozenset(
    {
        "harness_artifact",
        "self_healed",
        "defense_in_depth",
        "no_verification_bypass",
        "dos_only",
        "low_confidence",
        "model_specific_candidate",
        "needs_mechanism_confirmation",
    }
)
_NON_REPORTABLE_VALIDATION_STAGES = frozenset({"candidate", "dismissed"})
_INSTRUCTION_SKIP_DOS_OUTCOMES = frozenset(
    {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor", "config_crash", "bus_fault"}
)
_INSTRUCTION_SKIP_SECURITY_OUTCOMES = frozenset(
    {"wrong_image", "rollback_accepted", "toctou_corruption"}
)
_KNOWN_GOOD_IMAGE_HASH_MATCHES = frozenset(
    {"exec_image", "staging_image", "expected_image"}
)

_WRITEBACK_RECONSTRUCTION_OK = frozenset({"reconstructed", "trace_replay"})
_WRITEBACK_POWER_FAULT_CODES = frozenset(
    {
        "w",
        "e",
        "a",
        "power_loss",
        "interrupted_erase",
        "multi_sector_atomicity",
    }
)
_WRITEBACK_NON_POWER_FAULT_CODES = frozenset(
    set(FAULT_TYPE_NAME_TO_CODE)
    | set(FAULT_TYPE_NAME_TO_CODE.values())
) - _WRITEBACK_POWER_FAULT_CODES
_WRITEBACK_BEYOND_TRACE_REASONS = frozenset(
    {
        "no_write_at_index",
        "no_erase_at_index",
    }
)
_WRITEBACK_UNSUPPORTED_LIFECYCLE_PREFIXES = frozenset(
    {"m", "h", "cc", "p2", "mf", "c"}
)
_WRITEBACK_UNSUPPORTED_ERASE_FAULT_CODES = frozenset(
    {"e", "a", "interrupted_erase", "multi_sector_atomicity"}
)
_WRITEBACK_KNOWN_FAULT_CODES = frozenset(
    set(FAULT_TYPE_NAME_TO_CODE)
    | set(FAULT_TYPE_NAME_TO_CODE.values())
    | set(_WRITEBACK_UNSUPPORTED_LIFECYCLE_PREFIXES)
    | {"cascade"}
)


def _normalize_slot_name(raw: Any) -> Optional[str]:
    token = str(raw or "").strip().lower()
    return token or None


def _expected_boot_slot(result: Dict[str, Any]) -> Optional[str]:
    criteria = result.get("effective_success_criteria")
    if isinstance(criteria, dict):
        approved_cfg = criteria.get("approved_image_running")
        if isinstance(approved_cfg, dict):
            approved_slot = _normalize_slot_name(approved_cfg.get("slot"))
            if approved_slot not in {None, "any"}:
                return approved_slot
        hash_slot = _normalize_slot_name(criteria.get("image_hash_slot"))
        if hash_slot not in {None, "any"}:
            return hash_slot
        vtor_slot = _normalize_slot_name(
            criteria.get("vtor_slot") or criteria.get("vtor_in_slot")
        )
        if vtor_slot not in {None, "any"}:
            return vtor_slot

    signals = result.get("signals")
    if isinstance(signals, dict):
        approved_sig = signals.get("approved_image_running")
        if isinstance(approved_sig, dict):
            approved_slot = _normalize_slot_name(approved_sig.get("slot"))
            if approved_slot not in {None, "any"}:
                return approved_slot
        hash_slot = _normalize_slot_name(signals.get("image_hash_slot"))
        if hash_slot not in {None, "any"}:
            return hash_slot

    return None


def selected_unexpected_boot_slot(result: Dict[str, Any]) -> bool:
    _, observed_slot = _effective_boot_result(result)
    observed = _normalize_slot_name(observed_slot)
    if observed is None:
        return False

    expected = _expected_boot_slot(result)
    if expected is not None:
        return observed != expected

    signals = _effective_boot_signals(result)
    if isinstance(signals, dict):
        return signals.get("vtor_ok") is False

    return False


def _base_fault_type_code(result: Dict[str, Any]) -> str:
    raw = str(result.get("fault_type") or "").strip().lower()
    if not raw:
        return ""
    return raw.split(":", 1)[0]


def result_is_software_return_code_fault(result: Dict[str, Any]) -> bool:
    """Return whether the fault reached the target as a forced return code.

    ``rc_injection`` (``x``) always does.  ``driver_error`` (``g``) does only
    when the backend routed it through the ``rc_injection`` return hook
    (``rc_injection_model: software_return_code``) and the hook applied the
    value; otherwise it stays a peripheral status-flag fault.
    """
    base = _base_fault_type_code(result)
    if base == "x":
        return True
    if base != "g":
        return False
    signals = result.get("signals")
    if not isinstance(signals, dict):
        return False
    if signals.get("rc_injection_model") != "software_return_code":
        return False
    telemetry = result.get("rc_injection")
    applied = signals.get("rc_injection_applied")
    if applied is None and isinstance(telemetry, dict):
        applied = telemetry.get("applied")
    return applied is True


def rc_injection_availability_model(result: Dict[str, Any]) -> bool:
    """Return whether a return-code injection is judged for availability."""
    return bool(
        result_is_software_return_code_fault(result)
        and str(result.get("rc_injection_severity_model") or "security")
        .strip()
        .lower()
        == "availability"
    )


def _writeback_fault_type_code(result: Dict[str, Any]) -> str:
    """Return a safe writeback classification code for a result.

    Lifecycle and compound encodings do not carry a reconstructed persisted
    snapshot in the current runner.  Keep their prefix as the classification
    code; nested codes must not make an unsupported path look like a valid
    non-power result.  Ordinary prefixed wire codes (for example ``nv:0`` and
    ``i:...``) retain their recognized base code.
    """
    raw = str(result.get("fault_type") or "").strip().lower()
    base = raw.split(":", 1)[0] if raw else ""
    if base in _WRITEBACK_UNSUPPORTED_LIFECYCLE_PREFIXES:
        return base
    return base


def writeback_reconstruction_is_valid(result: Dict[str, Any]) -> bool:
    """Return whether a writeback result has a legitimate reconstruction state.

    A reconstructed committed snapshot is required for an injected power-loss
    fault.  Controls and known non-power fault types do not mutate persisted
    state through that path.  A power-loss point that was not injected is
    valid only when the runner can establish that the requested point was
    beyond the observed trace.
    """

    if str(result.get("durability_model", "")).strip().lower() != "writeback":
        return True
    reconstruction = result.get("writeback_snapshot_reconstruction")
    if not isinstance(reconstruction, dict):
        return False
    # Erase and multi-sector atomicity faults mutate a captured snapshot in
    # ways that cannot be reconstructed from the clean baseline: interrupted
    # erases are partial and atomicity faults may corrupt a neighbouring
    # sector.  Treat even a mistakenly marked ``reconstructed`` result as
    # infrastructure-incomplete until a provenance-preserving model exists.
    raw_fault_type = str(result.get("fault_type") or "").strip().lower()
    base_fault_type = raw_fault_type.split(":", 1)[0] if raw_fault_type else ""
    if (
        base_fault_type in _WRITEBACK_UNSUPPORTED_LIFECYCLE_PREFIXES
        or base_fault_type in _WRITEBACK_UNSUPPORTED_ERASE_FAULT_CODES
    ):
        return False
    # Control observations intentionally have no injectable fault encoding.
    if result.get("is_control") is True:
        return True
    # A producer cannot make an unknown fault family valid by labeling its
    # snapshot reconstructed.  Classification must recognize the encoding
    # before accepting any reconstruction status.
    if (
        raw_fault_type not in _WRITEBACK_KNOWN_FAULT_CODES
        and base_fault_type not in _WRITEBACK_KNOWN_FAULT_CODES
    ):
        return False
    status = str(reconstruction.get("status") or "").strip().lower()
    if status in _WRITEBACK_RECONSTRUCTION_OK:
        return True
    if status != "not_required":
        return False
    fault_type = _writeback_fault_type_code(result)
    if fault_type in _WRITEBACK_NON_POWER_FAULT_CODES:
        return True
    if fault_type not in _WRITEBACK_POWER_FAULT_CODES:
        return False
    if result.get("fault_injected") is not False:
        return False

    reason = str(result.get("skip_reason") or "").strip().lower()
    if reason in _WRITEBACK_BEYOND_TRACE_REASONS or (
        reason.startswith("stage") and reason.endswith("_fault_index_beyond_writes")
    ):
        return True
    try:
        requested = int(result.get("fault_requested", result.get("fault_at")))
        actual = int(result.get("actual_writes"))
    except (TypeError, ValueError):
        return False
    return requested >= 0 and actual >= 0 and requested >= actual


def instruction_skip_severity_model(result: Dict[str, Any], default: str = "security") -> str:
    raw = str(result.get("instruction_skip_severity_model") or default or "security").strip().lower()
    return raw if raw in {"security", "availability"} else "security"


def is_instruction_skip_nonsecurity_wrong_image(result: Dict[str, Any]) -> bool:
    """Return True for instruction-skip wrong-image results that are not bypasses.

    Two patterns are treated as non-security:
    - the boot reached a known-good image hash, but not the post-update image
      that the profile expected in exec; this is a rollback/update-block event,
      not unvalidated code execution
    - the app PC landed in a valid slot and all content checks passed, but the
      VTOR handoff instruction itself was skipped; that is a handoff anomaly,
      not a validation bypass
    """

    if _base_fault_type_code(result) != "i":
        return False
    eff_outcome, _ = _effective_boot_result(result)
    if str(eff_outcome or "unknown").strip().lower() != "wrong_image":
        return False

    signals = _effective_boot_signals(result)
    if not isinstance(signals, dict) or not signals:
        return False
    if signals.get("anti_rollback_ok") is False:
        return False

    hash_match = str(signals.get("image_hash_match", "") or "").strip().lower()
    if hash_match in _KNOWN_GOOD_IMAGE_HASH_MATCHES:
        return True

    if (
        signals.get("execution_observed") is True
        and signals.get("pc_ok") is True
        and signals.get("marker_ok") is True
        and signals.get("otadata_expect_ok") is not False
        and signals.get("reset_vector_offset_ok") is not False
        and signals.get("vtor_ok") is False
    ):
        return True

    return False


def classify_instruction_skip_severity(
    result: Dict[str, Any],
    expected_outcome: str = "success",
) -> Optional[Dict[str, str]]:
    if _base_fault_type_code(result) != "i":
        return None

    eff_outcome, _ = _effective_boot_result(result)
    effective = str(eff_outcome or "unknown").strip().lower()
    raw_outcome = str(
        result.get("initial_boot_outcome") or result.get("boot_outcome") or effective
    ).strip().lower()
    expected = str(expected_outcome or "success").strip().lower()

    if is_instruction_skip_nonsecurity_wrong_image(result):
        return None
    if selected_unexpected_boot_slot(result):
        return {
            "severity": "security_bypass",
            "severity_rationale": "Fault changed boot-slot selection to a slot that does not match the declared success criteria.",
        }
    if effective in _INSTRUCTION_SKIP_SECURITY_OUTCOMES or raw_outcome in _INSTRUCTION_SKIP_SECURITY_OUTCOMES:
        return {
            "severity": "security_bypass",
            "severity_rationale": "Bootloader jumped to unvalidated or policy-rejected firmware after a single instruction skip.",
        }
    if raw_outcome in _INSTRUCTION_SKIP_DOS_OUTCOMES or effective in _INSTRUCTION_SKIP_DOS_OUTCOMES:
        if effective == expected and raw_outcome in _INSTRUCTION_SKIP_DOS_OUTCOMES:
            return {
                "severity": "dos_recovery",
                "severity_rationale": "Instruction skip caused a transient denial of service but the device recovered on a later boot.",
            }
        return {
            "severity": "dos_crash",
            "severity_rationale": "CPU crash or hang from a skipped instruction caused denial of service without booting the wrong firmware.",
        }
    return None


def annotate_instruction_skip_severity(
    result: Dict[str, Any],
    *,
    expected_outcome: str = "success",
    default_model: str = "security",
) -> Optional[Dict[str, str]]:
    result["instruction_skip_severity_model"] = instruction_skip_severity_model(
        result, default=default_model
    )
    severity_info = classify_instruction_skip_severity(result, expected_outcome=expected_outcome)
    if severity_info is not None:
        result["severity"] = severity_info["severity"]
        result["severity_rationale"] = severity_info["severity_rationale"]
    return severity_info


def _should_promote_multi_boot_final(
    mba: Dict[str, Any],
    raw_outcome: Any,
    final_outcome: Any,
) -> bool:
    """Return whether ``multi_boot_analysis`` should promote the final cycle."""
    status = mba.get("status")
    if status in _MULTI_BOOT_PROMOTED_STATUSES:
        return True
    if status == "oscillating":
        raw_norm = str(raw_outcome or "").strip().lower()
        final_norm = str(final_outcome or "").strip().lower()
        if raw_norm == "success" and final_norm in _FAILURE_BOOT_OUTCOMES:
            return True
    return False


def _effective_boot_result(result: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return (effective_outcome, effective_slot) accounting for multi-boot.

    When ``multi_boot_analysis`` is present, statuses in
    ``_MULTI_BOOT_PROMOTED_STATUSES`` (``converged``, ``rollback_converged``,
    ``recovered_after_failure``, ``failed_after_success``) promote the final
    cycle's outcome/slot over the initial boot outcome; an ``oscillating``
    sequence whose initial boot succeeded and whose final boot ended in a
    failure outcome is also promoted so a later failure cannot be hidden behind
    cycle 0's success.  When promoted, explicit top-level
    ``final_boot_outcome`` / ``final_boot_slot`` are preferred over
    ``multi_boot_analysis["final_outcome"]`` / ``["final_slot"]``.  When
    ``multi_boot_analysis`` is absent (legacy single-span payloads without
    multi-boot analysis), explicit ``final_boot_outcome`` /
    ``final_boot_slot`` are still honored.

    Statuses that are NOT promoted (except ``oscillating`` ending in failure
    after an initial ``success``):
      - initial_no_boot_recovered
      - rollback_missing
      - rollback_late
      - rollback_observed_unconfirmed
      - rollback_observed_oscillating
      - changed_unconfirmed
      - stuck_revert
      - oscillating
      - timeout
    """
    raw_outcome = result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    raw_slot = result.get("initial_boot_slot") or result.get("boot_slot")
    if result.get("timeout", False):
        return ("timeout", raw_slot)
    mba = result.get("multi_boot_analysis")
    if isinstance(mba, dict):
        if str(mba.get("status") or "").strip().lower() == "infra_error":
            infrastructure_slot = mba.get("infrastructure_error_slot")
            if infrastructure_slot is None:
                infrastructure_slot = mba.get("final_slot")
            return ("infra_error", infrastructure_slot)
        final_outcome = result.get("final_boot_outcome")
        final_slot = result.get("final_boot_slot")
        if final_outcome is None:
            final_outcome = mba.get("final_outcome")
            final_slot = mba.get("final_slot")
        if final_outcome is None:
            return (raw_outcome, raw_slot)
        if not _should_promote_multi_boot_final(mba, raw_outcome, final_outcome):
            return (raw_outcome, raw_slot)
        return (final_outcome, final_slot)
    final_outcome = result.get("final_boot_outcome")
    final_slot = result.get("final_boot_slot")
    if final_outcome is not None:
        return (final_outcome, final_slot)
    return (raw_outcome, raw_slot)


def _effective_boot_cycle_is_final(result: Dict[str, Any]) -> bool:
    """Return whether ``_effective_boot_result`` resolves to the final boot cycle."""
    if result.get("timeout", False):
        return False
    mba = result.get("multi_boot_analysis")
    boot_cycles = result.get("boot_cycles")
    raw_outcome = result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    raw_slot = result.get("initial_boot_slot") or result.get("boot_slot")
    if isinstance(mba, dict):
        final_outcome = result.get("final_boot_outcome")
        final_slot = result.get("final_boot_slot")
        if final_outcome is None:
            final_outcome = mba.get("final_outcome")
            final_slot = mba.get("final_slot")
        if final_outcome is None:
            return False
        if not _should_promote_multi_boot_final(mba, raw_outcome, final_outcome):
            return False
        if isinstance(boot_cycles, list) and len(boot_cycles) >= 2:
            return True
        if int(mba.get("completed_cycles") or 0) >= 2:
            return True
        return (raw_outcome, raw_slot) != (final_outcome, final_slot)
    final_outcome = result.get("final_boot_outcome")
    final_slot = result.get("final_boot_slot")
    if final_outcome is None:
        return False
    if isinstance(boot_cycles, list) and len(boot_cycles) >= 2:
        return True
    return (raw_outcome, raw_slot) != (final_outcome, final_slot)


def _effective_boot_signals(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return the signal dict belonging to the effective boot cycle.

    Standard runtime sweeps store cycle 0's signals in top-level
    ``result["signals"]`` and each cycle's own signals in
    ``boot_cycles[i]["signals"]``.  Aligning per-boot signal checks with
    ``_effective_boot_result`` prevents stale cycle-0 failures (for example
    ``memory_checks_ok=False``) from leaking onto a result whose final cycle
    succeeded; transient initial failures are classified explicitly via
    ``result_recovered_after_failure``.
    """
    top_signals = result.get("signals")
    top_dict = top_signals if isinstance(top_signals, dict) else {}
    boot_cycles = result.get("boot_cycles")
    mba = result.get("multi_boot_analysis")
    if (
        isinstance(mba, dict)
        and str(mba.get("status") or "").strip().lower() == "infra_error"
        and isinstance(boot_cycles, list)
    ):
        error_cycle = mba.get("infrastructure_error_cycle")
        for index, cycle in enumerate(boot_cycles):
            if not isinstance(cycle, dict):
                continue
            cycle_index = cycle.get("cycle", index)
            if error_cycle is not None and cycle_index != error_cycle:
                continue
            outcome = str(cycle.get("boot_outcome") or "").strip().lower()
            if not cycle.get("infrastructure_error") and outcome not in {
                "infra_error", "infrastructure_error"
            }:
                continue
            signals = cycle.get("signals")
            return signals if isinstance(signals, dict) else {}
        return {}
    if _effective_boot_cycle_is_final(result):
        if isinstance(boot_cycles, list) and len(boot_cycles) >= 2:
            final_cycle = boot_cycles[-1]
            if isinstance(final_cycle, dict):
                final_signals = final_cycle.get("signals")
                if isinstance(final_signals, dict):
                    return final_signals
                return {}
        raw_outcome = result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
        raw_slot = result.get("initial_boot_slot") or result.get("boot_slot")
        eff_outcome, eff_slot = _effective_boot_result(result)
        if (raw_outcome, raw_slot) != (eff_outcome, eff_slot):
            return {}
        return top_dict
    if isinstance(boot_cycles, list) and boot_cycles:
        first_cycle = boot_cycles[0]
        if isinstance(first_cycle, dict) and isinstance(first_cycle.get("signals"), dict):
            return first_cycle["signals"]
    return top_dict


def _initial_boot_signals(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return cycle 0's signal dictionary when available."""
    boot_cycles = result.get("boot_cycles")
    if isinstance(boot_cycles, list) and boot_cycles:
        first_cycle = boot_cycles[0]
        if isinstance(first_cycle, dict) and isinstance(first_cycle.get("signals"), dict):
            return first_cycle["signals"]
    top_signals = result.get("signals")
    return top_signals if isinstance(top_signals, dict) else {}


def finding_validation_disposition(result: Dict[str, Any]) -> Optional[str]:
    validation = result.get("finding_validation")
    if not isinstance(validation, dict):
        return None
    raw = validation.get("disposition")
    if raw is None:
        return None
    return str(raw).strip().lower() or None


def finding_validation_stage(result: Dict[str, Any]) -> Optional[str]:
    raw = result.get("finding_stage")
    if raw is None:
        validation = result.get("finding_validation")
        if isinstance(validation, dict):
            raw = validation.get("stage")
    if raw is None:
        return None
    return str(raw).strip().lower() or None


def finding_glitch_realism(result: Dict[str, Any]) -> Optional[str]:
    raw = result.get("glitch_realism")
    if raw is None:
        validation = result.get("finding_validation")
        if isinstance(validation, dict):
            raw = validation.get("glitch_realism")
    if raw is None:
        return None
    return str(raw).strip().lower() or None


def result_is_invalidated_finding(result: Dict[str, Any]) -> bool:
    stage = finding_validation_stage(result)
    disposition = finding_validation_disposition(result)
    if (
        disposition == "dos_only"
        and rc_injection_availability_model(result)
    ):
        # Reports produced under the default security policy may carry a stale
        # dismissed/dos_only validation.  An embedded availability policy is
        # authoritative when reports are merged or re-summarized.
        return False
    if stage in _NON_REPORTABLE_VALIDATION_STAGES:
        return True
    return disposition in _NON_REPORTABLE_VALIDATION_DISPOSITIONS


def is_resilient_rollback(result: Dict[str, Any]) -> bool:
    """Return True when the result represents a correct rollback after fault injection.

    A resilient rollback is when:
    - A fault was injected (fault_injected is True)
    - The device booted successfully (raw/initial boot_outcome is "success")
    - The final boot outcome is "wrong_image" (booted original firmware, not the
      expected post-update image)

    This is correct bootloader behavior: the bootloader detected the corrupted
    update and fell back to the known-good image.
    """
    if not result.get("fault_injected", False):
        return False
    raw_outcome = result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    raw_outcome = str(raw_outcome or "unknown").strip().lower()
    if raw_outcome != "success":
        return False
    eff_outcome, _ = _effective_boot_result(result)
    eff_outcome = str(eff_outcome or "unknown").strip().lower()
    return eff_outcome == "wrong_image"


def result_recovered_after_failure(
    result: Dict[str, Any],
    expected_outcome: str = "success",
) -> bool:
    """Return True when cycle 0 failed but the effective/final cycle recovered.

    Distinguishes transient recovery failures (for example ``['hard_fault',
    'success']`` or ``['memory_checks_unmet', 'success']``) from permanent
    bricks and from expected ``rollback_converged`` transitions.
    """
    if result_is_invalidated_finding(result):
        return False
    if result_has_initial_timeout(result):
        return False
    iskip = classify_instruction_skip_severity(result, expected_outcome=expected_outcome)
    model = instruction_skip_severity_model(result)
    if iskip is not None and model == "security" and iskip["severity"] in {"dos_crash", "dos_recovery"}:
        return False
    eff_outcome, eff_slot = _effective_boot_result(result)
    eff = str(eff_outcome or "unknown").strip().lower()
    expected = str(expected_outcome or "success").strip().lower()
    if eff != expected or selected_unexpected_boot_slot(result):
        return False
    mba = result.get("multi_boot_analysis")
    mba_status = (
        str(mba.get("status") or "").strip().lower()
        if isinstance(mba, dict)
        else ""
    )
    if mba_status == "rollback_converged":
        return False
    if mba_status in _RECOVERED_AFTER_FAILURE_STATUSES:
        return True
    if not _effective_boot_cycle_is_final(result):
        return False
    boot_cycles = result.get("boot_cycles")
    if (
        isinstance(boot_cycles, list)
        and len(boot_cycles) >= 2
        and isinstance(boot_cycles[0], dict)
    ):
        initial_outcome = str(boot_cycles[0].get("boot_outcome") or "").strip().lower()
        initial_slot = _normalize_slot_name(boot_cycles[0].get("boot_slot"))
    else:
        initial_outcome = str(
            result.get("initial_boot_outcome")
            or (mba.get("initial_outcome") if isinstance(mba, dict) else None)
            or result.get("boot_outcome")
            or ""
        ).strip().lower()
        initial_slot = _normalize_slot_name(
            result.get("initial_boot_slot")
            or (mba.get("initial_slot") if isinstance(mba, dict) else None)
            or result.get("boot_slot")
        )
    if initial_outcome in _INITIAL_FAILURE_OUTCOMES:
        return True
    if initial_outcome == "bus_fault" and rc_injection_availability_model(result):
        return True
    if initial_outcome == "wrong_image" and initial_slot == _normalize_slot_name(eff_slot):
        init_signals = _initial_boot_signals(result)
        if (
            init_signals.get("memory_checks_ok") is False
            or init_signals.get("config_checks_ok") is False
            or init_signals.get("bootloader_integrity_ok") is False
        ):
            return True
    return False


def result_issue_reasons(result: Dict[str, Any], expected_outcome: str) -> List[str]:
    """Return all issue reasons for *result* using consistent cycle semantics.

    Cycle-signal contract:
    - ``boot_outcome`` and per-boot criteria signals (``content_criteria``,
      ``otadata_expect``, ``anti_rollback``, ``reset_vector_offset``,
      ``memory_check``, ``config_check``, ``bootloader_integrity``,
      ``vtor_expectation``, ``vtor_alignment``, ``pc_expectation``) read the
      effective cycle (final cycle when promoted, cycle 0 on single-boot runs
      or when a follow-up cycle timed out).
    - ``recovered_after_failure`` compares cycle 0 against the effective/final
      cycle (cross-cycle).
    - ``semantic_assertion`` reflects the final cycle's semantic state.
    - ``invariant`` reflects profile invariants (final/configured stage for
      state invariants, all cycles for multi-boot invariants).
    - ``metadata_delta`` reflects pre-fault -> cycle 0 (before follow-up boots).
    - ``terminal_error_path_escape`` checks effective or run-wide top-level
      signals.
    - ``confirm_*`` reflects the post-confirm cycle.
    """
    reasons: List[str] = []
    if result_is_invalidated_finding(result):
        return reasons
    # A wall-clock timeout has no terminal boot evidence.  Keep it visible as
    # an operational timeout, but never reinterpret the copied raw no_boot
    # fields as a security failure.
    if result_has_initial_timeout(result):
        return reasons
    iskip = classify_instruction_skip_severity(result, expected_outcome=expected_outcome)
    model = instruction_skip_severity_model(result)
    safe_instruction_skip_divergence = (
        model == "security" and is_instruction_skip_nonsecurity_wrong_image(result)
    )
    if iskip is not None:
        if model == "security" and iskip["severity"] in {"dos_crash", "dos_recovery"}:
            return reasons
    eff_outcome, _ = _effective_boot_result(result)
    unexpected_slot = selected_unexpected_boot_slot(result)
    # bus_fault is safe denial-of-service (HardFault on real silicon) — not
    # a security finding.  The bootloader crashed before reaching
    # validation/invariant code paths, so all issue signals are noise.
    if (
        eff_outcome == "bus_fault"
        and not unexpected_slot
        and not rc_injection_availability_model(result)
    ):
        return reasons
    # timeout means the bootloader was still working when the wall-clock
    # budget expired.  This is not a failure — increase run_duration.
    if eff_outcome == "timeout" and not unexpected_slot:
        return reasons
    if unexpected_slot and not safe_instruction_skip_divergence:
        reasons.append("boot_outcome")
    if eff_outcome != expected_outcome:
        # Resilient rollback: fault during OTA update caused the bootloader to
        # correctly fall back to the original image.  The device booted fine
        # (raw outcome = success) but not into the expected post-update image
        # (effective outcome = wrong_image).  This is correct behavior, not an
        # issue.
        if not is_resilient_rollback(result) and not safe_instruction_skip_divergence:
            reasons.append("boot_outcome")
    signals = _effective_boot_signals(result)
    if isinstance(signals, dict):
        if signals.get("marker_ok") is False and not safe_instruction_skip_divergence:
            reasons.append("content_criteria")
        if signals.get("otadata_expect_ok") is False:
            reasons.append("otadata_expect")
        if signals.get("anti_rollback_ok") is False:
            reasons.append("anti_rollback")
        if signals.get("reset_vector_offset_ok") is False:
            reasons.append("reset_vector_offset")
        if signals.get("memory_checks_ok") is False:
            reasons.append("memory_check")
        if signals.get("config_checks_ok") is False:
            reasons.append("config_check")
        if signals.get("bootloader_integrity_ok") is False:
            reasons.append("bootloader_integrity")
        # If the boot landed in the expected coarse outcome but still failed
        # execution checks, preserve that mismatch explicitly.
        if signals.get("expectations_met") is False:
            if signals.get("vtor_ok") is False and not safe_instruction_skip_divergence:
                reasons.append("vtor_expectation")
            if signals.get("vtor_aligned") is False:
                reasons.append("vtor_alignment")
            if signals.get("pc_ok") is False:
                reasons.append("pc_expectation")
        approved_sig = signals.get("approved_image_running")
        if isinstance(approved_sig, dict) and approved_sig.get("ok") is False:
            failed_part = str(approved_sig.get("failed_part") or "").strip().lower()
            if failed_part == "digest" and not safe_instruction_skip_divergence:
                reasons.append("content_criteria")
            elif failed_part in {"extent", "dwell"}:
                reasons.append("pc_expectation")
    if result_recovered_after_failure(result, expected_outcome):
        reasons.append("recovered_after_failure")
    if result.get("semantic_assertion_failures"):
        reasons.append("semantic_assertion")
    if result.get("invariant_violations"):
        reasons.append("invariant")
    if result.get("metadata_delta_violations"):
        reasons.append("metadata_delta")
    top_signals = result.get("signals") or {}
    if (
        (isinstance(signals, dict) and signals.get("terminal_error_escaped"))
        or (isinstance(top_signals, dict) and top_signals.get("terminal_error_escaped"))
    ):
        reasons.append("terminal_error_path_escape")
    # Confirm-cycle specific finding categories.
    confirm_meta = result.get("confirm_cycle")
    if isinstance(confirm_meta, dict):
        if confirm_meta.get("confirm_incomplete"):
            reasons.append("confirm_incomplete")
        if confirm_meta.get("rollback_not_ratcheted"):
            reasons.append("rollback_not_ratcheted")
        if confirm_meta.get("metadata_inconsistent_after_confirm"):
            reasons.append("metadata_inconsistent_after_confirm")
    # Preserve stable ordering while dropping duplicates from overlapping
    # criteria signals.
    deduped: List[str] = []
    seen = set()
    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        deduped.append(reason)
    return deduped


def classify_issue_category(
    result: Dict[str, Any],
    expected_outcome: str = "success",
) -> Optional[str]:
    """Return one mutually exclusive primary category for an issue point."""
    reasons = result_issue_reasons(result, expected_outcome)
    if not reasons:
        return None
    reason_set = set(reasons)
    if result_is_brick(result) or bool(reason_set & _BOOT_MISMATCH_ISSUE_REASONS):
        return "boot_mismatch"
    if "recovered_after_failure" in reason_set:
        return "recovered_after_failure"
    if "semantic_assertion" in reason_set:
        return "semantic"
    if "invariant" in reason_set:
        return "invariant"
    if "metadata_delta" in reason_set:
        return "metadata_delta"
    if bool(reason_set & _CONFIRM_CYCLE_ISSUE_REASONS):
        return "confirm_cycle"
    if "terminal_error_path_escape" in reason_set:
        return "terminal_error_escape"
    return "other"


def result_has_issues(result: Dict[str, Any], expected_outcome: str) -> bool:
    return bool(result_issue_reasons(result, expected_outcome))


def result_is_infrastructure_error(result: Dict[str, Any]) -> bool:
    """Return whether the effective result is an infrastructure failure."""
    if bool(result.get("infrastructure_error")):
        return True
    effective_outcome, _ = _effective_boot_result(result)
    return str(effective_outcome or "").strip().lower() in {
        "infra_error",
        "infrastructure_error",
    }


def result_is_skipped(result: Dict[str, Any]) -> bool:
    """Return whether the effective result is explicitly skipped."""
    effective_outcome, _ = _effective_boot_result(result)
    return str(effective_outcome or "").strip().lower() == "skipped"


def result_is_timeout(result: Dict[str, Any]) -> bool:
    if result_has_initial_timeout(result):
        return True
    cycles = result.get("boot_cycles")
    if isinstance(cycles, list) and cycles:
        if any(
            cycle_has_unresolved_timeout(cycle)
            for cycle in cycles if isinstance(cycle, dict)
        ):
            return True
        # A recorded cycle-0 terminal result outranks copied aggregate/raw
        # timeout fields, including a stale multi_boot_analysis status.
        return False
    mba = result.get("multi_boot_analysis")
    if isinstance(mba, dict) and mba.get("status") == "timeout":
        return True
    if result.get("timeout", False):
        # Some older result producers set a broad timeout flag for the
        # operation even after collecting a concrete terminal boot outcome.
        # Keep that evidence authoritative; only promote the flag when the
        # boot outcome is absent or itself inconclusive.
        raw_boot_outcome = str(
            result.get("initial_boot_outcome") or result.get("boot_outcome") or ""
        ).strip().lower()
        if raw_boot_outcome and raw_boot_outcome not in {"unknown", "no_boot", "timeout"}:
            return False
        return True
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    return outcome == "timeout"


def result_has_initial_timeout(result: Dict[str, Any]) -> bool:
    """Return whether the initial boot observation timed out.

    A later timed-out follow-up is distinct from an initial wall-clock
    timeout: the former may preserve a concrete initial failure, while the
    latter has no terminal boot evidence and must not be validated.
    """
    cycles = result.get("boot_cycles")
    if isinstance(cycles, list) and cycles:
        first = cycles[0]
        if isinstance(first, dict):
            return cycle_has_unresolved_timeout(first)
        return False

    initial_outcome = result.get("initial_boot_outcome")
    if str(initial_outcome or "").strip().lower() == "timeout":
        return True

    if result.get("timeout", False):
        # A concrete terminal outcome wins over the broad legacy flag.  A
        # raw no_boot remains inconclusive and is still operationally timed
        # out unless cycle-0 evidence below establishes a real stall.
        raw_boot_outcome = str(
            result.get("initial_boot_outcome") or result.get("boot_outcome") or ""
        ).strip().lower()
        if raw_boot_outcome and raw_boot_outcome not in {"unknown", "no_boot", "timeout"}:
            return False
        return True

    if str(result.get("boot_outcome") or "").strip().lower() == "timeout":
        return True
    signals = result.get("signals")
    if isinstance(signals, dict):
        for key in ("phase1_stop_reason", "phase2_stop_reason"):
            reason = str(signals.get(key) or "")
            if cycle_has_unresolved_timeout(
                {
                    "boot_outcome": (
                        result.get("boot_outcome")
                        or result.get("initial_boot_outcome")
                    ),
                    "stop_reason": reason,
                    "signals": signals,
                }
            ):
                return True
    return False


def result_is_brick(result: Dict[str, Any]) -> bool:
    if result_is_invalidated_finding(result):
        return False
    if result_has_initial_timeout(result):
        return False
    iskip = classify_instruction_skip_severity(result)
    if iskip is not None and iskip["severity"] in {"dos_crash", "dos_recovery"}:
        return False
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    # "timeout" is NOT a brick — the bootloader was still working when
    # the wall-clock budget expired. Increase run_duration to resolve.
    return bool(
        outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor", "config_crash"}
        or (outcome == "bus_fault" and rc_injection_availability_model(result))
    )


def result_is_recovery(result: Dict[str, Any], expected_outcome: str) -> bool:
    """Return whether a completed fault point reached an acceptable boot state."""
    if result_is_timeout(result) or result_has_issues(result, expected_outcome):
        return False
    outcome, _ = _effective_boot_result(result)
    normalized = str(outcome or "unknown").strip().lower()
    expected = str(expected_outcome or "success").strip().lower()
    return normalized == expected or is_resilient_rollback(result)


def classify_failure_class(result: Dict[str, Any]) -> str:
    """Return normalized failure class for a sweep result.

    Recognized classes:
      - recoverable: device booted successfully after fault
      - wrong_image: device booted the wrong firmware image
      - silent_corruption: device booted but image integrity is unknown
      - unrecoverable: device bricked (no boot, hard fault, etc.)
      - rollback_accepted: device accepted a downgrade without rejection
      - toctou_corruption: corruption injected between validation and execution
    """
    availability_rc = rc_injection_availability_model(result)
    eff_outcome, _ = _effective_boot_result(result)
    eff_outcome_norm = str(eff_outcome or "unknown").strip().lower()
    raw = str(result.get("fault_class", "") or "").strip().lower()
    if (
        raw
        and not (availability_rc and raw == "safe_dos")
        and not (
            raw == "recoverable"
            and _effective_boot_cycle_is_final(result)
            and eff_outcome_norm in _FAILURE_BOOT_OUTCOMES
        )
    ):
        return raw

    disposition = finding_validation_disposition(result)
    stage = finding_validation_stage(result)
    if stage == "candidate":
        return "candidate"
    if disposition == "harness_artifact":
        return "harness_artifact"
    if disposition == "self_healed":
        return "self_healed"
    if disposition == "defense_in_depth":
        return "defense_in_depth"
    if disposition == "no_verification_bypass":
        return "defense_in_depth"
    if disposition == "dos_only" and not availability_rc:
        return "safe_dos"
    if disposition == "low_confidence":
        return "low_confidence"
    if disposition == "model_specific_candidate":
        return "candidate"
    if disposition == "needs_mechanism_confirmation":
        return "candidate"

    # Metadata delta classifications: boot count suppression/exhaustion,
    # rollback floor regression.
    md_violations = result.get("metadata_delta_violations")
    if isinstance(md_violations, list) and md_violations:
        categories = {v.get("finding_category") for v in md_violations if isinstance(v, dict)}
        if "boot_count_exhausted" in categories:
            return "boot_count_exhausted"
        if "boot_count_suppressed" in categories:
            return "boot_count_suppressed"
        if "rollback_floor_decreased" in categories:
            return "rollback_floor_decreased"
        # Generic metadata delta violation.
        return "metadata_delta_violation"

    # NVS-specific classifications take precedence when present.
    config_outcome = result.get("config_outcome")
    if config_outcome == "config_lost":
        return "config_lost"
    if config_outcome == "config_crash":
        return "config_crash"

    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    iskip = classify_instruction_skip_severity(result)
    if iskip is not None and iskip["severity"] in {"dos_crash", "dos_recovery"}:
        return "safe_dos"
    if outcome == "config_lost":
        return "config_lost"
    if outcome == "config_crash":
        return "config_crash"
    if outcome == "rollback_accepted":
        return "rollback_accepted"
    if outcome == "toctou_corruption":
        return "toctou_corruption"
    if selected_unexpected_boot_slot(result):
        return "wrong_image"
    if outcome == "success":
        return "recoverable"
    if outcome == "memory_checks_unmet":
        return "memory_checks_unmet"
    if outcome == "bus_fault":
        return "unrecoverable" if availability_rc else "safe_dos"
    if outcome == "wrong_image":
        if is_resilient_rollback(result):
            return "resilient_rollback"
        signals = _effective_boot_signals(result)
        top_signals = result.get("signals")
        if not isinstance(top_signals, dict):
            top_signals = {}
        hash_match = str(
            signals.get("image_hash_match")
            or top_signals.get("image_hash_match")
            or ""
        ).strip().lower()
        expected_slot = str(
            signals.get("image_hash_slot")
            or top_signals.get("image_hash_slot")
            or ""
        ).strip().lower()
        _, eff_slot = _effective_boot_result(result)
        boot_slot = str(eff_slot or result.get("boot_slot", "") or "").strip().lower()
        if hash_match == "unknown" and (
            not expected_slot or expected_slot == "any" or boot_slot == expected_slot
        ):
            return "silent_corruption"
        return "wrong_image"
    if outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}:
        return "unrecoverable"
    return "unrecoverable"


@dataclasses.dataclass
class InterestingPoint:
    """A fault point identified as worth exploring in multi-fault runs.

    Carries provenance about *why* the point was selected, enabling
    downstream generators to produce human-readable rationale for each
    planned multi-fault sequence.
    """

    fault_at: int
    reason: str  # "brick", "wrong_image", "semantic", "invariant", "issue"
    boot_outcome: str
    fault_address: Optional[str] = None
    # Multi-fault stage codes of every issue-producing result at this point.
    fault_types: Tuple[str, ...] = ("w",)


def _interesting_multi_fault_points(
    results: List[Dict[str, Any]],
    expected_outcome: str,
) -> List[InterestingPoint]:
    """Return fault points worth exploring with sequential multi-fault runs.

    Each returned ``InterestingPoint`` carries provenance about why the
    point was selected (brick, wrong_image, semantic assertion failure,
    invariant violation, or generic boot-outcome mismatch).
    """
    _REASON_SEVERITY = {"brick": 0, "wrong_image": 1, "semantic": 2, "invariant": 3, "issue": 4}
    points: Dict[int, InterestingPoint] = {}
    point_types: Dict[int, set] = {}
    for result in results:
        if result.get("is_control", False):
            continue
        if not result.get("fault_injected", False):
            continue
        if result_is_brick(result) or result_has_issues(result, expected_outcome):
            fp = result.get("fault_at")
            if fp is not None:
                eff_outcome, _ = _effective_boot_result(result)
                eff_outcome_str = str(eff_outcome or "unknown").strip().lower()
                # Determine the most specific reason.
                if result_is_brick(result):
                    reason = "brick"
                elif eff_outcome_str == "wrong_image":
                    reason = "wrong_image"
                elif result.get("semantic_assertion_failures"):
                    reason = "semantic"
                elif result.get("invariant_violations"):
                    reason = "invariant"
                else:
                    reason = "issue"
                key = int(fp)
                point_types.setdefault(key, set()).add(
                    multi_fault_stage_code(result.get("fault_type"))
                )
                existing = points.get(key)
                if existing is None or _REASON_SEVERITY[reason] < _REASON_SEVERITY[existing.reason]:
                    points[key] = InterestingPoint(
                        fault_at=key,
                        reason=reason,
                        boot_outcome=eff_outcome_str,
                        fault_address=result.get("fault_address"),
                    )
    return sorted(
        (
            dataclasses.replace(point, fault_types=tuple(sorted(point_types[key])))
            for key, point in points.items()
        ),
        key=lambda p: p.fault_at,
    )
