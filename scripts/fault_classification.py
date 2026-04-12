"""Result classification: boot outcome promotion, brick/issue detection, failure classes.

Extracted from audit_bootloader.py to reduce its size and provide a
focused module for result classification logic.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional, Tuple


# Multi-boot statuses that represent a successful final state.
_MULTI_BOOT_SUCCESS_STATUSES = frozenset({"converged", "rollback_converged"})
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


def _normalize_slot_name(raw: Any) -> Optional[str]:
    token = str(raw or "").strip().lower()
    return token or None


def _expected_boot_slot(result: Dict[str, Any]) -> Optional[str]:
    criteria = result.get("effective_success_criteria")
    if isinstance(criteria, dict):
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

    signals = result.get("signals")
    if isinstance(signals, dict):
        return signals.get("vtor_ok") is False

    return False


def _base_fault_type_code(result: Dict[str, Any]) -> str:
    raw = str(result.get("fault_type") or "").strip().lower()
    if not raw:
        return ""
    return raw.split(":", 1)[0]


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

    signals = result.get("signals")
    if not isinstance(signals, dict):
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


def _effective_boot_result(result: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return (effective_outcome, effective_slot) accounting for multi-boot.

    Prefer explicit top-level ``final_boot_outcome`` / ``final_boot_slot`` when
    present. Otherwise fall back to ``multi_boot_analysis`` promotion for
    backwards compatibility, and finally to the raw initial ``boot_outcome`` /
    ``boot_slot``.

    Statuses that are NOT promoted:
      - rollback_missing
      - rollback_late
      - rollback_observed_oscillating
      - stuck_revert
      - oscillating
    """
    raw_outcome = result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    raw_slot = result.get("initial_boot_slot") or result.get("boot_slot")
    if result.get("timeout", False):
        return ("timeout", raw_slot)
    final_outcome = result.get("final_boot_outcome")
    final_slot = result.get("final_boot_slot")
    if final_outcome is not None:
        return (final_outcome, final_slot)
    mba = result.get("multi_boot_analysis")
    if not isinstance(mba, dict):
        return (raw_outcome, raw_slot)
    status = mba.get("status")
    if status not in _MULTI_BOOT_SUCCESS_STATUSES:
        return (raw_outcome, raw_slot)
    final_outcome = mba.get("final_outcome")
    final_slot = mba.get("final_slot")
    if final_outcome is None:
        return (raw_outcome, raw_slot)
    return (final_outcome, final_slot)


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
    if stage in _NON_REPORTABLE_VALIDATION_STAGES:
        return True
    disposition = finding_validation_disposition(result)
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


def result_issue_reasons(result: Dict[str, Any], expected_outcome: str) -> List[str]:
    reasons: List[str] = []
    if result_is_invalidated_finding(result):
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
    if eff_outcome == "bus_fault" and not unexpected_slot:
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
    signals = result.get("signals") or {}
    if isinstance(signals, dict):
        if signals.get("marker_ok") is False and not safe_instruction_skip_divergence:
            reasons.append("content_criteria")
        if signals.get("otadata_expect_ok") is False:
            reasons.append("otadata_expect")
        if signals.get("anti_rollback_ok") is False:
            reasons.append("anti_rollback")
        if signals.get("reset_vector_offset_ok") is False:
            reasons.append("reset_vector_offset")
        # If the boot landed in the expected coarse outcome but still failed
        # execution checks, preserve that mismatch explicitly.
        if signals.get("expectations_met") is False:
            if signals.get("vtor_ok") is False and not safe_instruction_skip_divergence:
                reasons.append("vtor_expectation")
            if signals.get("vtor_aligned") is False:
                reasons.append("vtor_alignment")
            if signals.get("pc_ok") is False:
                reasons.append("pc_expectation")
    if result.get("semantic_assertion_failures"):
        reasons.append("semantic_assertion")
    if result.get("invariant_violations"):
        reasons.append("invariant")
    if result.get("metadata_delta_violations"):
        reasons.append("metadata_delta")
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


def result_has_issues(result: Dict[str, Any], expected_outcome: str) -> bool:
    return bool(result_issue_reasons(result, expected_outcome))


def result_is_timeout(result: Dict[str, Any]) -> bool:
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    return outcome == "timeout"


def result_is_brick(result: Dict[str, Any]) -> bool:
    if result_is_invalidated_finding(result):
        return False
    iskip = classify_instruction_skip_severity(result)
    if iskip is not None and iskip["severity"] in {"dos_crash", "dos_recovery"}:
        return False
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    # "timeout" is NOT a brick — the bootloader was still working when
    # the wall-clock budget expired. Increase run_duration to resolve.
    return outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor", "config_crash"}


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
    raw = str(result.get("fault_class", "") or "").strip().lower()
    if raw:
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
    if disposition == "dos_only":
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
    if outcome == "bus_fault":
        return "safe_dos"
    if outcome == "wrong_image":
        if is_resilient_rollback(result):
            return "resilient_rollback"
        signals = result.get("signals", {})
        if not isinstance(signals, dict):
            signals = {}
        hash_match = str(signals.get("image_hash_match", "") or "").strip().lower()
        expected_slot = str(signals.get("image_hash_slot", "") or "").strip().lower()
        boot_slot = str(result.get("boot_slot", "") or "").strip().lower()
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
                existing = points.get(key)
                if existing is None or _REASON_SEVERITY[reason] < _REASON_SEVERITY[existing.reason]:
                    points[key] = InterestingPoint(
                        fault_at=key,
                        reason=reason,
                        boot_outcome=eff_outcome_str,
                        fault_address=result.get("fault_address"),
                    )
    return sorted(points.values(), key=lambda p: p.fault_at)
