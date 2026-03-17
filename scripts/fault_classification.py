"""Result classification: boot outcome promotion, brick/issue detection, failure classes.

Extracted from audit_bootloader.py to reduce its size and provide a
focused module for result classification logic.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional, Tuple


# Multi-boot statuses that represent a successful final state.
_MULTI_BOOT_SUCCESS_STATUSES = frozenset({"converged", "rollback_converged"})


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
    raw_outcome = result.get("initial_boot_outcome", result.get("boot_outcome", "unknown"))
    raw_slot = result.get("initial_boot_slot", result.get("boot_slot"))
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
    raw_outcome = result.get("initial_boot_outcome", result.get("boot_outcome", "unknown"))
    raw_outcome = str(raw_outcome or "unknown").strip().lower()
    if raw_outcome != "success":
        return False
    eff_outcome, _ = _effective_boot_result(result)
    eff_outcome = str(eff_outcome or "unknown").strip().lower()
    return eff_outcome == "wrong_image"


def result_issue_reasons(result: Dict[str, Any], expected_outcome: str) -> List[str]:
    reasons: List[str] = []
    eff_outcome, _ = _effective_boot_result(result)
    # bus_fault is safe denial-of-service (HardFault on real silicon) — not
    # a security finding.  The bootloader crashed before reaching
    # validation/invariant code paths, so all issue signals are noise.
    if eff_outcome == "bus_fault":
        return reasons
    if eff_outcome != expected_outcome:
        # Resilient rollback: fault during OTA update caused the bootloader to
        # correctly fall back to the original image.  The device booted fine
        # (raw outcome = success) but not into the expected post-update image
        # (effective outcome = wrong_image).  This is correct behavior, not an
        # issue.
        if not is_resilient_rollback(result):
            reasons.append("boot_outcome")
    if result.get("semantic_assertion_failures"):
        reasons.append("semantic_assertion")
    if result.get("invariant_violations"):
        reasons.append("invariant")
    return reasons


def result_has_issues(result: Dict[str, Any], expected_outcome: str) -> bool:
    return bool(result_issue_reasons(result, expected_outcome))


def result_is_brick(result: Dict[str, Any]) -> bool:
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
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

    # NVS-specific classifications take precedence when present.
    config_outcome = result.get("config_outcome")
    if config_outcome == "config_lost":
        return "config_lost"
    if config_outcome == "config_crash":
        return "config_crash"

    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    if outcome == "config_lost":
        return "config_lost"
    if outcome == "config_crash":
        return "config_crash"
    if outcome == "success":
        return "recoverable"
    if outcome == "bus_fault":
        return "safe_dos"
    if outcome == "rollback_accepted":
        return "rollback_accepted"
    if outcome == "toctou_corruption":
        return "toctou_corruption"
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
