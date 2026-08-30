"""Sweep result summarization, failure categorization, and git metadata.

Extracted from audit_bootloader.py to provide a focused module for
post-sweep reporting and region enrichment logic.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from fault_classification import (
    _effective_boot_result,
    annotate_instruction_skip_severity,
    classify_failure_class,
    classify_instruction_skip_severity,
    finding_glitch_realism,
    finding_validation_stage,
    finding_validation_disposition,
    instruction_skip_severity_model,
    is_resilient_rollback,
    result_has_issues,
    result_is_brick,
    result_is_timeout,
    result_issue_reasons,
)
from fault_inject import (
    BootloaderRegionConfig,
    MetadataFaultRegion,
    classify_fault_region,
    validate_bootloader_vector_table,
)
from bypass_probe import (
    CLASSIFICATION_NO_PROBES,
    build_defense_in_depth_layers,
    classify_probe_result,
)
from fault_types import _fault_type_label
from profile_loader import ProfileConfig
from read_fault_translation import (
    ReadFaultStats,
    cpu_path_capability_warning,
    read_fault_warning,
)


def _fault_type_base_code(fault_type: Any) -> str:
    raw = str(fault_type or "").strip().lower()
    if not raw:
        return ""
    return raw.split(":", 1)[0]


def enrich_results_with_fault_regions(
    results,  # type: List[Dict[str, Any]]
    metadata_regions,  # type: List[MetadataFaultRegion]
    bootloader_region=None,  # type: Optional[BootloaderRegionConfig]
):
    # type: (...) -> None
    """Annotate each result dict with a 'fault_region' classification."""
    if not metadata_regions and bootloader_region is None:
        return
    for r in results:
        if r.get("is_control", False):
            continue
        fault_addr = r.get("fault_address", "0x00000000")
        if isinstance(fault_addr, str):
            addr = int(fault_addr, 16)
        else:
            addr = int(fault_addr)
        r["fault_region"] = classify_fault_region(addr, metadata_regions, bootloader_region=bootloader_region)


def compute_region_breakdown(
    results,  # type: List[Dict[str, Any]]
    expected_outcome,  # type: str
):
    # type: (...) -> Dict[str, Dict[str, int]]
    """Compute per-region brick/issue/total counts from enriched results."""
    breakdown = {}  # type: Dict[str, Dict[str, int]]
    for r in results:
        if r.get("is_control", False):
            continue
        if not r.get("fault_injected", False):
            continue
        region = r.get("fault_region")
        if region is None:
            continue
        if region not in breakdown:
            breakdown[region] = {"total": 0, "bricks": 0, "issues": 0, "recoveries": 0}
        bucket = breakdown[region]
        bucket["total"] += 1
        if result_is_brick(r):
            bucket["bricks"] += 1
        if result_has_issues(r, expected_outcome):
            bucket["issues"] += 1
        else:
            bucket["recoveries"] += 1
    return breakdown


def check_bootloader_integrity(
    flash_bytes: bytes,
    bootloader_region: BootloaderRegionConfig,
    sram_start: int = 0x20000000,
    sram_end: int = 0x30000000,
):
    # type: (...) -> Tuple[bool, str]
    """Validate the bootloader region's vector table."""
    region_offset = bootloader_region.base
    region_end = region_offset + bootloader_region.size
    if region_end > len(flash_bytes):
        return False, "flash snapshot too small for bootloader region"
    region_data = flash_bytes[region_offset:region_end]
    return validate_bootloader_vector_table(
        region_data,
        bootloader_region.base,
        bootloader_region.size,
        sram_start=sram_start,
        sram_end=sram_end,
    )


def categorize_failure(
    result: Dict[str, Any],
    total_writes: int,
    profile: ProfileConfig,
) -> Dict[str, Any]:
    """Classify a single failure by outcome type and fault region."""
    fp = result.get("fault_at", 0)
    eff_outcome, _ = _effective_boot_result(result)
    outcome = eff_outcome if eff_outcome is not None else "unknown"
    fault_addr = result.get("fault_address", "0x00000000")

    # Parse fault address.
    if isinstance(fault_addr, str):
        addr = int(fault_addr, 16)
    else:
        addr = int(fault_addr)

    # Determine which memory region the faulted write targeted.
    # MCUboot puts trailers at the end of each slot (last page), so
    # check trailer before data to get the more specific classification.
    region = "unknown"
    page_size = getattr(profile.memory, "page_size", 4096)
    for slot_name, slot_info in profile.memory.slots.items():
        slot_end = slot_info.base + slot_info.size
        if slot_end - page_size <= addr < slot_end:
            region = slot_name + "_trailer"
            break
        if slot_info.base <= addr < slot_end:
            region = slot_name + "_data"
            break

    # Swap phase based on position.
    if total_writes > 0:
        pct = fp / total_writes
    else:
        pct = 0.0
    if pct < 0.01:
        phase = "early"
    elif pct > 0.99:
        phase = "late"
    else:
        phase = "mid"

    payload = {
        "fault_at": fp,
        "outcome": outcome,
        "failure_class": classify_failure_class(result),
        "fault_address": fault_addr,
        "region": region,
        "phase": phase,
        "position_pct": round(pct * 100, 2),
    }
    issue_reasons = result_issue_reasons(
        result,
        getattr(profile.expect, "control_outcome", "success") if profile else "success",
    )
    if issue_reasons:
        payload["issue_reasons"] = issue_reasons
    if result.get("semantic_assertion_failures"):
        payload["semantic_assertion_failures"] = result.get("semantic_assertion_failures")
    if result.get("semantic_observation_failures"):
        payload["semantic_observation_failures"] = result.get(
            "semantic_observation_failures"
        )
    if result.get("invariant_violations"):
        payload["invariant_violations"] = result.get("invariant_violations")
    if result.get("metadata_delta_violations"):
        payload["metadata_delta_violations"] = result.get("metadata_delta_violations")
    if result.get("fault_sequence"):
        payload["fault_sequence"] = result["fault_sequence"]
    window = result.get("fault_window")
    if isinstance(window, dict):
        payload["fault_window"] = window
    validation = result.get("finding_validation")
    if isinstance(validation, dict):
        payload["finding_validation"] = validation
    finding_stage = finding_validation_stage(result)
    if finding_stage is not None:
        payload["finding_stage"] = finding_stage
    if result.get("glitch_models") is not None:
        payload["glitch_models"] = result.get("glitch_models")
    realism = finding_glitch_realism(result)
    if realism is not None:
        payload["glitch_realism"] = realism
    if result.get("severity") is not None:
        payload["severity"] = result.get("severity")
    if result.get("severity_rationale"):
        payload["severity_rationale"] = result.get("severity_rationale")
    signals = result.get("signals") or {}
    if isinstance(signals, dict):
        if signals.get("function_return_probes") is not None:
            payload["function_return_probes"] = signals.get("function_return_probes")
        if signals.get("verification_probe_classification") is not None:
            payload["verification_probe_classification"] = signals.get(
                "verification_probe_classification"
            )
        if signals.get("verification_defense_in_depth") is not None:
            payload["verification_defense_in_depth"] = signals.get(
                "verification_defense_in_depth"
            )
        if signals.get("verification_bypass_labels"):
            payload["verification_bypass_labels"] = signals.get(
                "verification_bypass_labels"
            )
        if signals.get("verification_probes"):
            payload["verification_probes"] = signals.get("verification_probes")
        if signals.get("verification_full_bypass") is not None:
            payload["verification_full_bypass"] = bool(
                signals.get("verification_full_bypass")
            )
    # Per-result defense-in-depth layer breakdown.
    probe_result = classify_probe_result(result)
    if probe_result["classification"] != CLASSIFICATION_NO_PROBES:
        payload["defense_in_depth_layers"] = {
            "classification": probe_result["classification"],
            "defense_in_depth": probe_result["defense_in_depth"],
            "layers": probe_result["layers"],
            "bypassed_labels": probe_result["bypassed_labels"],
            "full_bypass": probe_result["full_bypass"],
        }
    if isinstance(validation, dict):
        if validation.get("negative_evidence"):
            payload["negative_evidence"] = validation.get("negative_evidence")
        if validation.get("counterfactuals"):
            payload["counterfactuals"] = validation.get("counterfactuals")
        if validation.get("skeptical_summary"):
            payload["skeptical_summary"] = validation.get("skeptical_summary")
    confirm_meta = result.get("confirm_cycle")
    if isinstance(confirm_meta, dict):
        payload["confirm_cycle"] = {
            k: v for k, v in confirm_meta.items()
            if k in ("confirm_incomplete", "rollback_not_ratcheted",
                      "metadata_inconsistent_after_confirm", "assertion_results")
        }
    return payload


def summarize_runtime_sweep(
    results: List[Dict[str, Any]],
    total_writes: int = 0,
    profile: Optional[ProfileConfig] = None,
    metadata_regions: Optional[List[MetadataFaultRegion]] = None,
    calibration_coverage: Optional[Dict[str, Any]] = None,
    expected_fault_points: Optional[int] = None,
    expected_control_points: int = 1,
) -> Dict[str, Any]:
    """Compute summary statistics from runtime sweep results."""
    non_control = [r for r in results if not r.get("is_control", False)]
    control = [r for r in results if r.get("is_control", False)]
    rc_telemetry = [
        r.get("rc_injection") for r in results
        if str(r.get("fault_type", "") or "").split(":", 1)[0] == "x"
        and isinstance(r.get("rc_injection"), dict)
    ]
    rc_cfg = getattr(getattr(profile, "fault_sweep", None), "rc_injection_config", None)
    if rc_cfg is not None and bool(getattr(rc_cfg, "require_applied", True)):
        # Validate the runtime contract at the reporting boundary too.  This
        # protects callers that construct result dictionaries without using
        # the Renode epilogue and keeps a missing return hook fail-closed.
        for result in non_control:
            fault_type = str(result.get("fault_type", "") or "").split(":", 1)[0]
            telemetry = result.get("rc_injection")
            if (
                fault_type == "x"
                and result.get("fault_injected") is True
                and (not isinstance(telemetry, dict) or not telemetry.get("applied"))
            ):
                result["infrastructure_error"] = True
                result["error_kind"] = "rc_injection_not_applied"
                result["boot_outcome"] = "infra_error"
    returned_fault_points = len(non_control)
    if expected_fault_points is None:
        planned_fault_points = returned_fault_points
        planner_count_supplied = False
    else:
        planned_fault_points = int(expected_fault_points)
        if planned_fault_points < 0:
            raise ValueError("expected_fault_points must be non-negative")
        planner_count_supplied = True
    missing_result_points = max(0, planned_fault_points - returned_fault_points)
    extra_result_points = max(0, returned_fault_points - planned_fault_points)
    result_cardinality_mismatch = missing_result_points + extra_result_points

    # Fail-closed: a wire value such as the string ``"false"`` must never be
    # interpreted as a fired fault merely because it is truthy in Python.
    malformed_fault_injection_results = [
        r for r in non_control if type(r.get("fault_injected")) is not bool
    ]
    injected = [r for r in non_control if r.get("fault_injected") is True]
    timeout_results = [
        r for r in non_control
        if bool(r.get("timeout")) or _effective_boot_result(r)[0] == "timeout"
    ]
    infrastructure_errors = [
        r for r in non_control
        if bool(r.get("infrastructure_error"))
        or _effective_boot_result(r)[0] == "infra_error"
    ]
    skipped_results = [
        r for r in non_control if _effective_boot_result(r)[0] == "skipped"
    ]
    control_timeouts = [
        r for r in control
        if bool(r.get("timeout")) or _effective_boot_result(r)[0] == "timeout"
    ]
    control_infrastructure_errors = [
        r for r in control
        if bool(r.get("infrastructure_error"))
        or _effective_boot_result(r)[0] == "infra_error"
    ]
    control_skipped_results = [
        r for r in control if _effective_boot_result(r)[0] == "skipped"
    ]
    malformed_control_results = [
        r for r in control if type(r.get("fault_injected")) is not bool
    ]
    faulted_control_results = [
        r for r in control if r.get("fault_injected") is True
    ]
    timeout_result_ids = {id(r) for r in timeout_results}
    infrastructure_error_ids = {id(r) for r in infrastructure_errors}
    skipped_result_ids = {id(r) for r in skipped_results}
    intentionally_skipped = [
        r for r in non_control
        if r.get("fault_injected") is False
        and str(r.get("skip_reason") or "").strip() == "probability_gate"
        and id(r) not in timeout_result_ids
        and id(r) not in infrastructure_error_ids
    ]
    intentionally_skipped_ids = {id(r) for r in intentionally_skipped}
    skipped_results = [
        r for r in skipped_results if id(r) not in intentionally_skipped_ids
    ]
    incomplete_result_ids = {
        id(r) for r in non_control
        if (
            type(r.get("fault_injected")) is not bool
            or (
                r.get("fault_injected") is not True
                and id(r) not in intentionally_skipped_ids
            )
            or id(r) in timeout_result_ids
            or id(r) in infrastructure_error_ids
            or (
                id(r) in skipped_result_ids
                and id(r) not in intentionally_skipped_ids
            )
        )
    }
    not_injected = [
        r for r in non_control
        if r.get("fault_injected") is False
        and id(r) not in intentionally_skipped_ids
        and id(r) not in timeout_result_ids
        and id(r) not in infrastructure_error_ids
    ]

    terminal_escape_results = [
        r for r in non_control
        if isinstance(r.get("signals"), dict)
        and r["signals"].get("terminal_error_escaped")
    ]
    terminal_unresolved_results = [
        r for r in non_control
        if isinstance(r.get("signals"), dict)
        and r["signals"].get("terminal_error_unresolved_candidates")
    ]

    total = len(injected)
    # Treat the profile's control outcome as the expected successful outcome.
    expected_outcome = "success"
    if profile and getattr(profile, "expect", None):
        expected_outcome = (
            getattr(profile.expect, "control_outcome", "success") or "success"
        )
    instruction_skip_model = "security"
    if profile and getattr(profile, "fault_sweep", None):
        isc = getattr(profile.fault_sweep, "instruction_skip_config", None)
        if isc is not None:
            instruction_skip_model = getattr(isc, "severity_model", "security") or "security"
    for r in injected:
        annotate_instruction_skip_severity(
            r,
            expected_outcome=expected_outcome,
            default_model=instruction_skip_model,
        )
    boot_failures = [r for r in injected if result_is_brick(r)]
    failures = [r for r in injected if result_has_issues(r, expected_outcome)]
    recoveries = sum(
        1 for r in injected
        if not result_has_issues(r, expected_outcome) and not result_is_timeout(r)
    )
    resilient_rollbacks = sum(1 for r in injected if is_resilient_rollback(r))
    semantic_issue_points = sum(1 for r in injected if r.get("semantic_assertion_failures"))
    semantic_observation_points = sum(
        1 for r in injected if r.get("semantic_observation_failures")
    )
    invariant_issue_points = sum(1 for r in injected if r.get("invariant_violations"))
    metadata_delta_issue_points = sum(1 for r in injected if r.get("metadata_delta_violations"))
    success_effect_issue_points = sum(
        1 for r in injected
        if any(
            isinstance(v, dict) and v.get("name") == "success_implies_effect"
            for v in (r.get("invariant_violations") or [])
        )
    )
    bus_fault_points = sum(
        1 for r in injected
        if _effective_boot_result(r)[0] == "bus_fault"
    )
    timeout_points = len(timeout_results)
    protocol_error_points = sum(
        1 for r in infrastructure_errors
        if str(r.get("error_kind") or "") == "protocol_error"
    )
    runner_error_points = sum(
        1 for r in infrastructure_errors
        if str(r.get("error_kind") or "") == "runner_error"
    )

    control_signals = control[-1].get("signals") if control else None
    explicit_zero_point_control = bool(
        isinstance(control_signals, dict)
        and control_signals.get("zero_point_execute_control") is True
    )
    allow_control_only = bool(
        profile is not None
        and getattr(profile, "expect", None) is not None
        and getattr(profile.expect, "allow_control_only_issues", False)
    )
    profile_requests_zero_points = False
    if profile is not None and getattr(profile, "fault_sweep", None) is not None:
        configured_max_writes = getattr(profile.fault_sweep, "max_writes", None)
        if not (
            isinstance(configured_max_writes, str)
            and configured_max_writes.strip().lower() == "auto"
        ):
            try:
                configured_limit = (
                    int(configured_max_writes, 0)
                    if isinstance(configured_max_writes, str)
                    else int(configured_max_writes)
                )
                profile_requests_zero_points = configured_limit <= 0
            except (TypeError, ValueError):
                profile_requests_zero_points = False
    control_cardinality_ok = len(control) == int(expected_control_points)
    intentional_control_only = bool(
        planned_fault_points == 0
        and not non_control
        and control_cardinality_ok
        and bool(control)
        and not control_timeouts
        and not control_infrastructure_errors
        and not control_skipped_results
        and not malformed_control_results
        and not faulted_control_results
        and (
            explicit_zero_point_control
            or profile_requests_zero_points
            or allow_control_only
        )
    )
    campaign_complete = bool(
        intentional_control_only
        if planned_fault_points == 0 and not non_control
        else (
            bool(injected)
            and
            not incomplete_result_ids
            and result_cardinality_mismatch == 0
            and control_cardinality_ok
            and not control_timeouts
            and not control_infrastructure_errors
            and not control_skipped_results
            and not malformed_control_results
            and not faulted_control_results
        )
    )

    # Categorize failures by outcome type.
    outcome_counts: Dict[str, int] = {}
    class_counts: Dict[str, int] = {}
    issue_reason_counts: Dict[str, int] = {}
    fault_type_counts: Dict[str, int] = {}
    fault_type_issue_counts: Dict[str, int] = {}
    fault_type_brick_counts: Dict[str, int] = {}
    validation_dispositions: Dict[str, int] = {}
    validation_stages: Dict[str, int] = {}
    glitch_realism_counts: Dict[str, int] = {}
    verification_probe_class_counts: Dict[str, int] = {}
    success_effect_points: List[Any] = []
    verification_bypass_points: List[Any] = []
    full_bypass_points: List[Any] = []
    defense_in_depth_held = 0
    security_bypass_points = 0
    dos_crash_points = 0
    dos_recovery_points = 0
    instruction_skip_points = 0
    categorized_failures: List[Dict[str, Any]] = []
    for r in injected:
        if _fault_type_base_code(r.get("fault_type")) == "i":
            instruction_skip_points += 1
        ft_name = _fault_type_label(r.get("fault_type"))
        fault_type_counts[ft_name] = fault_type_counts.get(ft_name, 0) + 1
        iskip = classify_instruction_skip_severity(r, expected_outcome=expected_outcome)
        if iskip is not None:
            if iskip["severity"] == "security_bypass":
                security_bypass_points += 1
            elif iskip["severity"] == "dos_crash":
                dos_crash_points += 1
            elif iskip["severity"] == "dos_recovery":
                dos_recovery_points += 1
        signals = r.get("signals") or {}
        if any(
            isinstance(v, dict) and v.get("name") == "success_implies_effect"
            for v in (r.get("invariant_violations") or [])
        ):
            success_effect_points.append(r.get("fault_at"))
        if isinstance(signals, dict):
            probe_class = str(signals.get("verification_probe_classification") or "").strip()
            if probe_class:
                verification_probe_class_counts[probe_class] = (
                    verification_probe_class_counts.get(probe_class, 0) + 1
                )
            if signals.get("verification_bypass_detected"):
                verification_bypass_points.append(r.get("fault_at"))
            if signals.get("verification_full_bypass") and result_has_issues(r, expected_outcome):
                full_bypass_points.append(r.get("fault_at"))
            if signals.get("verification_defense_in_depth") == "held":
                defense_in_depth_held += 1
        validation_stage = finding_validation_stage(r)
        if validation_stage:
            validation_stages[validation_stage] = (
                validation_stages.get(validation_stage, 0) + 1
            )
        validation_disposition = finding_validation_disposition(r)
        if validation_disposition:
            validation_dispositions[validation_disposition] = (
                validation_dispositions.get(validation_disposition, 0) + 1
            )
        glitch_realism = finding_glitch_realism(r)
        if glitch_realism:
            glitch_realism_counts[glitch_realism] = (
                glitch_realism_counts.get(glitch_realism, 0) + 1
            )
        if result_is_brick(r):
            fault_type_brick_counts[ft_name] = fault_type_brick_counts.get(ft_name, 0) + 1
        if result_has_issues(r, expected_outcome):
            fault_type_issue_counts[ft_name] = fault_type_issue_counts.get(ft_name, 0) + 1
    for r in failures:
        eff_out, _ = _effective_boot_result(r)
        if eff_out != expected_outcome:
            outcome_counts[eff_out] = outcome_counts.get(eff_out, 0) + 1
        fclass = classify_failure_class(r)
        class_counts[fclass] = class_counts.get(fclass, 0) + 1
        for reason in result_issue_reasons(r, expected_outcome):
            issue_reason_counts[reason] = issue_reason_counts.get(reason, 0) + 1
        if profile:
            categorized_failures.append(
                categorize_failure(r, total_writes, profile)
            )

    # Break down skip reasons for discarded (non-injected) results.
    skip_reason_counts: Dict[str, int] = {}
    phase2_skip_reason_counts: Dict[str, int] = {}
    hook_skip_reason_counts: Dict[str, int] = {}
    confirm_skip_reason_counts: Dict[str, int] = {}
    for r in not_injected + intentionally_skipped:
        reason = r.get("skip_reason", "unknown")
        skip_reason_counts[reason] = skip_reason_counts.get(reason, 0) + 1
        if r.get("fault_type") == "p2":
            phase2_fault = r.get("phase2_fault")
            if isinstance(phase2_fault, dict):
                phase2_reason = str(phase2_fault.get("skip_reason") or "unknown")
                phase2_skip_reason_counts[phase2_reason] = (
                    phase2_skip_reason_counts.get(phase2_reason, 0) + 1
                )
        _ft = str(r.get("fault_type", ""))
        if _ft == "h" or _ft.startswith("h:"):
            hook_fault = r.get("hook_fault")
            if isinstance(hook_fault, dict):
                hook_reason = str(hook_fault.get("skip_reason") or "unknown")
                hook_skip_reason_counts[hook_reason] = (
                    hook_skip_reason_counts.get(hook_reason, 0) + 1
                )
        if _ft == "cc" or _ft.startswith("cc:"):
            confirm_meta = r.get("confirm_cycle")
            if isinstance(confirm_meta, dict):
                cc_reason = str(confirm_meta.get("skip_reason") or "unknown")
                confirm_skip_reason_counts[cc_reason] = (
                    confirm_skip_reason_counts.get(cc_reason, 0) + 1
                )

    summary: Dict[str, Any] = {
        "requested_fault_points": planned_fault_points,
        "returned_fault_points": returned_fault_points,
        "missing_result_points": missing_result_points,
        "extra_result_points": extra_result_points,
        "injected_fault_points": total,
        "total_fault_points": total,
        "bricks": len(boot_failures),
        "issue_points": len(failures),
        "semantic_issue_points": semantic_issue_points,
        "semantic_observation_points": semantic_observation_points,
        "invariant_issue_points": invariant_issue_points,
        "metadata_delta_issue_points": metadata_delta_issue_points,
        "success_implies_effect_issue_points": success_effect_issue_points,
        "bus_fault_points": bus_fault_points,
        "timeout_points": timeout_points,
        "infrastructure_error_points": len(infrastructure_errors),
        "skipped_fault_points": len(skipped_results),
        "protocol_error_points": protocol_error_points,
        "runner_error_points": runner_error_points,
        "control_timeout_points": len(control_timeouts),
        "control_infrastructure_error_points": len(control_infrastructure_errors),
        "control_skipped_points": len(control_skipped_results),
        "malformed_result_points": len(malformed_fault_injection_results),
        "malformed_control_points": len(malformed_control_results),
        "faulted_control_points": len(faulted_control_results),
        "incomplete_fault_points": (
            len(incomplete_result_ids) + result_cardinality_mismatch
        ),
        "campaign_complete": campaign_complete,
        "campaign_intentionally_control_only": intentional_control_only,
        "recoveries": recoveries,
        "resilient_rollbacks": resilient_rollbacks,
        "brick_rate": (float(len(boot_failures)) / float(total)) if total else 0.0,
        "issue_rate": (float(len(failures)) / float(total)) if total else 0.0,
        "discarded_no_fault_fired": len(not_injected) + len(intentionally_skipped),
        "intentionally_skipped_fault_points": len(intentionally_skipped),
        "failure_outcomes": outcome_counts,
        "failure_classes": class_counts,
        "fault_type_points": fault_type_counts,
        "fault_type_issue_points": fault_type_issue_counts,
        "fault_type_bricks": fault_type_brick_counts,
        "instruction_skip_points": instruction_skip_points,
        "security_bypass_points": security_bypass_points,
        "terminal_error_escape_points": len(terminal_escape_results),
        "terminal_error_unresolved_points": len(terminal_unresolved_results),
        "dos_crash_points": dos_crash_points,
        "dos_recovery_points": dos_recovery_points,
        "campaign_integrity": {
            "requested": planned_fault_points,
            "returned": returned_fault_points,
            "planner_count_supplied": planner_count_supplied,
            "missing_results": missing_result_points,
            "extra_results": extra_result_points,
            "injected": total,
            "not_injected": len(not_injected),
            "intentionally_skipped": len(intentionally_skipped),
            "timeouts": timeout_points,
            "infrastructure_errors": len(infrastructure_errors),
            "skipped_results": len(skipped_results),
            "protocol_errors": protocol_error_points,
            "runner_errors": runner_error_points,
            "control_timeouts": len(control_timeouts),
            "control_infrastructure_errors": len(control_infrastructure_errors),
            "control_skipped": len(control_skipped_results),
            "malformed_results": len(malformed_fault_injection_results),
            "malformed_controls": len(malformed_control_results),
            "faulted_controls": len(faulted_control_results),
            "incomplete": len(incomplete_result_ids) + result_cardinality_mismatch,
            "control_points": len(control),
            "expected_control_points": int(expected_control_points),
            "intentional_control_only": intentional_control_only,
            "complete": campaign_complete,
        },
    }
    if rc_telemetry:
        first_rc = rc_telemetry[0]
        summary["rc_injection"] = {
            "configured_symbols": list(first_rc.get("configured_symbols") or []),
            "resolved_symbols": first_rc.get("resolved_symbols") or {},
            "return_value": int(first_rc.get("return_value", 0)) & 0xFFFFFFFF,
            "return_register": int(first_rc.get("return_register", 0)),
            "entered_calls": sum(int(item.get("entered_calls", 0) or 0) for item in rc_telemetry),
            "applied_points": sum(1 for item in rc_telemetry if item.get("applied")),
        }
    if skip_reason_counts:
        summary["skip_reasons"] = skip_reason_counts
    if phase2_skip_reason_counts:
        summary["phase2_skip_reasons"] = phase2_skip_reason_counts
    if hook_skip_reason_counts:
        summary["hook_skip_reasons"] = hook_skip_reason_counts
    if confirm_skip_reason_counts:
        summary["confirm_skip_reasons"] = confirm_skip_reason_counts
    if issue_reason_counts:
        summary["issue_reasons"] = issue_reason_counts
    if validation_dispositions:
        summary["validation_dispositions"] = validation_dispositions
    if validation_stages:
        summary["finding_stages"] = validation_stages
        summary["validated_findings"] = validation_stages.get("validated", 0)
        summary["candidate_findings"] = validation_stages.get("candidate", 0)
        summary["dismissed_findings"] = validation_stages.get("dismissed", 0)
    if glitch_realism_counts:
        summary["glitch_realism"] = glitch_realism_counts
    if verification_probe_class_counts:
        summary["verification_probe_classes"] = verification_probe_class_counts
        summary["verification_bypass_points"] = verification_bypass_points
        summary["defense_in_depth_held"] = defense_in_depth_held
        summary["full_bypass_points"] = full_bypass_points
    if success_effect_points:
        summary["success_implies_effect_points"] = success_effect_points
    if calibration_coverage is not None:
        summary["calibration_coverage"] = calibration_coverage
    did_layers = build_defense_in_depth_layers(injected)
    if did_layers is not None:
        summary["defense_in_depth_layers"] = did_layers

    if categorized_failures:
        summary["failures"] = categorized_failures

    if control:
        ctrl = control[-1]
        ctrl_eff_outcome, ctrl_eff_slot = _effective_boot_result(ctrl)
        control_summary: Dict[str, Any] = {
            "boot_outcome": ctrl.get("boot_outcome"),
            "boot_slot": ctrl.get("boot_slot"),
            "effective_outcome": ctrl_eff_outcome,
            "effective_slot": ctrl_eff_slot,
        }
        if "initial_boot_outcome" in ctrl:
            control_summary["initial_boot_outcome"] = ctrl.get("initial_boot_outcome")
            control_summary["initial_boot_slot"] = ctrl.get("initial_boot_slot")
        if "final_boot_outcome" in ctrl:
            control_summary["final_boot_outcome"] = ctrl.get("final_boot_outcome")
            control_summary["final_boot_slot"] = ctrl.get("final_boot_slot")
        ctrl_signals = ctrl.get("signals") or {}
        control_telemetry = {
            key: ctrl_signals.get(key)
            for key in (
                "phase1_stop_reason",
                "phase1_emulated_s",
                "phase2_stop_reason",
                "phase2_emulated_s",
                "phase3_stop_reason",
                "phase3_ms",
                "trace_replay_mode",
                "reload_ms",
                "replay_ms",
                "reset_ms",
                "setup_ms",
                "emulation_ms",
                "followup_ms",
                "total_ms",
                "p2_iters",
                "zero_point_execute_control",
                "vtor",
                "vtor_final",
                "pc",
                "marker_ok",
                "marker_actual",
                "expectations_met",
                "vtor_ok",
                "vtor_aligned",
                "pc_ok",
                "otadata_expect_ok",
                "anti_rollback_ok",
                "reset_vector_offset_ok",
            )
            if ctrl_signals.get(key) is not None
        }
        if control_telemetry:
            control_summary["signals"] = control_telemetry
        control_summary["issue_count"] = len(result_issue_reasons(ctrl, expected_outcome))
        if ctrl.get("semantic_assertion_failures"):
            control_summary["semantic_assertion_failures"] = ctrl.get(
                "semantic_assertion_failures"
            )
        if ctrl.get("semantic_observation_failures"):
            control_summary["semantic_observation_failures"] = ctrl.get(
                "semantic_observation_failures"
            )
        if ctrl.get("invariant_violations"):
            control_summary["invariant_violations"] = ctrl.get("invariant_violations")
        if ctrl.get("multi_boot_analysis"):
            control_summary["multi_boot_analysis"] = ctrl.get("multi_boot_analysis")
        if ctrl.get("fault_snapshot_file"):
            control_summary["fault_snapshot_file"] = ctrl.get("fault_snapshot_file")
        summary["control"] = control_summary

    # Aggregate per-step timing from signals.
    timing_keys = [
        "reload_ms", "replay_ms", "reset_ms", "setup_ms",
        "emulation_ms", "followup_ms", "total_ms", "p2_iters",
    ]
    timing_sums: Dict[str, int] = {}
    timing_maxes: Dict[str, int] = {}
    timing_count = 0
    for r in injected:
        s = r.get("signals", {})
        if "total_ms" not in s:
            continue
        timing_count += 1
        for k in timing_keys:
            v = s.get(k, 0)
            timing_sums[k] = timing_sums.get(k, 0) + v
            timing_maxes[k] = max(timing_maxes.get(k, 0), v)
    if timing_count > 0:
        summary["timing"] = {
            "points": timing_count,
            "totals": {k: timing_sums.get(k, 0) for k in timing_keys},
            "averages": {k: timing_sums.get(k, 0) // timing_count for k in timing_keys},
            "maximums": {k: timing_maxes.get(k, 0) for k in timing_keys},
        }

    # Metadata fault region breakdown.
    regions = metadata_regions or []
    if not regions and profile is not None:
        regions = getattr(profile, "metadata_fault_regions", []) or []
    if regions:
        enrich_results_with_fault_regions(results, regions)
        region_breakdown = compute_region_breakdown(results, expected_outcome)
        if region_breakdown:
            summary["region_breakdown"] = region_breakdown

    # Read-fault accounting aggregated across batches.
    rf_aggregate = _aggregate_read_fault_summaries(results)
    if rf_aggregate is not None:
        summary["read_fault"] = rf_aggregate

    return summary


def _aggregate_read_fault_summaries(
    results: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Combine per-batch read-fault sidecars into a single counter set.

    The per-batch counting, partition invariants, and warning text all live
    in read_fault_translation (the same module the harness writes the
    sidecars with), so this only merges the sidecars and asks that module for
    the verdict warning rather than re-deriving either.
    """
    requested = False
    seen_any = False
    merged = ReadFaultStats()
    for r in results:
        payload = r.get("read_fault_summary") if isinstance(r, dict) else None
        if not payload:
            continue
        seen_any = True
        if payload.get("requested"):
            requested = True
        merged.merge(ReadFaultStats.from_dict(payload.get("stats") or {}))
    if not seen_any:
        return None

    aggregate: Dict[str, Any] = dict(merged.as_dict())
    skip_reasons = aggregate.pop("skip_reasons", {})
    aggregate["requested"] = requested
    if skip_reasons:
        aggregate["skip_reasons"] = skip_reasons
    aggregate["coverage_validated"] = merged.coverage_validated()
    # Warning precedence matches the original inline order: not-planned and
    # not-armed first, then armed-but-CPU-bypassed-the-hook, then the generic
    # "armed but none fired". cpu_path_capability_warning only returns non-None
    # when armed > 0 with nothing validated (so nothing fired), which is
    # exactly the case where read_fault_warning would otherwise say "none
    # fired"; the CPU-bypass diagnosis is the more actionable one, so it wins.
    warning = cpu_path_capability_warning(merged) or read_fault_warning(merged, requested)
    if warning is not None:
        aggregate["warning"] = warning
    return aggregate


def _coverage_gate_reason(sweep_summary: Dict[str, Any]) -> Optional[str]:
    """Return a clean-verdict coverage failure reason, if any."""
    coverage = sweep_summary.get("calibration_coverage")
    if not isinstance(coverage, dict):
        return None
    status = str(coverage.get("status") or "").strip()
    if status in {"metadata_only", "outside_slots_only", "no_nvm_activity"}:
        reason = str(coverage.get("reason") or "").strip()
        if reason:
            return reason
        if status == "metadata_only":
            return "Calibration touched slot trailers/metadata but never moved slot data."
        if status == "outside_slots_only":
            return "Calibration touched flash but never touched declared slots."
        return "Calibration produced no NVM writes or erases."
    return None


def _campaign_integrity_gate_reason(
    sweep_summary: Dict[str, Any],
    *,
    allow_control_only: bool = False,
) -> Optional[str]:
    """Return a fail-closed reason for an incomplete runtime campaign.

    Older imported summaries do not contain ``campaign_integrity`` and keep
    their historical verdict behavior.  Every summary produced by
    ``summarize_runtime_sweep`` includes the block, which lets current runs
    distinguish an explicitly requested control-only run from an empty plan.
    """
    integrity = sweep_summary.get("campaign_integrity")
    if not isinstance(integrity, dict):
        return None

    requested = int(integrity.get("requested", 0) or 0)
    returned = int(integrity.get("returned", requested) or 0)
    missing_results = int(integrity.get("missing_results", 0) or 0)
    extra_results = int(integrity.get("extra_results", 0) or 0)
    injected = int(integrity.get("injected", 0) or 0)
    not_injected = int(integrity.get("not_injected", 0) or 0)
    timeouts = int(integrity.get("timeouts", 0) or 0)
    infra_errors = int(integrity.get("infrastructure_errors", 0) or 0)
    skipped_results = int(integrity.get("skipped_results", 0) or 0)
    protocol_errors = int(integrity.get("protocol_errors", 0) or 0)
    control_points = int(integrity.get("control_points", 0) or 0)
    expected_control_points = int(
        integrity.get("expected_control_points", 1) or 0
    )
    control_timeouts = int(integrity.get("control_timeouts", 0) or 0)
    control_infra_errors = int(
        integrity.get("control_infrastructure_errors", 0) or 0
    )
    control_skipped = int(integrity.get("control_skipped", 0) or 0)
    malformed_results = int(integrity.get("malformed_results", 0) or 0)
    malformed_controls = int(integrity.get("malformed_controls", 0) or 0)
    faulted_controls = int(integrity.get("faulted_controls", 0) or 0)
    intentional_control_only = bool(integrity.get("intentional_control_only"))

    if malformed_controls:
        return "control run returned malformed fault-injection telemetry"
    if faulted_controls:
        return "control run reported that fault injection fired"
    if control_infra_errors:
        return "control run failed with an infrastructure error"
    if control_timeouts:
        return "control run timed out"
    if control_skipped:
        return "control run was skipped"
    if control_points != expected_control_points:
        return "campaign requires {} clean control point(s), observed {}".format(
            expected_control_points, control_points
        )
    if missing_results or extra_results:
        return (
            "campaign incomplete: planner/result cardinality mismatch "
            "(requested {}, returned {}; {} missing, {} extra)"
        ).format(requested, returned, missing_results, extra_results)
    if protocol_errors:
        return "campaign incomplete: {} runner protocol/cardinality error(s)".format(
            protocol_errors
        )
    if malformed_results:
        return "campaign incomplete: {} malformed fault result(s)".format(
            malformed_results
        )
    if infra_errors:
        return "campaign incomplete: {} infrastructure error(s)".format(infra_errors)
    if timeouts:
        return "campaign incomplete: {} fault point(s) timed out".format(timeouts)
    if skipped_results:
        return "campaign incomplete: {} fault point(s) were skipped".format(
            skipped_results
        )
    if requested == 0:
        if control_points and (intentional_control_only or allow_control_only):
            return None
        return "campaign executed no fault points"
    if injected == 0:
        return "campaign injected none of {} requested fault point(s)".format(requested)
    if not_injected:
        return "campaign incomplete: {} of {} requested fault(s) did not fire".format(
            not_injected, requested
        )
    if not bool(integrity.get("complete", False)):
        return "campaign result coverage is incomplete"
    return None


def _partial_staging_integrity_gate_reason(
    partial_staging_summary: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Require a complete-image control and conclusive staging results."""
    if partial_staging_summary is None:
        return None
    total = int(partial_staging_summary.get("total_points", 0) or 0)
    missing_results = int(
        partial_staging_summary.get("missing_result_points", 0) or 0
    )
    extra_results = int(
        partial_staging_summary.get("extra_result_points", 0) or 0
    )
    partial_points_raw = partial_staging_summary.get("partial_image_points")
    complete_points_raw = partial_staging_summary.get("complete_image_points")
    infra_errors = int(
        partial_staging_summary.get("infrastructure_error", 0) or 0
    )
    timeouts = int(partial_staging_summary.get("timeout", 0) or 0)
    control_ok = int(partial_staging_summary.get("complete_image_ok", 0) or 0)
    control_failed = int(
        partial_staging_summary.get("complete_image_failed", 0) or 0
    )
    if total == 0:
        return "partial-staging campaign executed no points"
    if missing_results or extra_results:
        return (
            "partial-staging campaign incomplete: {} missing and {} extra result(s)"
        ).format(missing_results, extra_results)
    if partial_points_raw is not None and int(partial_points_raw or 0) < 1:
        return "partial-staging campaign executed no partial-image points"
    if infra_errors:
        return "partial-staging campaign incomplete: {} infrastructure error(s)".format(
            infra_errors
        )
    if timeouts:
        return "partial-staging campaign incomplete: {} timeout(s)".format(timeouts)
    if control_failed or control_ok < 1:
        return "partial-staging complete-image control did not succeed"
    if complete_points_raw is not None and int(complete_points_raw or 0) != 1:
        return "partial-staging campaign requires exactly one complete-image control"
    return None


def git_metadata(repo_root: Path) -> Dict[str, str]:
    def run_git(*args: str) -> str:
        proc = subprocess.run(
            ["git"] + list(args), cwd=str(repo_root),
            capture_output=True, text=True, check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    commit = run_git("rev-parse", "HEAD")
    short_commit = run_git("rev-parse", "--short", "HEAD")
    if not commit:
        commit = "unavailable"
    if not short_commit:
        short_commit = commit

    return {
        "commit": commit,
        "short_commit": short_commit,
        "dirty": "true" if run_git("status", "--porcelain") else "false",
    }


def compute_verdict(
    sweep_summary: Dict[str, Any],
    profile_expect: Any,
    multi_fault_summary: Optional[Dict[str, Any]] = None,
    partial_staging_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Derive a PASS/FAIL verdict from sweep summaries and profile expectations."""
    control_summary = sweep_summary.get("control") or {}
    expected_control_outcome = str(
        getattr(profile_expect, "control_outcome", "success") or "success"
    )
    control_outcome = str(
        control_summary.get("effective_outcome")
        or control_summary.get("final_boot_outcome")
        or control_summary.get("boot_outcome")
        or ""
    )
    allow_control_only_issues = bool(
        getattr(profile_expect, "allow_control_only_issues", False)
    )
    control_only_issue = (
        allow_control_only_issues
        and control_outcome == expected_control_outcome
    )
    found_issues = int(
        sweep_summary.get("issue_points", sweep_summary["bricks"])
    ) > 0
    if multi_fault_summary is not None:
        found_issues = found_issues or (
            int(
                multi_fault_summary.get(
                    "issue_points", multi_fault_summary["bricks"]
                )
            )
            > 0
        )
    if partial_staging_summary is not None:
        found_issues = found_issues or (
            int(partial_staging_summary.get("issue_count", 0)) > 0
        )
    control_issue_count = int(
        control_summary.get("issue_count", 0)
    )
    security_bypass_points = int(sweep_summary.get("security_bypass_points", 0))
    dos_crash_points = int(sweep_summary.get("dos_crash_points", 0))
    dos_recovery_points = int(sweep_summary.get("dos_recovery_points", 0))
    instruction_skip_points = int(
        sweep_summary.get(
            "instruction_skip_points",
            security_bypass_points + dos_crash_points + dos_recovery_points,
        )
    )

    resilient_rollbacks = int(sweep_summary.get("resilient_rollbacks", 0))
    invariant_observations = int(sweep_summary.get("invariant_issue_points", 0))
    coverage_gate_reason = _coverage_gate_reason(sweep_summary)
    campaign_integrity_reason = _campaign_integrity_gate_reason(
        sweep_summary,
        allow_control_only=allow_control_only_issues,
    )
    multi_fault_integrity_reason = (
        _campaign_integrity_gate_reason(multi_fault_summary)
        if multi_fault_summary is not None
        else None
    )
    partial_staging_integrity_reason = _partial_staging_integrity_gate_reason(
        partial_staging_summary
    )
    campaign_integrity = sweep_summary.get("campaign_integrity") or {}
    intentional_control_only_campaign = bool(
        isinstance(campaign_integrity, dict)
        and campaign_integrity.get("intentional_control_only")
    )

    def _append_warnings(text):
        """Append timeout + read-fault coverage warnings to a verdict string.

        compute_verdict has several early returns; routing them all through
        here keeps the read-fault coverage warning from being silently
        dropped on the security-bypass FAIL paths (which return before the
        tail), matching how the timeout warning is surfaced everywhere.
        """
        out = text
        timeouts = int(sweep_summary.get("timeout_points", 0))
        if timeouts > 0:
            out += (
                " (WARNING: {} points timed out — consider increasing "
                "run_duration)".format(timeouts)
            )
        rf_warning = (sweep_summary.get("read_fault") or {}).get("warning")
        if rf_warning:
            out += " (WARNING: {})".format(rf_warning)
        return out

    verdict = "PASS"
    if campaign_integrity_reason:
        verdict = "FAIL \u2014 {}".format(campaign_integrity_reason)
    elif multi_fault_integrity_reason:
        verdict = "FAIL \u2014 multi-fault {}".format(
            multi_fault_integrity_reason
        )
    elif partial_staging_integrity_reason:
        verdict = "FAIL \u2014 {}".format(partial_staging_integrity_reason)
    elif control_only_issue and not found_issues:
        verdict = "PASS \u2014 control exhibits expected {}".format(control_outcome)
    elif control_issue_count:
        verdict = "FAIL \u2014 control checks failed"
    elif (
        coverage_gate_reason
        and not found_issues
        and not intentional_control_only_campaign
    ):
        verdict = "FAIL \u2014 {}".format(coverage_gate_reason)
    elif profile_expect.should_find_issues and not found_issues:
        verdict = "FAIL \u2014 expected to find issues but found none"
    elif not profile_expect.should_find_issues and found_issues:
        total_issues = sweep_summary.get("issue_points", 0)
        if multi_fault_summary:
            total_issues += int(
                multi_fault_summary.get(
                    "issue_points", multi_fault_summary.get("bricks", 0)
                )
            )
        if partial_staging_summary:
            total_issues += int(partial_staging_summary.get("issue_count", 0))
        non_instruction_issues = max(0, int(total_issues) - int(security_bypass_points))
        if security_bypass_points > 0 and non_instruction_issues == 0:
            verdict = "FAIL \u2014 found {} security bypass points".format(
                security_bypass_points
            )
            if dos_crash_points > 0:
                verdict += " ({} DoS crash points, expected for glitch model)".format(
                    dos_crash_points
                )
            if dos_recovery_points > 0:
                verdict += " ({} recovering DoS points)".format(dos_recovery_points)
            return _append_warnings(verdict)
        if security_bypass_points > 0:
            parts = []
            if non_instruction_issues > 0:
                parts.append("{} non-instruction issues".format(non_instruction_issues))
            parts.append("{} security bypasses".format(security_bypass_points))
            if dos_crash_points > 0:
                parts.append("{} DoS crashes".format(dos_crash_points))
            if dos_recovery_points > 0:
                parts.append("{} recovering DoS".format(dos_recovery_points))
            verdict = "FAIL \u2014 found {} issue points ({})".format(
                total_issues,
                ", ".join(parts),
            )
            return _append_warnings(verdict)
        metadata_delta_observations = int(
            sweep_summary.get("metadata_delta_issue_points", 0)
        )
        parts_fmt = [
            "{} boot mismatches".format(sweep_summary.get("bricks", 0)),
            "{} semantic".format(sweep_summary.get("semantic_issue_points", 0)),
            "{} invariant".format(invariant_observations),
        ]
        if metadata_delta_observations > 0:
            parts_fmt.append(
                "{} metadata_delta".format(metadata_delta_observations)
            )
        verdict = (
            "FAIL \u2014 found {} issue points ({})"
        ).format(total_issues, ", ".join(parts_fmt))
    elif resilient_rollbacks > 0:
        # All fault points recovered or rolled back correctly — no real issues.
        parts = ["0 bricks", "{} resilient rollbacks".format(resilient_rollbacks)]
        if invariant_observations > 0:
            parts.append("{} invariant observations".format(invariant_observations))
        verdict = "PASS \u2014 " + ", ".join(parts)
    elif (
        instruction_skip_points > 0
        and security_bypass_points == 0
        and (dos_crash_points > 0 or dos_recovery_points > 0)
    ):
        verdict = (
            "PASS \u2014 0 security bypass points "
            "({} DoS crash points, expected for glitch model)".format(
                dos_crash_points
            )
        )
        if dos_recovery_points > 0:
            verdict += " ({} recovering DoS points)".format(dos_recovery_points)
    return _append_warnings(verdict)


def report_skip_reasons(
    sweep_summary: Dict[str, Any],
    progress_fn: Callable[[str], Any],
) -> None:
    """Print skip-reason diagnostics from a sweep summary."""
    _SKIP_KEYS = [
        ("skip_reasons", "Skipped {} fault points (not injected): {}",
         "discarded_no_fault_fired"),
        ("phase2_skip_reasons", "Phase 2 fault points skipped before injection: {}",
         None),
        ("hook_skip_reasons", "Hook fault points skipped before injection: {}",
         None),
        ("confirm_skip_reasons", "Confirm-cycle fault points skipped before injection: {}",
         None),
    ]
    for key, template, count_key in _SKIP_KEYS:
        reasons = sweep_summary.get(key)
        if not reasons:
            continue
        parts = [
            "{} {}".format(count, reason)
            for reason, count in sorted(reasons.items())
        ]
        if count_key:
            progress_fn(template.format(
                sweep_summary.get(count_key, 0), ", ".join(parts),
            ))
        else:
            progress_fn(template.format(", ".join(parts)))
