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
    classify_failure_class,
    finding_glitch_realism,
    finding_validation_stage,
    finding_validation_disposition,
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
    signals = result.get("signals") or {}
    if isinstance(signals, dict):
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
) -> Dict[str, Any]:
    """Compute summary statistics from runtime sweep results."""
    non_control = [r for r in results if not r.get("is_control", False)]
    control = [r for r in results if r.get("is_control", False)]

    # Fail-closed: exclude points where fault didn't actually fire.
    injected = [r for r in non_control if r.get("fault_injected", False)]
    not_injected = [r for r in non_control if not r.get("fault_injected", False)]

    total = len(injected)
    # Treat the profile's control outcome as the expected successful outcome.
    expected_outcome = "success"
    if profile and getattr(profile, "expect", None):
        expected_outcome = (
            getattr(profile.expect, "control_outcome", "success") or "success"
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
    bus_fault_points = sum(
        1 for r in injected
        if _effective_boot_result(r)[0] == "bus_fault"
    )
    timeout_points = sum(
        1 for r in injected
        if _effective_boot_result(r)[0] == "timeout"
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
    verification_bypass_points: List[Any] = []
    full_bypass_points: List[Any] = []
    defense_in_depth_held = 0
    categorized_failures: List[Dict[str, Any]] = []
    for r in injected:
        ft_name = _fault_type_label(r.get("fault_type"))
        fault_type_counts[ft_name] = fault_type_counts.get(ft_name, 0) + 1
        signals = r.get("signals") or {}
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
    for r in not_injected:
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
        "total_fault_points": total,
        "bricks": len(boot_failures),
        "issue_points": len(failures),
        "semantic_issue_points": semantic_issue_points,
        "semantic_observation_points": semantic_observation_points,
        "invariant_issue_points": invariant_issue_points,
        "metadata_delta_issue_points": metadata_delta_issue_points,
        "bus_fault_points": bus_fault_points,
        "timeout_points": timeout_points,
        "recoveries": recoveries,
        "resilient_rollbacks": resilient_rollbacks,
        "brick_rate": (float(len(boot_failures)) / float(total)) if total else 0.0,
        "issue_rate": (float(len(failures)) / float(total)) if total else 0.0,
        "discarded_no_fault_fired": len(not_injected),
        "failure_outcomes": outcome_counts,
        "failure_classes": class_counts,
        "fault_type_points": fault_type_counts,
        "fault_type_issue_points": fault_type_issue_counts,
        "fault_type_bricks": fault_type_brick_counts,
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

    return summary


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
        and expected_control_outcome != "success"
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

    resilient_rollbacks = int(sweep_summary.get("resilient_rollbacks", 0))
    invariant_observations = int(sweep_summary.get("invariant_issue_points", 0))

    verdict = "PASS"
    if control_only_issue and not found_issues:
        verdict = "PASS \u2014 control exhibits expected {}".format(control_outcome)
    elif control_issue_count:
        verdict = "FAIL \u2014 control checks failed"
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
    timeout_points = int(sweep_summary.get("timeout_points", 0))
    if timeout_points > 0:
        verdict += " (WARNING: {} points timed out — consider increasing run_duration)".format(
            timeout_points
        )
    return verdict


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
