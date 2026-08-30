"""Adversarial validator / skeptic stage for sweep findings.

Tardigrade's first pass is intentionally broad: it flags security-relevant
state deviations such as ``wrong_image`` or ``no_boot``. This module is the
second pass that tries to disprove those results before they are treated as
validated findings.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fault_classification import (
    _effective_boot_result,
    annotate_instruction_skip_severity,
    classify_instruction_skip_severity,
    instruction_skip_severity_model,
    result_has_issues,
    result_is_brick,
)
from renode_runner import merge_robot_vars, run_single_point
from result_checks import annotate_result_checks
from sweep import build_fault_robot_vars


_NON_POWER_WRITE_FAULT_CODES = frozenset({"b", "s", "g", "x", "r", "d", "l"})
_PRIMARY_GLITCH_MODEL = "nop"
_VALIDATION_STAGES = frozenset({"validated", "candidate", "dismissed"})
_DEFAULT_REALISM_BY_FAULT_CODE = {
    "w": "common",
    "e": "common",
    "a": "common",
    "i": "common",
    "b": "plausible",
    "s": "plausible",
    "g": "plausible",
    "x": "plausible",
    "r": "plausible",
    "d": "plausible",
    "l": "plausible",
    "k": "plausible",
    "t": "plausible",
    "f": "plausible",
}


def _base_fault_type_code(fault_type: Any) -> str:
    raw = str(fault_type or "w")
    return raw.split(":", 1)[0] if ":" in raw else raw


def _default_glitch_realism(fault_type: Any) -> str:
    return _DEFAULT_REALISM_BY_FAULT_CODE.get(
        _base_fault_type_code(fault_type),
        "not_applicable",
    )


def _security_property(result: Dict[str, Any], expected_outcome: str) -> str:
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    if result_is_brick(result):
        return "availability"
    if outcome == "wrong_image":
        return "rollback_integrity"
    if outcome in {"rollback_accepted", "toctou_corruption"}:
        return "auth_integrity"
    if outcome != str(expected_outcome or "success").strip().lower():
        return "boot_integrity"
    return "not_applicable"


def _steady_state_status(result: Dict[str, Any]) -> str:
    mba = result.get("multi_boot_analysis")
    if isinstance(mba, dict):
        status = str(mba.get("status") or "").strip()
        if status:
            return status
    if result.get("final_boot_outcome") is not None:
        initial = str(
            result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
        ).strip()
        final = str(result.get("final_boot_outcome") or "unknown").strip()
        if final != initial:
            return "changed_after_followup"
        return "persistent_after_followup"
    return "single_boot_only"


def _model_status_from_result(
    result: Dict[str, Any],
    expected_outcome: str,
) -> str:
    if not result:
        return "infra_error"
    if result.get("boot_outcome") == "skipped":
        return "unsupported"
    if result_is_brick(result) or result_has_issues(result, expected_outcome):
        return "bypass"
    return "no_bypass"


def _extract_instruction_skip_addr(result: Dict[str, Any]) -> Optional[int]:
    fault_type = str(result.get("fault_type", "") or "")
    if fault_type.startswith("i:"):
        parts = fault_type.split(":")
        if len(parts) >= 2:
            try:
                return int(parts[1], 0)
            except ValueError:
                return None
    signals = result.get("signals") or {}
    if isinstance(signals, dict):
        raw = signals.get("skip_address")
        if raw:
            try:
                return int(str(raw), 0)
            except ValueError:
                return None
    fault_at = result.get("fault_at")
    try:
        return int(fault_at) if fault_at is not None else None
    except (TypeError, ValueError):
        return None


def _summarize_validation_rerun(result: Dict[str, Any]) -> Dict[str, Any]:
    signals = result.get("signals") or {}
    out: Dict[str, Any] = {
        "boot_outcome": result.get("boot_outcome"),
        "boot_slot": result.get("boot_slot"),
        "fault_type": result.get("fault_type"),
    }
    if isinstance(signals, dict):
        for key in (
            "trace_replay_mode",
            "instruction_patch_model",
            "instruction_patch_supported",
            "instruction_patch_reason",
            "phase1_stop_reason",
        ):
            if signals.get(key) is not None:
                out[key] = signals.get(key)
    if result.get("skip_reason") is not None:
        out["skip_reason"] = result.get("skip_reason")
    if result.get("multi_boot_analysis") is not None:
        out["multi_boot_analysis"] = result.get("multi_boot_analysis")
    if result.get("final_boot_outcome") is not None:
        out["final_boot_outcome"] = result.get("final_boot_outcome")
        out["final_boot_slot"] = result.get("final_boot_slot")
    return out


def _verification_probe_summary(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    signals = result.get("signals") or {}
    if not isinstance(signals, dict):
        return None
    probe_class = str(signals.get("verification_probe_classification") or "").strip()
    if not probe_class:
        return None
    return {
        "classification": probe_class,
        "defense_in_depth": str(
            signals.get("verification_defense_in_depth") or "unknown"
        ).strip(),
        "bypassed_labels": list(signals.get("verification_bypass_labels") or []),
        "full_bypass": bool(signals.get("verification_full_bypass")),
        "bypass_detected": bool(signals.get("verification_bypass_detected")),
        "probes": signals.get("verification_probes") or {},
    }


def _success_effect_summary(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the structured success-implies-effect evidence, when present."""
    violations = result.get("invariant_violations") or []
    for violation in violations:
        if isinstance(violation, dict) and violation.get("name") == "success_implies_effect":
            details = dict(violation.get("details") or {})
            details.setdefault("fault_at", result.get("fault_at"))
            details.setdefault("fault_point", result.get("fault_address"))
            return details
    return None


def _state_relation_summary(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the first declarative state-relation finding, when present."""
    violations = result.get("invariant_violations") or []
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        if violation.get("name") != "state_relations":
            continue
        details = dict(violation.get("details") or {})
        details.setdefault("fault_at", result.get("fault_at"))
        details.setdefault("fault_point", result.get("fault_address"))
        return details
    return None


def _make_single_point_runner(
    *,
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: Any,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    keep_run_artifacts: bool,
) -> Callable[[int, str, Optional[List[str]]], Dict[str, Any]]:
    validation_root = work_dir / "finding_validation"
    validation_root.mkdir(parents=True, exist_ok=True)

    def rerun(
        fault_at: int,
        fault_type: str,
        extra_robot_vars: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        base_code = _base_fault_type_code(fault_type)
        if base_code in {"e", "a"}:
            fault_types_mode = "erase"
        elif base_code in {"w", "b", "s", "g", "x", "r", "d", "l", "t", "k", "i"}:
            fault_types_mode = "write"
        else:
            fault_types_mode = "write"
        validation_vars = merge_robot_vars(
            robot_vars,
            [
                "FAULT_TYPES:{}".format(fault_types_mode),
                "FAULT_TYPE_CSV:{}".format(fault_type),
            ],
        )
        if extra_robot_vars:
            validation_vars = merge_robot_vars(validation_vars, extra_robot_vars)
        point_label = str(fault_type).replace(":", "_").replace("/", "_")
        point_dir = validation_root / "fp{}_{}".format(int(fault_at), point_label)
        point_dir.mkdir(parents=True, exist_ok=True)
        return run_single_point(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_at=int(fault_at),
            robot_vars=validation_vars,
            work_dir=point_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            keep_run_artifacts=keep_run_artifacts,
            expected_fault_type=fault_type,
        )

    return rerun


def _build_validation(
    *,
    stage: str,
    disposition: str,
    fault_type: Any,
    expected_outcome: str,
    security_property: str,
    glitch_models: Optional[Dict[str, str]] = None,
    glitch_realism: Optional[str] = None,
    defense_in_depth: str = "not_applicable",
    inverse_validation: str = "not_applicable",
    self_healing: str = "not_applicable",
    counterfactuals: Optional[Dict[str, Any]] = None,
    negative_evidence: Optional[List[str]] = None,
    reasons: Optional[List[str]] = None,
    reruns: Optional[Dict[str, Any]] = None,
    skeptical_summary: str = "",
    severity: Optional[str] = None,
    severity_rationale: str = "",
) -> Dict[str, Any]:
    if stage not in _VALIDATION_STAGES:
        raise ValueError("unknown validation stage {!r}".format(stage))
    return {
        "stage": stage,
        "validated": stage == "validated",
        "disposition": disposition,
        "fault_model": _base_fault_type_code(fault_type),
        "security_property": security_property,
        "expected_outcome": expected_outcome,
        "glitch_models": glitch_models or {},
        "glitch_realism": glitch_realism or _default_glitch_realism(fault_type),
        "defense_in_depth": defense_in_depth,
        "inverse_validation": inverse_validation,
        "self_healing": self_healing,
        "counterfactuals": counterfactuals or {},
        "negative_evidence": negative_evidence or [],
        "reasons": reasons or [],
        "reruns": reruns or {},
        "skeptical_summary": skeptical_summary,
        "severity": severity,
        "severity_rationale": severity_rationale,
    }


def _validate_instruction_skip(
    result: Dict[str, Any],
    *,
    expected_outcome: str,
    rerun_point: Callable[[int, str, Optional[List[str]]], Dict[str, Any]],
    annotate_checks: Callable[[List[Dict[str, Any]]], None],
) -> Dict[str, Any]:
    severity_info = classify_instruction_skip_severity(result, expected_outcome=expected_outcome)
    severity_model = instruction_skip_severity_model(result)
    skip_addr = _extract_instruction_skip_addr(result)
    glitch_models: Dict[str, str] = {
        "nop": "not_tested",
        "register_zero": "not_available",
        "branch_invert": "not_tested",
        "arbitrary_patch": "not_available",
    }
    reruns: Dict[str, Any] = {}
    negative_evidence: List[str] = []
    security_property = _security_property(result, expected_outcome)
    probe_summary = _verification_probe_summary(result)
    counterfactuals = {
        "clean_firmware": "not_available",
        "tampered_firmware": "profile_defined",
        "adjacent_points": "not_tested",
        "multi_boot_replay": _steady_state_status(result),
    }
    if probe_summary is not None:
        counterfactuals["defense_chain"] = probe_summary.get("classification")
        if probe_summary.get("bypass_detected"):
            glitch_models["nop"] = "bypass"

    if probe_summary is not None:
        if probe_summary.get("classification") == "first_layer_breached_second_caught":
            bypassed = probe_summary.get("bypassed_labels") or []
            negative_evidence.append(
                "verification probes show {} returned success but a later verification layer still failed".format(
                    ", ".join(str(x) for x in bypassed) or "the first verification layer"
                )
            )
            return _build_validation(
                stage="dismissed",
                disposition="defense_in_depth",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property=security_property,
                glitch_models=glitch_models,
                glitch_realism="common",
                defense_in_depth="held",
                counterfactuals=counterfactuals,
                negative_evidence=negative_evidence,
                reasons=["verification_probe_later_layer_caught_fault"],
                skeptical_summary="Dismissed: the instruction skip breached an earlier verification layer, but a later verification layer still rejected the faulted path.",
                severity=(severity_info or {}).get("severity"),
                severity_rationale=(severity_info or {}).get("severity_rationale"),
            )
        if probe_summary.get("classification") in {
            "first_layer_held",
            "first_layer_not_reached",
        }:
            negative_evidence.append(
                "verification probes did not show a successful return from the first targeted verification layer"
            )
            return _build_validation(
                stage="dismissed",
                disposition="no_verification_bypass",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property=security_property,
                glitch_models=glitch_models,
                glitch_realism="common",
                defense_in_depth=probe_summary.get("defense_in_depth") or "held",
                counterfactuals=counterfactuals,
                negative_evidence=negative_evidence,
                reasons=["verification_probe_no_first_layer_bypass"],
                skeptical_summary="Dismissed: the instruction skip did not produce a successful return from the targeted first verification layer.",
                severity=(severity_info or {}).get("severity"),
                severity_rationale=(severity_info or {}).get("severity_rationale"),
            )

    if severity_info is not None and severity_info["severity"] in {"dos_crash", "dos_recovery"}:
        if severity_model == "availability":
            return _build_validation(
                stage="validated",
                disposition="confirmed",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property="availability",
                glitch_models={
                    "nop": glitch_models["nop"],
                    "register_zero": "not_available",
                    "branch_invert": "not_tested",
                    "arbitrary_patch": "not_available",
                },
                glitch_realism="common",
                defense_in_depth=(
                    (probe_summary or {}).get("defense_in_depth") or "not_applicable"
                ),
                counterfactuals=counterfactuals,
                negative_evidence=negative_evidence,
                reasons=[severity_info["severity"]],
                skeptical_summary="Validated as an availability finding: the instruction skip caused denial of service without needing replay confirmation.",
                severity=severity_info["severity"],
                severity_rationale=severity_info["severity_rationale"],
            )
        return _build_validation(
            stage="dismissed",
            disposition="dos_only",
            fault_type=result.get("fault_type"),
            expected_outcome=expected_outcome,
            security_property="availability",
            glitch_models={
                "nop": glitch_models["nop"],
                "register_zero": "not_available",
                "branch_invert": "not_tested",
                "arbitrary_patch": "not_available",
            },
            glitch_realism="common",
            defense_in_depth=((probe_summary or {}).get("defense_in_depth") or "not_applicable"),
            counterfactuals=counterfactuals,
            negative_evidence=negative_evidence,
            reasons=[severity_info["severity"]],
            skeptical_summary="Dismissed as security noise: the instruction skip caused denial of service but did not boot the wrong firmware.",
            severity=severity_info["severity"],
            severity_rationale=severity_info["severity_rationale"],
        )
    if skip_addr is None:
        return _build_validation(
            stage="candidate",
            disposition="needs_mechanism_confirmation",
            fault_type=result.get("fault_type"),
            expected_outcome=expected_outcome,
            security_property=security_property,
            glitch_models=glitch_models,
            glitch_realism="plausible",
            defense_in_depth="unknown",
            counterfactuals=counterfactuals,
            negative_evidence=["instruction skip address could not be resolved for replay"],
            reasons=["instruction_skip_address_unknown"],
            skeptical_summary="Candidate only: instruction skip address was not resolvable, so the validator could not replay a realistic skip model.",
            severity=(severity_info or {}).get("severity"),
            severity_rationale=(severity_info or {}).get("severity_rationale"),
        )

    model_fault_types = {
        "nop": "i:0x{:X}:nop".format(skip_addr),
        "branch_invert": "i:0x{:X}:branch_invert".format(skip_addr),
    }
    for model_name, fault_type in model_fault_types.items():
        try:
            rerun = rerun_point(skip_addr, fault_type)
            annotate_checks([rerun])
        except Exception as exc:
            reruns[model_name] = {"error": str(exc)}
            glitch_models[model_name] = "infra_error"
            negative_evidence.append(
                "{} replay failed in infrastructure: {}".format(model_name, exc)
            )
            continue
        reruns[model_name] = _summarize_validation_rerun(rerun)
        glitch_models[model_name] = _model_status_from_result(rerun, expected_outcome)
        if glitch_models[model_name] == "no_bypass":
            negative_evidence.append(
                "{} replay did not reproduce the end-to-end security failure".format(
                    model_name
                )
            )
        elif glitch_models[model_name] == "unsupported":
            negative_evidence.append(
                "{} replay was unsupported for the target instruction".format(model_name)
            )

    if glitch_models["nop"] == "bypass":
        return _build_validation(
            stage="validated",
            disposition="confirmed",
            fault_type=result.get("fault_type"),
            expected_outcome=expected_outcome,
            security_property=security_property,
            glitch_models=glitch_models,
            glitch_realism="common",
            defense_in_depth="defeated",
            counterfactuals=counterfactuals,
            negative_evidence=negative_evidence,
            reasons=["primary_nop_model_reproduced"],
            reruns=reruns,
            skeptical_summary="Validated: the primary NOP-style skip model reproduced the end-to-end failure.",
            severity=(severity_info or {}).get("severity"),
            severity_rationale=(severity_info or {}).get("severity_rationale"),
        )

    if glitch_models["branch_invert"] == "bypass":
        return _build_validation(
            stage="candidate",
            disposition="model_specific_candidate",
            fault_type=result.get("fault_type"),
            expected_outcome=expected_outcome,
            security_property=security_property,
            glitch_models=glitch_models,
            glitch_realism="plausible",
            defense_in_depth="partial",
            counterfactuals=counterfactuals,
            negative_evidence=negative_evidence,
            reasons=[
                "primary_nop_model_did_not_reproduce",
                "plausible_branch_inversion_model_reproduced",
            ],
            reruns=reruns,
            skeptical_summary="Candidate only: the outcome did not survive the primary NOP skip model, but it did reproduce under a branch-inversion model.",
            severity=(severity_info or {}).get("severity"),
            severity_rationale=(severity_info or {}).get("severity_rationale"),
        )

    return _build_validation(
        stage="dismissed",
        disposition="defense_in_depth",
        fault_type=result.get("fault_type"),
        expected_outcome=expected_outcome,
        security_property=security_property,
        glitch_models=glitch_models,
        glitch_realism="common",
        defense_in_depth="held",
        counterfactuals=counterfactuals,
        negative_evidence=negative_evidence,
        reasons=["candidate_did_not_survive_realistic_replay"],
        reruns=reruns,
        skeptical_summary="Dismissed: realistic skip-model replays did not preserve the end-to-end failure, so downstream control flow or later checks held.",
        severity=(severity_info or {}).get("severity"),
        severity_rationale=(severity_info or {}).get("severity_rationale"),
    )


def _validate_write_fault(
    result: Dict[str, Any],
    *,
    expected_outcome: str,
) -> Dict[str, Any]:
    signals = result.get("signals") or {}
    if not isinstance(signals, dict):
        signals = {}
    base_code = _base_fault_type_code(result.get("fault_type"))
    glitch_models = {
        "nop": "not_applicable",
        "register_zero": "observed" if base_code == "x" else "not_applicable",
        "branch_invert": "not_applicable",
        "arbitrary_patch": "not_applicable",
    }
    security_property = _security_property(result, expected_outcome)
    counterfactuals = {
        "clean_firmware": "not_available",
        "tampered_firmware": "profile_defined",
        "adjacent_points": "not_tested",
        "multi_boot_replay": _steady_state_status(result),
    }
    negative_evidence: List[str] = []
    self_healing = "not_applicable"
    inverse_validation = "not_applicable"

    if (
        signals.get("phase1_stop_reason") == "fault_fired"
        and base_code in _NON_POWER_WRITE_FAULT_CODES
    ):
        negative_evidence.append(
            "non-power write fault halted phase 1 instead of continuing, which indicates a harness artifact rather than a stable data-state bypass"
        )
        return _build_validation(
            stage="dismissed",
            disposition="harness_artifact",
            fault_type=result.get("fault_type"),
            expected_outcome=expected_outcome,
            security_property=security_property,
            glitch_models=glitch_models,
            defense_in_depth="not_applicable",
            inverse_validation="harness_artifact",
            self_healing=self_healing,
            counterfactuals=counterfactuals,
            negative_evidence=negative_evidence,
            reasons=["non_power_write_fault_halted_phase1"],
            skeptical_summary="Dismissed: the fault acted like a stop/reset instead of a continue-after-fault write error.",
        )

    if bool(signals.get("phase1_continued_after_fault")):
        changed_post_boot = signals.get("fault_word_changed_post_boot")
        if changed_post_boot is True:
            self_healing = "healed"
            negative_evidence.append(
                "the faulted flash word was rewritten later in the same boot or follow-up boot sequence"
            )
            return _build_validation(
                stage="dismissed",
                disposition="self_healed",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property=security_property,
                glitch_models=glitch_models,
                defense_in_depth="not_applicable",
                inverse_validation=inverse_validation,
                self_healing=self_healing,
                counterfactuals=counterfactuals,
                negative_evidence=negative_evidence,
                reasons=["faulted_word_rewritten_after_fault"],
                skeptical_summary="Dismissed: the faulted word did not persist to steady state, so later write ordering self-healed the candidate anomaly.",
            )
        if changed_post_boot is False:
            self_healing = "persisted"
        else:
            self_healing = "unknown"

    return _build_validation(
        stage="validated",
        disposition="confirmed",
        fault_type=result.get("fault_type"),
        expected_outcome=expected_outcome,
        security_property=security_property,
        glitch_models=glitch_models,
        defense_in_depth="not_applicable",
        inverse_validation=inverse_validation,
        self_healing=self_healing,
        counterfactuals=counterfactuals,
        negative_evidence=negative_evidence,
        reasons=[],
        skeptical_summary="Validated: the adverse outcome persisted under the declared write fault model and was not automatically dismissed as a harness artifact or self-heal.",
    )


def _apply_validation(result: Dict[str, Any], validation: Dict[str, Any]) -> None:
    result["finding_validation"] = validation
    result["finding_stage"] = validation.get("stage")
    result["glitch_models"] = validation.get("glitch_models")
    result["glitch_realism"] = validation.get("glitch_realism")
    result["defense_in_depth"] = validation.get("defense_in_depth")
    result["inverse_validation"] = validation.get("inverse_validation")
    result["self_healing"] = validation.get("self_healing")
    result["severity"] = validation.get("severity")
    result["severity_rationale"] = validation.get("severity_rationale")


def validate_runtime_findings(
    *,
    results: List[Dict[str, Any]],
    profile: Any,
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    no_hash_bypass: bool = False,
    keep_run_artifacts: bool = False,
    expected_outcome: Optional[str] = None,
) -> None:
    """Validate suspicious runtime sweep findings in-place.

    Results are mutated to include a ``finding_validation`` record plus
    convenience fields such as ``finding_stage`` and ``glitch_realism``.
    """
    if expected_outcome is None:
        expected_outcome = (
            getattr(getattr(profile, "expect", None), "control_outcome", "success")
            or "success"
        )
    instruction_skip_model = "security"
    if getattr(profile, "fault_sweep", None) is not None:
        isc = getattr(profile.fault_sweep, "instruction_skip_config", None)
        if isc is not None:
            instruction_skip_model = (
                getattr(isc, "severity_model", "security") or "security"
            )
    fault_robot_vars = build_fault_robot_vars(
        robot_vars,
        profile,
        no_hash_bypass=no_hash_bypass,
    )
    rerun_point = _make_single_point_runner(
        repo_root=repo_root,
        renode_test=renode_test,
        robot_suite=robot_suite,
        profile=profile,
        robot_vars=fault_robot_vars,
        work_dir=work_dir,
        renode_remote_server_dir=renode_remote_server_dir,
        keep_run_artifacts=keep_run_artifacts,
    )

    def annotate_checks(items: List[Dict[str, Any]]) -> None:
        annotate_result_checks(items, profile, repo_root=repo_root)

    # Separate instruction-skip findings (need Renode reruns, slow) from
    # others (instant, no Renode). Instruction-skip validations are
    # parallelized with ThreadPoolExecutor since each spawns a subprocess
    # and Python's GIL doesn't block subprocess.Popen I/O.
    iskip_items = []  # (index_into_results, result_dict)
    for idx, result in enumerate(results):
        if result.get("is_control", False):
            continue
        if not result.get("fault_injected", False):
            continue
        base_code = _base_fault_type_code(result.get("fault_type"))
        if base_code == "i":
            result["instruction_skip_severity_model"] = instruction_skip_model
            annotate_instruction_skip_severity(
                result,
                expected_outcome=expected_outcome,
                default_model=instruction_skip_model,
            )
            severity_info = classify_instruction_skip_severity(
                result,
                expected_outcome=expected_outcome,
            )
            if severity_info is not None and severity_info["severity"] in {"dos_crash", "dos_recovery"}:
                validation = _validate_instruction_skip(
                    result,
                    expected_outcome=expected_outcome,
                    rerun_point=rerun_point,
                    annotate_checks=annotate_checks,
                )
                _apply_validation(result, validation)
                continue
        if not (result_is_brick(result) or result_has_issues(result, expected_outcome)):
            continue

        effect_evidence = _success_effect_summary(result)
        if effect_evidence is not None:
            validation = _build_validation(
                stage="validated",
                disposition="confirmed",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property="auth_integrity",
                counterfactuals={
                    "success_implies_effect": effect_evidence,
                    "multi_boot_replay": _steady_state_status(result),
                },
                reasons=["success_without_required_effect"],
                skeptical_summary="Validated: the configured API returned success but its required durable effect was absent.",
            )
            _apply_validation(result, validation)
            continue

        relation_evidence = _state_relation_summary(result)
        if relation_evidence is not None:
            validation = _build_validation(
                stage="validated",
                disposition="confirmed",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property="auth_integrity",
                counterfactuals={
                    "state_relation": relation_evidence,
                    "multi_boot_replay": _steady_state_status(result),
                },
                reasons=["state_relation_violation"],
                skeptical_summary="Validated: the boot completed, but the observed component state violated the configured compatibility relation.",
            )
            _apply_validation(result, validation)
            continue

        if base_code == "i":
            iskip_items.append((idx, result))
        elif base_code in _NON_POWER_WRITE_FAULT_CODES:
            validation = _validate_write_fault(
                result,
                expected_outcome=expected_outcome,
            )
            _apply_validation(result, validation)
        else:
            security_property = _security_property(result, expected_outcome)
            validation = _build_validation(
                stage="validated",
                disposition="confirmed",
                fault_type=result.get("fault_type"),
                expected_outcome=expected_outcome,
                security_property=security_property,
                glitch_models={
                    "nop": "not_applicable",
                    "register_zero": "not_applicable",
                    "branch_invert": "not_applicable",
                    "arbitrary_patch": "not_applicable",
                },
                counterfactuals={
                    "clean_firmware": "not_available",
                    "tampered_firmware": "profile_defined",
                    "adjacent_points": "not_tested",
                    "multi_boot_replay": _steady_state_status(result),
                },
                skeptical_summary="Validated: the end-to-end failure already reflects the declared fault model and no specialized skeptic rerun is required for this fault class.",
            )
            _apply_validation(result, validation)

    if not iskip_items:
        return

    # Parallelize instruction-skip validation.  Each validation spawns
    # 2 Renode processes (NOP + branch_invert) via subprocesses, so
    # threads are fine (GIL released during subprocess I/O).
    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed

    max_workers = int(os.environ.get("OTA_VALIDATION_WORKERS", "8"))

    def _validate_one(item):
        _idx, _result = item
        return _idx, _validate_instruction_skip(
            _result,
            expected_outcome=expected_outcome,
            rerun_point=rerun_point,
            annotate_checks=annotate_checks,
        )

    sys.stderr.write(
        "[finding_validator] Validating {} instruction-skip findings "
        "with {} parallel workers\n".format(len(iskip_items), max_workers)
    )
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_validate_one, item): item
            for item in iskip_items
        }
        done_count = 0
        for future in as_completed(futures):
            idx, validation = future.result()
            _apply_validation(results[idx], validation)
            done_count += 1
            if done_count % 10 == 0 or done_count == len(iskip_items):
                sys.stderr.write(
                    "[finding_validator] {}/{} validations complete\n".format(
                        done_count, len(iskip_items)
                    )
                )
