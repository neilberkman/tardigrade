#!/usr/bin/env python3
"""Run exploratory profile matrix and cluster anomalies.

This script is discovery-oriented: it generates profile variants from baseline
profiles, runs `audit_bootloader.py`, and clusters non-success outcomes across
the matrix. It is designed to surface candidate bug classes without assuming
specific known defects.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import fnmatch
import json
import math
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml


FAULT_PRESETS = (
    "profile",
    "write_erase",
    "write_erase_bit",
    "write_integrity",
    "erase_atomicity",
    "write_reject",
    "time_reset",
)
CRITERIA_PRESETS = ("profile", "vtor_any", "image_hash_exec", "otadata_control")
ERASE_FAULT_TYPES = {"interrupted_erase", "multi_sector_atomicity"}
HARD_OUTCOMES = {"no_boot", "hard_fault"}
KNOWN_ESP_DEFECTS = (
    "crc_covers_state",
    "single_sector",
    "no_fallback",
    "no_abort",
    "no_crc",
)
SCENARIO_TAG_ALIASES = {
    "copy_guard": "upgrade_copy_guard",
}
HEALTHY_OTADATA_STATES = {"NEW", "PENDING_VERIFY", "VALID"}


@dataclass
class MatrixCase:
    case_id: str
    base_profile_path: Path
    base_profile_name: str
    base_role: str
    defect_kind: str
    scenario_tag: str
    variant_profile_path: Path
    report_path: Path
    fault_preset: str
    criteria_preset: str
    expected_control_outcome: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run exploratory profile matrix and anomaly clustering."
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Repository root path.",
    )
    parser.add_argument(
        "--renode-test",
        default=os.environ.get("RENODE_TEST", "renode-test"),
        help="Path to renode-test binary.",
    )
    parser.add_argument(
        "--renode-remote-server-dir",
        default=os.environ.get("RENODE_REMOTE_SERVER_DIR", ""),
        help="Path to Renode remote server directory.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Output directory. Default: "
            "results/exploratory/<UTC timestamp>-esp-idf-matrix"
        ),
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help=(
            "Base profile path (relative to repo root) or glob. "
            "Can be repeated. Default is baseline ESP-IDF set."
        ),
    )
    parser.add_argument(
        "--include-defect-profiles",
        action="store_true",
        help="Also include esp_idf_fault_* profiles in discovery matrix.",
    )
    parser.add_argument(
        "--fault-preset",
        action="append",
        choices=FAULT_PRESETS,
        default=[],
        help=(
            "Fault preset to apply. Can be repeated. "
            "Default: profile + write_erase_bit."
        ),
    )
    parser.add_argument(
        "--criteria-preset",
        action="append",
        choices=CRITERIA_PRESETS,
        default=[],
        help=(
            "Success-criteria preset to apply. Can be repeated. "
            "Default: profile + image_hash_exec."
        ),
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run audit with --quick.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Workers passed to audit_bootloader.py when not quick (default: 1).",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Optional case cap for incremental runs (0 = no cap).",
    )
    parser.add_argument(
        "--reuse-existing",
        action="store_true",
        help="Skip execution for cases with existing report JSON.",
    )
    parser.add_argument(
        "--bounded-step-limit",
        default="0x180000",
        help="Step limit used for bit-corruption presets.",
    )
    parser.add_argument(
        "--otadata-allowlist-min-fault-points",
        type=int,
        default=8,
        help=(
            "Minimum fault-injected baseline points required in a scenario lane "
            "before OtaData suspicious classes can be auto-allowlisted."
        ),
    )
    parser.add_argument(
        "--otadata-allowlist-min-success-points",
        type=int,
        default=4,
        help=(
            "Minimum successful fault-injected baseline points required in a "
            "scenario lane before OtaData suspicious classes can be auto-allowlisted."
        ),
    )
    parser.add_argument(
        "--top-clusters",
        type=int,
        default=25,
        help="Number of top clusters in markdown summary.",
    )
    return parser.parse_args()


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def default_profile_patterns(include_defects: bool) -> List[str]:
    base = [
        "profiles/esp_idf_ota_upgrade.yaml",
        "profiles/esp_idf_ota_fallback_guard.yaml",
        "profiles/esp_idf_ota_crc_schema_guard.yaml",
        "profiles/esp_idf_ota_rollback.yaml",
        "profiles/esp_idf_ota_rollback_guard.yaml",
        "profiles/esp_idf_ota_ss_guard.yaml",
        "profiles/esp_idf_ota_no_rollback.yaml",
        "profiles/esp_idf_ota_crc_guard.yaml",
    ]
    if include_defects:
        base.append("profiles/esp_idf_fault_*.yaml")
    return base


def expand_profile_patterns(repo_root: Path, patterns: Sequence[str]) -> List[Path]:
    profiles_dir = repo_root / "profiles"
    all_profiles = sorted(profiles_dir.glob("*.yaml"))
    all_rel = [p.relative_to(repo_root).as_posix() for p in all_profiles]
    matches: List[Path] = []
    seen = set()
    for pat in patterns:
        # Exact path first.
        candidate = repo_root / pat
        if candidate.exists():
            key = candidate.resolve().as_posix()
            if key not in seen:
                seen.add(key)
                matches.append(candidate)
            continue
        # Glob on repo-relative paths.
        matched_any = False
        for rel, abs_path in zip(all_rel, all_profiles):
            if fnmatch.fnmatch(rel, pat):
                matched_any = True
                key = abs_path.resolve().as_posix()
                if key not in seen:
                    seen.add(key)
                    matches.append(abs_path)
        if not matched_any:
            print(
                "warning: profile pattern matched nothing: {}".format(pat),
                file=sys.stderr,
            )
    return sorted(matches)


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Profile is not a YAML mapping: {}".format(path))
    return data


def sanitize_name(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch in ("_", "-"):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out)


def classify_profile_name(profile_name: str) -> Tuple[str, str, str]:
    if profile_name.startswith("esp_idf_ota_"):
        scenario = profile_name[len("esp_idf_ota_") :] or "upgrade"
        return "baseline", "", scenario

    if profile_name.startswith("esp_idf_fault_"):
        rest = profile_name[len("esp_idf_fault_") :]
        for defect in sorted(KNOWN_ESP_DEFECTS, key=len, reverse=True):
            if rest == defect:
                return "defect", defect, "upgrade"
            prefix = defect + "_"
            if rest.startswith(prefix):
                scenario = rest[len(prefix) :] or "upgrade"
                scenario = SCENARIO_TAG_ALIASES.get(scenario, scenario)
                return "defect", defect, scenario
        # Fallback parsing for unexpected defect name shapes.
        if "_" in rest:
            defect, scenario = rest.split("_", 1)
            scenario = SCENARIO_TAG_ALIASES.get(scenario, scenario)
            return "defect", defect, scenario
        return "defect", rest, "upgrade"

    return "other", "", profile_name


def apply_fault_preset(
    profile_doc: Dict[str, Any],
    preset: str,
    bounded_step_limit: int,
) -> None:
    if preset == "profile":
        return
    fs = profile_doc.setdefault("fault_sweep", {})
    if preset == "write_erase":
        fs["fault_types"] = ["power_loss", "interrupted_erase"]
    elif preset == "write_erase_bit":
        fs["fault_types"] = ["power_loss", "interrupted_erase", "bit_corruption"]
        fs["max_step_limit"] = bounded_step_limit
    elif preset == "write_integrity":
        fs["fault_types"] = [
            "silent_write_failure",
            "write_disturb",
            "wear_leveling_corruption",
        ]
        fs["max_step_limit"] = bounded_step_limit
    elif preset == "erase_atomicity":
        fs["fault_types"] = ["interrupted_erase", "multi_sector_atomicity"]
        fs["max_step_limit"] = bounded_step_limit
    elif preset == "write_reject":
        fs["fault_types"] = ["write_rejection"]
        fs["max_step_limit"] = bounded_step_limit
    elif preset == "time_reset":
        fs["fault_types"] = ["reset_at_time"]
        fs["max_step_limit"] = bounded_step_limit
    else:
        raise ValueError("Unknown fault preset: {}".format(preset))


def apply_criteria_preset(profile_doc: Dict[str, Any], preset: str) -> None:
    if preset == "profile":
        return
    sc = profile_doc.setdefault("success_criteria", {})
    if preset == "vtor_any":
        sc.clear()
        sc["vtor_in_slot"] = "any"
        return
    if preset == "image_hash_exec":
        sc.clear()
        sc["vtor_in_slot"] = "any"
        sc["image_hash"] = True
        sc["image_hash_slot"] = "exec"
        expected = "staging" if "staging" in profile_doc.get("images", {}) else "exec"
        sc["expected_image"] = expected
        return
    if preset == "otadata_control":
        # Keep existing success criteria, but scope OtaData assertions to the
        # control point. Profiles without otadata_expect remain unchanged.
        if isinstance(sc.get("otadata_expect"), dict) and sc.get("otadata_expect"):
            sc["otadata_expect_scope"] = "control"
        return
    raise ValueError("Unknown criteria preset: {}".format(preset))


def expected_control_outcome(profile_doc: Dict[str, Any]) -> str:
    expect = profile_doc.get("expect", {})
    if isinstance(expect, dict):
        return str(expect.get("control_outcome", "success"))
    return "success"


def build_matrix_cases(
    repo_root: Path,
    base_profiles: Sequence[Path],
    fault_presets: Sequence[str],
    criteria_presets: Sequence[str],
    bounded_step_limit: int,
    output_dir: Path,
    max_cases: int,
) -> List[MatrixCase]:
    temp_profiles_dir = output_dir / "profiles"
    temp_profiles_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    cases: List[MatrixCase] = []
    for base_path in base_profiles:
        base_doc = load_yaml(base_path)
        base_name = str(base_doc.get("name", base_path.stem))
        base_role, defect_kind, scenario_tag = classify_profile_name(base_name)
        for fp in fault_presets:
            for cp in criteria_presets:
                variant = copy.deepcopy(base_doc)
                apply_fault_preset(variant, fp, bounded_step_limit)
                apply_criteria_preset(variant, cp)
                variant_name = "{}__f_{}__c_{}".format(base_name, fp, cp)
                variant["name"] = sanitize_name(variant_name)
                variant["skip_self_test"] = True
                case_id = sanitize_name(variant_name)
                variant_path = temp_profiles_dir / "{}.yaml".format(case_id)
                report_path = reports_dir / "{}.json".format(case_id)
                with variant_path.open("w", encoding="utf-8") as f:
                    yaml.safe_dump(variant, f, sort_keys=False)
                cases.append(
                    MatrixCase(
                        case_id=case_id,
                        base_profile_path=base_path,
                        base_profile_name=base_name,
                        base_role=base_role,
                        defect_kind=defect_kind,
                        scenario_tag=scenario_tag,
                        variant_profile_path=variant_path,
                        report_path=report_path,
                        fault_preset=fp,
                        criteria_preset=cp,
                        expected_control_outcome=expected_control_outcome(variant),
                    )
                )
                if max_cases > 0 and len(cases) >= max_cases:
                    return cases
    return cases


def run_case(
    repo_root: Path,
    renode_test: str,
    renode_remote_server_dir: str,
    case: MatrixCase,
    quick: bool,
    workers: int,
    reuse_existing: bool,
) -> Dict[str, Any]:
    if reuse_existing and case.report_path.exists():
        return {
            "case_id": case.case_id,
            "status": "reused",
            "exit_code": 0,
            "report_path": case.report_path.as_posix(),
        }

    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "audit_bootloader.py"),
        "--profile",
        str(case.variant_profile_path),
        "--output",
        str(case.report_path),
        "--renode-test",
        renode_test,
        "--no-assert-control-boots",
        "--no-assert-verdict",
    ]
    if renode_remote_server_dir:
        cmd.extend(["--renode-remote-server-dir", renode_remote_server_dir])
    if quick:
        cmd.append("--quick")
    elif workers > 1:
        cmd.extend(["--workers", str(workers)])

    proc = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )

    result = {
        "case_id": case.case_id,
        "status": "ok" if proc.returncode == 0 else "nonzero_exit",
        "exit_code": proc.returncode,
        "report_path": case.report_path.as_posix(),
        "command": cmd,
    }
    if proc.stdout:
        result["stdout_tail"] = proc.stdout[-2000:]
    if proc.stderr:
        result["stderr_tail"] = proc.stderr[-2000:]
    return result


def load_report(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        return None
    return None


def phase_bucket(fault_at: int, total: int) -> str:
    if total <= 1:
        return "single"
    pct = float(fault_at) / float(max(total - 1, 1))
    if pct < 0.33:
        return "early"
    if pct < 0.66:
        return "mid"
    return "late"


def severity_for_outcome(outcome: str, control_mismatch: bool) -> int:
    if control_mismatch:
        return 4
    if outcome in HARD_OUTCOMES:
        return 3
    if outcome in ("wrong_image", "wrong_pc"):
        return 2
    return 1


def _as_signal_token(value: Any, fallback: str = "na") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def _sorted_counter(counter: Counter) -> Dict[str, int]:
    return {
        key: int(counter[key])
        for key, _ in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    }


def _otadata_digest(signals: Dict[str, Any]) -> str:
    digest = _as_signal_token(signals.get("otadata_digest"), "")
    if digest:
        return digest
    parts: List[str] = []
    for idx in (0, 1):
        seq = _as_signal_token(signals.get("otadata{}_seq".format(idx)), "")
        state = _as_signal_token(signals.get("otadata{}_state".format(idx)), "")
        crc = _as_signal_token(signals.get("otadata{}_crc".format(idx)), "")
        if not (seq or state or crc):
            continue
        parts.append("{}:{}:{}".format(seq, state, crc))
    return "|".join(parts)


def _parse_u32_token(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0) & 0xFFFFFFFF
    except ValueError:
        return None


def _extract_control_signals(points: Sequence[Any]) -> Dict[str, Any]:
    for p in points:
        if isinstance(p, dict) and p.get("is_control", False):
            maybe_signals = p.get("signals", {})
            if isinstance(maybe_signals, dict):
                return maybe_signals
    return {}


def _classify_otadata_drift(
    control_signals: Dict[str, Any],
    point_signals: Dict[str, Any],
    outcome: str,
) -> str:
    control_digest = _otadata_digest(control_signals)
    point_digest = _otadata_digest(point_signals)
    if not control_digest or not point_digest:
        return "none"
    if control_digest == point_digest:
        return "none"

    if outcome != "success":
        return "suspicious_failure"

    control_active = _as_signal_token(control_signals.get("otadata_active_entry"), "")
    point_active = _as_signal_token(point_signals.get("otadata_active_entry"), "")
    if (
        control_active
        and point_active
        and control_active not in ("tie",)
        and point_active not in ("tie",)
        and control_active != point_active
    ):
        return "suspicious_active_entry"

    state_changed = False
    for idx in (0, 1):
        control_seq = _parse_u32_token(control_signals.get("otadata{}_seq".format(idx)))
        point_seq = _parse_u32_token(point_signals.get("otadata{}_seq".format(idx)))
        if control_seq is not None and point_seq is not None and control_seq != point_seq:
            return "suspicious_seq"

        control_crc = _parse_u32_token(control_signals.get("otadata{}_crc".format(idx)))
        point_crc = _parse_u32_token(point_signals.get("otadata{}_crc".format(idx)))
        if control_crc is not None and point_crc is not None and control_crc != point_crc:
            return "suspicious_crc"

        control_state = _as_signal_token(
            control_signals.get("otadata{}_state_name".format(idx)), ""
        ).upper()
        point_state = _as_signal_token(
            point_signals.get("otadata{}_state_name".format(idx)), ""
        ).upper()

        if control_state and control_state not in HEALTHY_OTADATA_STATES:
            return "suspicious_state"
        if point_state and point_state not in HEALTHY_OTADATA_STATES:
            return "suspicious_state"
        if control_state and point_state and control_state != point_state:
            state_changed = True

    if state_changed:
        return "benign_state_transition"
    return "suspicious_unknown"


def _normalize_drift_class(
    drift_class: str,
    scenario_allowlist: Sequence[str],
) -> str:
    if drift_class.startswith("suspicious_") and drift_class in scenario_allowlist:
        return "benign_allowlisted"
    return drift_class


def build_otadata_allowlist(
    cases: Sequence[MatrixCase],
    run_records: Sequence[Dict[str, Any]],
    min_fault_points: int,
    min_success_points: int,
) -> Tuple[Dict[str, Dict[str, List[str]]], Dict[str, Any]]:
    case_by_id = {c.case_id: c for c in cases}
    allowlist: Dict[str, Dict[str, set]] = {}
    lane_samples: Dict[str, Dict[str, Dict[str, int]]] = {}

    for rr in run_records:
        case_id = rr.get("case_id")
        case = case_by_id.get(case_id)
        if case is None or case.base_role != "baseline":
            continue
        report = load_report(Path(rr.get("report_path", "")))
        if report is None:
            continue

        summary = report.get("summary", {})
        sweep_summary = summary.get("runtime_sweep", {})
        if not isinstance(sweep_summary, dict):
            sweep_summary = {}
        control_summary = sweep_summary.get("control", {})
        if not isinstance(control_summary, dict):
            control_summary = {}
        control_outcome = _as_signal_token(control_summary.get("boot_outcome"), "unknown")
        if control_outcome != case.expected_control_outcome:
            # Ignore baselines whose control run is already mismatched.
            continue

        points = report.get("runtime_sweep_results", [])
        if not isinstance(points, list):
            points = []
        control_signals = _extract_control_signals(points)

        scenario_bucket = allowlist.setdefault(case.scenario_tag, {})
        lane_key = "{}|{}".format(case.fault_preset, case.criteria_preset)
        lane_set = scenario_bucket.setdefault(lane_key, set())
        scenario_samples = lane_samples.setdefault(case.scenario_tag, {})
        lane_sample = scenario_samples.setdefault(
            lane_key,
            {
                "baseline_cases": 0,
                "fault_points_total": 0,
                "success_fault_points": 0,
            },
        )
        lane_sample["baseline_cases"] += 1
        for p in points:
            if not isinstance(p, dict):
                continue
            if p.get("is_control", False):
                continue
            if not p.get("fault_injected", False):
                continue
            lane_sample["fault_points_total"] += 1
            outcome = _as_signal_token(p.get("boot_outcome"), "unknown")
            if outcome != "success":
                continue
            lane_sample["success_fault_points"] += 1
            signals = p.get("signals", {})
            if not isinstance(signals, dict):
                signals = {}
            drift_class = _classify_otadata_drift(control_signals, signals, outcome)
            if drift_class.startswith("suspicious_"):
                lane_set.add(drift_class)

    min_fault_points = int(max(0, min_fault_points))
    min_success_points = int(max(0, min_success_points))

    normalized: Dict[str, Dict[str, List[str]]] = {}
    normalized_meta: Dict[str, Dict[str, Dict[str, Any]]] = {}
    lanes_total = 0
    lanes_eligible = 0
    lanes_with_allowlisted = 0

    for scenario_tag, samples in sorted(lane_samples.items()):
        lane_map = allowlist.get(scenario_tag, {})
        scenario_allowlist: Dict[str, List[str]] = {}
        scenario_meta: Dict[str, Dict[str, Any]] = {}
        for lane_key, sample in sorted(samples.items()):
            lanes_total += 1
            fault_points_total = int(sample.get("fault_points_total", 0))
            success_fault_points = int(sample.get("success_fault_points", 0))
            eligible = (
                fault_points_total >= min_fault_points
                and success_fault_points >= min_success_points
            )
            if eligible:
                lanes_eligible += 1
                classes = sorted(lane_map.get(lane_key, set()))
            else:
                classes = []
            if classes:
                lanes_with_allowlisted += 1
            scenario_allowlist[lane_key] = classes
            scenario_meta[lane_key] = {
                "baseline_cases": int(sample.get("baseline_cases", 0)),
                "fault_points_total": fault_points_total,
                "success_fault_points": success_fault_points,
                "eligible": bool(eligible),
                "allowlisted_classes_count": len(classes),
            }
        normalized[scenario_tag] = scenario_allowlist
        normalized_meta[scenario_tag] = scenario_meta

    allowlist_meta = {
        "min_fault_points": min_fault_points,
        "min_success_points": min_success_points,
        "lanes_total": lanes_total,
        "lanes_eligible": lanes_eligible,
        "lanes_ineligible": max(lanes_total - lanes_eligible, 0),
        "lanes_with_allowlisted_classes": lanes_with_allowlisted,
        "lane_samples": normalized_meta,
    }
    return normalized, allowlist_meta


def _collect_case_metrics(
    case: MatrixCase,
    report: Dict[str, Any],
    scenario_allowlist: Sequence[str],
) -> Dict[str, Any]:
    summary = report.get("summary", {})
    sweep_summary = summary.get("runtime_sweep", {})
    if not isinstance(sweep_summary, dict):
        sweep_summary = {}
    control_summary = sweep_summary.get("control", {})
    if not isinstance(control_summary, dict):
        control_summary = {}

    control_outcome = _as_signal_token(control_summary.get("boot_outcome"), "unknown")
    control_slot = _as_signal_token(control_summary.get("boot_slot"), "none")
    expected_control = case.expected_control_outcome
    control_mismatch = control_outcome != expected_control

    points = report.get("runtime_sweep_results", [])
    if not isinstance(points, list):
        points = []

    control_signals = _extract_control_signals(points)
    control_otadata = _otadata_digest(control_signals)

    fault_points_total = 0
    anomalous_points = 0
    hard_failure_points = 0
    wrong_image_points = 0
    otadata_drift_points = 0
    otadata_transition_points = 0
    otadata_suspicious_drift_points = 0
    otadata_allowlisted_points = 0
    outcomes = Counter()
    otadata_drift_classes = Counter()
    otadata_drift_raw_classes = Counter()

    for p in points:
        if not isinstance(p, dict):
            continue
        if p.get("is_control", False):
            continue
        if not p.get("fault_injected", False):
            continue

        fault_points_total += 1
        outcome = _as_signal_token(p.get("boot_outcome"), "unknown")
        outcomes[outcome] += 1

        point_signals = p.get("signals", {})
        if not isinstance(point_signals, dict):
            point_signals = {}
        drift_raw = _classify_otadata_drift(control_signals, point_signals, outcome)
        drift_class = _normalize_drift_class(drift_raw, scenario_allowlist)
        if drift_class != "none":
            otadata_drift_points += 1
            otadata_drift_classes[drift_class] += 1
            otadata_drift_raw_classes[drift_raw] += 1
            if drift_class == "benign_allowlisted":
                otadata_allowlisted_points += 1
            if drift_class.startswith("benign_"):
                otadata_transition_points += 1
            elif drift_class.startswith("suspicious_"):
                otadata_suspicious_drift_points += 1

        if outcome != "success":
            anomalous_points += 1
            if outcome in HARD_OUTCOMES:
                hard_failure_points += 1
            if outcome == "wrong_image":
                wrong_image_points += 1

    denom = float(max(fault_points_total, 1))
    return {
        "case_id": case.case_id,
        "base_profile_name": case.base_profile_name,
        "base_role": case.base_role,
        "defect_kind": case.defect_kind,
        "scenario_tag": case.scenario_tag,
        "fault_preset": case.fault_preset,
        "criteria_preset": case.criteria_preset,
        "expected_control_outcome": expected_control,
        "control_outcome": control_outcome,
        "control_slot": control_slot,
        "control_mismatch": control_mismatch,
        "fault_points_total": fault_points_total,
        "anomalous_points": anomalous_points,
        "hard_failure_points": hard_failure_points,
        "wrong_image_points": wrong_image_points,
        "otadata_drift_points": otadata_drift_points,
        "otadata_transition_points": otadata_transition_points,
        "otadata_suspicious_drift_points": otadata_suspicious_drift_points,
        "otadata_allowlisted_points": otadata_allowlisted_points,
        "failure_rate": round(float(anomalous_points) / denom, 6),
        "brick_rate": round(float(hard_failure_points) / denom, 6),
        "wrong_image_rate": round(float(wrong_image_points) / denom, 6),
        "otadata_drift_rate": round(float(otadata_drift_points) / denom, 6),
        "otadata_transition_rate": round(float(otadata_transition_points) / denom, 6),
        "otadata_suspicious_drift_rate": round(
            float(otadata_suspicious_drift_points) / denom, 6
        ),
        "control_otadata_digest": control_otadata,
        "outcome_counts": dict(sorted(outcomes.items())),
        "otadata_drift_class_counts": dict(sorted(otadata_drift_classes.items())),
        "otadata_drift_raw_class_counts": dict(sorted(otadata_drift_raw_classes.items())),
    }


def _delta(a: Dict[str, Any], b: Dict[str, Any], key: str) -> float:
    return float(a.get(key, 0.0) or 0.0) - float(b.get(key, 0.0) or 0.0)


def build_defect_deltas(
    cases: Sequence[MatrixCase],
    case_metrics_by_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    baseline_by_key: Dict[Tuple[str, str, str], List[str]] = {}
    for c in cases:
        if c.base_role != "baseline":
            continue
        key = (c.scenario_tag, c.fault_preset, c.criteria_preset)
        baseline_by_key.setdefault(key, []).append(c.case_id)

    deltas: List[Dict[str, Any]] = []
    for c in cases:
        if c.base_role != "defect":
            continue
        key = (c.scenario_tag, c.fault_preset, c.criteria_preset)
        baseline_ids = sorted(baseline_by_key.get(key, []))
        if not baseline_ids:
            continue
        baseline_case_id = baseline_ids[0]
        defect_metrics = case_metrics_by_id.get(c.case_id)
        baseline_metrics = case_metrics_by_id.get(baseline_case_id)
        if defect_metrics is None or baseline_metrics is None:
            continue

        defect_control_outcome = _as_signal_token(
            defect_metrics.get("control_outcome"), "unknown"
        )
        baseline_control_outcome = _as_signal_token(
            baseline_metrics.get("control_outcome"), "unknown"
        )
        control_outcome_changed = defect_control_outcome != baseline_control_outcome
        control_outcome_shift = severity_for_outcome(
            defect_control_outcome, False
        ) - severity_for_outcome(baseline_control_outcome, False)

        control_delta = int(bool(defect_metrics.get("control_mismatch"))) - int(
            bool(baseline_metrics.get("control_mismatch"))
        )
        failure_delta = _delta(defect_metrics, baseline_metrics, "failure_rate")
        brick_delta = _delta(defect_metrics, baseline_metrics, "brick_rate")
        wrong_image_delta = _delta(defect_metrics, baseline_metrics, "wrong_image_rate")
        otadata_drift_delta = _delta(
            defect_metrics, baseline_metrics, "otadata_drift_rate"
        )
        otadata_suspicious_drift_delta = _delta(
            defect_metrics, baseline_metrics, "otadata_suspicious_drift_rate"
        )
        anomaly_points_delta = int(defect_metrics.get("anomalous_points", 0)) - int(
            baseline_metrics.get("anomalous_points", 0)
        )

        positive_signal = max(
            float(max(control_delta, 0)),
            max(failure_delta, 0.0),
            max(brick_delta, 0.0),
            max(wrong_image_delta, 0.0),
            max(otadata_suspicious_drift_delta, 0.0),
            max(float(control_outcome_shift), 0.0),
        )
        negative_signal = min(
            float(min(control_delta, 0)),
            min(failure_delta, 0.0),
            min(brick_delta, 0.0),
            min(wrong_image_delta, 0.0),
            min(otadata_suspicious_drift_delta, 0.0),
            min(float(control_outcome_shift), 0.0),
        )
        if positive_signal > 0:
            direction = "worse"
        elif negative_signal < 0:
            direction = "better"
        else:
            direction = "same"

        behavior_regression = (
            control_delta > 0
            or control_outcome_shift > 0
            or failure_delta > 0.0
            or brick_delta > 0.0
            or wrong_image_delta > 0.0
        )
        otadata_score_term = (
            max(otadata_suspicious_drift_delta, 0.0) if behavior_regression else 0.0
        )

        delta_score = (
            4.0 * max(float(control_delta), 0.0)
            + 2.0 * max(float(control_outcome_shift), 0.0)
            + 3.0 * max(brick_delta, 0.0)
            + 2.0 * max(failure_delta, 0.0)
            + 1.5 * otadata_score_term
            + 1.0 * max(wrong_image_delta, 0.0)
            + 0.1 * max(float(anomaly_points_delta), 0.0)
        )

        deltas.append(
            {
                "defect_case_id": c.case_id,
                "baseline_case_id": baseline_case_id,
                "defect_kind": c.defect_kind or "unknown",
                "scenario_tag": c.scenario_tag,
                "fault_preset": c.fault_preset,
                "criteria_preset": c.criteria_preset,
                "direction": direction,
                "delta_score": round(delta_score, 6),
                "deltas": {
                    "control_mismatch": control_delta,
                    "control_outcome_changed": int(control_outcome_changed),
                    "control_outcome_shift": int(control_outcome_shift),
                    "failure_rate": round(failure_delta, 6),
                    "brick_rate": round(brick_delta, 6),
                    "wrong_image_rate": round(wrong_image_delta, 6),
                    "otadata_drift_rate": round(otadata_drift_delta, 6),
                    "otadata_suspicious_drift_rate": round(
                        otadata_suspicious_drift_delta, 6
                    ),
                    "anomalous_points": anomaly_points_delta,
                },
                "defect_metrics": {
                    "control_mismatch": bool(defect_metrics.get("control_mismatch", False)),
                    "control_outcome": defect_control_outcome,
                    "failure_rate": float(defect_metrics.get("failure_rate", 0.0) or 0.0),
                    "brick_rate": float(defect_metrics.get("brick_rate", 0.0) or 0.0),
                    "otadata_drift_rate": float(
                        defect_metrics.get("otadata_drift_rate", 0.0) or 0.0
                    ),
                    "otadata_suspicious_drift_rate": float(
                        defect_metrics.get("otadata_suspicious_drift_rate", 0.0)
                        or 0.0
                    ),
                },
                "baseline_metrics": {
                    "control_mismatch": bool(
                        baseline_metrics.get("control_mismatch", False)
                    ),
                    "control_outcome": baseline_control_outcome,
                    "failure_rate": float(
                        baseline_metrics.get("failure_rate", 0.0) or 0.0
                    ),
                    "brick_rate": float(baseline_metrics.get("brick_rate", 0.0) or 0.0),
                    "otadata_drift_rate": float(
                        baseline_metrics.get("otadata_drift_rate", 0.0) or 0.0
                    ),
                    "otadata_suspicious_drift_rate": float(
                        baseline_metrics.get("otadata_suspicious_drift_rate", 0.0)
                        or 0.0
                    ),
                },
            }
        )

    deltas.sort(
        key=lambda x: (
            float(x.get("delta_score", 0.0)),
            float(x.get("deltas", {}).get("failure_rate", 0.0)),
            float(x.get("deltas", {}).get("brick_rate", 0.0)),
        ),
        reverse=True,
    )
    return deltas


def extract_anomalies(
    cases: Sequence[MatrixCase],
    run_records: Sequence[Dict[str, Any]],
    otadata_allowlist_min_fault_points: int,
    otadata_allowlist_min_success_points: int,
) -> Tuple[
    List[Dict[str, Any]],
    Dict[str, Any],
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, List[str]]],
    Dict[str, Any],
]:
    case_by_id = {c.case_id: c for c in cases}
    clusters: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    case_metrics_by_id: Dict[str, Dict[str, Any]] = {}
    scenario_otadata_allowlist, allowlist_meta = build_otadata_allowlist(
        cases,
        run_records,
        min_fault_points=otadata_allowlist_min_fault_points,
        min_success_points=otadata_allowlist_min_success_points,
    )

    totals = {
        "cases_total": len(cases),
        "cases_with_report": 0,
        "cases_missing_report": 0,
        "cases_control_mismatch": 0,
        "anomalous_points_total": 0,
        "otadata_drift_points_total": 0,
        "otadata_transition_points_total": 0,
        "otadata_suspicious_drift_points_total": 0,
        "otadata_allowlisted_points_total": 0,
        "otadata_allowlist_scenarios": len(scenario_otadata_allowlist),
        "otadata_allowlist_lanes": int(allowlist_meta.get("lanes_total", 0)),
        "otadata_allowlist_eligible_lanes": int(
            allowlist_meta.get("lanes_eligible", 0)
        ),
        "otadata_allowlist_ineligible_lanes": int(
            allowlist_meta.get("lanes_ineligible", 0)
        ),
        "otadata_allowlist_min_fault_points": int(
            allowlist_meta.get("min_fault_points", 0)
        ),
        "otadata_allowlist_min_success_points": int(
            allowlist_meta.get("min_success_points", 0)
        ),
    }

    for rr in run_records:
        case_id = rr.get("case_id")
        case = case_by_id.get(case_id)
        if case is None:
            continue
        report = load_report(Path(rr.get("report_path", "")))
        if report is None:
            totals["cases_missing_report"] += 1
            continue
        totals["cases_with_report"] += 1

        scenario_allowlist: set = set()
        lane_map = scenario_otadata_allowlist.get(case.scenario_tag, {})
        lane_key = "{}|{}".format(case.fault_preset, case.criteria_preset)
        if lane_key in lane_map:
            scenario_allowlist.update(lane_map[lane_key])
        elif lane_map:
            # Fallback when no baseline lane exists for the exact variant.
            for values in lane_map.values():
                scenario_allowlist.update(values)
        case_metrics = _collect_case_metrics(case, report, scenario_allowlist)
        case_metrics_by_id[case.case_id] = case_metrics

        control_outcome = _as_signal_token(case_metrics.get("control_outcome"), "unknown")
        control_slot = _as_signal_token(case_metrics.get("control_slot"), "none")
        expected_control = case.expected_control_outcome

        if bool(case_metrics.get("control_mismatch", False)):
            totals["cases_control_mismatch"] += 1
            key = (
                "control_mismatch",
                expected_control,
                control_outcome,
            )
            entry = clusters.setdefault(
                key,
                {
                    "kind": "control_mismatch",
                    "signature": {
                        "expected_control_outcome": expected_control,
                        "actual_control_outcome": control_outcome,
                    },
                    "count": 0,
                    "case_ids": set(),
                    "base_profiles": set(),
                    "base_roles": set(),
                    "defect_kinds": set(),
                    "scenarios": set(),
                    "control_slots": Counter(),
                    "severity": severity_for_outcome(control_outcome, True),
                },
            )
            entry["count"] += 1
            entry["case_ids"].add(case_id)
            entry["base_profiles"].add(case.base_profile_name)
            entry["base_roles"].add(case.base_role)
            if case.defect_kind:
                entry["defect_kinds"].add(case.defect_kind)
            entry["scenarios"].add(case.scenario_tag)
            entry["control_slots"][control_slot] += 1

        points = report.get("runtime_sweep_results", [])
        if not isinstance(points, list):
            points = []
        control_signals = _extract_control_signals(points)
        calibrated_writes = int(report.get("calibrated_writes", 0) or 0)
        calibrated_erases = int(report.get("calibrated_erases", 0) or 0)

        for p in points:
            if not isinstance(p, dict):
                continue
            if p.get("is_control", False):
                continue
            if not p.get("fault_injected", False):
                continue
            outcome = str(p.get("boot_outcome", "unknown"))
            fault_type = str(p.get("fault_type", "w"))
            fault_at = int(p.get("fault_at", 0) or 0)
            boot_slot = str(p.get("boot_slot", "none"))
            signals = p.get("signals", {}) if isinstance(p.get("signals"), dict) else {}
            image_hash_match = str(signals.get("image_hash_match", "na"))
            total = calibrated_erases if fault_type in ("e", "a") else calibrated_writes
            phase = phase_bucket(fault_at, max(total, 1))
            drift_raw = _classify_otadata_drift(control_signals, signals, outcome)
            drift_class = _normalize_drift_class(drift_raw, scenario_allowlist)
            otadata_drift = drift_class != "none"
            otadata_suspicious_drift = drift_class.startswith("suspicious_")

            if otadata_drift:
                totals["otadata_drift_points_total"] += 1
            if drift_class.startswith("benign_"):
                totals["otadata_transition_points_total"] += 1
            if drift_class == "benign_allowlisted":
                totals["otadata_allowlisted_points_total"] += 1
            if otadata_suspicious_drift:
                totals["otadata_suspicious_drift_points_total"] += 1
                drift_key = (
                    "otadata_drift",
                    drift_class,
                    fault_type,
                    phase,
                )
                drift_entry = clusters.setdefault(
                    drift_key,
                    {
                        "kind": "otadata_drift",
                        "signature": {
                            "drift_class": drift_class,
                            "fault_type": fault_type,
                            "phase": phase,
                        },
                        "count": 0,
                        "case_ids": set(),
                        "base_profiles": set(),
                        "base_roles": set(),
                        "defect_kinds": set(),
                        "scenarios": set(),
                        "outcomes": Counter(),
                        "boot_slots": Counter(),
                        "severity": 2,
                    },
                )
                if drift_class == "suspicious_failure":
                    drift_entry["severity"] = 3
                drift_entry["count"] += 1
                drift_entry["case_ids"].add(case_id)
                drift_entry["base_profiles"].add(case.base_profile_name)
                drift_entry["base_roles"].add(case.base_role)
                if case.defect_kind:
                    drift_entry["defect_kinds"].add(case.defect_kind)
                drift_entry["scenarios"].add(case.scenario_tag)
                drift_entry["outcomes"][outcome] += 1
                drift_entry["boot_slots"][boot_slot] += 1

            if outcome == "success":
                continue

            key = (
                "fault_anomaly",
                outcome,
                fault_type,
                phase,
            )
            entry = clusters.setdefault(
                key,
                {
                    "kind": "fault_anomaly",
                    "signature": {
                        "outcome": outcome,
                        "fault_type": fault_type,
                        "phase": phase,
                    },
                    "count": 0,
                    "case_ids": set(),
                    "base_profiles": set(),
                    "base_roles": set(),
                    "defect_kinds": set(),
                    "scenarios": set(),
                    "boot_slots": Counter(),
                    "image_hash_matches": Counter(),
                    "otadata_drift": Counter(),
                    "severity": severity_for_outcome(outcome, False),
                },
            )
            entry["count"] += 1
            entry["case_ids"].add(case_id)
            entry["base_profiles"].add(case.base_profile_name)
            entry["base_roles"].add(case.base_role)
            if case.defect_kind:
                entry["defect_kinds"].add(case.defect_kind)
            entry["scenarios"].add(case.scenario_tag)
            entry["boot_slots"][boot_slot] += 1
            entry["image_hash_matches"][image_hash_match] += 1
            entry["otadata_drift"][drift_class] += 1
            totals["anomalous_points_total"] += 1

    cluster_rows: List[Dict[str, Any]] = []
    for entry in clusters.values():
        case_count = len(entry["case_ids"])
        profile_count = len(entry["base_profiles"])
        occurrence_count = int(entry["count"])
        novelty = 1.0 / float(max(profile_count, 1))
        reproducibility = float(case_count)
        severity = float(entry["severity"])
        kind = str(entry.get("kind", ""))
        kind_weight = 0.25 if kind == "otadata_drift" else 1.0
        score = (
            severity
            * reproducibility
            * novelty
            * math.log1p(occurrence_count)
            * kind_weight
        )
        cluster_rows.append(
            {
                "kind": entry["kind"],
                "signature": entry["signature"],
                "count": occurrence_count,
                "case_count": case_count,
                "profile_count": profile_count,
                "severity": entry["severity"],
                "score": round(score, 6),
                "case_ids": sorted(entry["case_ids"]),
                "base_profiles": sorted(entry["base_profiles"]),
                "base_roles": sorted(entry.get("base_roles", set())),
                "defect_kinds": sorted(entry.get("defect_kinds", set())),
                "scenarios": sorted(entry.get("scenarios", set())),
            }
        )
        extra = cluster_rows[-1]
        if isinstance(entry.get("boot_slots"), Counter):
            extra["boot_slots"] = _sorted_counter(entry["boot_slots"])
        if isinstance(entry.get("image_hash_matches"), Counter):
            extra["image_hash_matches"] = _sorted_counter(entry["image_hash_matches"])
        if isinstance(entry.get("otadata_drift"), Counter):
            extra["otadata_drift"] = _sorted_counter(entry["otadata_drift"])
        if isinstance(entry.get("outcomes"), Counter):
            extra["outcomes"] = _sorted_counter(entry["outcomes"])
        if isinstance(entry.get("control_slots"), Counter):
            extra["control_slots"] = _sorted_counter(entry["control_slots"])
    cluster_rows.sort(
        key=lambda x: (x["score"], x["severity"], x["case_count"], x["count"]),
        reverse=True,
    )
    return (
        cluster_rows,
        totals,
        case_metrics_by_id,
        scenario_otadata_allowlist,
        allowlist_meta,
    )


def render_markdown_summary(
    output_dir: Path,
    cases: Sequence[MatrixCase],
    runs: Sequence[Dict[str, Any]],
    clusters: Sequence[Dict[str, Any]],
    totals: Dict[str, Any],
    defect_deltas: Sequence[Dict[str, Any]],
    top_n: int,
) -> str:
    lines: List[str] = []
    lines.append("# Exploratory Matrix Summary")
    lines.append("")
    lines.append("- Generated: `{}`".format(utc_stamp()))
    lines.append("- Output dir: `{}`".format(output_dir.as_posix()))
    lines.append("- Cases planned: `{}`".format(len(cases)))
    lines.append("- Cases with report: `{}`".format(totals.get("cases_with_report", 0)))
    lines.append("- Cases missing report: `{}`".format(totals.get("cases_missing_report", 0)))
    lines.append("- Control mismatches: `{}`".format(totals.get("cases_control_mismatch", 0)))
    lines.append("- Anomalous fault points: `{}`".format(totals.get("anomalous_points_total", 0)))
    lines.append("- OtaData drift points (all): `{}`".format(totals.get("otadata_drift_points_total", 0)))
    lines.append(
        "- OtaData benign transitions: `{}`".format(
            totals.get("otadata_transition_points_total", 0)
        )
    )
    lines.append(
        "- OtaData allowlisted points: `{}`".format(
            totals.get("otadata_allowlisted_points_total", 0)
        )
    )
    lines.append(
        "- OtaData allowlist lanes: `{}`".format(
            totals.get("otadata_allowlist_lanes", 0)
        )
    )
    lines.append(
        "- OtaData allowlist eligible lanes: `{}`".format(
            totals.get("otadata_allowlist_eligible_lanes", 0)
        )
    )
    lines.append(
        "- OtaData allowlist ineligible lanes: `{}`".format(
            totals.get("otadata_allowlist_ineligible_lanes", 0)
        )
    )
    lines.append(
        "- OtaData allowlist min samples (fault/success): `{}/{}`".format(
            totals.get("otadata_allowlist_min_fault_points", 0),
            totals.get("otadata_allowlist_min_success_points", 0),
        )
    )
    lines.append(
        "- OtaData suspicious drift points: `{}`".format(
            totals.get("otadata_suspicious_drift_points_total", 0)
        )
    )
    lines.append("")
    lines.append("## Top Clusters")
    lines.append("")
    if not clusters:
        lines.append("No anomalies detected.")
    else:
        lines.append("| Rank | Score | Kind | Signature | Occurrences | Cases | Profiles |")
        lines.append("| --- | ---: | --- | --- | ---: | ---: | ---: |")
        for idx, c in enumerate(clusters[:top_n], 1):
            sig = json.dumps(c["signature"], sort_keys=True)
            if len(sig) > 120:
                sig = sig[:117] + "..."
            lines.append(
                "| {} | {:.3f} | {} | `{}` | {} | {} | {} |".format(
                    idx,
                    float(c["score"]),
                    c["kind"],
                    sig,
                    c["count"],
                    c["case_count"],
                    c["profile_count"],
                )
            )
    lines.append("")
    lines.append("## Baseline vs Defect Deltas")
    lines.append("")
    regressions = [d for d in defect_deltas if d.get("direction") == "worse"]
    if not regressions:
        lines.append("No defect regressions against baseline were detected.")
    else:
        lines.append(
            "| Rank | Score | Defect | Baseline | Scenario | Fault | Criteria | "
            "Δfailure | Δbrick | Δcontrol | Δcontrol_outcome | Δotadata(susp) |"
        )
        lines.append(
            "| --- | ---: | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"
        )
        for idx, row in enumerate(regressions[:top_n], 1):
            delta = row.get("deltas", {})
            lines.append(
                "| {} | {:.3f} | `{}` | `{}` | `{}` | `{}` | `{}` | "
                "{:+.3f} | {:+.3f} | {:+d} | {:+d} | {:+.3f} |".format(
                    idx,
                    float(row.get("delta_score", 0.0)),
                    row.get("defect_case_id", ""),
                    row.get("baseline_case_id", ""),
                    row.get("scenario_tag", ""),
                    row.get("fault_preset", ""),
                    row.get("criteria_preset", ""),
                    float(delta.get("failure_rate", 0.0)),
                    float(delta.get("brick_rate", 0.0)),
                    int(delta.get("control_mismatch", 0)),
                    int(delta.get("control_outcome_shift", 0)),
                    float(delta.get("otadata_suspicious_drift_rate", 0.0)),
                )
            )
    lines.append("")
    lines.append("## Run Records")
    lines.append("")
    lines.append("| Case | Status | Exit | Report |")
    lines.append("| --- | --- | ---: | --- |")
    for rr in runs:
        lines.append(
            "| `{}` | {} | {} | `{}` |".format(
                rr.get("case_id", "?"),
                rr.get("status", "?"),
                rr.get("exit_code", "?"),
                rr.get("report_path", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print("repo root does not exist: {}".format(repo_root), file=sys.stderr)
        return 2

    ts = utc_stamp()
    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else (repo_root / "results" / "exploratory" / ("{}-esp-idf-matrix".format(ts)))
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    profile_patterns = args.profile or default_profile_patterns(args.include_defect_profiles)
    base_profiles = expand_profile_patterns(repo_root, profile_patterns)
    if not base_profiles:
        print("no base profiles found for patterns: {}".format(profile_patterns), file=sys.stderr)
        return 2

    fault_presets = args.fault_preset or ["profile", "write_erase_bit"]
    criteria_presets = args.criteria_preset or ["profile", "image_hash_exec"]
    bounded_step_limit = int(str(args.bounded_step_limit), 0)

    cases = build_matrix_cases(
        repo_root=repo_root,
        base_profiles=base_profiles,
        fault_presets=fault_presets,
        criteria_presets=criteria_presets,
        bounded_step_limit=bounded_step_limit,
        output_dir=output_dir,
        max_cases=args.max_cases,
    )

    print(
        "Exploratory matrix: {} base profiles, {} cases".format(
            len(base_profiles), len(cases)
        ),
        file=sys.stderr,
    )

    run_records: List[Dict[str, Any]] = []
    for i, case in enumerate(cases, 1):
        print(
            "[{}/{}] {}".format(i, len(cases), case.case_id),
            file=sys.stderr,
        )
        rr = run_case(
            repo_root=repo_root,
            renode_test=args.renode_test,
            renode_remote_server_dir=args.renode_remote_server_dir,
            case=case,
            quick=args.quick,
            workers=args.workers,
            reuse_existing=args.reuse_existing,
        )
        run_records.append(rr)

    (
        clusters,
        totals,
        case_metrics_by_id,
        scenario_otadata_allowlist,
        otadata_allowlist_meta,
    ) = extract_anomalies(
        cases,
        run_records,
        otadata_allowlist_min_fault_points=args.otadata_allowlist_min_fault_points,
        otadata_allowlist_min_success_points=args.otadata_allowlist_min_success_points,
    )
    defect_deltas = build_defect_deltas(cases, case_metrics_by_id)

    matrix_payload = {
        "generated_at_utc": ts,
        "repo_root": repo_root.as_posix(),
        "output_dir": output_dir.as_posix(),
        "config": {
            "profile_patterns": profile_patterns,
            "fault_presets": fault_presets,
            "criteria_presets": criteria_presets,
            "quick": bool(args.quick),
            "workers": int(args.workers),
            "max_cases": int(args.max_cases),
            "reuse_existing": bool(args.reuse_existing),
            "bounded_step_limit": int(bounded_step_limit),
            "otadata_allowlist_min_fault_points": int(
                args.otadata_allowlist_min_fault_points
            ),
            "otadata_allowlist_min_success_points": int(
                args.otadata_allowlist_min_success_points
            ),
        },
        "cases": [
            {
                "case_id": c.case_id,
                "base_profile_name": c.base_profile_name,
                "base_profile_path": c.base_profile_path.relative_to(repo_root).as_posix(),
                "base_role": c.base_role,
                "defect_kind": c.defect_kind,
                "scenario_tag": c.scenario_tag,
                "variant_profile_path": c.variant_profile_path.as_posix(),
                "report_path": c.report_path.as_posix(),
                "fault_preset": c.fault_preset,
                "criteria_preset": c.criteria_preset,
                "expected_control_outcome": c.expected_control_outcome,
            }
            for c in cases
        ],
        "runs": run_records,
        "totals": totals,
        "clusters": clusters,
        "otadata_allowlist": scenario_otadata_allowlist,
        "otadata_allowlist_meta": otadata_allowlist_meta,
        "case_metrics": [
            case_metrics_by_id[k]
            for k in sorted(case_metrics_by_id.keys())
        ],
        "defect_deltas": defect_deltas,
    }

    matrix_json = output_dir / "matrix_results.json"
    matrix_json.write_text(
        json.dumps(matrix_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = render_markdown_summary(
        output_dir=output_dir,
        cases=cases,
        runs=run_records,
        clusters=clusters,
        totals=totals,
        defect_deltas=defect_deltas,
        top_n=args.top_clusters,
    )
    summary_md = output_dir / "anomaly_summary.md"
    summary_md.write_text(md, encoding="utf-8")

    print(
        json.dumps(
            {
                "output_dir": output_dir.as_posix(),
                "matrix_results": matrix_json.as_posix(),
                "summary": summary_md.as_posix(),
                "cases": len(cases),
                "clusters": len(clusters),
                "control_mismatches": totals.get("cases_control_mismatch", 0),
                "defect_deltas": len(defect_deltas),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
