#!/usr/bin/env python3
"""Summarize maintainer-facing profile parity by target.

This helper is intentionally repo-local and static: it inspects profile YAML,
self-test eligibility, semantic wiring, and the OSS-validation manifest to
produce a target-by-target coverage snapshot. The output is meant for internal
coverage accounting, not for user-facing support claims in the README.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from profile_loader import load_profile_raw


TARGET_ORDER = [
    "mcuboot",
    "esp_idf",
    "nuttx_nxboot",
    "nxboot_style",
    "rustboot",
    "tf_m_bl2",
    "other",
]

FEATURE_ORDER = [
    "power_loss",
    "interrupted_erase",
    "bit_corruption",
    "instruction_skip",
    "multi_fault",
    "phase2_fault",
    "security_policy",
]

TARGET_METADATA = {
    "mcuboot": {"target_class": "upstream", "claimable": True},
    "esp_idf": {"target_class": "reference", "claimable": False},
    "nuttx_nxboot": {"target_class": "upstream", "claimable": True},
    "nxboot_style": {"target_class": "reference", "claimable": False},
    "rustboot": {"target_class": "upstream", "claimable": True},
    "tf_m_bl2": {"target_class": "scaffolding", "claimable": False},
    "other": {"target_class": "support", "claimable": False},
}

COUNT_FIELDS = (
    "profiles_total",
    "semantic_profiles",
    "invariant_profiles",
    "self_test_profiles",
    "skip_self_test_profiles",
    "oss_validation_profiles",
)


def _state_probe_script(raw: Dict[str, Any]) -> str:
    state_probe = raw.get("state_probe")
    if isinstance(state_probe, str):
        return state_probe
    if isinstance(state_probe, dict):
        return str(state_probe.get("script", "")).strip()
    return ""


def infer_target(raw: Dict[str, Any], profile_name: str) -> str:
    name = str(raw.get("name") or profile_name)
    lower_name = name.lower()
    bootloader = raw.get("bootloader") if isinstance(raw.get("bootloader"), dict) else {}
    elf = str(bootloader.get("elf", "")).lower()
    probe_script = _state_probe_script(raw).lower()

    if lower_name.startswith("mcuboot_") or "targets/mcuboot/" in probe_script or "mcuboot" in elf:
        return "mcuboot"
    if lower_name.startswith("esp_idf_") or "targets/esp_idf/" in probe_script or "esp_idf_ota" in elf:
        return "esp_idf"
    if lower_name.startswith("nuttx_nxboot_") or "targets/nuttx_nxboot/" in probe_script or "nuttx_nxboot" in elf:
        return "nuttx_nxboot"
    if lower_name.startswith("nxboot_style_") or "examples/nxboot_style" in elf:
        return "nxboot_style"
    if lower_name.startswith("rustboot_") or "targets/rustboot/" in probe_script or "rustboot" in elf:
        return "rustboot"
    if lower_name.startswith("tf_m_") or "targets/tf_m_bl2/" in probe_script or "tf-m" in lower_name or "tfm" in elf:
        return "tf_m_bl2"
    return "other"


def _empty_metrics(target: str) -> Dict[str, Any]:
    metadata = TARGET_METADATA[target]
    return {
        "target_class": metadata["target_class"],
        "claimable": metadata["claimable"],
        "profiles_total": 0,
        "semantic_profiles": 0,
        "invariant_profiles": 0,
        "self_test_profiles": 0,
        "skip_self_test_profiles": 0,
        "oss_validation_profiles": 0,
        "features": {name: 0 for name in FEATURE_ORDER},
        "profiles": [],
    }


def _empty_totals() -> Dict[str, Any]:
    return {
        **{field: 0 for field in COUNT_FIELDS},
        "features": {name: 0 for name in FEATURE_ORDER},
    }


def _profile_features(raw: Dict[str, Any]) -> List[str]:
    features: List[str] = []
    fault_sweep = raw.get("fault_sweep")
    if not isinstance(fault_sweep, dict):
        fault_sweep = {}

    raw_fault_types = fault_sweep.get("fault_types")
    if isinstance(raw_fault_types, list):
        fault_types = [str(item).strip() for item in raw_fault_types if str(item).strip()]
    elif isinstance(raw_fault_types, str) and raw_fault_types.strip():
        fault_types = [raw_fault_types.strip()]
    else:
        fault_types = ["power_loss"]

    for name in ("power_loss", "interrupted_erase", "bit_corruption", "instruction_skip"):
        if name in fault_types:
            features.append(name)

    multi_fault = fault_sweep.get("multi_fault")
    if isinstance(multi_fault, dict) and multi_fault.get("enabled"):
        features.append("multi_fault")

    phase2_fault = fault_sweep.get("phase2_fault")
    if isinstance(phase2_fault, dict) and phase2_fault.get("enabled"):
        features.append("phase2_fault")

    security_policy = raw.get("security_policy")
    if isinstance(security_policy, dict):
        if any(
            value not in (None, False, "", 0)
            for value in security_policy.values()
        ):
            features.append("security_policy")

    return features


def _has_semantic_wiring(raw: Dict[str, Any]) -> bool:
    return any(
        bool(raw.get(key))
        for key in ("state_probe", "semantic_assertions", "invariant_providers", "invariants")
    )


def _has_invariants(raw: Dict[str, Any]) -> bool:
    return bool(raw.get("invariant_providers")) or bool(raw.get("invariants"))


def collect_profile_metrics(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    profiles_dir = repo_root / "profiles"
    results: Dict[str, Dict[str, Any]] = {
        target: _empty_metrics(target) for target in TARGET_ORDER
    }

    for path in sorted(profiles_dir.glob("*.yaml")):
        raw = load_profile_raw(path)
        target = infer_target(raw, path.stem)
        metrics = results.setdefault(target, _empty_metrics(target))
        metrics["profiles_total"] += 1
        metrics["profiles"].append(path.name)
        if _has_semantic_wiring(raw):
            metrics["semantic_profiles"] += 1
        if _has_invariants(raw):
            metrics["invariant_profiles"] += 1
        if raw.get("skip_self_test", False):
            metrics["skip_self_test_profiles"] += 1
        else:
            metrics["self_test_profiles"] += 1
        for feature in _profile_features(raw):
            metrics["features"][feature] += 1

    return results


def collect_oss_validation_metrics(repo_root: Path) -> Dict[str, int]:
    manifest_path = repo_root / "docs" / "oss_validation_profiles.json"
    if not manifest_path.exists():
        return {}
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = payload.get("profiles", []) if isinstance(payload, dict) else []
    counts: Dict[str, int] = {}
    for item in profiles:
        if not isinstance(item, dict):
            continue
        target = infer_target(item, str(item.get("name", "")))
        counts[target] = counts.get(target, 0) + 1
    return counts


def build_report(repo_root: Path) -> Dict[str, Any]:
    per_target = collect_profile_metrics(repo_root)
    oss_counts = collect_oss_validation_metrics(repo_root)
    for target, count in oss_counts.items():
        per_target.setdefault(target, _empty_metrics(target))["oss_validation_profiles"] = count

    totals = _empty_totals()
    claimable_totals = _empty_totals()
    for target in TARGET_ORDER:
        metrics = per_target.get(target)
        if metrics is None:
            continue
        for key in COUNT_FIELDS:
            totals[key] += metrics[key]
            if metrics["claimable"]:
                claimable_totals[key] += metrics[key]
        for feature in FEATURE_ORDER:
            totals["features"][feature] += metrics["features"][feature]
            if metrics["claimable"]:
                claimable_totals["features"][feature] += metrics["features"][feature]

    return {
        "repo_root": str(repo_root),
        "targets": {
            target: {
                key: value
                for key, value in metrics.items()
                if key != "profiles"
            }
            for target, metrics in per_target.items()
            if metrics["profiles_total"] or metrics["oss_validation_profiles"]
        },
        "totals": totals,
        "claimable_totals": claimable_totals,
    }


def _table_rows(report: Dict[str, Any]) -> Iterable[List[str]]:
    yield [
        "target",
        "class",
        "claim",
        "profiles",
        "semantic",
        "invariants",
        "selftest",
        "skip_self",
        "oss",
        "power",
        "erase",
        "bit",
        "skip",
        "multi",
        "phase2",
        "secpol",
    ]
    for target in TARGET_ORDER:
        metrics = report["targets"].get(target)
        if not metrics:
            continue
        features = metrics["features"]
        yield [
            target,
            str(metrics["target_class"]),
            "yes" if metrics["claimable"] else "no",
            str(metrics["profiles_total"]),
            str(metrics["semantic_profiles"]),
            str(metrics["invariant_profiles"]),
            str(metrics["self_test_profiles"]),
            str(metrics["skip_self_test_profiles"]),
            str(metrics["oss_validation_profiles"]),
            str(features["power_loss"]),
            str(features["interrupted_erase"]),
            str(features["bit_corruption"]),
            str(features["instruction_skip"]),
            str(features["multi_fault"]),
            str(features["phase2_fault"]),
            str(features["security_policy"]),
        ]


def render_table(report: Dict[str, Any]) -> str:
    rows = list(_table_rows(report))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    rendered = []
    for idx, row in enumerate(rows):
        rendered.append("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
        if idx == 0:
            rendered.append("  ".join("-" * width for width in widths))
    return "\n".join(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize profile parity by target.")
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="Repository root (defaults to this script's parent repo).",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format.",
    )
    args = parser.parse_args()

    report = build_report(args.repo_root.resolve())
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_table(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
