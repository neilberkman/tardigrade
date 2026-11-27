#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
"""Built-in explicit-point trial runner for verdict bisection."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml

from fault_classification import (
    result_has_issues,
    result_is_infrastructure_error,
    result_is_skipped,
    result_is_timeout,
)
from profile_loader import MAX_PROFILE_FAULT_POINTS, load_profile_raw

ROOT = Path(__file__).resolve().parents[1]
POINT_RE = re.compile(r"[we](?:0|[1-9][0-9]*)(?:,[we](?:0|[1-9][0-9]*)){0,7}")


def _parse_point(point):
    if not isinstance(point, str) or not POINT_RE.fullmatch(point):
        raise ValueError("expected 1 to 8 explicit write/erase cuts, such as w0, w3,w6 or w1,e2,w0")
    return [(token[0], int(token[1:])) for token in point.split(",")]


def _resolve_build_export(raw_path):
    candidate = Path.cwd() / raw_path
    if not candidate.is_file():
        candidate = Path.cwd() / Path(raw_path).name
    if not candidate.is_file():
        raise ValueError(f"missing build export {Path(raw_path).name}")
    return str(candidate.resolve())


def _bind_artifacts(config, profile_path):
    bootloader = config.get("bootloader")
    if not isinstance(bootloader, dict) or not bootloader.get("elf"):
        raise ValueError("profile is missing bootloader.elf")
    bootloader["elf"] = _resolve_build_export(bootloader["elf"])
    images = config.get("images")
    if not isinstance(images, dict) or not images:
        raise ValueError("profile is missing images")
    for slot, image_path in list(images.items()):
        images[slot] = _resolve_build_export(image_path)
    for key in ("firmware_elf", "residual_image"):
        if config.get(key):
            config[key] = _resolve_build_export(config[key])
    platform = config.get("platform")
    if isinstance(platform, str) and platform and not (ROOT / platform).is_file():
        relative = profile_path.resolve().parent / platform
        if relative.is_file():
            config["platform"] = str(relative.resolve())


def _configure_point_sweep(config, cuts):
    if config.get("initial_states") or config.get("components"):
        raise ValueError("explicit point trial requires a single-state, single-component profile")
    for key in ("state_fuzzer", "fuzz_corpus", "boundary_campaigns", "update_sequence"):
        config.pop(key, None)
    fault_sweep = dict(config.get("fault_sweep") or {})
    config["fault_sweep"] = fault_sweep
    fault_sweep["mode"] = "runtime"
    fault_sweep["evaluation_mode"] = "execute"
    for key in (
        "multi_fault",
        "metadata_fault",
        "hook_fault",
        "confirm_cycle",
        "partial_staging",
        "nvs_corruption",
        "instruction_skip_config",
        "read_fault_config",
        "timed_bit_corruption_config",
    ):
        fault_sweep.pop(key, None)
    if len(cuts) == 1:
        op, index = cuts[0]
        fault_sweep.pop("phase2_fault", None)
        fault_sweep["fault_types"] = ["power_loss" if op == "w" else "interrupted_erase"]
        if op == "e":
            fault_sweep["include_erase_fault_points"] = True
        return ["--fault-start", str(index), "--fault-end", str(index + 1)]
    fault_sweep["fault_types"] = []
    if any(op == "e" for op, _ in cuts):
        fault_sweep["include_erase_fault_points"] = True
    if len(cuts) == 2:
        (op1, idx1), (op2, idx2) = cuts
        fault_sweep["phase2_fault"] = {
            "enabled": True,
            "first_fault_types": ["power_loss" if op1 == "w" else "interrupted_erase"],
            "fault_types": ["power_loss" if op2 == "w" else "interrupted_erase"],
            "pairs": [[idx1, idx2]],
        }
    else:
        fault_sweep["phase2_fault"] = {
            "enabled": True,
            "first_fault_types": ["power_loss" if cuts[0][0] == "w" else "interrupted_erase"],
            "fault_types": ["power_loss" if cuts[1][0] == "w" else "interrupted_erase"],
            "chains": [[[idx, "power_loss" if op == "w" else "interrupted_erase"] for op, idx in cuts]],
        }
    return ["--fault-start", str(MAX_PROFILE_FAULT_POINTS)]


def _observation_matches_point(row, cuts):
    if row.get("fault_injected") is not True:
        return False
    if len(cuts) == 1:
        op, index = cuts[0]
        return row.get("fault_at") == index and row.get("fault_type") == op
    if len(cuts) == 2:
        (op1, idx1), (op2, idx2) = cuts
        expected_type = f"p2:{idx1}:{idx2}:{op1}:{op2}"
        p2 = row.get("phase2_fault")
        if row.get("fault_at") != idx1 or row.get("fault_type") not in ("p2", expected_type):
            return False
        if not isinstance(p2, dict) or p2.get("skip_reason") is not None:
            return False
        return (
            p2.get("p1_fault_at") == idx1
            and p2.get("p2_fault_at") == idx2
            and p2.get("p1_fault_type") == op1
            and p2.get("p2_fault_type") == op2
            and p2.get("p1_injected") is True
            and p2.get("p2_injected") is True
        )
    expected_code = "pc:" + ":".join(f"{idx}:{op}" for op, idx in cuts)
    chain = row.get("phase2_fault_chain")
    if row.get("fault_at") != cuts[0][1] or row.get("fault_type") not in ("pc", expected_code):
        return False
    if not isinstance(chain, dict) or chain.get("skip_reason") is not None:
        return False
    if chain.get("first_unreached_cut") is not None:
        return False
    recorded = chain.get("cuts")
    if (
        chain.get("cut_count") != len(cuts)
        or chain.get("requested_cut_count") != len(cuts)
        or not isinstance(recorded, list)
        or len(recorded) != len(cuts)
    ):
        return False
    return all(
        isinstance(item, dict)
        and item.get("fault_at") == idx
        and item.get("fault_type") == op
        and item.get("injected") is True
        for (op, idx), item in zip(cuts, recorded)
    )


def measure(profile_path, point):
    cuts = _parse_point(point)
    config = load_profile_raw(profile_path)
    _bind_artifacts(config, profile_path)
    slice_args = _configure_point_sweep(config, cuts)
    # Keep generated inputs outside the copied build, even if an exported
    # artifact happens to have the same name.
    scratch = Path(os.environ["BISECT_RESULT"]).parent
    profile = scratch / "record-profile.yaml"
    report = scratch / "audit.json"
    profile.write_text(yaml.safe_dump(config))
    subprocess.run([
        sys.executable, str(ROOT / "scripts/audit_bootloader.py"), "--profile", str(profile),
        "--output", str(report), "--renode-test", os.environ.get("RENODE_TEST", "renode-test"),
        "--workers", "1", *slice_args, "--no-assert-verdict",
    ], check=True)
    rows = [r for r in json.loads(report.read_text())["runtime_sweep_results"] if not r.get("is_control")]
    if len(rows) != 1:
        raise ValueError(f"expected one point observation, got {len(rows)}")
    row = rows[0]
    if (
        not _observation_matches_point(row, cuts)
        or result_is_skipped(row)
        or result_is_infrastructure_error(row)
        or result_is_timeout(row)
    ):
        raise ValueError("the requested point did not yield a complete observation")
    if not row.get("boot_outcome"):
        raise ValueError("missing recovery outcome")
    expected_outcome = str((config.get("expect") or {}).get("control_outcome") or "success")
    return {"verdict": "fail" if result_has_issues(row, expected_outcome) else "pass", "reason": row["boot_outcome"]}


if __name__ == "__main__":
    try:
        verdict = measure(Path(sys.argv[1]), sys.argv[2])
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        verdict = {"verdict": "skip", "reason": str(exc)}
    Path(os.environ["BISECT_RESULT"]).write_text(json.dumps(verdict))
