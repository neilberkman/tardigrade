#!/usr/bin/env python3
"""Find a PR2206 image-size threshold and compare broken/fixed.

This script automates:
1) generating signed staging images with varying payload sizes,
2) running control-only audits for the fixed build to find the largest
   payload size that still boots,
3) evaluating broken/fixed at the threshold neighborhood.
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


def parse_int(value: str) -> int:
    return int(value, 0)


def run(cmd: List[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, check=check)


def load_base_payload(base_image: Path) -> bytes:
    data = base_image.read_bytes()
    if data[:4] != b"\x3d\xb8\xf3\x96":
        raise RuntimeError("Unexpected MCUboot header magic in {}".format(base_image))
    img_size = struct.unpack_from("<I", data, 0x0C)[0]
    start = 0x200
    end = start + img_size
    return data[start:end]


def sign_image(
    repo_root: Path,
    payload: bytes,
    payload_size: int,
    output_path: Path,
    version: str,
    slot_size: int,
    align: int,
    header_size: int,
    imgtool_python: Path,
    imgtool_script: Path,
    key_file: Path,
) -> None:
    if len(payload) >= payload_size:
        shaped = payload[:payload_size]
    else:
        shaped = payload + (b"\xC3" * (payload_size - len(payload)))

    with tempfile.TemporaryDirectory(prefix="pr2206_payload_") as td:
        payload_file = Path(td) / "payload.bin"
        payload_file.write_bytes(shaped)
        cmd = [
            str(imgtool_python),
            str(imgtool_script),
            "sign",
            "--key",
            str(key_file),
            "--align",
            str(align),
            "--header-size",
            hex(header_size),
            "--slot-size",
            hex(slot_size),
            "--pad-header",
            "--pad",
            "--confirm",
            "--version",
            version,
            str(payload_file),
            str(output_path),
        ]
        proc = run(cmd, cwd=repo_root, check=False)
        if proc.returncode != 0:
            raise RuntimeError(
                "imgtool sign failed for payload_size=0x{:X}\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    payload_size, proc.stdout, proc.stderr
                )
            )


def make_profile(
    profile_name: str,
    bootloader_elf: Path,
    exec_image: Path,
    staging_image: Path,
    slot_base_exec: int,
    slot_size_exec: int,
    slot_base_staging: int,
    slot_size_staging: int,
    run_duration: str,
    max_writes_cap: int,
    max_step_limit: int,
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "name": profile_name,
        "description": "Auto-generated PR2206 geometry control probe.",
        "platform": "platforms/cortex_m4_flash_fast.repl",
        "bootloader": {
            "elf": str(bootloader_elf),
            "entry": 0x00000000,
        },
        "memory": {
            "sram": {"start": 0x20000000, "end": 0x20040000},
            "write_granularity": 4,
            "slots": {
                "exec": {"base": slot_base_exec, "size": slot_size_exec},
                "staging": {"base": slot_base_staging, "size": slot_size_staging},
            },
        },
        "images": {
            "exec": str(exec_image),
            "staging": str(staging_image),
        },
        "update_trigger": {
            "type": "mcuboot_trailer_magic",
            "slot": "staging",
        },
        "success_criteria": {
            "vtor_in_slot": "exec",
            "image_hash": True,
            "expected_image": "staging",
        },
        "fault_sweep": {
            "mode": "runtime",
            "evaluation_mode": "execute",
            # Force non-auto to skip calibration; we only need control outcome.
            "max_writes": 1,
            "max_writes_cap": max_writes_cap,
            "run_duration": run_duration,
            "max_step_limit": max_step_limit,
            "fault_types": ["power_loss", "interrupted_erase"],
        },
        "skip_self_test": True,
        "expect": {
            "should_find_issues": False,
        },
    }


def run_control_only(
    repo_root: Path,
    profile: Dict[str, Any],
    output_json: Path,
    renode_test: Path,
    renode_server_dir: Path,
) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pr2206_profile_") as td:
        profile_path = Path(td) / "{}.yaml".format(profile["name"])
        profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")

        cmd = [
            "python3",
            "scripts/audit_bootloader.py",
            "--profile",
            str(profile_path),
            "--output",
            str(output_json),
            "--fault-start",
            "0",
            "--fault-end",
            "0",
            "--no-assert-control-boots",
            "--renode-test",
            str(renode_test),
            "--renode-remote-server-dir",
            str(renode_server_dir),
        ]
        proc = run(cmd, cwd=repo_root, check=False)
        if not output_json.exists():
            raise RuntimeError(
                "audit_bootloader produced no output JSON.\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    proc.stdout, proc.stderr
                )
            )
        payload = json.loads(output_json.read_text(encoding="utf-8"))
        payload["_cmd_rc"] = proc.returncode
        payload["_stderr_tail"] = (proc.stderr or "")[-1200:]
        return payload


def midpoint(low: int, high: int, quantum: int) -> int:
    mid = (low + high) // 2
    # Round down to quantum for deterministic payload sizing.
    mid -= (mid % quantum)
    if mid <= low:
        mid = low + quantum
    if mid >= high:
        mid = high - quantum
    return mid


def collect_control_row(
    payload_size: int,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    sweep = result.get("summary", {}).get("runtime_sweep", {})
    ctrl = sweep.get("control", {})
    return {
        "payload_size": payload_size,
        "payload_size_hex": "0x{:X}".format(payload_size),
        "control_outcome": ctrl.get("boot_outcome"),
        "control_slot": ctrl.get("boot_slot"),
        "bricks": sweep.get("bricks"),
        "total_fault_points": sweep.get("total_fault_points"),
        "calibrated_writes": result.get("calibrated_writes"),
        "calibrated_erases": result.get("calibrated_erases"),
        "verdict": result.get("verdict"),
        "cmd_rc": result.get("_cmd_rc"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sweep PR2206 geometry payload threshold.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument(
        "--output",
        default="results/oss_validation/reports/2026-02-27-pr2206-geom-threshold.json",
        help="Sweep report JSON output path.",
    )
    parser.add_argument(
        "--results-dir",
        default="results/oss_validation/reports/2026-02-27-pr2206-geom-threshold",
        help="Directory for per-run audit JSON files.",
    )
    parser.add_argument(
        "--min-payload",
        type=parse_int,
        default=0x12000,
        help="Minimum payload size to consider (hex or decimal).",
    )
    parser.add_argument(
        "--max-payload",
        type=parse_int,
        default=0x69000,
        help="Maximum payload size to consider (hex or decimal).",
    )
    parser.add_argument(
        "--quantum",
        type=parse_int,
        default=0x2000,
        help="Payload size increment quantum.",
    )
    parser.add_argument(
        "--run-duration",
        default="2.0",
        help="Fault script run duration passed via temporary profile.",
    )
    parser.add_argument(
        "--max-writes-cap",
        type=parse_int,
        default=200000,
        help="Temporary profile fault_sweep.max_writes_cap override.",
    )
    parser.add_argument(
        "--max-step-limit",
        type=parse_int,
        default=20000000,
        help="Temporary profile fault_sweep.max_step_limit override.",
    )
    parser.add_argument(
        "--fixed-elf",
        default="results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_fixed.elf",
        help="Fixed MCUboot ELF path (relative to repo root unless absolute).",
    )
    parser.add_argument(
        "--broken-elf",
        default="results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_broken.elf",
        help="Broken MCUboot ELF path (relative to repo root unless absolute).",
    )
    parser.add_argument(
        "--exec-image",
        default="results/oss_validation/assets/zephyr_slot0_padded.bin",
        help="Exec slot image path (relative to repo root unless absolute).",
    )
    parser.add_argument(
        "--slot-size",
        type=parse_int,
        default=0x6E000,
        help="Slot size used for signing and profile memory layout.",
    )
    parser.add_argument(
        "--slot-exec-base",
        type=parse_int,
        default=0x0000C000,
        help="Exec slot base address.",
    )
    parser.add_argument(
        "--slot-staging-base",
        type=parse_int,
        default=0x0007A000,
        help="Staging slot base address.",
    )
    parser.add_argument(
        "--floor-payload",
        type=parse_int,
        default=0x4000,
        help="Lowest payload size to probe when searching for any fixed-bootable point.",
    )
    parser.add_argument(
        "--renode-test",
        default=None,
        help="Path to renode-test.",
    )
    parser.add_argument(
        "--renode-remote-server-dir",
        default="/tmp/renode-server",
        help="Path to renode remote-server directory.",
    )
    parser.add_argument(
        "--reuse-existing",
        action="store_true",
        help="Reuse existing per-run result JSON files in --results-dir when present.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    output_path = (repo_root / args.output).resolve()
    results_dir = (repo_root / args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    assets = repo_root / "results" / "oss_validation" / "assets"
    base_payload = load_base_payload(assets / "zephyr_slot1_padded.bin")

    imgtool_python = repo_root / "third_party" / "zephyr-venv" / "bin" / "python3"
    imgtool_script = repo_root / "third_party" / "zephyr_ws" / "bootloader" / "mcuboot" / "scripts" / "imgtool.py"
    key_file = repo_root / "third_party" / "zephyr_ws" / "bootloader" / "mcuboot" / "root-rsa-2048.pem"

    broken_elf = Path(args.broken_elf)
    if not broken_elf.is_absolute():
        broken_elf = (repo_root / broken_elf).resolve()
    fixed_elf = Path(args.fixed_elf)
    if not fixed_elf.is_absolute():
        fixed_elf = (repo_root / fixed_elf).resolve()
    exec_image = Path(args.exec_image)
    if not exec_image.is_absolute():
        exec_image = (repo_root / exec_image).resolve()

    renode_test = Path(args.renode_test)
    renode_server = Path(args.renode_remote_server_dir)

    slot_size = args.slot_size
    slot_exec_base = args.slot_exec_base
    slot_staging_base = args.slot_staging_base

    # Align bounds to quantum.
    low = args.min_payload - (args.min_payload % args.quantum)
    high = args.max_payload - (args.max_payload % args.quantum)
    if low >= high:
        raise RuntimeError("Invalid payload range: low >= high")

    runs: List[Dict[str, Any]] = []

    run_cache: Dict[Tuple[int, str], Tuple[Dict[str, Any], Path]] = {}

    def run_one(payload_size: int, variant: str, elf: Path) -> Tuple[Dict[str, Any], Path]:
        cache_key = (payload_size, variant)
        cached = run_cache.get(cache_key)
        if cached is not None:
            return cached

        image_path = results_dir / "slot1_payload_{:05x}.bin".format(payload_size)
        if not image_path.exists():
            sign_image(
                repo_root=repo_root,
                payload=base_payload,
                payload_size=payload_size,
                output_path=image_path,
                version="1.0.5+{}".format(payload_size),
                slot_size=slot_size,
                align=8,
                header_size=0x200,
                imgtool_python=imgtool_python,
                imgtool_script=imgtool_script,
                key_file=key_file,
            )

        profile = make_profile(
            profile_name="pr2206_{}_payload_{:x}".format(variant, payload_size),
            bootloader_elf=elf,
            exec_image=exec_image,
            staging_image=image_path,
            slot_base_exec=slot_exec_base,
            slot_size_exec=slot_size,
            slot_base_staging=slot_staging_base,
            slot_size_staging=slot_size,
            run_duration=args.run_duration,
            max_writes_cap=args.max_writes_cap,
            max_step_limit=args.max_step_limit,
        )

        out_json = results_dir / "{}.json".format(profile["name"])
        if args.reuse_existing and out_json.exists():
            result = json.loads(out_json.read_text(encoding="utf-8"))
            result["_cmd_rc"] = 0
            result["_stderr_tail"] = ""
        else:
            result = run_control_only(
                repo_root=repo_root,
                profile=profile,
                output_json=out_json,
                renode_test=renode_test,
                renode_server_dir=renode_server,
            )
        run_cache[cache_key] = (result, out_json)
        return run_cache[cache_key]

    # Sanity probes at bounds.
    sanity_points = [low, high]
    sanity_rows: List[Dict[str, Any]] = []
    for size in sanity_points:
        result, out_json = run_one(size, "fixed", fixed_elf)
        row = collect_control_row(size, result)
        row["variant"] = "fixed"
        row["result_file"] = str(out_json)
        sanity_rows.append(row)
        runs.append(row)

    # If lower bound does not boot, search downward for any fixed-success point.
    if sanity_rows[0]["control_outcome"] != "success":
        probe = low - args.quantum
        while probe >= args.floor_payload:
            result, out_json = run_one(probe, "fixed", fixed_elf)
            row = collect_control_row(probe, result)
            row["variant"] = "fixed"
            row["result_file"] = str(out_json)
            runs.append(row)
            if row["control_outcome"] == "success":
                low = probe
                sanity_rows.append(dict(row))
                break
            probe -= args.quantum

    threshold: Optional[int] = None
    search_status = "uninitialized"

    low_boots = any(r["payload_size"] == low and r["control_outcome"] == "success" for r in runs)
    high_boots = any(r["payload_size"] == high and r["control_outcome"] == "success" for r in runs)

    if low_boots and not high_boots:
        # Binary-search the largest fixed-success payload.
        lo = low
        hi = high
        while (hi - lo) > args.quantum:
            mid = midpoint(lo, hi, args.quantum)
            result, out_json = run_one(mid, "fixed", fixed_elf)
            row = collect_control_row(mid, result)
            row["variant"] = "fixed"
            row["result_file"] = str(out_json)
            runs.append(row)
            if row["control_outcome"] == "success":
                lo = mid
            else:
                hi = mid
        threshold = lo
        search_status = "bracketed_binary_search"
    elif low_boots and high_boots:
        threshold = high
        search_status = "all_bootable_in_range"
    else:
        # No fixed-success point found in range.
        threshold = None
        search_status = "no_bootable_point_in_range"

    # Compare broken/fixed around threshold neighborhood.
    if threshold is None:
        probe_sizes = sorted(set([low, high]))
    else:
        probe_sizes = sorted(set(filter(lambda x: x >= low and x <= high, [
            threshold - args.quantum,
            threshold,
            threshold + args.quantum,
        ])))
    comparisons: List[Dict[str, Any]] = []
    for size in probe_sizes:
        for variant, elf in [("fixed", fixed_elf), ("broken", broken_elf)]:
            result, out_json = run_one(size, variant, elf)
            row = collect_control_row(size, result)
            row["variant"] = variant
            row["result_file"] = str(out_json)
            runs.append(row)
            comparisons.append(row)

    candidate_differentials = [
        {
            "payload_size": size,
            "payload_size_hex": "0x{:X}".format(size),
            "fixed": next(
                (r for r in comparisons if r["payload_size"] == size and r["variant"] == "fixed"),
                None,
            ),
            "broken": next(
                (r for r in comparisons if r["payload_size"] == size and r["variant"] == "broken"),
                None,
            ),
        }
        for size in probe_sizes
    ]

    report: Dict[str, Any] = {
        "run_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "repo_root": str(repo_root),
        "min_payload": low,
        "max_payload": high,
        "quantum": args.quantum,
        "search_status": search_status,
        "threshold_fixed_success": threshold,
        "threshold_fixed_success_hex": ("0x{:X}".format(threshold) if threshold is not None else None),
        "sanity": sanity_rows,
        "candidate_differentials": candidate_differentials,
        "all_runs": runs,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "search_status": report["search_status"],
        "threshold_fixed_success_hex": report["threshold_fixed_success_hex"],
        "candidate_differentials": report["candidate_differentials"],
        "output": str(output_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
