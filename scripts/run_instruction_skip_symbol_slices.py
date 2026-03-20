#!/usr/bin/env python3
"""Run an instruction-skip profile as per-range slices, then merge outputs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from merge_runtime_sweep_reports import merge_runtime_sweep_files
from profile_loader import ProfileError, load_profile


@dataclass(frozen=True)
class SliceJob:
    index: int
    start: int
    end: int
    output_path: Path


def build_slice_jobs(profile_path: Path, output_dir: Path) -> List[SliceJob]:
    profile = load_profile(profile_path)
    cfg = profile.fault_sweep.instruction_skip_config
    if cfg is None or not cfg.target_addresses:
        raise ProfileError("profile has no instruction_skip target ranges to slice")
    jobs: List[SliceJob] = []
    for index, (start, end) in enumerate(cfg.target_addresses, start=1):
        jobs.append(
            SliceJob(
                index=index,
                start=int(start),
                end=int(end),
                output_path=output_dir / f"slice_{index:03d}_{start:08x}_{end:08x}.json",
            )
        )
    return jobs


def _build_audit_command(
    *,
    python_executable: str,
    audit_script: Path,
    profile_path: Path,
    job: SliceJob,
    renode_test: str,
    robot_suite: str,
    workers: int,
    max_batch_points: int,
    progress_stall_timeout_s: float,
    renode_remote_server_dir: str | None,
    no_hash_bypass: bool,
    no_trace_replay: bool,
    keep_run_artifacts: bool,
) -> List[str]:
    cmd = [
        python_executable,
        str(audit_script),
        "--profile",
        str(profile_path),
        "--output",
        str(job.output_path),
        "--fault-start",
        str(job.start),
        "--fault-end",
        str(job.end),
        "--renode-test",
        renode_test,
        "--robot-suite",
        robot_suite,
        "--workers",
        str(workers),
        "--max-batch-points",
        str(max_batch_points),
        "--progress-stall-timeout-s",
        str(progress_stall_timeout_s),
        "--no-assert-verdict",
        "--no-assert-control-boots",
    ]
    if renode_remote_server_dir:
        cmd.extend(["--renode-remote-server-dir", renode_remote_server_dir])
    if no_hash_bypass:
        cmd.append("--no-hash-bypass")
    if no_trace_replay:
        cmd.append("--no-trace-replay")
    if keep_run_artifacts:
        cmd.append("--keep-run-artifacts")
    return cmd


def run_sliced_instruction_skip_campaign(
    *,
    profile_path: Path,
    output_dir: Path,
    merged_output: Path,
    python_executable: str,
    audit_script: Path,
    renode_test: str,
    robot_suite: str,
    workers: int,
    max_batch_points: int,
    progress_stall_timeout_s: float,
    renode_remote_server_dir: str | None,
    no_hash_bypass: bool,
    no_trace_replay: bool,
    keep_run_artifacts: bool,
) -> dict:
    jobs = build_slice_jobs(profile_path, output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for job in jobs:
        cmd = _build_audit_command(
            python_executable=python_executable,
            audit_script=audit_script,
            profile_path=profile_path,
            job=job,
            renode_test=renode_test,
            robot_suite=robot_suite,
            workers=workers,
            max_batch_points=max_batch_points,
            progress_stall_timeout_s=progress_stall_timeout_s,
            renode_remote_server_dir=renode_remote_server_dir,
            no_hash_bypass=no_hash_bypass,
            no_trace_replay=no_trace_replay,
            keep_run_artifacts=keep_run_artifacts,
        )
        print(
            "Running slice {:03d}: fault range {}..{}".format(
                job.index, job.start, job.end
            ),
            file=sys.stderr,
        )
        subprocess.run(cmd, check=True)

    merged = merge_runtime_sweep_files(job.output_path for job in jobs)
    merged_output.parent.mkdir(parents=True, exist_ok=True)
    merged_output.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run instruction-skip profiles as per-range slices and merge results.",
    )
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--merged-output", required=True, type=Path)
    parser.add_argument(
        "--audit-script",
        type=Path,
        default=Path(__file__).resolve().parent / "audit_bootloader.py",
    )
    parser.add_argument("--renode-test", required=True)
    parser.add_argument(
        "--robot-suite",
        default=str(Path(__file__).resolve().parents[1] / "tests" / "ota_fault_point.robot"),
    )
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-batch-points", type=int, default=1)
    parser.add_argument("--progress-stall-timeout-s", type=float, default=20.0)
    parser.add_argument("--renode-remote-server-dir")
    parser.add_argument("--no-hash-bypass", action="store_true")
    parser.add_argument("--no-trace-replay", action="store_true")
    parser.add_argument("--keep-run-artifacts", action="store_true")
    args = parser.parse_args()

    merged = run_sliced_instruction_skip_campaign(
        profile_path=args.profile,
        output_dir=args.output_dir,
        merged_output=args.merged_output,
        python_executable=sys.executable,
        audit_script=args.audit_script,
        renode_test=args.renode_test,
        robot_suite=args.robot_suite,
        workers=args.workers,
        max_batch_points=args.max_batch_points,
        progress_stall_timeout_s=args.progress_stall_timeout_s,
        renode_remote_server_dir=args.renode_remote_server_dir,
        no_hash_bypass=args.no_hash_bypass,
        no_trace_replay=args.no_trace_replay,
        keep_run_artifacts=args.keep_run_artifacts,
    )
    print(json.dumps({"profile": merged.get("profile"), "summary": merged.get("summary")}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
