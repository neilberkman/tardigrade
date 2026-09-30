#!/usr/bin/env python3
"""Capture a raw control observation for a negative self-update fixture."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_bootloader import _cleanup_generated_robot_files, _common_robot_vars  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from renode_runner import run_single_point  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--renode-test", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    profile = load_profile(ROOT / args.profile, strict=True)
    robot_vars = _common_robot_vars(
        profile,
        ROOT,
        evaluation_mode="execute",
        stall_timeout=0.0,
        extra_robot_vars=[],
    )
    try:
        with tempfile.TemporaryDirectory(prefix="runtime_self_update_negative_") as td:
            result = run_single_point(
                repo_root=ROOT,
                renode_test=args.renode_test,
                robot_suite="tests/ota_fault_point.robot",
                profile=profile,
                fault_at=0,
                robot_vars=robot_vars,
                work_dir=Path(td),
                renode_remote_server_dir="",
                is_control=True,
            )
    finally:
        _cleanup_generated_robot_files(robot_vars)

    result["is_control"] = True
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
