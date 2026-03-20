from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from run_instruction_skip_symbol_slices import (  # noqa: E402
    SliceJob,
    _build_audit_command,
    build_slice_jobs,
    run_sliced_instruction_skip_campaign,
)


def _write_profile(tmp_path: Path) -> Path:
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        """
schema_version: 1
name: slice-test
platform: platforms/cortex_m4_flash_fast.repl
flash_backend: faultFlash
bootloader:
  elf: examples/vulnerable_ota/firmware.elf
  entry: 0x10000045
memory:
  sram:
    start: 0x20000000
    end: 0x20008000
  slots:
    exec:
      base: 0x10004000
      size: 0x8000
    staging:
      base: 0x1000C000
      size: 0x8000
  bootloader_region:
    base: 0x10000000
    size: 0x4000
images:
  exec: examples/vulnerable_ota/slot0.bin
  staging: examples/vulnerable_ota/slot1.bin
fault_sweep:
  mode: runtime
  evaluation_mode: execute
  fault_types: [instruction_skip]
  instruction_skip_config:
    target_addresses:
      - { start: 0x10000044, end: 0x10000048 }
      - { start: 0x10000048, end: 0x1000004c }
""".strip(),
        encoding="utf-8",
    )
    return profile_path


def test_build_slice_jobs(tmp_path: Path) -> None:
    profile_path = _write_profile(tmp_path)
    jobs = build_slice_jobs(profile_path, tmp_path / "out")
    assert jobs == [
        SliceJob(
            index=1,
            start=0x10000044,
            end=0x10000048,
            output_path=tmp_path / "out" / "slice_001_10000044_10000048.json",
        ),
        SliceJob(
            index=2,
            start=0x10000048,
            end=0x1000004C,
            output_path=tmp_path / "out" / "slice_002_10000048_1000004c.json",
        ),
    ]


def test_build_audit_command_includes_slice_range(tmp_path: Path) -> None:
    job = SliceJob(1, 0x1000, 0x1008, tmp_path / "slice.json")
    cmd = _build_audit_command(
        python_executable="python3",
        audit_script=Path("scripts/audit_bootloader.py"),
        profile_path=Path("profiles/test.yaml"),
        job=job,
        renode_test="renode-test",
        robot_suite="tests/ota_fault_point.robot",
        workers=2,
        max_batch_points=1,
        progress_stall_timeout_s=10.0,
        renode_remote_server_dir="/tmp/renode",
        no_hash_bypass=True,
        no_trace_replay=False,
        keep_run_artifacts=True,
    )
    assert "--fault-start" in cmd
    assert "4096" in cmd
    assert "--fault-end" in cmd
    assert "4104" in cmd
    assert "--no-hash-bypass" in cmd
    assert "--keep-run-artifacts" in cmd


def test_run_sliced_instruction_skip_campaign_merges_outputs(tmp_path: Path) -> None:
    profile_path = _write_profile(tmp_path)
    output_dir = tmp_path / "out"
    merged_output = tmp_path / "merged.json"

    def fake_run(cmd, check):
        output_path = Path(cmd[cmd.index("--output") + 1])
        payload = {
            "engine": "renode-test",
            "profile": "slice-test",
            "profile_path": str(profile_path),
            "schema_version": 1,
            "calibrated_writes": 10,
            "calibrated_erases": 0,
            "setup_writes": 0,
            "quick": False,
            "heuristic": {},
            "heuristic_config": {},
            "multi_fault": None,
            "verdict": "FAIL",
            "expect": {"should_find_issues": True},
            "security_policy": {},
            "git": {},
            "runtime_sweep_results": [
                {"is_control": True, "boot_outcome": "success", "boot_slot": "exec"},
                {
                    "fault_at": int(cmd[cmd.index("--fault-start") + 1]),
                    "fault_type": "i",
                    "fault_injected": True,
                    "boot_outcome": "wrong_image",
                    "boot_slot": "staging",
                },
            ],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload), encoding="utf-8")
        return mock.Mock(returncode=0)

    with mock.patch("run_instruction_skip_symbol_slices.subprocess.run", side_effect=fake_run):
        merged = run_sliced_instruction_skip_campaign(
            profile_path=profile_path,
            output_dir=output_dir,
            merged_output=merged_output,
            python_executable="python3",
            audit_script=Path("scripts/audit_bootloader.py"),
            renode_test="renode-test",
            robot_suite="tests/ota_fault_point.robot",
            workers=1,
            max_batch_points=1,
            progress_stall_timeout_s=20.0,
            renode_remote_server_dir=None,
            no_hash_bypass=False,
            no_trace_replay=False,
            keep_run_artifacts=False,
        )

    assert merged_output.exists()
    assert merged["fault_points_tested"] == 2
    assert merged["summary"]["runtime_sweep"]["issue_points"] == 2
