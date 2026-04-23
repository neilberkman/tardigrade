#!/usr/bin/env python3
"""Regression tests for quick-mode state-evaluator routing."""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit_bootloader  # noqa: E402
from renode_runner import CalibrationResult  # noqa: E402


class AuditQuickStateEvaluatorTests(unittest.TestCase):
    def _write_profile(self, tempdir: Path, extra_fault_sweep: str = "") -> Path:
        profile_path = tempdir / "profile.yaml"
        profile_path.write_text(
            textwrap.dedent(
                """
                schema_version: 1
                name: quick_state_eval_profile
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  exec: examples/vulnerable_ota/firmware.bin
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  max_writes: auto
                  run_duration: "2.0"
                  quick_use_heuristic: true
                expect:
                  should_find_issues: false
                """
            ).strip()
            + ("\n" + textwrap.dedent(extra_fault_sweep).strip() if extra_fault_sweep.strip() else "")
            + "\n",
            encoding="utf-8",
        )
        return profile_path

    def test_quick_mode_keeps_state_evaluator_for_quick_heuristic_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(tempdir)
            output_path = tempdir / "audit.json"
            trace_file = tempdir / "trace.csv"
            trace_file.write_text(
                "write_index,flash_offset,value\n1,0,0\n2,4,0\n",
                encoding="utf-8",
            )

            cal = CalibrationResult(
                total_writes=2,
                total_erases=0,
                trace_file=str(trace_file),
                erase_trace_file=None,
                trace_file_bin=None,
                erase_trace_file_bin=None,
                stop_reason="vtor_captured",
            )

            def fake_run_runtime_sweep(**kwargs):
                self.assertTrue(kwargs["allow_state_evaluator"])
                return [
                    {
                        "fault_at": 0,
                        "fault_type": "w",
                        "fault_injected": True,
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "signals": {"state_evaluator_used": True},
                        "is_control": False,
                    },
                    {
                        "fault_at": 999999,
                        "fault_requested": -1,
                        "fault_injected": False,
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "signals": {"trace_replay_mode": "execute"},
                        "is_control": True,
                    },
                ]

            argv = [
                "audit_bootloader.py",
                "--profile",
                str(profile_path),
                "--output",
                str(output_path),
                "--quick",
            ]

            with mock.patch.object(sys, "argv", argv):
                with mock.patch("audit_bootloader.ensure_tool", return_value="renode-test"):
                    with mock.patch("audit_bootloader.run_calibration", return_value=cal):
                        with mock.patch(
                            "audit_bootloader.build_fault_plan",
                            return_value=SimpleNamespace(
                                fault_points=[0],
                                fault_types_list=["w"],
                                heuristic_summary={"selected_fault_points": 1},
                                clustered_bit_count=0,
                                swap_progress_summary=None,
                            ),
                        ):
                            with mock.patch("audit_bootloader.run_runtime_sweep", side_effect=fake_run_runtime_sweep):
                                with mock.patch("audit_bootloader.annotate_clean_trace", return_value=None):
                                    with mock.patch("audit_bootloader.annotate_result_checks"):
                                        with mock.patch("audit_bootloader.validate_runtime_findings"):
                                            with mock.patch(
                                                "audit_bootloader.summarize_runtime_sweep",
                                                return_value={
                                                    "bricks": 0,
                                                    "issue_points": 0,
                                                    "semantic_issue_points": 0,
                                                    "invariant_issue_points": 0,
                                                    "metadata_delta_issue_points": 0,
                                                    "timeout_points": 0,
                                                    "resilient_rollbacks": 0,
                                                    "control": {
                                                        "boot_outcome": "success",
                                                        "effective_outcome": "success",
                                                        "final_boot_outcome": "success",
                                                        "issue_count": 0,
                                                    },
                                                },
                                            ):
                                                with mock.patch("audit_bootloader.report_skip_reasons"):
                                                    with mock.patch(
                                                        "audit_bootloader.run_multi_fault_phase",
                                                        return_value=SimpleNamespace(
                                                            plan=None,
                                                            plan_data=None,
                                                            results=None,
                                                            summary=None,
                                                        ),
                                                    ):
                                                        with mock.patch(
                                                            "audit_bootloader.compute_verdict",
                                                            return_value="PASS",
                                                        ):
                                                            with mock.patch(
                                                                "audit_bootloader.git_metadata",
                                                                return_value={},
                                                            ):
                                                                rc = audit_bootloader.main()

            self.assertEqual(rc, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["quick"])


if __name__ == "__main__":
    unittest.main()
