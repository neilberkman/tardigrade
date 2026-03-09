"""Tests for scripts/run_heuristic_benchmark.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import run_heuristic_benchmark as rhb  # noqa: E402


class TestValidateAuditArgs(unittest.TestCase):
    def test_rejects_quick_mode(self):
        with self.assertRaises(ValueError):
            rhb.validate_audit_args(["--quick"])

    def test_rejects_fault_start(self):
        with self.assertRaises(ValueError):
            rhb.validate_audit_args(["--fault-start", "0"])

    def test_rejects_non_default_fault_step(self):
        with self.assertRaises(ValueError):
            rhb.validate_audit_args(["--fault-step", "2"])

    def test_allows_default_fault_step(self):
        rhb.validate_audit_args(["--fault-step", "1", "--workers", "2"])


class TestBuildAuditCommand(unittest.TestCase):
    def test_exhaustive_run_forces_fault_start_zero(self):
        cmd = rhb.build_audit_command(
            "/usr/bin/python3",
            Path("/tmp/profile.yaml"),
            Path("/tmp/out.json"),
            ["--workers", "2"],
            exhaustive=True,
        )
        self.assertEqual(
            cmd[-2:],
            ["--fault-start", "0"],
        )

    def test_heuristic_run_preserves_passthrough_args(self):
        cmd = rhb.build_audit_command(
            "/usr/bin/python3",
            Path("/tmp/profile.yaml"),
            Path("/tmp/out.json"),
            ["--workers", "2", "--no-control"],
            exhaustive=False,
        )
        self.assertIn("--workers", cmd)
        self.assertIn("--no-control", cmd)
        self.assertNotIn("--fault-start", cmd)


class TestMain(unittest.TestCase):
    def test_main_writes_comparison_report(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            profile = tmp / "demo.yaml"
            profile.write_text("schema_version: 1\nname: demo\n", encoding="utf-8")
            output_dir = tmp / "bench"

            def fake_run(cmd, cwd, env, text, capture_output, check):
                output_path = Path(cmd[cmd.index("--output") + 1])
                exhaustive = "--fault-start" in cmd
                if exhaustive:
                    payload = {
                        "profile": "demo",
                        "verdict": "PASS",
                        "fault_points_tested": 10,
                        "heuristic": None,
                        "heuristic_config": {"tier2_step": 3},
                        "summary": {
                            "runtime_sweep": {
                                "wall_time_s": 20.0,
                                "issue_points": 2,
                                "bricks": 2,
                                "semantic_issue_points": 0,
                                "invariant_issue_points": 0,
                            }
                        },
                        "runtime_sweep_results": [
                            {"fault_at": 1, "boot_outcome": "no_boot"},
                            {"fault_at": 5, "boot_outcome": "wrong_image"},
                            {"fault_at": 9, "boot_outcome": "success"},
                        ],
                    }
                else:
                    payload = {
                        "profile": "demo",
                        "verdict": "PASS",
                        "fault_points_tested": 2,
                        "heuristic": {
                            "selected_fault_points": 2,
                            "total_writes": 10,
                            "reduction_ratio": 0.2,
                        },
                        "heuristic_config": {"tier2_step": 3},
                        "summary": {
                            "runtime_sweep": {
                                "wall_time_s": 5.0,
                                "issue_points": 1,
                                "bricks": 1,
                                "semantic_issue_points": 0,
                                "invariant_issue_points": 0,
                            }
                        },
                        "runtime_sweep_results": [
                            {"fault_at": 1, "boot_outcome": "no_boot"},
                            {"fault_at": 9, "boot_outcome": "success"},
                        ],
                    }
                output_path.write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="log\n")

            with mock.patch.object(rhb.subprocess, "run", side_effect=fake_run):
                rc = rhb.main(
                    [
                        "--profile",
                        str(profile),
                        "--output-dir",
                        str(output_dir),
                        "--workers",
                        "2",
                    ]
                )

            self.assertEqual(rc, 0)
            report = json.loads((output_dir / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(report["comparison"]["issue_recall"], 0.5)
            self.assertEqual(report["comparison"]["missed_issue_points"], [5])
            self.assertEqual(
                report["comparison"]["exhaustive_over_heuristic_wall_ratio"],
                4.0,
            )
            self.assertEqual(
                report["comparison"]["exhaustive_over_heuristic_point_ratio"],
                5.0,
            )
            self.assertTrue((output_dir / "heuristic.stdout.log").exists())
            self.assertTrue((output_dir / "exhaustive.stderr.log").exists())


if __name__ == "__main__":
    unittest.main()
