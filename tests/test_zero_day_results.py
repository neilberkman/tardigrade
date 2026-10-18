"""Tests for scripts/zero_day_summary.py and scripts/zero_day_results.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import zero_day_results  # noqa: E402
import zero_day_summary  # noqa: E402


class TestZeroDaySummary(unittest.TestCase):
    def test_extracts_summary_and_writes_step_summary_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mcuboot_file = root / "mcuboot_head_commit.txt"
            zephyr_file = root / "zephyr_head_commit.txt"
            mcuboot_file.write_text("f84b9d3fd019fb1945e532924bee7a9c03c77373\n", encoding="utf-8")
            zephyr_file.write_text("36940db938a8f4a1e919496793ed439850a221c2\n", encoding="utf-8")

            report_path = root / "mcuboot_head_scratch_stm32f4_writeback.json"
            report_path.write_text(
                json.dumps(
                    {
                        "profile": "mcuboot_head_scratch_stm32f4_writeback",
                        "verdict": "FAIL — found 1 issue point",
                        "expect": {"should_find_issues": False},
                        "security_aggregate": {
                            "status": "FINDINGS",
                            "issue_points": 1,
                            "security_bypass_points": 0,
                            "brick_rate": 0.0,
                            "finding_sources": {"runtime_sweep": 1},
                            "security_bypass_sources": {},
                            "inconclusive_reasons": [],
                            "schema_version": 1,
                        },
                        "summary": {
                            "runtime_sweep": {
                                "total_fault_points": 3,
                                "issue_points": 1,
                                "bricks": 0,
                                "timeout_points": 2,
                                "control_timeout_points": 1,
                                "wall_time_s": 142.64,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            jsonl_path = root / "summary.jsonl"
            step_summary_path = root / "step_summary.md"

            rc = zero_day_summary.main(
                [
                    "--report",
                    str(report_path),
                    "--profile",
                    "profiles/mcuboot_head_scratch_stm32f4_writeback.yaml",
                    "--mcuboot-commit-file",
                    str(mcuboot_file),
                    "--zephyr-commit-file",
                    str(zephyr_file),
                    "--jsonl",
                    str(jsonl_path),
                    "--step-summary",
                    str(step_summary_path),
                ]
            )
            self.assertEqual(rc, 0)

            lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(
                record["mcuboot_commit"],
                "f84b9d3fd019fb1945e532924bee7a9c03c77373",
            )
            self.assertEqual(
                record["zephyr_commit"],
                "36940db938a8f4a1e919496793ed439850a221c2",
            )
            self.assertEqual(
                record["profile"],
                "mcuboot_head_scratch_stm32f4_writeback",
            )
            self.assertEqual(record["verdict"], "FAIL -- found 1 issue point")
            self.assertEqual(record["security_status"], "FINDINGS")
            self.assertEqual(record["security_aggregate"]["status"], "FINDINGS")
            self.assertEqual(record["points"], 3)
            self.assertEqual(record["issue_points"], 1)
            self.assertEqual(record["bricks"], 0)
            self.assertEqual(record["timeouts"], 3)
            self.assertEqual(record["wall_time_s"], 142.6)

            step_md = step_summary_path.read_text(encoding="utf-8")
            self.assertIn("f84b9d3fd019fb1945e532924bee7a9c03c77373", step_md)
            self.assertIn("36940db938a8f4a1e919496793ed439850a221c2", step_md)
            self.assertIn("mcuboot_head_scratch_stm32f4_writeback", step_md)
            self.assertIn("`security_aggregate.status` | `FINDINGS`", step_md)
            self.assertIn("| Points | `3` |", step_md)
            self.assertIn("| Issue points | `1` |", step_md)
            self.assertIn("| Bricks | `0` |", step_md)
            self.assertIn("| Timeouts | `3` |", step_md)
            self.assertIn("| Wall time | `142.6s` |", step_md)

    def test_missing_report_produces_fallback_summary_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jsonl_path = root / "missing.jsonl"
            step_summary_path = root / "step_summary.md"

            rc = zero_day_summary.main(
                [
                    "--report",
                    str(root / "nonexistent.json"),
                    "--profile",
                    "profiles/mcuboot_head_move_nrf52_upgrade_extended.yaml",
                    "--mcuboot-commit",
                    "deadbeef1234",
                    "--zephyr-commit",
                    "cafebabe5678",
                    "--jsonl",
                    str(jsonl_path),
                    "--step-summary",
                    str(step_summary_path),
                ]
            )
            self.assertEqual(rc, 0)
            record = json.loads(jsonl_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["verdict"], "MISSING_REPORT")
            self.assertEqual(record["security_status"], "INCONCLUSIVE")
            self.assertEqual(
                record["profile"],
                "mcuboot_head_move_nrf52_upgrade_extended",
            )
            self.assertTrue(step_summary_path.is_file())


class TestZeroDayResults(unittest.TestCase):
    def test_from_dir_renders_table_from_synthetic_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixtures_dir = root / "artifacts"
            output_md = root / "zero-day-results.md"

            zero_day_results.write_synthetic_fixtures(fixtures_dir)
            rc = zero_day_results.main(
                [
                    "--from-dir",
                    str(fixtures_dir),
                    "--synthetic-note",
                    "--output",
                    str(output_md),
                ]
            )
            self.assertEqual(rc, 0)
            rendered = output_md.read_text(encoding="utf-8")

            self.assertIn("`f84b9d3fd019`", rendered)
            self.assertIn("`36940db938a8`", rendered)
            self.assertIn("`5c039f4842cf`", rendered)
            self.assertIn("`e35b686be50a`", rendered)
            self.assertIn("[run 24019002][run-24019002]", rendered)
            self.assertIn(
                "[run-24019002]: https://github.com/xuku/tardigrade/actions/runs/24019002",
                rendered,
            )
            self.assertIn("`PASS`, `FINDINGS`, 1/3 issues", rendered)
            self.assertIn("`FAIL`, `FINDINGS`, 1/3 issues", rendered)
            self.assertNotIn("\u2014", rendered)
            self.assertNotIn("(", rendered)
            self.assertNotIn(")", rendered)

    def test_download_workflow_artifacts_uses_gh_run_list_and_gh_api(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls: list[list[str]] = []

            def fake_run(cmd, capture_output, text, check):
                calls.append(cmd)
                if cmd[:3] == ["gh", "run", "list"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=json.dumps(
                            [
                                {
                                    "databaseId": 9901,
                                    "url": "https://github.com/xuku/tardigrade/actions/runs/9901",
                                    "createdAt": "2026-10-17T09:00:00Z",
                                    "status": "completed",
                                    "conclusion": "success",
                                    "headSha": "abcdef123456",
                                }
                            ]
                        ),
                        stderr="",
                    )
                if cmd[:2] == ["gh", "api"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=json.dumps(
                            {
                                "total_count": 2,
                                "artifacts": [
                                    {
                                        "id": 1,
                                        "name": "mcuboot-current-head-assets",
                                        "expired": False,
                                    },
                                    {
                                        "id": 2,
                                        "name": "mcuboot-zero-day-f84b9d3fd019fb1945e532924bee7a9c03c77373",
                                        "expired": False,
                                    },
                                ],
                            }
                        ),
                        stderr="",
                    )
                if cmd[:3] == ["gh", "run", "download"]:
                    dest = Path(cmd[cmd.index("--dir") + 1])
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / "summary.jsonl").write_text(
                        json.dumps(
                            {
                                "mcuboot_commit": "f84b9d3fd019fb1945e532924bee7a9c03c77373",
                                "zephyr_commit": "36940db938a8f4a1e919496793ed439850a221c2",
                                "profile": "mcuboot_head_move_nrf52_revert_full_fault_coverage",
                                "verdict": "PASS",
                                "security_status": "CLEAN",
                                "points": 3,
                                "issue_points": 0,
                                "bricks": 0,
                                "timeouts": 0,
                                "wall_time_s": 50.0,
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
                raise AssertionError(f"unexpected command: {cmd}")

            with mock.patch("zero_day_results.subprocess.run", side_effect=fake_run):
                zero_day_results.download_workflow_artifacts(root, limit=5)

            self.assertEqual(calls[0][:3], ["gh", "run", "list"])
            self.assertEqual(
                calls[1],
                ["gh", "api", "repos/{owner}/{repo}/actions/runs/9901/artifacts"],
            )
            self.assertEqual(calls[2][:3], ["gh", "run", "download"])

            rows = zero_day_results.load_results_from_dir(root)
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                rows[0]["mcuboot_commit"],
                "f84b9d3fd019fb1945e532924bee7a9c03c77373",
            )
            self.assertEqual(rows[0]["run_id"], 9901)

    def test_workflow_uploads_90_day_commit_named_artifacts_and_runs_summary_always(
        self,
    ) -> None:
        workflow_path = ROOT / ".github" / "workflows" / "mcuboot-head-zero-day.yml"
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

        build_outputs = workflow["jobs"]["build"]["outputs"]
        self.assertIn("mcuboot_commit", build_outputs)

        sweep_steps = workflow["jobs"]["sweep"]["steps"]
        summary_step = next(
            s for s in sweep_steps if s.get("name") == "Print summary"
        )
        self.assertEqual(summary_step.get("if"), "always()")
        self.assertIn("scripts/zero_day_summary.py", summary_step["run"])

        upload_step = next(
            s for s in sweep_steps if s.get("name") == "Upload sweep result"
        )
        self.assertEqual(upload_step.get("if"), "always()")
        self.assertEqual(upload_step["with"]["retention-days"], 90)
        self.assertIn(
            "needs.build.outputs.mcuboot_commit",
            upload_step["with"]["name"],
        )
        self.assertIn("results/*.json", upload_step["with"]["path"])
        self.assertIn("results/*.jsonl", upload_step["with"]["path"])

        results_job = workflow["jobs"]["results"]
        self.assertEqual(results_job.get("if"), "always()")
        commit_upload = next(
            s
            for s in results_job["steps"]
            if s.get("name") == "Upload commit zero-day artifact"
        )
        self.assertEqual(commit_upload["with"]["retention-days"], 90)
        self.assertEqual(
            commit_upload["with"]["name"],
            "mcuboot-zero-day-${{ needs.build.outputs.mcuboot_commit }}",
        )


if __name__ == "__main__":
    unittest.main()
