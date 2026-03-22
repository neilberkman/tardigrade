#!/usr/bin/env python3
"""Unit tests for sweep-scoped hash bypass configuration."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, load_profile  # noqa: E402
from sweep import run_runtime_sweep  # noqa: E402


class SweepHashBypassProfileTest(unittest.TestCase):
    def _write_profile(self, tempdir: Path, field_line: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(
            textwrap.dedent(
                f"""
                schema_version: 1
                name: sweep_hash_bypass_profile
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  fault_types: [power_loss]
                  {field_line}
                expect:
                  should_find_issues: false
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_new_field_parses_but_robot_vars_stay_clean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = load_profile(
                self._write_profile(
                    Path(td),
                    'sweep_hash_bypass_symbols: ["bootutil_img_validate"]',
                )
            )
        self.assertEqual(
            profile.fault_sweep.sweep_hash_bypass_symbols,
            ["bootutil_img_validate"],
        )
        self.assertFalse(
            any(rv.startswith("HASH_BYPASS_SYMBOLS:") for rv in profile.robot_vars(ROOT))
        )

    def test_old_field_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                Path(td),
                'hash_bypass_symbols: ["bootutil_img_validate"]',
            )
            with self.assertRaises(ProfileError) as ctx:
                load_profile(path)
        self.assertIn("renamed", str(ctx.exception))
        self.assertIn("sweep_hash_bypass_symbols", str(ctx.exception))


class SweepHashBypassRuntimeScopeTest(unittest.TestCase):
    def test_fault_batches_and_control_share_sweep_bypass_symbols(self) -> None:
        profile = SimpleNamespace(
            name="scope_profile",
            fault_sweep=SimpleNamespace(
                sweep_hash_bypass_symbols=["bootutil_img_validate", "bootutil_sha256"],
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)
            with mock.patch("sweep._run_batches_chunked", return_value=[]) as mock_batch:
                with mock.patch("sweep.run_single_point", return_value={}) as mock_single:
                    run_runtime_sweep(
                        repo_root=work_dir,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[3, 7],
                        robot_vars=[
                            "BASE:1",
                            "HASH_BYPASS_SYMBOLS:bootutil_img_validate",
                        ],
                        work_dir=work_dir,
                        renode_remote_server_dir="",
                        include_control=True,
                    )

        batch_robot_vars = mock_batch.call_args.kwargs["robot_vars"]
        self.assertIn("BASE:1", batch_robot_vars)
        self.assertIn(
            "HASH_BYPASS_SYMBOLS:bootutil_img_validate,bootutil_sha256",
            batch_robot_vars,
        )
        self.assertEqual(
            [
                rv for rv in batch_robot_vars if rv.startswith("HASH_BYPASS_SYMBOLS:")
            ],
            ["HASH_BYPASS_SYMBOLS:bootutil_img_validate,bootutil_sha256"],
        )

        control_robot_vars = mock_single.call_args.kwargs["robot_vars"]
        self.assertIn("BASE:1", control_robot_vars)
        self.assertIn(
            "HASH_BYPASS_SYMBOLS:bootutil_img_validate,bootutil_sha256",
            control_robot_vars,
        )
        self.assertEqual(
            [
                rv for rv in control_robot_vars if rv.startswith("HASH_BYPASS_SYMBOLS:")
            ],
            ["HASH_BYPASS_SYMBOLS:bootutil_img_validate,bootutil_sha256"],
        )

    def test_no_hash_bypass_disables_fault_batch_injection(self) -> None:
        profile = SimpleNamespace(
            name="scope_profile",
            fault_sweep=SimpleNamespace(
                sweep_hash_bypass_symbols=["bootutil_img_validate"],
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)
            with mock.patch("sweep._run_batches_chunked", return_value=[]) as mock_batch:
                run_runtime_sweep(
                    repo_root=work_dir,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[11],
                    robot_vars=["BASE:1"],
                    work_dir=work_dir,
                    renode_remote_server_dir="",
                    include_control=False,
                    no_hash_bypass=True,
                )

        batch_robot_vars = mock_batch.call_args.kwargs["robot_vars"]
        self.assertEqual(batch_robot_vars, ["BASE:1"])


if __name__ == "__main__":
    unittest.main()
