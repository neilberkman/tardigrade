#!/usr/bin/env python3
"""Guardrails for the runtime fault sweep loader/reset boundary."""

from __future__ import annotations

import unittest
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
RESC_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.resc"
PY_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"
ROBOT_PATH = ROOT / "tests" / "ota_fault_point.robot"


class RuntimeFaultSweepLoaderTests(unittest.TestCase):
    def test_resc_uses_explicit_file_scoped_exec(self) -> None:
        text = RESC_PATH.read_text(encoding="utf-8")
        self.assertNotIn("exec(open(_sweep_py).read())", text)
        self.assertIn("_sweep_globals = globals()", text)
        self.assertIn("_sweep_globals['__file__'] = _sweep_py", text)
        self.assertTrue(
            "execfile(_sweep_py, _sweep_globals)" in text
            or "exec(compile(_sweep_src, _sweep_py, 'exec'), _sweep_globals, _sweep_globals)" in text
        )

    def test_runtime_runner_routes_resets_through_refreshing_helper(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def _machine_reset():", text)
        self.assertIn("refresh_runtime_handles()", text)
        self.assertEqual(
            text.count("monitor.Parse('machine Reset')"),
            1,
            "raw machine Reset should only exist inside _machine_reset()",
        )

    def test_runtime_runner_uses_verified_inline_binary_loads(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def _verify_loaded_binary_samples(path, addr):", text)
        self.assertIn(
            "monitor.Parse(\"python \\\"bus=monitor.Machine.SystemBus; bus.LoadBinary",
            text,
        )
        self.assertIn("_verify_loaded_binary_samples(path, _a)", text)

    def test_progress_stall_branch_only_breaks_after_threshold(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("elif progress_stall_timeout_s > 0:", text)
        self.assertIn("if emulated_stall >= progress_stall_timeout_s:", text)
        self.assertRegex(
            text,
            re.compile(
                r"if emulated_stall >= progress_stall_timeout_s:\n"
                r"\s+if cur_writes == 0:\n"
                r"\s+reason = 'no_boot_stall\(\{:\.2f\}s_emulated\)'\.format\(emulated_stall\)\n"
                r"\s+else:\n"
                r"\s+reason = 'no_progress_stall\(\{:\.2f\}s_emulated\)'\.format\(emulated_stall\)\n"
                r"\s+break\n"
            ),
        )

    def test_phase1_uses_scaled_wall_timeout_helper(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def phase1_wall_timeout(default_s=4.0, min_wall_s=120.0, wall_per_emulated_s=30.0):", text)
        self.assertNotIn("max(120, progress_stall_timeout_s * 3)", text)
        self.assertIn("wall_timeout=phase1_wall_timeout(default_s=4.0)", text)
        self.assertIn("p1_wall_timeout = phase1_wall_timeout(default_s=4.0)", text)

    def test_phase1_uses_configurable_time_slice(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("phase1_time_slice = str(monitor.GetVariable('phase1_time_slice')).strip()", text)
        self.assertIn("if not phase1_time_slice:", text)
        self.assertIn("def run_until_done(cpu_ref, time_slice=None, max_iters=200, wall_timeout=120, label='',", text)
        self.assertIn("if time_slice is None:", text)
        self.assertIn("time_slice = phase1_time_slice", text)
        self.assertIn("if time_slice_s is None:", text)
        self.assertIn("time_slice_s = float(phase1_time_slice)", text)

    def test_robot_suite_forwards_phase1_time_slice(self) -> None:
        text = ROBOT_PATH.read_text(encoding="utf-8")
        self.assertIn("${PHASE1_TIME_SLICE}           ${EMPTY}", text)
        self.assertIn(
            "Run Keyword If    '${PHASE1_TIME_SLICE}' != ''    Execute Command    $phase1_time_slice=\"${PHASE1_TIME_SLICE}\"",
            text,
        )


if __name__ == "__main__":
    unittest.main()
