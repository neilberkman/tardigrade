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
        self.assertIn("phase1_time_slice = get_optional_var('phase1_time_slice', '0.02')", text)
        self.assertIn("def run_until_done(cpu_ref, time_slice=None, max_iters=200, wall_timeout=120, label='',", text)
        self.assertIn("def phase1_max_iters(default_s=4.0, time_slice_s=None):", text)
        self.assertIn("if time_slice is None:", text)
        self.assertIn("time_slice = phase1_time_slice", text)
        self.assertIn("if time_slice_s is None:", text)
        self.assertIn("time_slice_s = float(phase1_time_slice)", text)

    def test_optional_time_slices_use_safe_monitor_helper(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("resume_trace_time_slice = get_optional_var('resume_trace_time_slice', '0.02')", text)
        self.assertIn("calibration_time_slice = get_optional_var('calibration_time_slice', '0.02')", text)
        self.assertIn("phase1_time_slice = get_optional_var('phase1_time_slice', '0.02')", text)
        self.assertIn("phase2_time_slice = get_optional_var('phase2_time_slice', '0.05')", text)

    def test_phase1_max_iters_defaults_to_phase1_time_slice(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(def parse_duration_seconds\(default=2\.0\):.*?"
            r"def phase1_max_iters\(default_s=4\.0, time_slice_s=None\):.*?)(?=\ndef phase1_wall_timeout)",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        ns = {"run_duration": "4.1", "phase1_time_slice": "0.25"}
        exec(match.group(1), ns)
        self.assertEqual(ns["phase1_max_iters"](default_s=4.0), 200)

    def test_phase1_budget_helpers_scale_control_runs_to_run_duration(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(def parse_duration_seconds\(default=2\.0\):.*?"
            r"def phase1_max_iters\(default_s=4\.0, time_slice_s=None\):.*?"
            r"def phase1_wall_timeout\(default_s=4\.0, min_wall_s=120\.0, wall_per_emulated_s=30\.0\):.*?)(?=\ndef run_read_bit_flip_fault)",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        ns = {
            "run_duration": "30.0",
            "phase1_time_slice": "0.10",
            "progress_stall_timeout_s": 20.0,
        }
        exec(match.group(1), ns)
        self.assertEqual(ns["phase1_max_iters"](default_s=4.0), 300)
        self.assertEqual(ns["phase1_wall_timeout"](default_s=4.0), 900)

    def test_robot_suite_forwards_phase1_time_slice(self) -> None:
        text = ROBOT_PATH.read_text(encoding="utf-8")
        self.assertIn("${PHASE1_TIME_SLICE}           ${EMPTY}", text)
        self.assertIn(
            "Run Keyword If    '${PHASE1_TIME_SLICE}' != ''    Execute Command    $phase1_time_slice=\"${PHASE1_TIME_SLICE}\"",
            text,
        )

    def test_robot_suite_forwards_platform_repl(self) -> None:
        text = ROBOT_PATH.read_text(encoding="utf-8")
        self.assertIn('Execute Command    $platform_repl="${PLATFORM_REPL}"', text)

    def test_restore_hw_init_reseeds_uicr_words(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("platform_repl = get_optional_var('platform_repl', '').strip().lower()", text)
        self.assertIn("def restore_hw_init():", text)
        self.assertIn(
            "platform_name = os.path.basename(platform_repl)",
            text,
        )
        self.assertIn(
            "if platform_name not in ('cortex_m4_flash.repl', 'cortex_m4_flash_fast.repl'):",
            text,
        )
        self.assertIn("bus.WriteDoubleWord(0x10001200, 0x12)", text)
        self.assertIn("bus.WriteDoubleWord(0x10001204, 0x12)", text)

    def test_prepare_clean_phase1_state_restores_hw_init_after_reset(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            re.compile(
                r"def prepare_clean_phase1_state\(\):\n"
                r"\s+_machine_reset\(\)\n"
                r"\s+monitor.Parse\('machine Pause'\)\n"
                r"\s+restore_hw_init\(\)\n"
                r"\s+needs_pre_boot = restore_initial_flash_cache\(\)\n"
            ),
        )

    def test_control_phase1_uses_default_progress_mode(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            re.compile(
                r"phase1_status = run_until_done\(\n"
                r"\s+cpu_ref,\n"
                r"\s+label='control_p1',\n"
                r"\s+stop_on_fault=False,\n"
                r"\s+max_iters=p1_max_iters,\n"
            ),
        )

    def test_run_until_done_tracks_pc_progress_for_read_only_control_runs(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("pc_progress = None", text)
        self.assertIn("if (not expect_writes) and cur_writes == 0 and not sticky_vtor['captured']:", text)
        self.assertIn("pc_progress = pc_now", text)
        self.assertRegex(
            text,
            re.compile(
                r"progress_key = \(\n"
                r"\s+cur_writes,\n"
                r"\s+cur_erases,\n"
                r"\s+bool\(sticky_vtor\['captured'\]\),\n"
                r"\s+pc_progress,\n"
                r"\s+\)\n"
            ),
        )

    def test_execute_runner_tracks_sticky_pc_slot_observation(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("sticky_pc = {'value': 0, 'slot': None, 'captured': False}", text)
        self.assertIn("def capture_sticky_pc(pc_value):", text)
        self.assertIn("sticky_pc['value'] = pc", text)
        self.assertIn("sticky_pc['slot'] = sn", text)
        self.assertIn("sticky_pc['captured'] = True", text)
        self.assertIn("capture_sticky_pc(pc_now)", text)

    def test_evaluate_boot_outcome_uses_sticky_pc_as_execution_observation(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("sticky_pc_slot = sticky_pc.get('slot') if sticky_pc.get('captured') else None", text)
        self.assertIn("if boot_slot is None and sticky_pc_slot in slot_ranges:", text)
        self.assertIn("execution_observed = boot_slot is not None", text)
        self.assertIn("'pc_sticky': sticky_pc['captured']", text)
        self.assertIn("'pc_sticky_slot': sticky_pc['slot']", text)
        self.assertIn("if not execution_observed:", text)


if __name__ == "__main__":
    unittest.main()
