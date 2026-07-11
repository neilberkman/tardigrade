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

    def test_runtime_runner_exposes_console_observations_in_stop_status(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def capture_console_state(include_recent=False):", text)
        self.assertIn("console_state = capture_console_state(include_recent=bool(console_fatal))", text)
        self.assertIn("'console_attached_names': console_state.get('attached_names', [])", text)
        self.assertIn("'console_last_line': console_state.get('last_line')", text)
        self.assertIn("'console_fatal_pattern': console_fatal", text)

    def test_runtime_runner_merges_console_status_into_signals(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def merge_stop_status_signals(signals, prefix, status):", text)
        self.assertIn("signals[prefix + '_console_attached_names'] = status.get('console_attached_names')", text)
        self.assertIn("signals[prefix + '_console_last_line'] = status.get('console_last_line')", text)
        self.assertIn("signals[prefix + '_console_fatal_pattern'] = status.get('console_fatal_pattern')", text)
        self.assertIn("merge_stop_status_signals(signals, 'phase1', phase1_status)", text)
        self.assertIn("merge_stop_status_signals(signals, 'phase2', p2_status)", text)

    def test_runtime_runner_uses_verified_inline_binary_loads(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def _verify_loaded_binary_samples(path, addr):", text)
        self.assertIn(
            "monitor.Parse(\"python \\\"bus=monitor.Machine.SystemBus; bus.LoadBinary",
            text,
        )
        self.assertIn("_verify_loaded_binary_samples(path, _a)", text)

    def test_runtime_runner_persists_fault_snapshots_under_robot_artifacts(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def persist_fault_snapshot(fault_at, fault_type, snapshot_bytes):", text)
        self.assertIn("os.path.join(root, 'robot', 'snapshots')", text)
        self.assertIn("result['fault_snapshot_file'] = _snapshot_path", text)
        self.assertIn("persist_snapshot=False", text)
        self.assertIn("if persist_snapshot and fault_snapshot_bytes is not None:", text)
        self.assertIn("control_snapshot_bytes = None", text)
        self.assertIn("control_stop_reason = phase1_status.get('reason') if phase1_status is not None else ''", text)
        self.assertIn("if boot_outcome == 'no_boot' or str(control_stop_reason).startswith('no_boot'):", text)
        self.assertIn("control_snapshot_bytes = to_py_bytes(_snapshot_current_flash())", text)

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
        self.assertIn(
            "def phase1_wall_timeout(default_s=4.0, min_wall_s=120.0, wall_per_emulated_s=30.0, budget_s=None):",
            text,
        )
        self.assertNotIn("max(120, progress_stall_timeout_s * 3)", text)
        self.assertIn("wall_timeout=phase1_wall_timeout(default_s=4.0)", text)
        self.assertIn("p1_wall_timeout = phase1_wall_timeout(default_s=4.0)", text)

    def test_phase1_uses_configurable_time_slice(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("phase1_time_slice = get_optional_var('phase1_time_slice', '0.02')", text)
        self.assertIn("def run_until_done(cpu_ref, time_slice=None, max_iters=200, wall_timeout=120, label='',", text)
        self.assertIn("def phase1_max_iters(default_s=4.0, time_slice_s=None, budget_s=None):", text)
        self.assertIn("if time_slice is None:", text)
        self.assertIn("time_slice = phase1_time_slice", text)
        self.assertIn("if time_slice_s is None:", text)
        self.assertIn("time_slice_s = float(phase1_time_slice)", text)

    def test_optional_time_slices_use_safe_monitor_helper(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("resume_trace_time_slice = get_optional_var('resume_trace_time_slice', '0.02')", text)
        self.assertIn("calibration_time_slice = get_optional_var('calibration_time_slice', '0.02')", text)
        self.assertIn("zero_point_execute_control = get_optional_var(", text)
        self.assertIn(").strip().lower() in ('1', 'true', 'yes')", text)
        self.assertIn("phase1_time_slice = get_optional_var('phase1_time_slice', '0.02')", text)
        self.assertIn("phase2_time_slice = get_optional_var('phase2_time_slice', '0.05')", text)

    def test_phase1_max_iters_defaults_to_phase1_time_slice(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(def parse_duration_seconds\(default=2\.0\):.*?"
            r"def phase1_budget_duration\(default_s=4\.0, prefer_run_duration=False\):.*?"
            r"def phase1_max_iters\(default_s=4\.0, time_slice_s=None, budget_s=None\):.*?)(?=\ndef phase1_wall_timeout)",
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
            r"def phase1_budget_duration\(default_s=4\.0, prefer_run_duration=False\):.*?"
            r"def phase1_max_iters\(default_s=4\.0, time_slice_s=None, budget_s=None\):.*?"
            r"def phase1_wall_timeout\(default_s=4\.0, min_wall_s=120\.0, wall_per_emulated_s=30\.0, budget_s=None\):.*?)(?=\ndef run_read_bit_flip_fault)",
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

    def test_phase1_budget_helpers_honor_explicit_resolved_budget(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(def parse_duration_seconds\(default=2\.0\):.*?"
            r"def phase1_budget_duration\(default_s=4\.0, prefer_run_duration=False\):.*?"
            r"def phase1_max_iters\(default_s=4\.0, time_slice_s=None, budget_s=None\):.*?"
            r"def phase1_wall_timeout\(default_s=4\.0, min_wall_s=120\.0, wall_per_emulated_s=30\.0, budget_s=None\):.*?)(?=\ndef run_read_bit_flip_fault)",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        ns = {
            "run_duration": "0.04",
            "phase1_time_slice": "0.02",
            "progress_stall_timeout_s": 20.0,
        }
        exec(match.group(1), ns)
        self.assertEqual(
            ns["phase1_max_iters"](default_s=0.04, budget_s=10.0),
            500,
        )
        self.assertEqual(
            ns["phase1_wall_timeout"](default_s=0.04, budget_s=10.0),
            300,
        )

    def test_phase1_budget_duration_keeps_control_floor_for_zero_point_execute(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(def parse_duration_seconds\(default=2\.0\):.*?"
            r"def phase1_budget_duration\(default_s=4\.0, prefer_run_duration=False\):.*?)(?=\ndef phase1_max_iters)",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        ns = {"run_duration": "10.0"}
        exec(match.group(1), ns)
        self.assertEqual(ns["phase1_budget_duration"](default_s=4.0), 10.0)
        self.assertEqual(
            ns["phase1_budget_duration"](default_s=4.0, prefer_run_duration=True),
            10.0,
        )

        ns = {"run_duration": "0.04"}
        exec(match.group(1), ns)
        self.assertEqual(ns["phase1_budget_duration"](default_s=4.0), 4.0)
        self.assertEqual(
            ns["phase1_budget_duration"](default_s=4.0, prefer_run_duration=True),
            4.0,
        )

    def test_zero_point_execute_control_uses_dedicated_control_phase1_helper(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def run_control_phase1(cpu_ref, label='control_p1', vtor_settle_iters=0):", text)
        self.assertIn("control_budget_s = phase1_budget_duration(", text)
        self.assertIn("prefer_run_duration=zero_point_execute_control", text)
        self.assertIn("control_time_slice = phase1_time_slice", text)
        self.assertIn("control_time_slice = str(max(1.0, float(phase1_time_slice)))", text)
        self.assertIn(
            "p1_wall_timeout = phase1_wall_timeout(default_s=control_budget_s, budget_s=control_budget_s)",
            text,
        )
        self.assertIn(
            "p1_max_iters = phase1_max_iters(",
            text,
        )
        self.assertIn("saved_stall_timeout_s = progress_stall_timeout_s", text)
        self.assertIn("if zero_point_execute_control:", text)
        self.assertIn("progress_stall_timeout_s = max(1.0, float(control_budget_s))", text)
        self.assertIn("time_slice=control_time_slice", text)
        self.assertIn("progress_stall_timeout_s = saved_stall_timeout_s", text)

    def test_robot_suite_forwards_phase1_time_slice(self) -> None:
        text = ROBOT_PATH.read_text(encoding="utf-8")
        self.assertIn("${PHASE1_TIME_SLICE}           ${EMPTY}", text)
        self.assertIn(
            "Run Keyword If    '${PHASE1_TIME_SLICE}' != ''    Execute Command    $phase1_time_slice=\"${PHASE1_TIME_SLICE}\"",
            text,
        )
        self.assertIn("${ZERO_POINT_EXECUTE_CONTROL}  false", text)
        self.assertIn(
            'Execute Command    $zero_point_execute_control="${ZERO_POINT_EXECUTE_CONTROL}"',
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

    def test_control_phase1_switches_to_read_only_progress_for_zero_point_execute(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("control_expect_writes = not zero_point_execute_control", text)
        self.assertIn("progress_stall_timeout_s = max(1.0, float(control_budget_s))", text)
        self.assertRegex(
            text,
            re.compile(
                r"return run_until_done\(\n"
                r"\s+cpu_ref,\n"
                r"\s+label=label,\n"
                r"\s+stop_on_fault=False,\n"
                r"\s+expect_writes=control_expect_writes,\n"
                r"\s+zero_writes_is_brick=control_expect_writes,\n"
                r"\s+max_iters=p1_max_iters,\n"
            ),
        )
        self.assertIn("phase1_status = run_control_phase1(", text)
        self.assertIn("p2_status=phase1_status", text)

    def test_control_runner_captures_offset_slot_header_debug(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("staging_offset_header_debug = None", text)
        self.assertIn("staging_offset = effective_page_size()", text)
        self.assertIn("if 0 < staging_offset < slot_staging_size:", text)
        self.assertIn(
            "staging_offset_header_debug = capture_slot_header_debug(",
            text,
        )
        self.assertIn("slot_staging_base + staging_offset", text)
        self.assertIn("signals['staging_offset_header_offset'] = fmt_u32(staging_offset)", text)
        self.assertIn("signals['staging_offset_header_debug'] = staging_offset_header_debug", text)

    def test_zero_point_execute_control_flag_parses_to_boolean(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"zero_point_execute_control = get_optional_var\(\n"
            r"\s+'zero_point_execute_control', 'false'\n"
            r"\s*\)\.strip\(\)\.lower\(\) in \('1', 'true', 'yes'\)",
            text,
        )
        self.assertIsNotNone(match)

        ns = {"get_optional_var": lambda _name, default="": "true"}
        exec(match.group(0), ns)
        self.assertIs(ns["zero_point_execute_control"], True)

        ns = {"get_optional_var": lambda _name, default="": "false"}
        exec(match.group(0), ns)
        self.assertIs(ns["zero_point_execute_control"], False)

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
        self.assertIn(
            "and not sticky_pc['captured']\n"
            "            and progress_stall_timeout_s > 0\n"
            "            and emulated_s >= progress_stall_timeout_s",
            text,
        )

    def test_run_until_done_can_stop_on_configured_pc_handoff(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "pc_handoff_slot = success_pc_slot if success_pc_slot in slot_ranges else None",
            text,
        )
        self.assertIn("and sticky_pc.get('slot') == pc_handoff_slot", text)
        self.assertIn("and not sticky_vtor['captured']", text)
        self.assertIn("reason = 'pc_captured'", text)

    def test_execute_runner_tracks_sticky_pc_slot_observation(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("console_fatal_patterns = (", text)
        self.assertIn("def _get_console_peripherals():", text)
        self.assertIn("def check_console_fatal():", text)
        self.assertIn("if uart.ContainsLineFragment(pattern):", text)
        self.assertIn("reason = 'console_fatal({})'.format(console_fatal)", text)
        self.assertIn("sticky_pc = {'value': 0, 'slot': None, 'captured': False}", text)
        self.assertIn("def capture_sticky_pc(pc_value):", text)
        self.assertIn("sticky_pc['value'] = pc", text)
        self.assertIn("sticky_pc['slot'] = sn", text)
        self.assertIn("sticky_pc['captured'] = True", text)
        self.assertIn("capture_sticky_pc(pc_now)", text)

    def test_evaluate_boot_outcome_uses_sticky_pc_as_execution_observation(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("no_boot_phase_without_vtor = (", text)
        self.assertIn("sticky_pc_slot = sticky_pc.get('slot') if sticky_pc.get('captured') else None", text)
        self.assertIn("and not no_boot_phase_without_vtor", text)
        self.assertIn("execution_observed = boot_slot is not None", text)
        self.assertIn("'pc_sticky': sticky_pc['captured']", text)
        self.assertIn("'pc_sticky_slot': sticky_pc['slot']", text)
        self.assertIn("'pc_sticky_ignored_no_boot_phase': no_boot_phase_without_vtor", text)
        self.assertIn("if not execution_observed:", text)

    def test_vtor_capture_does_not_override_a_zero_final_pc(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("if sticky_vtor['captured'] and pc_value == 0:", text)
        self.assertNotIn("treat the VTOR jump as proof of execution attempt", text)

    def test_slow_backend_flash_reads_use_bulk_nvm_reads(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("def read_flash_bytes(start_addr, size):", text)
        self.assertIn("return read_flash_bytes(start_addr, max_len)", text)
        self.assertIn("return to_py_bytes(b['data'].Nvm.ReadBytes(rel, max_len, None))", text)
        self.assertIn("data = read_flash_bytes(slot_base, data_size)", text)

    def test_elf_symbol_loader_falls_back_when_shutil_which_is_missing(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("_which = getattr(_shutil, 'which', None)", text)
        self.assertIn("for _name in ('arm-none-eabi-nm', 'nm'):", text)
        self.assertIn("if _name not in _nm_candidates:", text)
        self.assertIn("log('elf_symbols: could not launch {} ({})'.format(_nm_bin, _launch_err))", text)
        self.assertIn("log('elf_symbols: {} failed (rc={}), trying next symbol resolver'.format(_nm_bin, _nm_rc))", text)

    def test_run_until_done_does_not_abort_on_write_volume_or_host_slowdown(self) -> None:
        # Write volume and host-side slowdown are diagnostics, not boot
        # outcomes. MCUboot swap/revert legitimately performs thousands of
        # writes, and instruction-skip points must still be classified from
        # VTOR/PC/fault evidence or explicit wall-budget exhaustion.
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("enable_pathological_aborts", text)
        self.assertNotIn("write_storm(", text)
        self.assertNotIn("step_slowdown(", text)
        self.assertIn("if elapsed > wall_timeout:", text)


if __name__ == "__main__":
    unittest.main()
