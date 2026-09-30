#!/usr/bin/env python3
"""Regression guards for adaptive calibration trace capture."""

from __future__ import annotations

import ast
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PY_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"
sys.path.insert(0, str(ROOT / "scripts"))

import renode_runner  # noqa: E402


class RuntimeFaultSweepCalibrationTests(unittest.TestCase):
    def test_instruction_limit_error_names_profile_setting_and_value(self) -> None:
        profile = SimpleNamespace(
            expect=SimpleNamespace(control_outcome="success"),
            fault_sweep=SimpleNamespace(max_writes_cap=1000),
        )
        result = {
            "total_writes": 1176,
            "total_erases": 0,
            "calibration_stop_reason": "instruction_limit(9808060)",
            "instruction_limit": 500000,
            "instruction_limit_source": "profile",
        }
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            renode_runner, "run_single_point", return_value=result
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                r"fault_sweep\.max_step_limit=500000",
            ):
                renode_runner.run_calibration(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    robot_vars=[],
                    work_dir=Path(td),
                    renode_remote_server_dir="",
                )

    def test_phase2_trace_capture_reason_gate(self) -> None:
        """Fine tracing follows actual successful run_until_done outcomes."""
        tree = ast.parse(PY_PATH.read_text(encoding="utf-8"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_calibration_phase2_trace_allowed"
        )
        namespace = {
            "_CALIBRATION_TRACE_COMPLETION_REASONS": frozenset(
                ("vtor_captured", "pc_captured")
            )
        }
        exec(
            compile(ast.Module(body=[function], type_ignores=[]), str(PY_PATH), "exec"),
            namespace,
        )
        allowed = namespace["_calibration_phase2_trace_allowed"]

        self.assertTrue(allowed("vtor_captured", True, True))
        self.assertFalse(allowed("vtor_captured", True, False))
        self.assertTrue(allowed("pc_captured", True, False))
        self.assertTrue(allowed("pc_captured", True, True))
        for reason in (
            "vtor",
            "vtor_settled",
            "vtor_captured_hardfault",
            "fault_fired",
            "budget",
            "wall_timeout(600s)",
            "no_progress_stall(20.0s)",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(allowed(reason, True, True))
        self.assertFalse(allowed("vtor_captured", False, True))

    def test_semantic_trace_modes_request_phase2_after_vtor_capture(self) -> None:
        """Erase and mixed selectors retain the trace their planner consumes."""
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "or (heuristic_trace_required and backend['kind'] == 'fast')",
            text,
        )
        self.assertIn("or calibration_trace_required", text)

    def test_slow_controller_trace_stubs_are_not_trace_capable(self) -> None:
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn("backend['kind'] in ('fast', 'mram')", text)
        self.assertIn(
            "getattr(backend['data'], 'WriteTraceWidthExplicit', False)",
            text,
        )

    def test_fine_trace_enables_address_tracking_for_accurate_pg_backends(self) -> None:
        tree = ast.parse(PY_PATH.read_text(encoding="utf-8"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_enable_fine_trace"
        )
        namespace = {}
        exec(
            compile(ast.Module(body=[function], type_ignores=[]), str(PY_PATH), "exec"),
            namespace,
        )

        class Backend:
            PerWriteAccurate = True
            SkipShadowScan = True
            WriteTraceEnabled = False
            EraseTraceEnabled = False

            def __init__(self):
                self.clears = []

            def InvalidateShadow(self):
                self.clears.append("shadow")

            def WriteTraceClear(self):
                self.clears.append("write")

            def EraseTraceClear(self):
                self.clears.append("erase")

        accurate = Backend()
        namespace["_enable_fine_trace"](accurate)
        self.assertFalse(accurate.SkipShadowScan)
        self.assertTrue(accurate.WriteTraceEnabled)
        self.assertTrue(accurate.EraseTraceEnabled)
        self.assertEqual(accurate.clears, ["shadow", "write", "erase"])

        class CountOnlyBackend(Backend):
            PerWriteAccurate = False

        count_only = CountOnlyBackend()
        namespace["_enable_fine_trace"](count_only)
        self.assertTrue(count_only.SkipShadowScan)
        self.assertTrue(count_only.WriteTraceEnabled)
        self.assertTrue(count_only.EraseTraceEnabled)
        self.assertEqual(count_only.clears, ["write", "erase"])


if __name__ == "__main__":
    unittest.main()
