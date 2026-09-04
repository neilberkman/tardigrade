#!/usr/bin/env python3
"""Regression guards for adaptive calibration trace capture."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


class RuntimeFaultSweepCalibrationTests(unittest.TestCase):
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
            "writeback_active() or fault_types_mode in ('erase', 'both')",
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
