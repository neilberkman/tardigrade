#!/usr/bin/env python3
"""Regression guards for adaptive calibration trace capture."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


class RuntimeFaultSweepCalibrationTests(unittest.TestCase):
    def test_phase2_trace_capture_reason_gate(self) -> None:
        """Phase 2 calibration condition must NOT include vtor_captured yet.

        vtor_captured was accidentally included and broke 3 MCUboot profiles
        (phase 2 had never run for those before, changing fault point
        distribution). The dead-code 'vtor' entry and the vtor_captured
        question need deliberate investigation before re-enabling.
        """
        text = PY_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "if phase1_reason in ('vtor', 'vtor_settled', 'pc_captured') and trace_capable:",
            text,
        )


if __name__ == "__main__":
    unittest.main()
