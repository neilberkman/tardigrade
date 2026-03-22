#!/usr/bin/env python3
"""Guardrails for the runtime fault sweep loader/reset boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESC_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.resc"
PY_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


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


if __name__ == "__main__":
    unittest.main()
