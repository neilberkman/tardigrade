#!/usr/bin/env python3
"""Fail-closed ordering checks for the runtime campaign control."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from sweep import run_runtime_sweep  # noqa: E402


class RuntimeControlGateTests(unittest.TestCase):
    @staticmethod
    def _profile(*, marker_value: int = 0xA11CE001) -> SimpleNamespace:
        return SimpleNamespace(
            name="control_gate_test",
            expect=SimpleNamespace(control_outcome="success"),
            success_criteria=SimpleNamespace(
                pc_in_slot="exec",
                vtor_in_slot="exec",
                marker_address=0x20000000,
                marker_value=marker_value,
            ),
            fault_sweep=SimpleNamespace(sweep_hash_bypass_symbols=[]),
        )

    @staticmethod
    def _control_result(*, slot: str = "exec", marker: int = 0xA11CE001):
        return {
            "fault_at": 1000000,
            "boot_outcome": "success",
            "boot_slot": slot,
            "signals": {
                "marker_ok": True,
                "marker_actual": "0x{:08X}".format(marker),
            },
        }

    def _run(self, profile, control_result, events):
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)

            def run_control(**_kwargs):
                events.append("control")
                return control_result

            def select_points(**_kwargs):
                events.append("state_evaluator")
                return None

            def run_batch(**_kwargs):
                events.append("fault_batch")
                return [
                    {
                        "fault_at": 1,
                        "fault_type": "w",
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                    }
                ]

            with mock.patch("sweep.run_single_point", side_effect=run_control), mock.patch(
                "sweep._select_mcuboot_state_evaluator_points",
                side_effect=select_points,
            ) as select_mock, mock.patch(
                "sweep._run_batches_chunked",
                side_effect=run_batch,
            ) as batch_mock:
                try:
                    results = run_runtime_sweep(
                        repo_root=ROOT,
                        renode_test="renode-test",
                        robot_suite="tests/ota_fault_point.robot",
                        profile=profile,
                        fault_points=[1],
                        robot_vars=[],
                        work_dir=work_dir,
                        renode_remote_server_dir="",
                        include_control=True,
                        allow_state_evaluator=True,
                    )
                except Exception:
                    self.assertFalse(select_mock.called)
                    self.assertFalse(batch_mock.called)
                    raise
        return results

    def test_valid_control_executes_first_but_is_returned_last(self) -> None:
        events = []
        results = self._run(self._profile(), self._control_result(), events)

        self.assertEqual(events, ["control", "state_evaluator", "fault_batch"])
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["is_control"])
        self.assertTrue(results[1]["is_control"])

    def test_failed_control_dispatches_no_faults(self) -> None:
        events = []
        failed = self._control_result()
        failed["boot_outcome"] = "no_boot"

        with self.assertRaisesRegex(RuntimeError, "expected outcome"):
            self._run(self._profile(), failed, events)
        self.assertEqual(events, ["control"])

    def test_wrong_slot_control_is_rejected_before_dispatch(self) -> None:
        events = []
        with self.assertRaisesRegex(RuntimeError, "requires slot 'exec'"):
            self._run(
                self._profile(),
                self._control_result(slot="staging"),
                events,
            )
        self.assertEqual(events, ["control"])

    def test_zero_marker_sentinel_is_rejected_before_dispatch(self) -> None:
        events = []
        with self.assertRaisesRegex(RuntimeError, "non-zero sentinel"):
            self._run(
                self._profile(marker_value=0),
                self._control_result(marker=0),
                events,
            )
        self.assertEqual(events, ["control"])


if __name__ == "__main__":
    unittest.main()
