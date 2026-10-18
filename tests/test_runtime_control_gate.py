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

    def test_instruction_limit_control_error_names_profile_setting(self) -> None:
        events = []
        failed = self._control_result()
        failed["boot_outcome"] = "timeout"
        failed["signals"].update(
            {
                "phase1_stop_reason": "instruction_limit(600000)",
                "phase1_instruction_limit": 500000,
            }
        )

        with self.assertRaisesRegex(
            RuntimeError,
            r"fault_sweep\.max_step_limit=500000",
        ):
            self._run(self._profile(), failed, events)
        self.assertEqual(events, ["control"])

    def test_wall_and_emulated_limits_remain_infrastructure_failures(self) -> None:
        for reason in ("wall_timeout(121s)", "budget"):
            with self.subTest(reason=reason):
                events = []
                failed = self._control_result()
                failed["boot_outcome"] = "timeout"
                failed["signals"].update(
                    phase1_stop_reason=reason,
                    phase1_emulated_s=2.0,
                )
                with self.assertRaisesRegex(RuntimeError, "observed 'timeout'") as error:
                    self._run(self._profile(), failed, events)
                self.assertIn(f"stop={reason!r}, emulated_s=2.0", str(error.exception))
                self.assertEqual(events, ["control"])

    def test_followup_timeout_error_preserves_cycle_and_stop_reason(self) -> None:
        events = []
        failed = self._control_result()
        failed["boot_outcome"] = "timeout"
        failed["boot_cycles"] = [
            {
                "cycle": 1,
                "signals": {
                    "phase_followup_stop_reason": "wall_timeout(121s)",
                    "phase_followup_emulated_s": 1.2,
                },
            }
        ]
        with self.assertRaisesRegex(RuntimeError, "observed 'timeout'") as error:
            self._run(self._profile(), failed, events)
        self.assertIn(
            "cycle 1 phase_followup stop='wall_timeout(121s)', emulated_s=1.2",
            str(error.exception),
        )
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

    def test_image_hash_control_without_marker_is_validated_by_hash_evidence(self) -> None:
        events = []
        profile = SimpleNamespace(
            name="image_hash_only_control",
            expect=SimpleNamespace(control_outcome="success"),
            success_criteria=SimpleNamespace(
                pc_in_slot="exec",
                vtor_in_slot="exec",
                marker_address=None,
                marker_value=None,
                image_hash=True,
                image_hash_slot="exec",
                expected_image="staging",
                allowed_images=[],
            ),
            fault_sweep=SimpleNamespace(sweep_hash_bypass_symbols=[]),
        )
        control_result = {
            "fault_at": 1000000,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {
                "marker_ok": True,
                "marker_actual": "0x00000000",
                "image_hash_match": "staging_image",
                "matched_image": "staging",
            },
        }

        results = self._run(profile, control_result, events)

        self.assertEqual(events, ["control", "state_evaluator", "fault_batch"])
        self.assertEqual(len(results), 2)

    def test_image_hash_control_without_marker_rejects_missing_or_wrong_hash_evidence(self) -> None:
        profile = SimpleNamespace(
            name="image_hash_only_control",
            expect=SimpleNamespace(control_outcome="success"),
            success_criteria=SimpleNamespace(
                pc_in_slot="exec",
                vtor_in_slot="exec",
                marker_address=None,
                marker_value=None,
                image_hash=True,
                image_hash_slot="exec",
                expected_image="staging",
                allowed_images=[],
            ),
            fault_sweep=SimpleNamespace(sweep_hash_bypass_symbols=[]),
        )
        invalid_signals = (
            {"marker_ok": True, "marker_actual": "0x00000000"},
            {
                "marker_ok": False,
                "marker_actual": "0x00000000",
                "image_hash_match": "staging_image",
            },
            {
                "marker_ok": True,
                "marker_actual": "0x00000000",
                "image_hash_match": "unknown",
            },
            {
                "marker_ok": True,
                "marker_actual": "0x00000000",
                "image_hash_match": "exec_image",
                "matched_image": "exec",
            },
        )

        for signals in invalid_signals:
            with self.subTest(signals=signals):
                events = []
                control_result = {
                    "fault_at": 1000000,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "signals": dict(signals),
                }
                with self.assertRaisesRegex(RuntimeError, "Clean control failed"):
                    self._run(profile, control_result, events)
                self.assertEqual(events, ["control"])

    def test_declared_marker_requirement_is_kept_when_image_hash_is_enabled(self) -> None:
        profile = SimpleNamespace(
            name="image_hash_with_declared_marker",
            expect=SimpleNamespace(control_outcome="success"),
            success_criteria=SimpleNamespace(
                pc_in_slot="exec",
                vtor_in_slot="exec",
                marker_address=0x20000000,
                marker_value=0xA11CE001,
                image_hash=True,
                image_hash_slot="exec",
                expected_image="staging",
                allowed_images=[],
            ),
            fault_sweep=SimpleNamespace(sweep_hash_bypass_symbols=[]),
        )
        missing_marker = {
            "fault_at": 1000000,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {
                "marker_ok": True,
                "marker_actual": "0x00000000",
                "image_hash_match": "staging_image",
                "matched_image": "staging",
            },
        }
        events = []
        with self.assertRaisesRegex(RuntimeError, "expected marker 0xA11CE001"):
            self._run(profile, missing_marker, events)
        self.assertEqual(events, ["control"])

        confirmed_both = {
            "fault_at": 1000000,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {
                "marker_ok": True,
                "marker_actual": "0xA11CE001",
                "image_hash_match": "staging_image",
                "matched_image": "staging",
            },
        }
        events = []
        results = self._run(profile, confirmed_both, events)
        self.assertEqual(events, ["control", "state_evaluator", "fault_batch"])
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
