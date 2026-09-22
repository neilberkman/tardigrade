#!/usr/bin/env python3
"""Focused coverage for multi-image success and bounded calibration."""

from __future__ import annotations

import ast
import base64
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, load_profile  # noqa: E402
from result_checks import annotate_result_checks  # noqa: E402
from trigger_discovery import (  # noqa: E402
    _image_digest_for_evidence,
    _trace_less_content_evidence,
)


RUNTIME_PATH = SCRIPTS / "run_runtime_fault_sweep.py"


def _runtime_function(name: str):
    tree = ast.parse(RUNTIME_PATH.read_text(encoding="utf-8"), filename=str(RUNTIME_PATH))
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return compile(ast.Module(body=[node], type_ignores=[]), str(RUNTIME_PATH), "exec")


class AllowedImagesProfileTests(unittest.TestCase):
    def _profile(self, directory: Path, success: str, fault_sweep: str = ""):
        exec_image = directory / "exec.bin"
        staging_image = directory / "staging.bin"
        exec_image.write_bytes(b"old".ljust(256, b"\x11"))
        staging_image.write_bytes(b"new".ljust(256, b"\x22"))
        path = directory / "profile.yaml"
        path.write_text(
            textwrap.dedent(
                """
                schema_version: 1
                name: allowed_images_test
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x2000 }
                    staging: { base: 0x10002000, size: 0x2000 }
                images:
                  exec: EXEC_IMAGE
                  staging: STAGING_IMAGE
                success_criteria:
                SUCCESS
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  max_writes: auto
                  fault_types: [power_loss]
                FAULT_SWEEP
                expect:
                  should_find_issues: false
                """
            )
            .replace("EXEC_IMAGE", exec_image.name)
            .replace("STAGING_IMAGE", staging_image.name)
            .replace("SUCCESS", textwrap.indent(textwrap.dedent(success).strip(), "  "))
            .replace("FAULT_SWEEP", textwrap.indent(textwrap.dedent(fault_sweep).strip(), "  "))
            .strip()
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_allowed_images_encode_exact_names_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._profile(
                Path(td),
                """
                vtor_in_slot: exec
                image_hash: true
                image_hash_slot: exec
                allowed_images: [exec, staging]
                """,
            )
            profile = load_profile(path, strict=True)
            self.assertEqual(profile.success_criteria.allowed_images, ["exec", "staging"])
            variables = profile.robot_vars(path.parent)
            encoded = next(
                item.split(":", 1)[1]
                for item in variables
                if item.startswith("ALLOWED_IMAGE_HASHES_B64:")
            )
            payload = json.loads(base64.b64decode(encoded).decode("utf-8"))
            self.assertEqual([item["name"] for item in payload], ["exec", "staging"])
            self.assertTrue(all(len(item["sha256"]) == 64 for item in payload))

    def test_allowed_images_reject_ambiguous_or_unknown_declarations(self) -> None:
        invalid = (
            (
                "image_hash: true\nexpected_image: staging\nallowed_images: [exec]",
                "alternatives",
            ),
            ("image_hash: false\nallowed_images: [exec]", "requires"),
            ("image_hash: true\nallowed_images: [missing]", "not present"),
            ("image_hash: true\nallowed_images: [exec, exec]", "duplicate"),
        )
        for success, message in invalid:
            with self.subTest(success=success), tempfile.TemporaryDirectory() as td:
                path = self._profile(Path(td), success)
                with self.assertRaisesRegex(ProfileError, message):
                    load_profile(path, strict=True)

    def test_calibration_stop_parses_and_emits_runtime_variables(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._profile(
                Path(td),
                "vtor_in_slot: exec",
                """
                calibration_stop:
                  address: 0x10000120
                  success_criteria: true
                """,
            )
            profile = load_profile(path, strict=True)
            stop = profile.fault_sweep.calibration_stop
            self.assertEqual(stop.address, 0x10000120)
            self.assertTrue(stop.success_criteria)
            variables = set(profile.robot_vars(ROOT))
            self.assertIn("CALIBRATION_STOP_ADDRESS:0x10000120", variables)
            self.assertIn("CALIBRATION_STOP_ON_SUCCESS:true", variables)

    def test_calibration_stop_rejects_empty_odd_and_state_mode_configs(self) -> None:
        cases = (
            ("calibration_stop: {}", "must configure"),
            ("calibration_stop: { address: 0x10000121 }", "halfword-aligned"),
            (
                "evaluation_mode: state\ncalibration_stop: { success_criteria: true }",
                "requires execute",
            ),
        )
        for fault_sweep, message in cases:
            with self.subTest(fault_sweep=fault_sweep), tempfile.TemporaryDirectory() as td:
                path = self._profile(Path(td), "vtor_in_slot: exec", fault_sweep)
                with self.assertRaisesRegex(ProfileError, message):
                    load_profile(path, strict=True)

    def test_result_checks_retain_exact_matched_image(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._profile(
                Path(td),
                """
                vtor_in_slot: exec
                image_hash: true
                image_hash_slot: exec
                allowed_images: [exec, staging]
                """,
            )
            profile = load_profile(path)
            result = {
                "fault_at": 1,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"matched_image": "staging"},
            }
            annotate_result_checks([result], profile, ROOT)
            self.assertEqual(result["matched_image"], "staging")


class AllowedImagesDiscoveryTests(unittest.TestCase):
    def _profile(self, directory: Path):
        exec_image = directory / "exec.bin"
        staging_image = directory / "staging.bin"
        exec_image.write_bytes(b"baseline".ljust(0x100, b"\x11"))
        staging_image.write_bytes(b"candidate".ljust(0x100, b"\x22"))
        return SimpleNamespace(
            success_criteria=SimpleNamespace(
                vtor_in_slot="exec",
                pc_in_slot=None,
                marker_address=None,
                marker_value=None,
                image_hash=True,
                image_hash_slot="exec",
                expected_image=None,
                allowed_images=["exec", "staging"],
            ),
            memory=SimpleNamespace(
                slots={
                    "exec": SimpleNamespace(base=0xC000, size=0x2000),
                    "staging": SimpleNamespace(base=0xE000, size=0x2000),
                }
            ),
            images={"exec": str(exec_image), "staging": str(staging_image)},
            flash_backend="faultFlash",
        )

    @staticmethod
    def _data(digest: str, matched_image: str):
        return {
            "total_writes": 2,
            "total_erases": 0,
            "calibration_stop_reason": "calibration_stop_success_criteria",
            "calibration_boot_outcome": "success",
            "calibration_exec_hash": digest,
            "calibration_matched_image": matched_image,
            "boot_slot": "exec",
            "signals": {
                "expectations_met": True,
                "vtor_final": "0x0000C000",
                "vtor_aligned": True,
                "pc": "0x0000C100",
                "image_hash_actual": digest,
                "matched_image": matched_image,
            },
        }

    def test_discovery_records_allowed_candidate_name(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._profile(Path(td))
            digest = _image_digest_for_evidence(profile, ROOT, "staging")
            evidence = _trace_less_content_evidence(
                profile, self._data(digest, "staging"), ROOT
            )
            self.assertEqual(evidence["kind"], "exact_allowed_image_hash")
            self.assertEqual(evidence["target_image"], "staging")

    def test_discovery_does_not_credit_unchanged_allowed_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._profile(Path(td))
            digest = _image_digest_for_evidence(profile, ROOT, "exec")
            self.assertIsNone(
                _trace_less_content_evidence(
                    profile, self._data(digest, "exec"), ROOT
                )
            )


class CalibrationRuntimeBoundaryTests(unittest.TestCase):
    def test_tracking_start_discards_writes_before_update(self) -> None:
        class Data:
            TrackingStartAddress = 0x10000100
            TotalWordWrites = 7
            trace_cleared = False
            invalidated = False

            def WriteTraceClear(self):
                self.trace_cleared = True

            def InvalidateShadow(self):
                self.invalidated = True

        class Cpu:
            removed = False

            def RemoveHook(self, _address, _callback):
                self.removed = True

        data = Data()
        cpu = Cpu()
        namespace = {
            "backend": {"data": data},
            "_python_tracking_gate": {
                "address": 0x10000100,
                "cpu": cpu,
                "installed": True,
                "started": False,
            },
            "log": lambda _message: None,
        }
        exec(_runtime_function("_python_tracking_gate_hook"), namespace)
        namespace["_python_tracking_gate_hook"](cpu, 0x100000FE)
        self.assertEqual(data.TotalWordWrites, 7)
        namespace["_python_tracking_gate_hook"](cpu, 0x10000100)
        self.assertEqual(data.TotalWordWrites, 0)
        self.assertTrue(data.trace_cleared)
        self.assertTrue(data.invalidated)

    def test_success_stop_keeps_update_writes_and_excludes_post_reboot_writes(self) -> None:
        state = {"writes": 0, "run_calls": 0, "instructions": 0}

        class Monitor:
            def Parse(self, _command):
                state["run_calls"] += 1
                state["instructions"] += 10
                if state["run_calls"] == 1:
                    state["writes"] += 3  # final update operation included
                else:
                    state["writes"] += 5  # unrelated reboot persistence

        class Bus:
            @staticmethod
            def ReadDoubleWord(_address):
                return 0

        class Cpu:
            IsHalted = False

            @property
            def ExecutedInstructions(self):
                return state["instructions"]

            @staticmethod
            def GetRegisterUnsafe(_index):
                return 0

        calibration_state = {"address_hit": False, "triggered": False}

        def success_observation(_cpu):
            calibration_state["triggered"] = True
            return {"boot_outcome": "success", "signals": {}}

        namespace = {
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.02",
            "success_pc_slot": None,
            "slot_ranges": {},
            "monitor": Monitor(),
            "calibration_mode": True,
            "_calibration_stop_state": calibration_state,
            "calibration_stop_address": 0,
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "as_int": int,
            "capture_sticky_pc": lambda _pc: None,
            "bus": Bus(),
            "sticky_vtor": {"captured": False, "value": 0, "slot": None},
            "sticky_pc": {"captured": False, "value": 0, "slot": None},
            "_calibration_success_stop_observation": success_observation,
            "get_total_writes": lambda: state["writes"],
            "get_total_erases": lambda: 0,
            "fmt_u32": lambda value: "0x{:08X}".format(int(value)),
            "log": lambda _message: None,
            "capture_console_state": lambda include_recent=False: {
                "attached_names": [],
                "attached_count": 0,
                "last_line": None,
                "last_lines": [],
                "recent_logs": [],
            },
            "progress_stall_timeout_s": 0,
            "max_step_limit": 1,
            "_recovery_zero_vector_guard": False,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
        }
        exec(_runtime_function("run_until_done"), namespace)
        status = namespace["run_until_done"](
            Cpu(), time_slice="0.02", max_iters=5
        )
        self.assertEqual(status["reason"], "calibration_stop_success_criteria")
        self.assertEqual(status["writes"], 3)
        self.assertEqual(status["executed_instructions"], 10)
        self.assertEqual(state["run_calls"], 1)

    def test_instruction_limit_stops_runtime_loop_across_counter_reset(self) -> None:
        state = {"run_calls": 0, "instructions": 0}

        class Monitor:
            def Parse(self, _command):
                state["run_calls"] += 1
                if state["run_calls"] == 1:
                    state["instructions"] = 300
                else:
                    state["instructions"] = 100

        class Bus:
            @staticmethod
            def ReadDoubleWord(_address):
                return 0

        class Cpu:
            IsHalted = False

            @property
            def ExecutedInstructions(self):
                return state["instructions"]

            @staticmethod
            def GetRegisterUnsafe(_index):
                return 0

        namespace = {
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.02",
            "success_pc_slot": None,
            "slot_ranges": {},
            "monitor": Monitor(),
            "calibration_mode": False,
            "_calibration_stop_state": {"address_hit": False},
            "calibration_stop_address": 0,
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "as_int": int,
            "capture_sticky_pc": lambda _pc: None,
            "bus": Bus(),
            "sticky_vtor": {"captured": False, "value": 0, "slot": None},
            "sticky_pc": {"captured": False, "value": 0, "slot": None},
            "_calibration_success_stop_observation": lambda _cpu: None,
            "get_total_writes": lambda: 0,
            "get_total_erases": lambda: 0,
            "fmt_u32": lambda value: "0x{:08X}".format(int(value)),
            "log": lambda _message: None,
            "capture_console_state": lambda include_recent=False: {
                "attached_names": [],
                "attached_count": 0,
                "last_line": None,
                "last_lines": [],
                "recent_logs": [],
            },
            "progress_stall_timeout_s": 0,
            "max_step_limit": 350,
            "_recovery_zero_vector_guard": False,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
        }
        exec(_runtime_function("run_until_done"), namespace)

        status = namespace["run_until_done"](
            Cpu(), time_slice="0.02", max_iters=5
        )

        self.assertEqual(status["reason"], "instruction_limit(400)")
        self.assertEqual(status["iters"], 2)
        self.assertEqual(status["executed_instructions"], 400)
        self.assertEqual(status["instruction_limit"], 350)

    def test_block_counter_survives_reset_to_same_public_count(self) -> None:
        state = {"run_calls": 0, "instructions": 0, "block_hook": None}

        class Monitor:
            def Parse(self, _command):
                state["run_calls"] += 1
                state["instructions"] = 300
                state["block_hook"](0x1000, 150)

        class Bus:
            @staticmethod
            def ReadDoubleWord(_address):
                return 0

        class Cpu:
            IsHalted = False

            @property
            def ExecutedInstructions(self):
                return state["instructions"]

            @staticmethod
            def GetRegisterUnsafe(_index):
                return 0

            @staticmethod
            def SetHookAtBlockEnd(callback):
                state["block_hook"] = callback

        namespace = {
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.02",
            "success_pc_slot": None,
            "slot_ranges": {},
            "monitor": Monitor(),
            "calibration_mode": False,
            "_calibration_stop_state": {"address_hit": False},
            "calibration_stop_address": 0,
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "as_int": int,
            "capture_sticky_pc": lambda _pc: None,
            "bus": Bus(),
            "sticky_vtor": {"captured": False, "value": 0, "slot": None},
            "sticky_pc": {"captured": False, "value": 0, "slot": None},
            "_calibration_success_stop_observation": lambda _cpu: None,
            "get_total_writes": lambda: 0,
            "get_total_erases": lambda: 0,
            "fmt_u32": lambda value: "0x{:08X}".format(int(value)),
            "log": lambda _message: None,
            "capture_console_state": lambda include_recent=False: {
                "attached_names": [],
                "attached_count": 0,
                "last_line": None,
                "last_lines": [],
                "recent_logs": [],
            },
            "progress_stall_timeout_s": 0,
            "max_step_limit": 350,
            "_recovery_zero_vector_guard": False,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
        }
        exec(_runtime_function("run_until_done"), namespace)

        status = namespace["run_until_done"](
            Cpu(), time_slice="0.02", max_iters=5
        )

        self.assertEqual(status["reason"], "instruction_limit(450)")
        self.assertEqual(status["iters"], 3)
        self.assertEqual(status["executed_instructions"], 450)
        self.assertIsNone(state["block_hook"])


if __name__ == "__main__":
    unittest.main()
