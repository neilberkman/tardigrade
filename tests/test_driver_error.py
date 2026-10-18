#!/usr/bin/env python3
"""Registration and planner coverage for the driver_error fault type."""

from __future__ import annotations

import ast
import sys
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from fault_types import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from profile_loader import IMPLEMENTED_FAULT_TYPES, KNOWN_FAULT_TYPES, load_profile  # noqa: E402


_BASE_PROFILE = textwrap.dedent("""\
    schema_version: 1
    name: driver_error_test
    description: driver_error planner test
    platform: platforms/cortex_m4_flash_fast.repl
    bootloader:
      elf: examples/vulnerable_ota/firmware.elf
      entry: 0x00000000
    memory:
      sram: { start: 0x20000000, end: 0x20020000 }
      write_granularity: 4
      slots:
        exec: { base: 0x00000000, size: 0x40000 }
        staging: { base: 0x00040000, size: 0x40000 }
    images:
      staging: examples/vulnerable_ota/firmware.bin
    success_criteria:
      vtor_in_slot: exec
    expect:
      should_find_issues: true
    fault_sweep:
      mode: runtime
      max_writes: 8
      fault_types: [driver_error]
""")


class DriverErrorFaultTypeTest(unittest.TestCase):
    @staticmethod
    def _runtime_functions(*names):
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        wanted = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        namespace = {}
        for node in wanted:
            exec(
                compile(ast.Module(body=[node], type_ignores=[]), "runtime", "exec"),
                namespace,
            )
        return namespace

    def test_driver_error_registered_everywhere(self) -> None:
        self.assertIn("driver_error", KNOWN_FAULT_TYPES)
        self.assertIn("driver_error", IMPLEMENTED_FAULT_TYPES)
        self.assertIn("driver_error", EXECUTE_ONLY_FAULT_TYPES)
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["driver_error"], "g")
        self.assertEqual(_fault_type_label("g"), "driver_error")

    def test_profile_parses_driver_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        self.assertEqual(profile.fault_sweep.fault_types, ["driver_error"])

    def test_fault_plan_emits_driver_error_points(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=4),
            quick=False,
        )
        self.assertEqual(plan.fault_points, [0, 1, 2, 3])
        self.assertEqual(plan.fault_types_list, ["g", "g", "g", "g"])

    def test_existing_mcuboot_revert_profiles_include_driver_error(self) -> None:
        profile_paths = [
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml",
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml",
            ROOT / "profiles" / "mcuboot_head_move_stm32f4_revert_driver_error.yaml",
        ]
        for profile_path in profile_paths:
            with self.subTest(profile=profile_path.name):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    profile = load_profile(profile_path)
                self.assertIn("driver_error", profile.fault_sweep.fault_types)

    def test_nrf52_nvmc_declares_driver_error_return_hook_requirement(self) -> None:
        source = (ROOT / "peripherals" / "NRF52NVMC.cs").read_text(encoding="utf-8")
        self.assertIn("public bool DriverErrorRequiresReturnHook => true;", source)
        self.assertIn("DriverErrorFired = true;", source)
        self.assertIn("FaultTracker.WriteU32(snap, off, oldWord);", source)

    def test_stm32f4_fast_flash_declares_driver_error_return_hook_requirement(self) -> None:
        source = (ROOT / "peripherals" / "STM32F4FastFlash.cs").read_text(
            encoding="utf-8"
        )
        self.assertIn("public bool DriverErrorRequiresReturnHook => true;", source)
        self.assertGreaterEqual(source.count("DriverErrorFired = true;"), 3)
        self.assertIn("FaultTracker.WriteU32(snap, off, oldWord);", source)
        runtime_source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("or 'STM32F4FastFlash' in str(type(backend_obj))", runtime_source)
        ns = self._runtime_functions("resolve_backend")

        class _FakeSTM32F4FastFlash:
            PerWriteAccurate = True
            WriteTraceWidthExplicit = True
            DriverErrorRequiresReturnHook = True

        fake_backend = _FakeSTM32F4FastFlash()
        ns.update(
            {
                "get_optional_var": lambda name, default="": (
                    "faultFlash" if name == "flash_backend" else default
                ),
                "monitor": type(
                    "_Monitor",
                    (),
                    {
                        "Machine": {"sysbus.faultFlash": fake_backend},
                        "GetVariable": staticmethod(
                            lambda name: "faultFlash" if name == "flash_backend" else ""
                        ),
                    },
                )(),
                "log": lambda _msg: None,
            }
        )
        resolved = ns["resolve_backend"]()
        self.assertEqual(resolved["kind"], "fast")
        self.assertTrue(resolved["driver_error_requires_return_hook"])

    def test_runtime_reuses_rc_injection_return_hook_for_nrf52_driver_error(self) -> None:
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("if _fault_uses_rc_injection_return_hook(fault_type):", source)
        self.assertIn(
            "reset_rc_injection_state(enabled=_fault_uses_rc_injection_return_hook(fault_type))",
            source,
        )
        ns = self._runtime_functions(
            "_fault_uses_rc_injection_return_hook",
            "_apply_rc_injection_result_contract",
        )
        telemetry = {
            "configured_symbols": ["flash_area_write"],
            "resolved_symbols": {"flash_area_write": [0x4638]},
            "return_value": 0xFFFFFFFB,
            "return_register": 0,
            "entered_calls": 1,
            "applied": True,
            "applied_symbol": "flash_area_write",
            "applied_return_address": 0x0F88,
        }
        ns.update(
            {
                "_base_fault_type_code": lambda value: str(value).split(":", 1)[0],
                "rc_injection_telemetry": lambda: telemetry,
                "_rc_injection_state": {"require_applied": True},
                "fmt_u32": lambda value: "0x{:08X}".format(value & 0xFFFFFFFF),
                "backend": {"driver_error_requires_return_hook": True},
            }
        )
        self.assertTrue(ns["_fault_uses_rc_injection_return_hook"]("g"))
        self.assertTrue(ns["_fault_uses_rc_injection_return_hook"]("x"))
        self.assertFalse(ns["_fault_uses_rc_injection_return_hook"]("s"))

        result = {"fault_type": "g"}
        signals = {}
        ns["_apply_rc_injection_result_contract"](result, signals, "g", True)
        self.assertEqual(result["rc_injection"]["applied_symbol"], "flash_area_write")
        self.assertEqual(signals["rc_injection_value"], "0xFFFFFFFB")
        self.assertTrue(signals["rc_injection_applied"])

        ns["backend"] = {"driver_error_requires_return_hook": False}
        self.assertFalse(ns["_fault_uses_rc_injection_return_hook"]("g"))
        hw_result = {"fault_type": "g"}
        hw_signals = {}
        ns["_apply_rc_injection_result_contract"](hw_result, hw_signals, "g", True)
        self.assertNotIn("rc_injection", hw_result)
        self.assertNotIn("rc_injection", hw_signals)


if __name__ == "__main__":
    unittest.main()
