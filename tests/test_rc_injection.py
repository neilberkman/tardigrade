#!/usr/bin/env python3
"""Registration and runtime guardrails for the rc_injection fault type."""

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
from audit_report import summarize_runtime_sweep  # noqa: E402
from render_results_html import render_audit_card  # noqa: E402
from fault_types import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from profile_loader import (  # noqa: E402
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    ProfileError,
    load_profile,
)


_BASE_PROFILE = textwrap.dedent("""\
    schema_version: 1
    name: rc_injection_test
    description: rc_injection planner test
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
      fault_types: [rc_injection]
""")


class RcInjectionFaultTypeTest(unittest.TestCase):
    def test_rc_injection_registered_everywhere(self) -> None:
        self.assertIn("rc_injection", KNOWN_FAULT_TYPES)
        self.assertIn("rc_injection", IMPLEMENTED_FAULT_TYPES)
        self.assertIn("rc_injection", EXECUTE_ONLY_FAULT_TYPES)
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["rc_injection"], "x")
        self.assertEqual(_fault_type_label("x"), "rc_injection")

    def test_profile_parses_rc_injection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        self.assertEqual(profile.fault_sweep.fault_types, ["rc_injection"])

    def test_config_fields_and_robot_wiring(self) -> None:
        raw = _BASE_PROFILE.replace(
            "  fault_types: [rc_injection]\n",
            "  fault_types: [rc_injection]\n"
            "  rc_injection_config:\n"
            "    symbols: [storage_write, security_state_write]\n"
            "    return_value: -42\n"
            "    return_register: 3\n"
            "    require_applied: false\n",
        )
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(raw, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        cfg = profile.fault_sweep.rc_injection_config
        self.assertEqual(cfg.symbols, ["storage_write", "security_state_write"])
        self.assertEqual(cfg.return_value, 0xFFFFFFD6)
        self.assertEqual(cfg.return_register, 3)
        self.assertFalse(cfg.require_applied)
        vars_by_key = dict(item.split(":", 1) for item in profile.robot_vars(ROOT))
        self.assertEqual(vars_by_key["RC_INJECTION_SYMBOLS"], "storage_write,security_state_write")
        self.assertEqual(vars_by_key["RC_INJECTION_RETURN_VALUE"], str(0xFFFFFFD6))
        self.assertEqual(vars_by_key["RC_INJECTION_RETURN_REGISTER"], "3")
        self.assertEqual(vars_by_key["RC_INJECTION_REQUIRE_APPLIED"], "false")

    def test_config_defaults_and_rejections(self) -> None:
        cases = [
            ("symbols: []", "symbols"),
            ("symbols: [dup, dup]", "unique"),
            ("return_value: 4294967296", "return_value"),
            ("return_value: -2147483649", "return_value"),
            ("return_register: 16", "return_register"),
            ("require_applied: 'yes'", "require_applied"),
            ("unknown: true", "unknown field"),
        ]
        with tempfile.TemporaryDirectory() as td:
            for body, expected in cases:
                with self.subTest(body=body):
                    profile_path = Path(td) / "profile.yaml"
                    profile_path.write_text(
                        _BASE_PROFILE.replace(
                            "  fault_types: [rc_injection]\n",
                            "  fault_types: [rc_injection]\n"
                            "  rc_injection_config:\n"
                            "    " + body + "\n",
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ProfileError) as raised:
                        load_profile(profile_path)
                    self.assertIn(expected, str(raised.exception))

    def test_existing_defaults_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(_BASE_PROFILE, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                profile = load_profile(profile_path)
        self.assertEqual(
            profile.fault_sweep.rc_injection_config.to_dict(),
            {
                "symbols": ["flash_area_write"],
                "return_value": 0xFFFFFFFB,
                "return_register": 0,
                "require_applied": True,
            },
        )

    def test_fault_plan_emits_rc_injection_points(self) -> None:
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
        self.assertEqual(plan.fault_types_list, ["x", "x", "x", "x"])

    def test_existing_mcuboot_revert_profiles_include_rc_injection(self) -> None:
        profile_paths = [
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml",
            ROOT / "profiles" / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml",
        ]
        for profile_path in profile_paths:
            with self.subTest(profile=profile_path.name):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    profile = load_profile(profile_path)
                self.assertIn("rc_injection", profile.fault_sweep.fault_types)

    def test_runtime_uses_flash_area_write_hooks(self) -> None:
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("_rc_injection_symbols_raw = get_optional_var('rc_injection_symbols', 'flash_area_write')", source)
        self.assertIn("cpu.AddHook(return_addr, _rc_injection_return_hook)", source)
        self.assertIn("active_frames", source)
        self.assertIn("rc_injection_telemetry", source)

    @staticmethod
    def _runtime_functions(*names):
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        wanted = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        namespace = {}
        for node in wanted:
            exec(compile(ast.Module(body=[node], type_ignores=[]), "runtime", "exec"), namespace)
        return namespace

    def test_runtime_hook_writes_configured_register_and_value(self) -> None:
        class RegisterValue:
            @staticmethod
            def Create(value, bits):
                return (value, bits)

        class Cpu:
            def __init__(self):
                self.hooks = {}
                self.writes = []

            def GetRegister(self, index):
                return type("Reg", (), {"RawValue": 0x500 | 1})()

            def AddHook(self, addr, callback):
                self.hooks[addr] = callback

            def SetRegister(self, index, value):
                self.writes.append((index, value))

        ns = self._runtime_functions("_rc_injection_entry_hook", "_rc_injection_return_hook")
        state = {
            "enabled": True, "entry_symbol_by_addr": {0x100: "storage_write"},
            "installed_return_hooks": set(), "active_frames": [], "entered_calls": 0,
            "injected": False, "return_value": 0xFFFFFFD6, "return_register": 3,
            "injected_symbol": None, "injected_return_addr": None,
        }
        ns.update({"_rc_injection_state": state, "RegisterValue": RegisterValue,
                   "was_fault_injected": lambda: True, "log": lambda *args: None})
        cpu = Cpu()
        ns["_rc_injection_entry_hook"](cpu, 0x101)
        cpu.hooks[0x500](cpu, 0x501)
        self.assertEqual(cpu.writes, [(3, (0xFFFFFFD6, 32))])
        self.assertEqual(state["injected_symbol"], "storage_write")

    def test_nested_return_frames_match_the_correct_wrapper(self) -> None:
        class Cpu:
            def __init__(self):
                self.hooks = {}
                self.writes = []

            def GetRegister(self, index):
                lr = 0x500 if not self.hooks else 0x300
                return type("Reg", (), {"RawValue": lr | 1})()

            def AddHook(self, addr, callback):
                self.hooks[addr] = callback

            def SetRegister(self, index, value):
                self.writes.append((index, value))

        ns = self._runtime_functions("_rc_injection_entry_hook", "_rc_injection_return_hook")
        state = {
            "enabled": True, "entry_symbol_by_addr": {0x100: "outer", 0x200: "inner"},
            "installed_return_hooks": set(), "active_frames": [], "entered_calls": 0,
            "injected": False, "return_value": 7, "return_register": 0,
            "injected_symbol": None, "injected_return_addr": None,
        }
        inject = [False, True]
        ns.update({"_rc_injection_state": state, "RegisterValue": type("RV", (), {"Create": staticmethod(lambda v, b: v)}),
                   "was_fault_injected": lambda: inject.pop(0), "log": lambda *args: None})
        cpu = Cpu()
        ns["_rc_injection_entry_hook"](cpu, 0x101)
        ns["_rc_injection_entry_hook"](cpu, 0x201)
        ns["_rc_injection_return_hook"](cpu, 0x301)
        self.assertEqual([frame["symbol"] for frame in state["active_frames"]], ["outer"])
        ns["_rc_injection_return_hook"](cpu, 0x501)
        self.assertEqual(state["injected_symbol"], "outer")

    def test_runtime_rejects_one_missing_explicit_symbol(self) -> None:
        ns = self._runtime_functions("_collect_rc_injection_symbol_addresses")
        addresses, missing = ns["_collect_rc_injection_symbol_addresses"](
            ["present", "missing"], {"present": [0x100]}, lambda name: []
        )
        self.assertEqual(addresses, [("present", 0x100)])
        self.assertEqual(missing, ["missing"])

    def test_runtime_contract_fails_closed_when_not_applied(self) -> None:
        ns = self._runtime_functions("_apply_rc_injection_result_contract")
        telemetry = {
            "configured_symbols": ["storage_write"], "resolved_symbols": {"storage_write": [0x100]},
            "return_value": 5, "return_register": 2, "entered_calls": 0,
            "applied": False, "applied_symbol": None, "applied_return_address": None,
        }
        ns.update({"rc_injection_telemetry": lambda: telemetry, "_base_fault_type_code": lambda value: value,
                   "_rc_injection_state": {"require_applied": True}, "fmt_u32": lambda value: hex(value)})
        result = {"fault_type": "x"}
        ns["_apply_rc_injection_result_contract"](result, {}, "x", True)
        self.assertTrue(result["infrastructure_error"])
        self.assertEqual(result["boot_outcome"], "infra_error")

    def test_runtime_contract_emits_execute_telemetry(self) -> None:
        ns = self._runtime_functions("_apply_rc_injection_result_contract")
        telemetry = {
            "configured_symbols": ["storage_write"], "resolved_symbols": {"storage_write": [0x100]},
            "return_value": 0xFFFFFFFB, "return_register": 0, "entered_calls": 1,
            "applied": True, "applied_symbol": "storage_write", "applied_return_address": 0x120,
        }
        ns.update({"rc_injection_telemetry": lambda: telemetry, "_base_fault_type_code": lambda value: value,
                   "_rc_injection_state": {"require_applied": True}, "fmt_u32": lambda value: hex(value)})
        signals = {}
        result = {}
        ns["_apply_rc_injection_result_contract"](result, signals, "x", True)
        self.assertEqual(result["rc_injection"]["applied_symbol"], "storage_write")
        self.assertEqual(signals["rc_injection"]["return_value"], 0xFFFFFFFB)

    def test_runtime_contract_is_scoped_to_rc_faults(self) -> None:
        ns = self._runtime_functions("_apply_rc_injection_result_contract")
        ns.update({"_base_fault_type_code": lambda value: value,
                   "rc_injection_telemetry": lambda: (_ for _ in ()).throw(AssertionError("called"))})
        control = {"fault_type": "control"}
        ns["_apply_rc_injection_result_contract"](control, {}, "control", False)
        self.assertNotIn("rc_injection", control)
        summary = summarize_runtime_sweep([control], profile=None)
        self.assertNotIn("rc_injection", summary)

    def test_report_and_html_expose_configured_and_applied_symbol(self) -> None:
        result = {
            "fault_type": "x",
            "fault_injected": True,
            "fault_class": "recoverable",
            "boot_outcome": "success",
            "rc_injection": {
                "configured_symbols": ["storage_write"],
                "resolved_symbols": {"storage_write": [0x100]},
                "return_value": 0xFFFFFFFB,
                "return_register": 0,
                "entered_calls": 1,
                "applied": True,
                "applied_symbol": "storage_write",
                "applied_return_address": 0x120,
            },
        }
        summary = summarize_runtime_sweep([result], profile=None)
        self.assertEqual(summary["rc_injection"]["configured_symbols"], ["storage_write"])
        card, _ = render_audit_card(
            Path("rc.json"),
            {
                "profile": "rc",
                "rc_injection_config": {
                    "symbols": ["storage_write"],
                    "return_value": 0xFFFFFFFB,
                    "return_register": 0,
                },
                "summary": {"runtime_sweep": {}},
                "runtime_sweep_results": [result],
            },
        )
        self.assertIn("storage_write", card)
        self.assertIn("storage_write@0x00000120", card)


if __name__ == "__main__":
    unittest.main()
