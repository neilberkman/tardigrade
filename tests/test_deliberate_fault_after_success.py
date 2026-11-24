#!/usr/bin/env python3
"""Regression tests for fault-vs-success precedence and timing comparison."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"
FIXTURE = ROOT / "examples" / "deliberate_crash_report"
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


ALLOWED_HASH = "aa" * 32


class _Event:
    def __init__(self) -> None:
        self._handlers = []

    def __iadd__(self, handler):
        self._handlers.append(handler)
        return self

    def __isub__(self, handler):
        if handler in self._handlers:
            self._handlers.remove(handler)
        return self

    def fire(self, *args) -> None:
        for handler in list(self._handlers):
            handler(*args)


class _VirtualTime:
    def __init__(self, seconds: float = 0.0) -> None:
        self.seconds = float(seconds)

    @property
    def TimeElapsed(self):
        return SimpleNamespace(
            TotalMicroseconds=int(round(self.seconds * 1_000_000)),
            TotalSeconds=self.seconds,
        )


def _load_runtime_functions(*names: str, extra_namespace: dict | None = None) -> dict:
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    wanted = set(names)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    found = {node.name for node in selected}
    missing = wanted - found
    assert not missing, f"missing runtime functions: {sorted(missing)}"
    namespace = dict(extra_namespace or {})
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(RUNTIME), "exec"),
        namespace,
        namespace,
    )
    return namespace


def _build_harness(
    *,
    step_fn,
    memory_specs: list[dict] | None = None,
    config_specs: list[dict] | None = None,
    bootloader_integrity: bool = False,
    mem_values: dict[int, int] | None = None,
    terminal_after_reset: bool = False,
    allow_fault_after_success: bool = False,
    supports_interrupt_hook: bool = True,
    initial_vtor: int = 0x20000100,
    success_vtor_slot: str = "",
    success_pc_slot: str = "exec",
    success_image_hash: bool = True,
    expected_exec_sha256: str = ALLOWED_HASH,
    image_exec_sha256: str = ALLOWED_HASH,
    image_staging_sha256: str = "",
    slot_hash_fn=None,
    success_marker_addr: int = 0,
    success_marker_value: int = 0,
    success_otadata_expect: dict | None = None,
    boot_cycle_hook: str = "",
    uncorrectable_target=None,
):
    sticky_vtor = {"captured": False, "value": 0, "slot": None}
    sticky_pc = {"captured": False, "value": 0, "slot": None}
    mem = dict(mem_values or {})
    state = {
        "run_calls": 0,
        "instructions": 0,
        "pc": 0x10100050,
        "vtor": initial_vtor,
        "ipsr": 0,
        "cfsr": 0,
        "hfsr": 0,
        "pending_irq": 528,
        "writes": 0,
        "hooks": {},
        "irq_hooks": [],
        "virtual_time": _VirtualTime(0.0),
    }

    class FakeNvic:
        @staticmethod
        def FindPendingInterrupt():
            return state["pending_irq"]

    class FakeCpu:
        IsHalted = False

        @property
        def ExecutedInstructions(self):
            return state["instructions"]

        @property
        def PC(self):
            return state["pc"]

        @property
        def XProgramStatusRegister(self):
            return state["ipsr"]

        @staticmethod
        def GetRegisterUnsafe(_index):
            return state["pc"]

        @staticmethod
        def AddHook(address, callback):
            state["hooks"][address] = callback

        @staticmethod
        def RemoveHook(address, callback):
            if state["hooks"].get(address) is callback:
                del state["hooks"][address]

    if supports_interrupt_hook:
        def _add_irq_hook(self, callback):
            state["irq_hooks"].append(callback)

        FakeCpu.AddHookAtInterruptBegin = _add_irq_hook  # type: ignore[attr-defined]

    cpu = FakeCpu()
    nvic = FakeNvic()

    class FakeMachine:
        def __init__(self) -> None:
            self.MachineReset = _Event()
            self.PeripheralReset = _Event()

        def __getitem__(self, name: str):
            if name in ("sysbus.cpu", "cpu"):
                return cpu
            if name in ("sysbus.nvic", "nvic"):
                return nvic
            raise KeyError(name)

        @property
        def ElapsedVirtualTime(self):
            return state["virtual_time"]

    machine = FakeMachine()

    class FakeBus:
        @staticmethod
        def ReadDoubleWord(address):
            if address == 0xE000ED08:
                return state["vtor"]
            if address == 0xE000ED28:
                return state["cfsr"]
            if address == 0xE000ED2C:
                return state["hfsr"]
            if address == 0x00000004:
                return 0x00000021
            if address == 0x10100000:
                return 0x20002000
            if address == 0x10100004:
                return 0x10100021
            if address == 0x1010000C:
                return 0x10100081
            if address == 0x10100014:
                return 0x10100091
            return mem.get(int(address), 0)

        @staticmethod
        def ReadWord(_address):
            return 0

    def fire_fault(exc_num: int, *, set_cfsr: int = 0, set_hfsr: int = 0) -> None:
        state["pending_irq"] = exc_num
        for cb in list(state["irq_hooks"]):
            cb(5)
        state["ipsr"] = exc_num
        if set_cfsr:
            state["cfsr"] |= set_cfsr
        if set_hfsr:
            state["hfsr"] |= set_hfsr

    class FakeMonitor:
        Machine = machine

        @staticmethod
        def Parse(_command):
            state["run_calls"] += 1
            step_fn(state, machine, cpu, mem, fire_fault)

    def capture_sticky_pc(value):
        pc = int(value) & ~1
        if 0x10100000 <= pc < 0x10101000:
            sticky_pc.update(captured=True, value=pc, slot="exec")

    ns = _load_runtime_functions(
        "evaluate_structured_success_checks",
        "collect_recovery_execution_evidence",
        "recovery_failure_outcome",
        "evaluate_boot_outcome",
        "_calibration_success_stop_observation",
        "_reset_gated_success_stop_observation",
        "_dispatch_interrupt_begin",
        "_ensure_interrupt_begin_hook",
        "run_until_done",
        extra_namespace={
            "_interrupt_begin_hook_cpus": [],
            "_active_interrupt_begin_observer": [None],
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.02",
            "success_vtor_slot": success_vtor_slot,
            "success_vector_offset": 0,
            "success_pc_slot": success_pc_slot,
            "success_image_hash": success_image_hash,
            "success_image_hash_slot": "exec",
            "success_terminal_after_reset": terminal_after_reset,
            "success_allow_fault_after_success": allow_fault_after_success,
            "boot_cycle_hook": boot_cycle_hook,
            "update_sequence_enabled": False,
            "volatile_regions": [{"name": "sram", "base": 0x20000000, "size": 0x2000}],
            "bootloader_entry": 0x00000000,
            "slot_ranges": {"exec": (0x10100000, 0x10101000)},
            "allowed_image_hashes": [],
            "expected_exec_sha256": expected_exec_sha256,
            "expected_image_name": "exec",
            "image_exec_sha256": image_exec_sha256,
            "image_staging_sha256": image_staging_sha256,
            "success_marker_addr": success_marker_addr,
            "success_marker_value": success_marker_value,
            "security_anti_rollback": False,
            "success_otadata_expect": dict(success_otadata_expect or {}),
            "success_otadata_expect_scope": "always",
            "max_reset_vector_offset": None,
            "success_checks_config": {
                "memory_checks": list(memory_specs or []),
                "config_checks": list(config_specs or []),
                "bootloader_integrity": bool(bootloader_integrity),
                "bootloader_region": {"base": 0x00000000, "size": 0x1000},
            },
            "success_checks_parse_error": None,
            "sram_start": 0x20000000,
            "sram_end": 0x20002000,
            "compute_slot_hash": slot_hash_fn or (lambda _slot: expected_exec_sha256),
            "_match_configured_image_hash": (
                lambda digest: (
                    "exec"
                    if image_exec_sha256 and digest == image_exec_sha256
                    else (
                        "staging"
                        if image_staging_sha256 and digest == image_staging_sha256
                        else ("expected" if expected_exec_sha256 and digest == expected_exec_sha256 else None)
                    )
                )
            ),
            "collect_otadata_signals": lambda: {},
            "normalize_signal_token": lambda value: str(value or "").strip().lower(),
            "capture_boot_registers": lambda: None,
            "boot_outcome_after_stop": lambda outcome, reason: (
                "timeout"
                if reason == "budget"
                or str(reason).startswith(("wall_timeout", "instruction_limit"))
                else outcome
            ),
            "monitor": FakeMonitor(),
            "bus": FakeBus(),
            "sticky_vtor": sticky_vtor,
            "sticky_pc": sticky_pc,
            "capture_sticky_pc": capture_sticky_pc,
            "calibration_mode": False,
            "calibration_stop_on_success": False,
            "_calibration_stop_state": {"address_hit": False},
            "calibration_stop_address": 0,
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "get_total_writes": lambda: state["writes"],
            "get_total_erases": lambda: 0,
            "as_int": int,
            "fmt_u32": lambda value: "0x{:08X}".format(int(value) & 0xFFFFFFFF),
            "log": lambda _msg: None,
            "capture_console_state": lambda include_recent=False: {
                "attached_names": [],
                "attached_count": 0,
                "last_line": None,
                "last_lines": [],
                "recent_logs": [],
            },
            "progress_stall_timeout_s": 0.0,
            "max_step_limit": 10_000_000,
            "max_step_limit_resolution": {
                "configured": 10_000_000,
                "source": "profile",
                "performance_mips": 100.0,
            },
            "_recovery_zero_vector_guard": False,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
            "_mram_uncorrectable_target": lambda: uncorrectable_target,
        },
    )
    return ns, state, machine, cpu


CHECKS = [
    {"address": 0x20000200, "expected_value": 1, "op": "eq"},
    {"address": 0x20000204, "expected_value": 5, "op": "ge"},
]


def test_deliberate_fault_after_checks_in_single_slice_classifies_as_success() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        # Now deliberately take HardFault (IPSR=3) and spin in handler with CFSR=0.
        state["instructions"] = 1000
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        state["pc"] = 0x10100090
        state["writes"] = 4
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["reason"] == "pc_captured"
    ft = status["fault_timing"]
    assert ft["interrupt_hook_installed"] is True
    assert ft["checks_held_before_fault"] is True
    assert ft["checks_first_held"]["source"] == "pre_fault_entry"
    assert ft["fault_first_active"]["exception"] == 3
    assert ft["fault_first_active"]["checks_held_at_entry"] is True

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"
    rec = signals["recovery_execution"]
    assert rec["ipsr"] == 3
    assert rec["fault_exception_active"] is True
    assert rec["checks_held_before_fault"] is True
    assert rec["allow_fault_after_success"] is True
    assert rec["post_success_fault_suppressed"] is True
    assert rec["hardfault_observed"] is False


def test_fault_after_checks_without_opt_in_classifies_as_hard_fault() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 1000
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        allow_fault_after_success=False,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["fault_timing"]["checks_held_before_fault"] is True

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"
    assert slot == "exec"
    rec = signals["recovery_execution"]
    assert rec["fault_exception_active"] is True
    assert rec["checks_held_before_fault"] is True
    assert rec["allow_fault_after_success"] is False
    assert rec["post_success_fault_suppressed"] is False
    assert rec["hardfault_observed"] is True


def test_vector_entry_spin_after_checks_respects_opt_in() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 1000
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        # HardFault vector at 0x1010000C is 0x10100081 -> spin at 0x10100080.
        state["pc"] = 0x10100080
        state["virtual_time"].seconds = 0.020

    ns_opt, state_opt, _m, cpu_opt = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        initial_vtor=0x10100000,
        allow_fault_after_success=True,
    )
    status_opt = ns_opt["run_until_done"](cpu_opt, time_slice="0.02", max_iters=5)
    outcome_opt, slot_opt, signals_opt = ns_opt["evaluate_boot_outcome"](
        state_opt["vtor"], state_opt["pc"], fault_injected=False, p2_status=status_opt
    )
    assert outcome_opt == "success"
    assert slot_opt == "exec"
    assert signals_opt["recovery_execution"]["hardfault_vector"] == "0x10100081"
    assert signals_opt["recovery_execution"]["hardfault_handler_active"] is False
    assert signals_opt["recovery_execution"]["hardfault_observed"] is False

    # Without opt-in, spinning at the vector entry instruction is hard_fault.
    ns_no, state_no, _m2, cpu_no = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        initial_vtor=0x10100000,
        allow_fault_after_success=False,
    )
    status_no = ns_no["run_until_done"](cpu_no, time_slice="0.02", max_iters=5)
    outcome_no, _slot_no, signals_no = ns_no["evaluate_boot_outcome"](
        state_no["vtor"], state_no["pc"], fault_injected=False, p2_status=status_no
    )
    assert outcome_no == "hard_fault"
    assert signals_no["recovery_execution"]["hardfault_handler_active"] is True
    assert signals_no["recovery_execution"]["hardfault_observed"] is True


def test_fault_before_checks_hold_remains_hard_fault() -> None:
    def step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100050
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.001
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["reason"] == "pc_captured"
    assert status["fault_timing"]["checks_held_before_fault"] is False
    assert status["fault_timing"]["checks_first_held"] is None

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"
    assert signals["recovery_execution"]["fault_exception_active"] is True
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_fault_handler_forging_checks_after_entry_remains_hard_fault() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100050
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.001
        fire_fault(3)
        # Inside HardFault_Handler (IPSR=3), write the check addresses and even
        # take a nested fault afterward.
        state["pc"] = 0x10100088
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 200
        state["virtual_time"].seconds = 0.002
        fire_fault(3)
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["fault_timing"]["checks_held_before_fault"] is False
    assert status["fault_timing"]["checks_first_held"] is None
    assert status["fault_timing"]["fault_first_active"]["instructions"] == 100

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"
    assert signals["memory_checks_ok"] is True
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_cross_slice_checks_then_fault_without_interrupt_hook_passes() -> None:
    def step(state, _machine, _cpu, mem, _fire_fault):
        if state["run_calls"] == 1:
            state["pc"] = 0x10100050
            state["vtor"] = 0x10100000
            state["instructions"] = 500
            state["virtual_time"].seconds = 0.02
            mem[0x20000200] = 1
            mem[0x20000204] = 5
        elif state["run_calls"] == 2:
            state["instructions"] = 1000
            state["virtual_time"].seconds = 0.04
            state["ipsr"] = 3
            state["pc"] = 0x10100090

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        supports_interrupt_hook=False,
        initial_vtor=0x10100000,
        success_vtor_slot="exec",
        success_pc_slot="",
        allow_fault_after_success=True,
    )
    # Settle 1 slice after VTOR capture so slice 1 observes checks with IPSR=0
    # and slice 2 observes IPSR=3.
    status = ns["run_until_done"](
        cpu, time_slice="0.02", max_iters=5, vtor_settle_iters=1
    )
    assert status["reason"] == "vtor_captured"
    ft = status["fault_timing"]
    assert ft["interrupt_hook_installed"] is False
    assert ft["checks_held_before_fault"] is True
    assert ft["checks_first_held"]["iter"] == 1
    assert ft["fault_first_active"]["iter"] == 2

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"
    assert signals["recovery_execution"]["hardfault_observed"] is False


def test_ambiguous_same_slice_without_interrupt_hook_fails_closed_as_hard_fault() -> None:
    def step(state, _machine, cpu, mem, _fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["ipsr"] = 3
        state["pc"] = 0x10100090
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.02

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        supports_interrupt_hook=False,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["fault_timing"]["checks_held_before_fault"] is False

    outcome, _slot, _signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"


def test_uncorrectable_mram_read_fault_after_handoff_remains_hard_fault() -> None:
    mram = SimpleNamespace(UncorrectableReadCount=0)

    def step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 200
        state["virtual_time"].seconds = 0.002
        # Recovery reads a marked uncorrectable MRAM word right before faulting.
        mram.UncorrectableReadCount = 1
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.02

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=[],
        uncorrectable_target=mram,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    ft = status["fault_timing"]
    assert ft["uncorrectable_read_triggered_fault"] is True
    assert ft["checks_held_before_fault"] is False

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=True, p2_status=status
    )
    assert outcome == "hard_fault"
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_handled_uncorrectable_read_then_checks_then_deliberate_fault_passes() -> None:
    mram = SimpleNamespace(UncorrectableReadCount=0)

    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        # 1. Early uncorrectable read fault caught and recovered (IPSR returns to 0).
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.001
        mram.UncorrectableReadCount = 1
        fire_fault(3)
        state["ipsr"] = 0
        # 2. Recovery finishes and satisfies checks.
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        # 3. Deliberate terminal fault (no new uncorrectable read).
        state["instructions"] = 900
        state["virtual_time"].seconds = 0.009
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        uncorrectable_target=mram,
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    ft = status["fault_timing"]
    assert ft["uncorrectable_read_triggered_fault"] is False
    assert ft["checks_held_before_fault"] is True

    outcome, slot, _signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=True, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"


def test_post_fault_check_corruption_revokes_suppression() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        fire_fault(3)
        # Fault handler wipes scheduler flag so checks no longer hold at stop.
        mem[0x20000200] = 0
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"
    rec = signals["recovery_execution"]
    assert rec["checks_broken_after_fault"] is True
    assert rec["checks_held_before_fault"] is False
    assert rec["hardfault_observed"] is True


def test_nonzero_cfsr_still_classifies_as_hard_fault_like_ca02138() -> None:
    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.005
        fire_fault(6, set_cfsr=0x00010000)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "hard_fault"
    assert signals["recovery_execution"]["cfsr"] == "0x00010000"
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_terminal_after_reset_clears_pre_reset_timing_and_accepts_post_reset_deliberate_fault() -> None:
    def step(state, machine, cpu, mem, fire_fault):
        if state["run_calls"] == 1:
            # Pre-reset checks and reset inside slice 1.
            mem[0x20000200] = 1
            mem[0x20000204] = 5
            state["instructions"] = 500
            state["virtual_time"].seconds = 0.010
            machine.MachineReset.fire(machine)
            mem[0x20000200] = 0
            mem[0x20000204] = 0
            state["instructions"] = 100
            state["virtual_time"].seconds = 0.020
        elif state["run_calls"] == 2:
            # Post-reset checks hold, then deliberate fault inside slice 2.
            hook = state["hooks"].get(0x10100020)
            if hook is not None:
                hook(cpu, 0x10100020)
            state["pc"] = 0x10100060
            mem[0x20000200] = 1
            mem[0x20000204] = 5
            state["instructions"] = 600
            state["virtual_time"].seconds = 0.030
            fire_fault(3)
            state["pc"] = 0x10100090
            state["virtual_time"].seconds = 0.040

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        terminal_after_reset=True,
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["reason"] == "success_terminal_after_reset"
    assert status["fault_timing"]["checks_held_before_fault"] is True

    outcome, slot, _signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"


def test_uncorrectable_read_after_checks_remains_hard_fault_even_with_opt_in() -> None:
    mram = SimpleNamespace(UncorrectableReadCount=0)

    def step(state, _machine, cpu, mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        mem[0x20000200] = 1
        mem[0x20000204] = 5
        state["instructions"] = 200
        state["virtual_time"].seconds = 0.005
        # Checks already hold, then an uncorrectable MRAM read faults and spins
        # on the HardFault vector entry instruction.
        mram.UncorrectableReadCount = 1
        state["instructions"] = 400
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        state["pc"] = 0x10100080
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        initial_vtor=0x10100000,
        uncorrectable_target=mram,
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["fault_timing"]["uncorrectable_read_triggered_fault"] is True
    assert status["fault_timing"]["checks_held_before_fault"] is False

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=True, p2_status=status
    )
    assert outcome == "hard_fault"
    assert signals["recovery_execution"]["post_success_fault_suppressed"] is False
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_followup_cycle_evaluates_memory_checks_and_rejects_early_fault() -> None:
    def step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100050
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.001
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=CHECKS,
        mem_values={0x20000200: 0, 0x20000204: 0},
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](
        cpu,
        time_slice="0.02",
        max_iters=5,
        enforce_content_criteria=True,
        followup_cycle=True,
    )
    assert status["fault_timing"]["checks_held_before_fault"] is False
    assert status["fault_timing"]["checks_first_held"] is None

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"],
        state["pc"],
        fault_injected=False,
        enforce_content_criteria=True,
        p2_status=status,
        followup_cycle=True,
    )
    assert outcome == "hard_fault"
    assert signals["memory_checks_ok"] is False
    assert signals["recovery_execution"]["hardfault_observed"] is True


def test_followup_cycle_evaluates_volatile_marker_and_structured_checks() -> None:
    def step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100050
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.001
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns, state, _machine, cpu = _build_harness(
        step_fn=step,
        memory_specs=[],
        config_specs=[{"address": 0x20000300, "expected": 0xCAFEBABE}],
        bootloader_integrity=True,
        mem_values={0x20000100: 0, 0x20000300: 0, 0x00000000: 0x20002000},
        success_marker_addr=0x20000100,
        success_marker_value=0x5245434F,
        allow_fault_after_success=True,
    )
    status = ns["run_until_done"](
        cpu,
        time_slice="0.02",
        max_iters=5,
        enforce_content_criteria=True,
        followup_cycle=True,
    )
    assert status["fault_timing"]["checks_held_before_fault"] is False

    outcome, _slot, signals = ns["evaluate_boot_outcome"](
        state["vtor"],
        state["pc"],
        fault_injected=False,
        enforce_content_criteria=True,
        p2_status=status,
        followup_cycle=True,
    )
    assert outcome == "hard_fault"
    assert signals["marker_ok"] is False
    assert signals["config_checks_ok"] is False


def test_followup_cycle_unconfirmed_in_slot_marker_revert_passes_cleanly_but_never_counts_as_held() -> None:
    # Models scenarios/mcuboot_head_exploratory.yaml (mcuboot_head_upgrade +
    # boot_cycles=3, no confirm hook): static in-slot header marker at
    # 0x10100014 reverts to slot0's version word on cycle 1.
    def clean_step(state, _machine, cpu, _mem, _fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.010

    ns_clean, state_clean, _m, cpu_clean = _build_harness(
        step_fn=clean_step,
        memory_specs=[],
        mem_values={0x10100014: 0x00000001},
        success_image_hash=False,
        success_marker_addr=0x10100014,
        success_marker_value=0x00010001,
        boot_cycle_hook="",
        allow_fault_after_success=True,
    )
    status_clean = ns_clean["run_until_done"](
        cpu_clean, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    outcome_clean, _slot, signals_clean = ns_clean["evaluate_boot_outcome"](
        state_clean["vtor"],
        state_clean["pc"],
        fault_injected=False,
        p2_status=status_clean,
        followup_cycle=True,
    )
    assert outcome_clean == "success"
    assert signals_clean["followup_skipped_criteria"] == ["marker_address"]

    # If the firmware faults on that follow-up cycle, the skipped marker must
    # NOT count as held even when allow_fault_after_success=True.
    def fault_step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    ns_fault, state_fault, _m2, cpu_fault = _build_harness(
        step_fn=fault_step,
        memory_specs=[],
        mem_values={0x10100014: 0x00000001},
        success_image_hash=False,
        success_marker_addr=0x10100014,
        success_marker_value=0x00010001,
        boot_cycle_hook="",
        allow_fault_after_success=True,
    )
    status_fault = ns_fault["run_until_done"](
        cpu_fault, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    assert status_fault["fault_timing"]["checks_held_before_fault"] is False
    outcome_fault, _slot2, _sig2 = ns_fault["evaluate_boot_outcome"](
        state_fault["vtor"],
        state_fault["pc"],
        fault_injected=False,
        p2_status=status_fault,
        followup_cycle=True,
    )
    assert outcome_fault == "hard_fault"


def test_followup_cycle_skipped_otadata_and_unconfirmed_hash_never_count_as_held() -> None:
    exec_hash = "11" * 32
    staging_hash = "22" * 32
    corrupt_hash = "33" * 32

    def fault_step(state, _machine, cpu, _mem, fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.010
        fire_fault(3)
        state["pc"] = 0x10100090
        state["virtual_time"].seconds = 0.020

    # Skipped otadata_expect on follow-up cycle cannot count as held.
    ns_ota, state_ota, _m, cpu_ota = _build_harness(
        step_fn=fault_step,
        memory_specs=[],
        success_image_hash=False,
        success_otadata_expect={"otadata1_state_name": ["pending_verify"]},
        allow_fault_after_success=True,
    )
    status_ota = ns_ota["run_until_done"](
        cpu_ota, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    assert status_ota["fault_timing"]["checks_held_before_fault"] is False
    outcome_ota, _s, sig_ota = ns_ota["evaluate_boot_outcome"](
        state_ota["vtor"],
        state_ota["pc"],
        fault_injected=False,
        p2_status=status_ota,
        followup_cycle=True,
    )
    assert outcome_ota == "hard_fault"
    assert sig_ota["followup_skipped_criteria"] == ["otadata_expect"]

    # Unconfirmed upgrade reverted to exec_hash: clean cycle succeeds (with
    # skipped restriction noted), corrupt flash fails with wrong_image, and
    # faulting cycle stays hard_fault (never counts as held).
    def clean_step(state, _machine, cpu, _mem, _fire_fault):
        hook = state["hooks"].get(0x10100020)
        if hook is not None:
            hook(cpu, 0x10100020)
        state["pc"] = 0x10100060
        state["instructions"] = 500
        state["virtual_time"].seconds = 0.010

    ns_rev, state_rev, _m2, cpu_rev = _build_harness(
        step_fn=clean_step,
        memory_specs=[],
        success_image_hash=True,
        expected_exec_sha256=staging_hash,
        image_exec_sha256=exec_hash,
        image_staging_sha256=staging_hash,
        slot_hash_fn=lambda _slot: exec_hash,
        boot_cycle_hook="",
        allow_fault_after_success=True,
    )
    status_rev = ns_rev["run_until_done"](
        cpu_rev, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    out_rev, _s2, sig_rev = ns_rev["evaluate_boot_outcome"](
        state_rev["vtor"],
        state_rev["pc"],
        fault_injected=False,
        p2_status=status_rev,
        followup_cycle=True,
    )
    assert out_rev == "success"
    assert sig_rev["followup_skipped_criteria"] == ["image_hash_expected_image"]

    ns_corrupt, state_corrupt, _m3, cpu_corrupt = _build_harness(
        step_fn=clean_step,
        memory_specs=[],
        success_image_hash=True,
        expected_exec_sha256=staging_hash,
        image_exec_sha256=exec_hash,
        image_staging_sha256=staging_hash,
        slot_hash_fn=lambda _slot: corrupt_hash,
        boot_cycle_hook="",
        allow_fault_after_success=True,
    )
    status_corrupt = ns_corrupt["run_until_done"](
        cpu_corrupt, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    out_corrupt, _s3, _sig3 = ns_corrupt["evaluate_boot_outcome"](
        state_corrupt["vtor"],
        state_corrupt["pc"],
        fault_injected=False,
        p2_status=status_corrupt,
        followup_cycle=True,
    )
    assert out_corrupt == "wrong_image"

    ns_rev_fault, state_rev_fault, _m4, cpu_rev_fault = _build_harness(
        step_fn=fault_step,
        memory_specs=[],
        success_image_hash=True,
        expected_exec_sha256=staging_hash,
        image_exec_sha256=exec_hash,
        image_staging_sha256=staging_hash,
        slot_hash_fn=lambda _slot: exec_hash,
        boot_cycle_hook="",
        allow_fault_after_success=True,
    )
    status_rev_fault = ns_rev_fault["run_until_done"](
        cpu_rev_fault, time_slice="0.02", max_iters=5, followup_cycle=True
    )
    assert status_rev_fault["fault_timing"]["checks_held_before_fault"] is False
    out_rev_fault, _s4, _sig4 = ns_rev_fault["evaluate_boot_outcome"](
        state_rev_fault["vtor"],
        state_rev_fault["pc"],
        fault_injected=False,
        p2_status=status_rev_fault,
        followup_cycle=True,
    )
    assert out_rev_fault == "hard_fault"


def test_boot_followup_cycle_passes_content_criteria_and_followup_flag() -> None:
    calls: dict[str, dict] = {}

    def fake_run_until_done(_cpu, **kwargs):
        calls["run_until_done"] = dict(kwargs)
        return {"reason": "pc_captured", "emulated_s": 0.02, "iters": 1}

    def fake_evaluate_boot_outcome(_vtor, _pc, **kwargs):
        calls["evaluate_boot_outcome"] = dict(kwargs)
        return ("hard_fault", "exec", {"memory_checks_ok": False})

    ns = _load_runtime_functions(
        "_boot_followup_cycle",
        extra_namespace={
            "phase2_wall_timeout_s": 10.0,
            "phase2_time_slice": "0.02",
            "backend": {"kind": "fast"},
            "monitor": SimpleNamespace(
                Machine={
                    "sysbus.cpu": SimpleNamespace(
                        GetRegisterUnsafe=lambda _idx: 0x10100080
                    )
                }
            ),
            "bus": SimpleNamespace(ReadDoubleWord=lambda _addr: 0x10100000),
            "as_int": int,
            "reset_nvmc_for_recovery": lambda: None,
            "arm_vtor_watchpoint": lambda: None,
            "disarm_vtor_watchpoint": lambda: None,
            "run_until_done": fake_run_until_done,
            "evaluate_boot_outcome": fake_evaluate_boot_outcome,
            "build_cycle_record": lambda cycle_index, outcome, slot, signals, **_kw: {
                "cycle": cycle_index,
                "boot_outcome": outcome,
                "boot_slot": slot,
                "signals": signals,
            },
        },
    )
    record = ns["_boot_followup_cycle"](1, False, "control_followup")
    assert record["boot_outcome"] == "hard_fault"
    assert calls["run_until_done"]["enforce_content_criteria"] is True
    assert calls["run_until_done"]["followup_cycle"] is True
    assert calls["evaluate_boot_outcome"]["enforce_content_criteria"] is True
    assert calls["evaluate_boot_outcome"]["followup_cycle"] is True


def test_allow_fault_after_success_profile_schema_and_transport(tmp_path: Path) -> None:
    from boundary_reserved import BOUNDARY_RESERVED_VARIABLES
    from profile_loader import ProfileError

    assert "SUCCESS_ALLOW_FAULT_AFTER_SUCCESS" in BOUNDARY_RESERVED_VARIABLES
    assert '$success_allow_fault_after_success?="false"' in (
        ROOT / "scripts" / "run_runtime_fault_sweep.resc"
    ).read_text(encoding="utf-8")
    robot_text = (ROOT / "tests" / "ota_fault_point.robot").read_text(encoding="utf-8")
    assert "${SUCCESS_ALLOW_FAULT_AFTER_SUCCESS}    false" in robot_text
    assert '$success_allow_fault_after_success="${SUCCESS_ALLOW_FAULT_AFTER_SUCCESS}"' in robot_text

    # State mode must reject allow_fault_after_success: true.
    bad_state = tmp_path / "bad_state.yaml"
    bad_state.write_text(
        (FIXTURE / "profile.yaml")
        .read_text(encoding="utf-8")
        .replace("evaluation_mode: execute", "evaluation_mode: state"),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="execute evaluation mode"):
        load_profile(bad_state, strict=True)

    # Runtime dict and robot_vars propagate the opt-in cleanly without requiring
    # prebuilt example binaries on a clean checkout.
    dummy_bin = tmp_path / "app.bin"
    dummy_bin.write_bytes(b"\xff" * 64)
    profile_text = (FIXTURE / "profile.yaml").read_text(encoding="utf-8")
    pos_yaml = tmp_path / "pos.yaml"
    pos_yaml.write_text(
        profile_text.replace("examples/deliberate_crash_report/app.bin", "app.bin"),
        encoding="utf-8",
    )
    no_opt_yaml = tmp_path / "no_opt.yaml"
    no_opt_yaml.write_text(
        pos_yaml.read_text(encoding="utf-8").replace(
            "allow_fault_after_success: true", "allow_fault_after_success: false"
        ),
        encoding="utf-8",
    )

    assert load_profile(FIXTURE / "profile.yaml", strict=True).success_criteria.allow_fault_after_success is True
    assert load_profile(FIXTURE / "profile_no_opt_in.yaml", strict=True).success_criteria.allow_fault_after_success is False

    pos = load_profile(pos_yaml, strict=True)
    assert pos.success_criteria.allow_fault_after_success is True
    assert "SUCCESS_ALLOW_FAULT_AFTER_SUCCESS:true" in pos.robot_vars(ROOT)
    assert (
        pos._success_criteria_runtime_dict(ROOT, pos.success_criteria, pos.images)[
            "allow_fault_after_success"
        ]
        is True
    )

    no_opt = load_profile(no_opt_yaml, strict=True)
    assert no_opt.success_criteria.allow_fault_after_success is False
    assert "SUCCESS_ALLOW_FAULT_AFTER_SUCCESS:true" not in no_opt.robot_vars(ROOT)
    assert (
        no_opt._success_criteria_runtime_dict(
            ROOT, no_opt.success_criteria, no_opt.images
        )["allow_fault_after_success"]
        is False
    )


def test_followup_memory_checks_compose_with_cycle_signal_contract() -> None:
    """Verify follow-up memory_checks enforcement composes with cycle-signal reporting."""
    from audit_report import compute_verdict, summarize_runtime_sweep
    from boot_cycle_analysis import analyze_boot_cycles
    from fault_classification import (
        _effective_boot_result,
        _effective_boot_signals,
        classify_issue_category,
        result_is_brick,
        result_issue_reasons,
        result_recovered_after_failure,
    )
    from profile_loader import ExpectConfig

    annotate_ns = _load_runtime_functions("annotate_boot_span_result")
    annotate = annotate_ns["annotate_boot_span_result"]

    def _run_followup_eval(mem_values: dict[int, int], *, early_fault: bool = False) -> dict:
        def step(state, _machine, cpu, _mem, fire_fault):
            hook = state["hooks"].get(0x10100020)
            if hook is not None:
                hook(cpu, 0x10100020)
            state["pc"] = 0x10100050
            state["instructions"] = 100
            state["virtual_time"].seconds = 0.001
            if early_fault:
                fire_fault(3)
                state["pc"] = 0x10100090
            state["virtual_time"].seconds = 0.020

        ns, state, _machine, cpu = _build_harness(
            step_fn=step,
            memory_specs=CHECKS,
            mem_values=mem_values,
            allow_fault_after_success=True,
        )
        status = ns["run_until_done"](
            cpu,
            time_slice="0.02",
            max_iters=5,
            enforce_content_criteria=True,
            followup_cycle=True,
        )
        outcome, slot, signals = ns["evaluate_boot_outcome"](
            state["vtor"],
            state["pc"],
            fault_injected=True,
            enforce_content_criteria=True,
            p2_status=status,
            followup_cycle=True,
        )
        return {"boot_outcome": outcome, "boot_slot": slot, "signals": signals}

    # Case A: cycle 0 hard_fault (memory_checks_ok=False) -> cycle 1 passes
    # memory_checks on follow-up -> recovered_after_failure, effective signals
    # read cycle 1 (memory_checks_ok=True), non-brick, verdict sums cleanly.
    c0_fail = {
        "cycle": 0,
        "boot_outcome": "hard_fault",
        "boot_slot": None,
        "signals": {"expectations_met": False, "memory_checks_ok": False},
    }
    c1_pass = _run_followup_eval({0x20000200: 1, 0x20000204: 5})
    assert c1_pass["boot_outcome"] == "success"
    assert c1_pass["signals"]["memory_checks_ok"] is True
    cycles_a = [c0_fail, {"cycle": 1, **c1_pass}]
    res_a = annotate({
        "fault_at": 2,
        "fault_type": "w",
        "is_control": False,
        "fault_injected": True,
        "boot_outcome": c0_fail["boot_outcome"],
        "boot_slot": c0_fail["boot_slot"],
        "signals": dict(c0_fail["signals"]),
        "boot_cycles": cycles_a,
        "multi_boot_analysis": analyze_boot_cycles(cycles_a, requested_cycles=2),
    })
    assert res_a["multi_boot_analysis"]["status"] == "recovered_after_failure"
    assert _effective_boot_result(res_a) == ("success", "exec")
    assert _effective_boot_signals(res_a)["memory_checks_ok"] is True
    assert result_is_brick(res_a) is False
    assert result_recovered_after_failure(res_a, "success") is True
    assert result_issue_reasons(res_a, "success") == ["recovered_after_failure"]
    assert classify_issue_category(res_a, "success") == "recovered_after_failure"

    # Case B: cycle 0 hard_fault -> cycle 1 lands in exec without faulting, but
    # follow-up memory_checks fail -> memory_checks_unmet (not success), status
    # is changed_unconfirmed (not promoted), stays brick / boot_mismatch.
    c1_unmet = _run_followup_eval({0x20000200: 0, 0x20000204: 0})
    assert c1_unmet["boot_outcome"] == "memory_checks_unmet"
    assert c1_unmet["signals"]["memory_checks_ok"] is False
    cycles_b = [c0_fail, {"cycle": 1, **c1_unmet}]
    res_b = annotate({
        "fault_at": 3,
        "fault_type": "w",
        "is_control": False,
        "fault_injected": True,
        "boot_outcome": c0_fail["boot_outcome"],
        "boot_slot": c0_fail["boot_slot"],
        "signals": dict(c0_fail["signals"]),
        "boot_cycles": cycles_b,
        "multi_boot_analysis": analyze_boot_cycles(cycles_b, requested_cycles=2),
    })
    assert res_b["multi_boot_analysis"]["status"] == "changed_unconfirmed"
    assert _effective_boot_result(res_b) == ("hard_fault", None)
    assert _effective_boot_signals(res_b)["memory_checks_ok"] is False
    assert result_is_brick(res_b) is True
    assert result_recovered_after_failure(res_b, "success") is False
    assert classify_issue_category(res_b, "success") == "boot_mismatch"

    # Case C: cycle 0 clean success -> cycles 1 & 2 fault before checks hold
    # (even with allow_fault_after_success=True) -> converges on hard_fault,
    # effective signals read final cycle's memory_checks_ok=False, brick.
    c0_ok = {
        "cycle": 0,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "signals": {"expectations_met": True, "memory_checks_ok": True},
    }
    c1_fault = _run_followup_eval({0x20000200: 0, 0x20000204: 0}, early_fault=True)
    c2_fault = _run_followup_eval({0x20000200: 0, 0x20000204: 0}, early_fault=True)
    assert c1_fault["boot_outcome"] == "hard_fault"
    assert c1_fault["signals"]["memory_checks_ok"] is False
    cycles_c = [c0_ok, {"cycle": 1, **c1_fault}, {"cycle": 2, **c2_fault}]
    res_c = annotate({
        "fault_at": 4,
        "fault_type": "w",
        "is_control": False,
        "fault_injected": True,
        "boot_outcome": c0_ok["boot_outcome"],
        "boot_slot": c0_ok["boot_slot"],
        "signals": dict(c0_ok["signals"]),
        "boot_cycles": cycles_c,
        "multi_boot_analysis": analyze_boot_cycles(cycles_c, requested_cycles=3),
    })
    assert res_c["multi_boot_analysis"]["status"] == "converged"
    assert _effective_boot_result(res_c) == ("hard_fault", "exec")
    assert _effective_boot_signals(res_c)["memory_checks_ok"] is False
    assert result_is_brick(res_c) is True
    assert classify_issue_category(res_c, "success") == "boot_mismatch"

    # Summarize all three points together with a clean control and confirm the
    # verdict breakdown sums exactly (2 boot mismatches + 1 recovered = 3).
    ctrl = {
        "fault_at": 0,
        "fault_type": "w",
        "is_control": True,
        "fault_injected": False,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "signals": {"expectations_met": True, "memory_checks_ok": True},
    }
    summary = summarize_runtime_sweep([ctrl, res_a, res_b, res_c])
    assert summary["issue_points"] == 3
    assert summary["bricks"] == 2
    assert summary["recovered_after_failure_points"] == 1
    assert summary["issue_breakdown"]["boot_mismatch"] == 2
    assert summary["issue_breakdown"]["recovered_after_failure"] == 1
    assert sum(summary["issue_breakdown"].values()) == summary["issue_points"]
    verdict = compute_verdict(
        sweep_summary=summary,
        profile_expect=ExpectConfig(should_find_issues=False),
    )
    assert (
        verdict
        == "FAIL — found 3 issue points (2 boot mismatches, 1 recovered after failure, 0 semantic, 0 invariant)"
    )


def test_deliberate_crash_report_fixture_builds_and_profiles_validate() -> None:
    if shutil.which("arm-none-eabi-gcc") is None:
        pytest.skip("arm-none-eabi-gcc is not installed")
    subprocess.run(
        ["make", "-C", str(FIXTURE), "clean", "all"],
        cwd=ROOT,
        check=True,
    )
    pos = load_profile(FIXTURE / "profile.yaml", strict=True)
    no_opt = load_profile(FIXTURE / "profile_no_opt_in.yaml", strict=True)
    vec_spin = load_profile(FIXTURE / "profile_vector_entry_spin.yaml", strict=True)
    followup = load_profile(
        FIXTURE / "profile_followup_fault_before_checks.yaml", strict=True
    )
    neg_before = load_profile(
        FIXTURE / "profile_fault_before_checks.yaml", strict=True
    )
    neg_forges = load_profile(
        FIXTURE / "profile_fault_forges_checks.yaml", strict=True
    )

    assert pos.expect.control_outcome == "success"
    assert pos.expect.should_find_issues is True
    assert pos.success_criteria.pc_in_slot == "exec"
    assert pos.success_criteria.allow_fault_after_success is True
    assert len(pos.success_criteria.memory_checks) == 2
    assert no_opt.success_criteria.allow_fault_after_success is False
    assert no_opt.expect.control_outcome == "hard_fault"
    assert no_opt.expect.allow_control_only_issues is True
    assert vec_spin.success_criteria.allow_fault_after_success is True
    assert vec_spin.expect.control_outcome == "success"
    assert followup.success_criteria.allow_fault_after_success is True
    assert followup.fault_sweep.boot_cycles == 3
    assert followup.expect.control_outcome == "hard_fault"
    assert followup.expect.allow_control_only_issues is True
    assert neg_before.expect.control_outcome == "hard_fault"
    assert neg_before.expect.allow_control_only_issues is True
    assert neg_forges.expect.control_outcome == "hard_fault"
    assert neg_forges.expect.allow_control_only_issues is True
