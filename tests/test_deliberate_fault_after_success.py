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
    mem_values: dict[int, int] | None = None,
    terminal_after_reset: bool = False,
    supports_interrupt_hook: bool = True,
    initial_vtor: int = 0x20000100,
    success_vtor_slot: str = "",
    success_pc_slot: str = "exec",
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
            "success_image_hash": True,
            "success_image_hash_slot": "exec",
            "success_terminal_after_reset": terminal_after_reset,
            "bootloader_entry": 0x00000000,
            "slot_ranges": {"exec": (0x10100000, 0x10101000)},
            "allowed_image_hashes": [],
            "expected_exec_sha256": ALLOWED_HASH,
            "expected_image_name": "exec",
            "image_exec_sha256": ALLOWED_HASH,
            "image_staging_sha256": "",
            "success_marker_addr": 0,
            "success_marker_value": 0,
            "security_anti_rollback": False,
            "success_otadata_expect": {},
            "success_otadata_expect_scope": "always",
            "max_reset_vector_offset": None,
            "success_checks_config": {
                "memory_checks": list(memory_specs or []),
                "config_checks": [],
                "bootloader_integrity": False,
            },
            "success_checks_parse_error": None,
            "sram_start": 0x20000000,
            "sram_end": 0x20002000,
            "compute_slot_hash": lambda _slot: ALLOWED_HASH,
            "_match_configured_image_hash": (
                lambda digest: "exec" if digest == ALLOWED_HASH else None
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
    assert rec["hardfault_observed"] is False


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
    )
    status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
    assert status["reason"] == "success_terminal_after_reset"
    assert status["fault_timing"]["checks_held_before_fault"] is True

    outcome, slot, _signals = ns["evaluate_boot_outcome"](
        state["vtor"], state["pc"], fault_injected=False, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"


def test_deliberate_crash_report_fixture_builds_and_profiles_validate() -> None:
    if shutil.which("arm-none-eabi-gcc") is None:
        pytest.skip("arm-none-eabi-gcc is not installed")
    subprocess.run(
        ["make", "-C", str(FIXTURE), "clean", "all"],
        cwd=ROOT,
        check=True,
    )
    pos = load_profile(FIXTURE / "profile.yaml", strict=True)
    neg_before = load_profile(
        FIXTURE / "profile_fault_before_checks.yaml", strict=True
    )
    neg_forges = load_profile(
        FIXTURE / "profile_fault_forges_checks.yaml", strict=True
    )

    assert pos.expect.control_outcome == "success"
    assert pos.expect.should_find_issues is True
    assert pos.success_criteria.pc_in_slot == "exec"
    assert len(pos.success_criteria.memory_checks) == 2
    assert neg_before.expect.control_outcome == "hard_fault"
    assert neg_before.expect.allow_control_only_issues is True
    assert neg_forges.expect.control_outcome == "hard_fault"
    assert neg_forges.expect.allow_control_only_issues is True
