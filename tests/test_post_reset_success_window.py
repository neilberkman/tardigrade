#!/usr/bin/env python3
"""Tests for direct reset observation and post-reset memory-check evaluation."""

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
DELAYED_FIXTURE = ROOT / "examples" / "runtime_self_update_delayed"
sys.path.insert(0, str(ROOT / "scripts"))

from audit_report import categorize_failure, summarize_runtime_sweep  # noqa: E402
from boot_cycle_analysis import cycle_has_unresolved_timeout  # noqa: E402
from boot_outcomes import (  # noqa: E402
    DEVICE_BOOT_OUTCOMES,
    SUPPORTED_BOOT_OUTCOMES,
    is_canonical_boot_outcome,
)
from fault_classification import (  # noqa: E402
    classify_failure_class,
    result_has_initial_timeout,
    result_has_issues,
    result_is_brick,
    result_is_timeout,
    result_issue_reasons,
)
from profile_loader import load_profile  # noqa: E402
from renode_runner import _validate_batch_results, calibration_completed  # noqa: E402


ALLOWED_HASH = "11" * 32
UNKNOWN_HASH = "22" * 32


class _Event:
    """Minimal C#-like event supporting += and -= in Python unit tests."""

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

    @property
    def count(self) -> int:
        return len(self._handlers)


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


def _build_integrated_harness(
    *,
    memory_specs: list[dict],
    mem_values: dict[int, int],
    image_hash_ref: dict[str, str],
    step_fn,
    calibration_mode: bool = False,
    calibration_stop_on_success: bool = False,
    progress_stall_timeout_s: float = 0.0,
    max_step_limit: int = 10_000_000,
    has_machine_reset_event: bool = True,
    has_peripheral_reset_event: bool = True,
    boot_entry_handler: int = 0x10200024,
):
    sticky_vtor = {"captured": False, "value": 0, "slot": None}
    sticky_pc = {"captured": False, "value": 0, "slot": None}
    state = {
        "run_calls": 0,
        "instructions": 0,
        "pc": 0x10100050,
        "vtor": 0x20000100,
        "writes": 0,
        "hooks": {},
        "virtual_time": _VirtualTime(0.0),
    }

    class FakeMachine:
        def __init__(self) -> None:
            if has_machine_reset_event:
                self.MachineReset = _Event()
            if has_peripheral_reset_event:
                self.PeripheralReset = _Event()

        @property
        def ElapsedVirtualTime(self):
            return state["virtual_time"]

    machine = FakeMachine()

    class FakeCpu:
        IsHalted = False

        @property
        def ExecutedInstructions(self):
            return state["instructions"]

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

    cpu = FakeCpu()

    class FakeBus:
        @staticmethod
        def ReadDoubleWord(address):
            if address == 0xE000ED08:
                return state["vtor"]
            if address == 0x10200004:
                return boot_entry_handler | 1
            if address == 0x10100000:
                return 0x20002000
            if address == 0x10100004:
                return 0x10100021
            return mem_values.get(int(address), 0)

        @staticmethod
        def ReadWord(_address):
            return 0

    class FakeMonitor:
        Machine = machine

        @staticmethod
        def Parse(command):
            state["run_calls"] += 1
            step_fn(state, machine, cpu, mem_values, image_hash_ref)

    def capture_sticky_pc(value):
        pc = int(value) & ~1
        if 0x10100000 <= pc < 0x10101000:
            sticky_pc.update(captured=True, value=pc, slot="exec")

    cal_stop_state = {
        "address_hit": False,
        "address_reached": False,
        "triggered": False,
        "reason": None,
        "writes": None,
        "erases": None,
        "matched_image": None,
        "image_hash_actual": None,
        "success_before_address": False,
        "success_reset_gate_required": True,
        "success_reset_gate_satisfied": False,
    }

    ns = _load_runtime_functions(
        "evaluate_structured_success_checks",
        "recovery_failure_outcome",
        "evaluate_boot_outcome",
        "_calibration_success_stop_observation",
        "_reset_gated_success_stop_observation",
        "classify_fault_result",
        "run_until_done",
        extra_namespace={
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.1",
            "success_vtor_slot": "",
            "success_vector_offset": 0,
            "success_pc_slot": "exec",
            "success_image_hash": True,
            "success_image_hash_slot": "exec",
            "success_terminal_after_reset": True,
            "bootloader_entry": 0x10200000,
            "slot_ranges": {"exec": (0x10100000, 0x10101000)},
            "allowed_image_hashes": [{"name": "staging", "sha256": ALLOWED_HASH}],
            "expected_exec_sha256": "",
            "expected_image_name": "",
            "image_exec_sha256": "",
            "image_staging_sha256": ALLOWED_HASH,
            "success_marker_addr": 0,
            "success_marker_value": 0,
            "security_anti_rollback": False,
            "success_otadata_expect": {},
            "success_otadata_expect_scope": "always",
            "max_reset_vector_offset": None,
            "success_checks_config": {
                "memory_checks": memory_specs,
                "config_checks": [],
                "bootloader_integrity": False,
            },
            "success_checks_parse_error": None,
            "sram_start": 0x20000000,
            "sram_end": 0x20002000,
            "compute_slot_hash": lambda _slot: image_hash_ref["digest"],
            "_match_configured_image_hash": (
                lambda digest: "staging" if digest == ALLOWED_HASH else None
            ),
            "collect_otadata_signals": lambda: {},
            "normalize_signal_token": lambda value: str(value or "").strip().lower(),
            "capture_boot_registers": lambda: None,
            "collect_recovery_execution_evidence": lambda _vtor, _pc, _slot, status: (
                {"stop_reason": status.get("reason", ""), "hardfault_observed": False}
                if status is not None
                else {}
            ),
            "boot_outcome_after_stop": lambda outcome, reason: (
                "timeout"
                if reason == "budget" or str(reason).startswith(("wall_timeout", "instruction_limit"))
                else outcome
            ),
            "monitor": FakeMonitor(),
            "bus": FakeBus(),
            "sticky_vtor": sticky_vtor,
            "sticky_pc": sticky_pc,
            "capture_sticky_pc": capture_sticky_pc,
            "calibration_mode": calibration_mode,
            "calibration_stop_on_success": calibration_stop_on_success,
            "_calibration_stop_state": cal_stop_state,
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
            "progress_stall_timeout_s": progress_stall_timeout_s,
            "max_step_limit": max_step_limit,
            "max_step_limit_resolution": {
                "configured": max_step_limit,
                "source": "profile",
                "performance_mips": 100.0,
            },
            "_recovery_zero_vector_guard": False,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
        },
    )
    return ns, state, machine, cpu


def test_reset_observed_directly_without_boot_entry_or_prior_sample() -> None:
    """MachineReset observes a reset inside slice 1 with no prior sample or boot re-entry."""

    def step(state, machine, cpu, mem, _hash_ref):
        # Single initial entry into boot stub, then copy, then SYSRESETREQ at 0.165s,
        # restarting directly at app (no second boot_entry hit) and counter=1 by 0.5s.
        boot_hook = state["hooks"].get(0x10200024)
        if state["run_calls"] == 1:
            if boot_hook is not None:
                boot_hook(cpu, 0x10200024)
            state["writes"] = 1024
            state["virtual_time"].seconds = 0.165
            machine.MachineReset.fire(machine)
            # Instructions at end of slice are strictly positive (never dropped vs 0).
            state["instructions"] = 3_350_000
            state["virtual_time"].seconds = 0.5
            mem[0x20000200] = 1

    ns, _state, machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
    )

    status = ns["run_until_done"](cpu, time_slice="0.5", max_iters=5)
    ro = status["reset_observation"]

    assert status["reason"] == "success_terminal_after_reset"
    assert status["iters"] == 1
    assert ro["observed"] is True
    assert "machine_reset" in ro["sources"]
    assert ro["machine_resets"] == 1
    assert ro["boot_entry_hits"] == 1
    assert ro["instruction_counter_resets"] == 0
    assert ro["reset_emulated_s"] == pytest.approx(0.165)
    assert ro["observed_at_iter"] == 1
    assert ro["observed_at_emulated_s"] == pytest.approx(0.5)
    assert ro["checks_first_held_at_iter"] == 1
    assert ro["checks_first_held_at_emulated_s"] == pytest.approx(0.5)
    assert ro["checks_held_after_reset_s"] == pytest.approx(0.335)
    assert ro["post_reset_samples"] == 1
    # Event handler must detach cleanly on exit.
    assert machine.MachineReset.count == 0
    assert machine.PeripheralReset.count == 0


def test_cpu_peripheral_reset_observed_without_machine_reset() -> None:
    """PeripheralReset targeting the CPU also observes a reset directly."""

    def step(state, machine, cpu, mem, _hash_ref):
        if state["run_calls"] == 1:
            state["virtual_time"].seconds = 0.12
            machine.PeripheralReset.fire(machine, cpu)
            state["instructions"] = 500_000
            state["virtual_time"].seconds = 0.5
            mem[0x20000200] = 1

    ns, _state, machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
        has_machine_reset_event=False,
        has_peripheral_reset_event=True,
    )

    status = ns["run_until_done"](cpu, time_slice="0.5", max_iters=5)
    ro = status["reset_observation"]

    assert status["reason"] == "success_terminal_after_reset"
    assert ro["observed"] is True
    assert "cpu_reset" in ro["sources"]
    assert ro["cpu_resets"] == 1
    assert ro["reset_emulated_s"] == pytest.approx(0.12)
    assert machine.PeripheralReset.count == 0


def test_memory_check_passing_several_slices_after_reset_gives_success() -> None:
    """Pending memory checks do not fail early; the first passing slice returns success."""

    def step(state, machine, cpu, mem, _hash_ref):
        call = state["run_calls"]
        if call == 1:
            state["writes"] = 512
            state["instructions"] = 1_000_000
            state["virtual_time"].seconds = 0.1
        elif call == 2:
            state["writes"] = 1024
            state["virtual_time"].seconds = 0.165
            machine.MachineReset.fire(machine)
            state["instructions"] = 350_000
            state["virtual_time"].seconds = 0.2
            mem[0x20000200] = 0
        elif call == 3:
            # Still starting up; writes unchanged while stall timeout is tiny.
            state["instructions"] = 1_350_000
            state["virtual_time"].seconds = 0.3
            mem[0x20000200] = 0
        elif call == 4:
            state["instructions"] = 2_350_000
            state["virtual_time"].seconds = 0.4
            mem[0x20000200] = 1

    ns, _state, _machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
        progress_stall_timeout_s=0.05,
    )

    status = ns["run_until_done"](cpu, time_slice="0.1", max_iters=10)
    ro = status["reset_observation"]

    assert status["reason"] == "success_terminal_after_reset"
    assert status["iters"] == 4
    assert ro["observed"] is True
    assert "machine_reset" in ro["sources"]
    assert "instruction_counter_reset" in ro["sources"]
    assert ro["observed_at_iter"] == 2
    assert ro["observed_at_emulated_s"] == pytest.approx(0.2)
    assert ro["checks_first_held_at_iter"] == 4
    assert ro["checks_first_held_at_emulated_s"] == pytest.approx(0.4)
    assert ro["checks_held_after_reset_s"] == pytest.approx(0.235)
    assert ro["checks_held_after_reset_observed_s"] == pytest.approx(0.2)
    assert ro["post_reset_samples"] == 3

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x20000100, 0x10100050, fault_injected=False, p2_status=status
    )
    assert outcome == "success"
    assert slot == "exec"
    assert signals["memory_checks_ok"] is True
    assert signals["content_criteria_ok"] is True


def test_content_mismatch_after_reset_is_still_immediately_terminal_wrong_image() -> None:
    """A bad image hash after reset terminates immediately as wrong_image."""

    def step(state, machine, _cpu, mem, hash_ref):
        if state["run_calls"] == 1:
            state["writes"] = 512
            state["instructions"] = 1_000_000
            state["virtual_time"].seconds = 0.1
        elif state["run_calls"] == 2:
            hash_ref["digest"] = UNKNOWN_HASH
            state["virtual_time"].seconds = 0.15
            machine.MachineReset.fire(machine)
            state["instructions"] = 200_000
            state["virtual_time"].seconds = 0.2
            mem[0x20000200] = 0

    ns, _state, _machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
    )

    status = ns["run_until_done"](cpu, time_slice="0.1", max_iters=10)
    assert status["iters"] == 2
    assert status["reason"] == "outcome_terminal_after_reset(wrong_image)"

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x20000100, 0x10100050, fault_injected=False, p2_status=status
    )
    assert outcome == "wrong_image"
    assert slot == "exec"
    assert signals["content_mismatch"] is True
    assert signals["content_criteria_ok"] is False


@pytest.mark.parametrize("exhaust_mode", ["budget", "instruction_limit"])
def test_checks_never_holding_gives_memory_checks_unmet_naming_failed_checks(
    exhaust_mode: str,
) -> None:
    """Exhausting the budget with valid content and unmet checks reports memory_checks_unmet."""

    def step(state, machine, _cpu, mem, _hash_ref):
        call = state["run_calls"]
        if call == 1:
            state["writes"] = 1024
            state["virtual_time"].seconds = 0.165
            machine.MachineReset.fire(machine)
            state["instructions"] = 350_000
            state["virtual_time"].seconds = 0.2
            mem[0x20000200] = 1  # check 0 holds
            mem[0x20000204] = 0  # check 1 never holds
        else:
            state["instructions"] += 1_000_000
            state["virtual_time"].seconds += 0.1

    step_limit = 2_000_000 if exhaust_mode == "instruction_limit" else 100_000_000
    ns, _state, _machine, cpu = _build_integrated_harness(
        memory_specs=[
            {"address": 0x20000200, "expected_value": 1, "op": "eq"},
            {"address": 0x20000204, "expected_value": 5, "op": "ge"},
        ],
        mem_values={0x20000200: 0, 0x20000204: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
        max_step_limit=step_limit,
    )

    status = ns["run_until_done"](cpu, time_slice="0.1", max_iters=4)
    ro = status["reset_observation"]

    assert status["reason"] == "post_reset_checks_unmet"
    if exhaust_mode == "budget":
        assert status["iters"] == 4
        assert ro["budget_exhausted_reason"] == "budget"
    else:
        assert str(ro["budget_exhausted_reason"]).startswith("instruction_limit(")
    assert ro["observed"] is True
    assert ro["checks_first_held_at_iter"] is None
    assert ro["checks_held_after_reset_s"] is None

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x20000100, 0x10100050, fault_injected=False, p2_status=status
    )
    assert outcome == "memory_checks_unmet"
    assert slot == "exec"
    assert signals["content_mismatch"] is False
    assert signals["content_criteria_ok"] is True
    assert signals["memory_checks_ok"] is False
    assert len(signals["failed_memory_checks"]) == 1
    failed = signals["failed_memory_checks"][0]
    assert failed["index"] == 1
    assert failed["address"] == "0x20000204"
    assert failed["op"] == "ge"
    assert failed["expected"] == 5
    assert failed["actual"] == 0
    assert any("0x20000204" in line for line in signals["unmet_memory_checks"])
    assert "0x20000204" in signals["failure_reason"]

    # Verify host-side outcome, classification, protocol, and reporting integration.
    assert "memory_checks_unmet" in DEVICE_BOOT_OUTCOMES
    assert "memory_checks_unmet" in SUPPORTED_BOOT_OUTCOMES
    assert is_canonical_boot_outcome("memory_checks_unmet") is True
    assert ns["classify_fault_result"](outcome, slot, signals) == "memory_checks_unmet"

    signals["phase1_stop_reason"] = status["reason"]
    signals["phase1_reset_observation"] = ro
    result = {
        "is_control": True,
        "fault_at": 0,
        "fault_requested": 0,
        "fault_type": "control",
        "fault_injected": False,
        "fault_address": "0x00000000",
        "boot_outcome": outcome,
        "boot_slot": slot,
        "fault_class": "memory_checks_unmet",
        "signals": signals,
    }
    assert cycle_has_unresolved_timeout({"boot_outcome": outcome, "stop_reason": "budget"}) is False
    assert result_is_timeout(result) is False
    assert result_has_initial_timeout(result) is False
    assert result_is_brick(result) is False
    assert result_has_issues(result, "success") is True
    reasons = result_issue_reasons(result, "success")
    assert "boot_outcome" in reasons
    assert "memory_check" in reasons
    assert classify_failure_class(result) == "memory_checks_unmet"

    validated = _validate_batch_results(
        [{**result, "is_control": False, "fault_type": "w", "fault_injected": True}],
        [0],
        ["w"],
    )
    assert validated[0]["boot_outcome"] == "memory_checks_unmet"

    summary = summarize_runtime_sweep([result], expected_fault_points=0)
    ctrl_sig = summary["control"]["signals"]
    assert ctrl_sig["unmet_memory_checks"] == signals["unmet_memory_checks"]
    assert ctrl_sig["failed_memory_checks"] == signals["failed_memory_checks"]
    assert ctrl_sig["phase1_reset_observation"]["observed"] is True

    profile = load_profile(DELAYED_FIXTURE / "profile.yaml", strict=True)
    cat = categorize_failure(
        {**result, "is_control": False, "fault_injected": True, "fault_type": "w"},
        total_writes=1024,
        profile=profile,
    )
    assert cat["outcome"] == "memory_checks_unmet"
    assert cat["failure_class"] == "memory_checks_unmet"
    assert cat["unmet_memory_checks"] == signals["unmet_memory_checks"]

    assert calibration_completed("post_reset_checks_unmet", "success") is False
    assert calibration_completed("post_reset_checks_unmet", "memory_checks_unmet") is True


def test_calibration_success_stop_waits_for_post_reset_checks_and_records_timing() -> None:
    """Calibration success stop does not terminate on unmet post-reset checks."""

    def step(state, machine, _cpu, mem, _hash_ref):
        call = state["run_calls"]
        if call == 1:
            state["writes"] = 512
            state["instructions"] = 1_000_000
            state["virtual_time"].seconds = 0.1
            # Even if memory check looks true pre-reset, reset gate blocks it.
            mem[0x20000200] = 1
        elif call == 2:
            state["writes"] = 1024
            state["virtual_time"].seconds = 0.165
            machine.MachineReset.fire(machine)
            state["instructions"] = 350_000
            state["virtual_time"].seconds = 0.2
            mem[0x20000200] = 0
        elif call == 3:
            state["instructions"] = 1_350_000
            state["virtual_time"].seconds = 0.3
            mem[0x20000200] = 1

    ns, _state, _machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
        calibration_mode=True,
        calibration_stop_on_success=True,
    )

    status = ns["run_until_done"](cpu, time_slice="0.1", max_iters=6)
    ro = status["reset_observation"]

    assert status["reason"] == "calibration_stop_success_criteria"
    assert status["iters"] == 3
    assert ro["observed"] is True
    assert ro["observed_at_iter"] == 2
    assert ro["checks_first_held_at_iter"] == 3
    assert ro["checks_held_after_reset_s"] == pytest.approx(0.135)
    assert status["calibration_stop"]["reason"] == "success_criteria"


def test_pre_reset_sticky_pc_cleared_on_in_run_reset() -> None:
    """Execution in exec before reset cannot spoof post-reset liveness."""

    def step(state, machine, _cpu, mem, _hash_ref):
        call = state["run_calls"]
        if call == 1:
            state["pc"] = 0x10100050  # executing in exec pre-reset
            state["instructions"] = 500_000
            state["virtual_time"].seconds = 0.1
        else:
            if call == 2:
                state["virtual_time"].seconds = 0.15
                machine.MachineReset.fire(machine)
            # Post-reset CPU never reaches exec (stays stuck in ROM).
            state["pc"] = 0x10200010
            state["instructions"] += 500_000
            state["virtual_time"].seconds += 0.1
            mem[0x20000200] = 1

    ns, _state, _machine, cpu = _build_integrated_harness(
        memory_specs=[{"address": 0x20000200, "expected_value": 1, "op": "ge"}],
        mem_values={0x20000200: 0},
        image_hash_ref={"digest": ALLOWED_HASH},
        step_fn=step,
    )

    status = ns["run_until_done"](cpu, time_slice="0.1", max_iters=3)
    assert status["reason"] == "budget"
    assert ns["sticky_pc"]["captured"] is False

    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x0, 0x10200010, fault_injected=False, p2_status=status
    )
    assert outcome == "timeout"
    assert slot is None
    assert signals["liveness_established"] is False


def test_delayed_fixture_profile_and_symbols() -> None:
    if shutil.which("arm-none-eabi-gcc") is None:
        pytest.skip("arm-none-eabi-gcc is not installed")
    subprocess.run(
        ["make", "-C", str(DELAYED_FIXTURE), "clean", "all"],
        cwd=ROOT,
        check=True,
    )
    profile = load_profile(DELAYED_FIXTURE / "profile.yaml", strict=True)
    unmet = load_profile(DELAYED_FIXTURE / "profile_checks_unmet.yaml", strict=True)

    assert profile.success_criteria.terminal_after_reset is True
    assert profile.bootloader_entry == 0x10200000
    assert profile.memory.slots["exec"].base == 0x10100000
    assert len(profile.success_criteria.memory_checks) == 1
    assert unmet.images["staging"].endswith("never_ready.bin")

    nm = shutil.which("arm-none-eabi-nm")
    if nm is not None:
        out = subprocess.check_output(
            [nm, "-n", str(DELAYED_FIXTURE / "old.elf")], text=True
        )
        syms = {
            parts[-1]: int(parts[0], 16)
            for line in out.splitlines()
            for parts in [line.split()]
            if len(parts) >= 3
        }
        assert profile.fault_sweep.tracking_start_address == syms["copy_update"]
        assert profile.fault_sweep.calibration_stop.address == syms["request_reset"]
