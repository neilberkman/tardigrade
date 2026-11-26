#!/usr/bin/env python3
"""Regression coverage for parity between one-cut and phase-two faults."""

from __future__ import annotations

import ast
import sys
import time
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_runtime_fault_sweep.py"
PROFILE = ROOT / "profiles" / "nxboot_style_update_phase2fault.yaml"
sys.path.insert(0, str(ROOT / "scripts"))

from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from profile_loader import load_profile  # noqa: E402


def _load_phase2_fault(namespace: dict) -> None:
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_phase2_fault"
    )
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(RUNNER), "exec"),
        namespace,
        namespace,
    )


class _FakeMram:
    Size = 64
    TotalPageErases = 0
    FaultFlashSnapshot = None

    def __init__(self) -> None:
        self.TotalWordWrites = 0
        self.FaultFired = False
        self.marks: set[int] = set()
        self.fault_marks: set[int] = set()
        self.reads: list[dict] = []
        self.Nvm = self

    def ReadBytes(self, offset: int, count: int) -> bytes:
        return bytes(count)


class _FakeController:
    """Only the backing-NVM member needed from the real controller API."""

    def __init__(self, nvm: _FakeMram) -> None:
        self.Nvm = nvm


class _Phase2Runtime:
    def __init__(self, *, boot_cycles: int = 1, backend_kind: str = "mram") -> None:
        self.nvm = _FakeMram()
        self.data = self.nvm if backend_kind == "mram" else _FakeController(self.nvm)
        self.cpu = SimpleNamespace(
            IsHalted=False,
            GetRegisterUnsafe=lambda _reg: 0x10000001,
        )
        self.modes_at_cut: list[str] = []
        self.marks_seen_by_boot: dict[str, set[int]] = {}
        self.semantic_contexts: list[dict] = []
        self.followup_calls: list[dict] = []
        self.hook_calls: list[int] = []
        self.current_cut = 0
        self.ns = {
            "_time": time,
            "get_effective_criteria": lambda _code: {"vtor_in_slot": "exec"},
            "monitor": SimpleNamespace(Machine={"sysbus.cpu": self.cpu}, Parse=lambda _cmd: None),
            "bus": SimpleNamespace(ReadDoubleWord=lambda _addr: 0x10000000),
            "backend": {"kind": backend_kind, "data": self.data},
            "log": lambda _message: None,
            "restore_phase1_baseline": self._restore_phase1,
            "restore_flash_and_boot": self._restore_flash_and_boot,
            "reset_nvmc_for_sweep": lambda **_kwargs: None,
            "reset_nvmc_for_recovery": lambda **_kwargs: None,
            "arm_fault": self._arm_fault,
            "arm_erase_fault": self._arm_fault,
            "disarm_fault": lambda: None,
            "disarm_write_fault": lambda: None,
            "disarm_erase_fault": lambda: None,
            "was_fault_injected": lambda: True,
            "get_total_writes": lambda: self.nvm.TotalWordWrites,
            "get_total_erases": lambda: self.nvm.TotalPageErases,
            "get_last_write_address": lambda: 0x10000000 + self.current_cut * 8,
            "run_until_done": self._run_until_done,
            "arm_vtor_watchpoint": lambda: None,
            "disarm_vtor_watchpoint": lambda: None,
            "phase1_wall_timeout": lambda default_s: default_s,
            "phase1_max_iters": lambda default_s: 100,
            "phase2_time_slice": "0.01",
            "phase2_wall_timeout_s": 1.0,
            "max_writes_cap": 100,
            "fault_points": [0, 1],
            "_WRITE_FAULT_MODE": {"w": 0},
            "_hash_bypass_active": False,
            "apply_hash_bypass": lambda: None,
            "parse_duration_seconds": lambda default: default,
            "as_int": int,
            "fmt_u32": lambda value: "0x{:08x}".format(int(value) & 0xFFFFFFFF),
            "evaluate_boot_outcome": self._evaluate_boot_outcome,
            "merge_stop_status_signals": self._merge_stop_status_signals,
            "collect_semantic_state": self._collect_semantic_state,
            "classify_fault_result": lambda *_args, **_kwargs: "success",
            "postmortem_dump_no_boot": False,
            "resume_trace_no_boot": False,
            "build_postmortem_partition_dump": lambda **_kwargs: {},
            "run_resume_trace_from_snapshot": lambda *_args: {},
            "boot_cycles": boot_cycles,
            "run_followup_boot_cycles": self._run_followup_boot_cycles,
            "set_multiboot_cycles_run": self._set_multiboot_cycles_run,
            "_snapshot_mram_fault_uncorrectable_offsets": self._fault_offsets,
            "_snapshot_mram_fault_uncorrectable_addresses": self._fault_addresses,
            "_snapshot_mram_uncorrectable_addresses": self._addresses,
            "_restore_mram_uncorrectable_offsets": self._restore_offsets,
            "_clear_mram_uncorrectable_read_log": self.nvm.reads.clear,
            "_attach_uncorrectable_read_signals": self._attach_uncorrectable,
            "mram_torn_word": "half",
            "mram_torn_word_choices": [],
            "mram_torn_word_seed": 0,
            "_select_point_mram_torn_word": self._select_mode,
        }
        _load_phase2_fault(self.ns)

    def _restore_phase1(self) -> None:
        self.nvm.marks.clear()
        self.nvm.fault_marks.clear()
        self.nvm.reads.clear()
        self.nvm.TotalWordWrites = 0

    def _restore_flash_and_boot(self, _saved_flash: bytes) -> None:
        # A reset/reload drops peripheral-only ECC metadata.
        self.nvm.marks.clear()
        self.nvm.fault_marks.clear()
        self.nvm.reads.clear()

    def _arm_fault(self, *_args, **_kwargs) -> None:
        self.current_cut += 1
        self.modes_at_cut.append(self.ns["mram_torn_word"])

    def _run_until_done(self, _cpu, *, label: str, **_kwargs) -> dict:
        self.marks_seen_by_boot[label] = set(self.nvm.marks)
        if "_p1_" in label:
            self.nvm.TotalWordWrites = 1
            self._apply_cut(8)
            return {"reason": "fault_fired", "emulated_s": 0.01}
        if "_p2_" in label:
            # The recovery boot observes cut one's word and then repairs it
            # before cut two interrupts a different program operation.
            if 8 in self.nvm.marks:
                self.nvm.reads.append(
                    {"word_address": "0x10000008", "pc": "0x10000040"}
                )
            self.nvm.marks.discard(8)
            self.nvm.TotalWordWrites = 1
            self._apply_cut(16)
            return {"reason": "fault_fired", "emulated_s": 0.02}
        return {"reason": "vtor_captured", "emulated_s": 0.03}

    def _apply_cut(self, offset: int) -> None:
        if self.ns["mram_torn_word"] == "uncorrectable":
            self.nvm.marks.add(offset)
        self.nvm.fault_marks = set(self.nvm.marks)

    def _evaluate_boot_outcome(self, *_args, **_kwargs):
        return "success", "exec", {"expectations_met": True}

    @staticmethod
    def _merge_stop_status_signals(signals: dict, prefix: str, status: dict) -> None:
        signals[prefix + "_stop_reason"] = status.get("reason")

    def _collect_semantic_state(self, context: dict):
        self.semantic_contexts.append(dict(context))
        return {
            "stage": context["stage"],
            "cycle": context.get("cycle"),
            "phase2_cut": context.get("phase2_cut"),
            "uncorrectable_offsets": sorted(self.nvm.marks),
        }

    def _run_followup_boot_cycles(self, outcome, slot, signals, **kwargs):
        self.followup_calls.append(dict(kwargs))
        if self.ns["boot_cycles"] <= 1:
            return None, None, 0
        cycle0 = {
            "cycle": 0,
            "boot_outcome": outcome,
            "boot_slot": slot,
            "signals": dict(signals),
            "semantic_state": self._collect_semantic_state(
                {"stage": "boot_cycle", "cycle": 0}
            ),
        }
        self.hook_calls.append(1)
        cycle1 = {
            "cycle": 1,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {"hook_effect": "written"},
            "semantic_state": self._collect_semantic_state(
                {"stage": "boot_cycle", "cycle": 1}
            ),
        }
        return [cycle0, cycle1], {"status": "stable_success"}, 4

    @staticmethod
    def _set_multiboot_cycles_run(signals: dict, records) -> None:
        signals["multiboot_cycles_run"] = max(0, len(records or []) - 1)

    def _fault_offsets(self) -> list[int]:
        return sorted(self.nvm.fault_marks)

    def _fault_addresses(self) -> list[str]:
        return ["0x{:08x}".format(0x10000000 + off) for off in self._fault_offsets()]

    def _addresses(self) -> list[str]:
        return ["0x{:08x}".format(0x10000000 + off) for off in sorted(self.nvm.marks)]

    def _restore_offsets(self, offsets) -> None:
        self.nvm.marks = {int(offset) for offset in offsets}

    def _attach_uncorrectable(self, signals, _outcome, **kwargs) -> None:
        marked = list(kwargs.get("marked_at_fault") or [])
        if marked:
            signals["uncorrectable_words_at_fault"] = marked
        if self.nvm.reads:
            signals["uncorrectable_read"] = {
                "read_count": len(self.nvm.reads),
                "word_addresses": [entry["word_address"] for entry in self.nvm.reads],
                "reads": list(self.nvm.reads),
            }

    def _select_mode(self, fault_at: int):
        choices = self.ns["mram_torn_word_choices"]
        if not choices:
            return None
        mode = dict(choices)[int(fault_at)]
        self.ns["mram_torn_word"] = mode
        return mode

    def run(self, p1: int = 0, p2: int = 1) -> dict:
        return self.ns["run_phase2_fault"](p1, p2)


def test_phase2_fault_skips_controller_backend_before_first_cut() -> None:
    runtime = _Phase2Runtime(backend_kind="slow")

    result = runtime.run()

    assert not hasattr(runtime.data, "Flash")
    assert not hasattr(runtime.data, "FlashSize")
    assert runtime.data.Nvm is runtime.nvm
    assert runtime.current_cut == 0
    assert runtime.modes_at_cut == []
    assert result["fault_injected"] is False
    assert result["skip_reason"] == "phase2_unsupported_backend"
    assert result["phase2_fault"]["p1_injected"] is False
    assert result["phase2_fault"]["p2_injected"] is False


def test_nxboot_controller_profile_plans_nine_early_skips() -> None:
    profile = load_profile(PROFILE)
    plan = build_fault_plan(
        profile,
        CalibrationInputs(max_writes=profile.fault_sweep.max_writes),
        quick=True,
    )
    phase2_types = [
        fault_type
        for fault_type in plan.fault_types_list or []
        if fault_type.startswith("p2:")
    ]

    assert profile.flash_backend == "nvm_ctrl"
    assert len(phase2_types) == 9
    for fault_type in phase2_types:
        _, p1_raw, p2_raw, _, _ = fault_type.split(":")
        runtime = _Phase2Runtime(backend_kind="slow")
        result = runtime.run(int(p1_raw), int(p2_raw))
        assert result["skip_reason"] == "phase2_unsupported_backend"
        assert runtime.current_cut == 0


def test_phase2_fault_restores_uncorrectable_words_for_both_later_boots() -> None:
    runtime = _Phase2Runtime()
    runtime.ns["mram_torn_word"] = "uncorrectable"

    result = runtime.run()

    assert runtime.marks_seen_by_boot["p2fault_p2_0_1"] == {8}
    assert runtime.marks_seen_by_boot["p2fault_p3_0_1"] == {16}
    assert result["phase2_fault"]["p1_fault_semantic_state"][
        "uncorrectable_offsets"
    ] == [8]
    assert result["phase2_fault"]["p2_fault_semantic_state"][
        "uncorrectable_offsets"
    ] == [16]
    recovery = result["phase2_fault"]["recovery_boot_signals"]
    assert recovery["uncorrectable_read"]["read_count"] == 1
    assert recovery["uncorrectable_read"]["word_addresses"] == ["0x10000008"]
    assert recovery["uncorrectable_read"]["reads"][0]["pc"] == "0x10000040"


def test_phase2_fault_runs_followup_boots_and_probes_each_boundary() -> None:
    runtime = _Phase2Runtime(boot_cycles=2)

    result = runtime.run()

    assert [record["cycle"] for record in result["boot_cycles"]] == [0, 1]
    assert result["boot_cycles"][1]["signals"]["hook_effect"] == "written"
    assert result["multi_boot_analysis"] == {"status": "stable_success"}
    assert runtime.hook_calls == [1]
    boundary_cuts = [
        context.get("phase2_cut")
        for context in runtime.semantic_contexts
        if context.get("stage") == "fault_snapshot"
    ]
    assert boundary_cuts == [1, 2]
    boot_cycles = [
        context.get("cycle")
        for context in runtime.semantic_contexts
        if context.get("stage") == "boot_cycle"
    ]
    assert boot_cycles == [0, 1]


def test_phase2_fault_draws_and_records_each_cuts_torn_word_mode() -> None:
    runtime = _Phase2Runtime()
    runtime.ns["mram_torn_word_choices"] = [(3, "uncorrectable"), (9, "erased")]

    result = runtime.run(3, 9)

    assert runtime.modes_at_cut == ["uncorrectable", "erased"]
    assert result["phase2_fault"]["p1_mram_torn_word"] == "uncorrectable"
    assert result["phase2_fault"]["p2_mram_torn_word"] == "erased"
    assert result["mram_torn_word"] == "uncorrectable"
