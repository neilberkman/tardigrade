"""Regression checks for state-mode completion-marker semantics."""

import ast
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_naive_completion_marker_is_external_to_image_slots() -> None:
    profile = yaml.safe_load(
        (ROOT / "profiles" / "naive_copy_with_marker.yaml").read_text(
            encoding="utf-8"
        )
    )
    marker = int(profile["success_criteria"]["marker_address"])
    slots = profile["memory"]["slots"].values()

    assert all(
        not (int(slot["base"]) <= marker < int(slot["base"]) + int(slot["size"]))
        for slot in slots
    )


class _MemoryBus:
    def __init__(self, initial):
        self.memory = dict(initial)
        self.writes = []

    def ReadDoubleWord(self, address):
        return self.memory.get(address, 0)

    def WriteDoubleWord(self, address, value):
        self.writes.append((address, value))
        self.memory[address] = value & 0xFFFFFFFF

    def WriteQuadWord(self, address, value):
        self.writes.append((address, value))
        self.memory[address] = value


def _state_runner():
    source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_state_fault"
    )
    bus = _MemoryBus(
        {
            0x1000: 0,
            0x1004: 0,
            0x2000: 0x2001FFFC,
            0x2004: 0x1021,
        }
    )
    namespace = {
        "total_copy_writes": 2,
        "slot_staging_base": 0x2000,
        "slot_exec_base": 0x1000,
        "write_granularity": 4,
        "backend": {"kind": "fast"},
        "bus": bus,
        "success_vector_offset": 0,
        "sram_start": 0x20000000,
        "sram_end": 0x20020000,
        "slot_exec_size": 0x100,
        "slot_ranges": {"exec": (0x1000, 0x1100), "staging": (0x2000, 0x2100)},
        "success_marker_addr": 0x3000,
        "success_marker_value": 0xC0FEBEEF,
        "evaluate_structured_success_checks": lambda: {
            "requested": False,
            "all_ok": True,
        },
        "add_boundary_contract_signals": lambda _signals: None,
        "collect_semantic_state": lambda _state: None,
        "get_effective_criteria": lambda _fault_type: {},
        "classify_fault_result": lambda *_args, **_kwargs: "none",
        "as_int": int,
        "fmt_u32": lambda value: "0x{:08X}".format(value & 0xFFFFFFFF),
        "boundary_setup_env": "",
        "boundary_durable_state_file": "",
        "calibration_mode": False,
        "boundary_phase": "",
    }
    module = ast.Module(body=[function], type_ignores=[])
    exec(compile(module, "run_runtime_fault_sweep.py", "exec"), namespace)
    return namespace["run_state_fault"], bus


def test_state_runner_only_synthesizes_external_marker_after_complete_copy() -> None:
    run_state_fault, bus = _state_runner()

    result = run_state_fault(-1)

    assert result["boot_outcome"] == "success"
    assert result["signals"]["marker_ok"] is True
    assert (0x3000, 0xC0FEBEEF) in bus.writes


def test_state_runner_does_not_synthesize_external_marker_for_partial_copy() -> None:
    run_state_fault, bus = _state_runner()

    result = run_state_fault(1)

    assert result["boot_outcome"] == "hard_fault"
    assert "marker_actual" not in result["signals"]
    assert all(address != 0x3000 for address, _value in bus.writes)
