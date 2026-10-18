#!/usr/bin/env python3
"""Focused checks for the MCUboot STM32F4 writeback campaign profile."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


def test_mcuboot_scratch_stm32f4_writeback_profile() -> None:
    profile_path = ROOT / "profiles" / "mcuboot_head_scratch_stm32f4_writeback.yaml"
    raw = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile = load_profile(profile_path)

    assert raw["base_profile"] == "mcuboot_head_scratch_stm32f4_upgrade.yaml"
    assert raw["skip_self_test"] is True
    assert profile.name == "mcuboot_head_scratch_stm32f4_writeback"
    assert profile.platform == "platforms/stm32f4.repl"
    assert profile.fault_sweep.evaluation_mode == "execute"
    assert profile.fault_sweep.fault_types == ["power_loss"]
    assert profile.fault_sweep.durability_model == "writeback"
    assert profile.fault_sweep.writeback.buffer_capacity == "auto"
    assert profile.fault_sweep.writeback.erase_flushes_domain is False
    assert profile.fault_sweep.writeback.barriers == []
    assert profile.fault_sweep.max_writes_cap == 400000
    assert profile.fault_sweep.max_step_limit == 500000000
    assert profile.fault_sweep.calibration_stop.success_criteria is True
    # VTOR, vector_table_offset, and staged-version marker match the 0x200
    # header of the mirrored STM32F4 slot images.
    assert raw.get("success_criteria") == {"vector_table_offset": 0x200}
    assert profile.success_criteria.vtor_in_slot == "exec"
    assert profile.success_criteria.vector_table_offset == 0x200
    assert profile.success_criteria.marker_address == 0x08008014
    assert profile.success_criteria.marker_value == 0x00000101
    assert profile.success_criteria.image_hash is False
    assert profile.success_criteria.pc_in_slot is None
    assert profile.expect.should_find_issues is True
    assert "BOOT_STATUS_STATE_1" in profile.description


def _build_runtime_outcome_harness(
    *,
    vtor_slot: str = "",
    pc_slot: str = "",
    vector_table_offset: int = 0,
    slot_ranges: dict[str, tuple[int, int]] | None = None,
):
    import ast

    runtime_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
    tree = ast.parse(
        runtime_path.read_text(encoding="utf-8"),
        filename=str(runtime_path),
    )
    wanted = {
        "on_vtor_write",
        "capture_sticky_pc",
        "recovery_failure_outcome",
        "evaluate_boot_outcome",
    }
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    sticky_vtor = {"captured": False, "value": 0, "slot": None}
    sticky_pc = {"captured": False, "value": 0, "slot": None}
    namespace = {
        "success_vtor_slot": vtor_slot,
        "success_pc_slot": pc_slot or None,
        "success_vector_offset": vector_table_offset,
        "success_image_hash": False,
        "success_image_hash_slot": "",
        "slot_ranges": slot_ranges
        or {
            "exec": (0x08008000, 0x08040000),
            "staging": (0x08040000, 0x08078000),
        },
        "sticky_vtor": sticky_vtor,
        "sticky_pc": sticky_pc,
        "allowed_image_hashes": [],
        "expected_exec_sha256": "",
        "expected_image_name": "",
        "image_exec_sha256": "",
        "image_staging_sha256": "",
        "success_marker_addr": 0,
        "success_marker_value": 0,
        "security_anti_rollback": False,
        "success_otadata_expect": {},
        "success_otadata_expect_scope": "all",
        "max_reset_vector_offset": None,
        "compute_slot_hash": lambda _slot: "",
        "_match_configured_image_hash": lambda _digest: None,
        "collect_otadata_signals": lambda: {},
        "evaluate_structured_success_checks": lambda: {"requested": False, "all_ok": True},
        "normalize_signal_token": lambda value: str(value),
        "capture_boot_registers": lambda: None,
        "collect_recovery_execution_evidence": lambda *_args: {},
        "boot_outcome_after_stop": lambda outcome, _reason: outcome,
        "fmt_u32": lambda value: "0x{:08X}".format(int(value) & 0xFFFFFFFF),
        "as_int": int,
        "log": lambda _msg: None,
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(runtime_path), "exec"),
        namespace,
        namespace,
    )
    return namespace


def test_vtor_in_slot_enforces_declared_vector_table_offset() -> None:
    ns = _build_runtime_outcome_harness(
        vtor_slot="exec",
        vector_table_offset=0x200,
    )
    ns["on_vtor_write"](0x08008200)
    outcome, slot, signals = ns["evaluate_boot_outcome"](0x08008200, 0x08009131)
    assert outcome == "success"
    assert slot == "exec"
    assert signals["vtor_ok"] is True
    assert signals["vtor_expected"] == "0x08008200"
    assert "failure_reason" not in signals

    ns_mismatch = _build_runtime_outcome_harness(
        vtor_slot="exec",
        vector_table_offset=0x400,
    )
    ns_mismatch["on_vtor_write"](0x08008200)
    outcome, slot, signals = ns_mismatch["evaluate_boot_outcome"](0x08008200, 0x08009131)
    assert outcome == "wrong_image"
    assert slot == "exec"
    assert signals["vtor_ok"] is False
    assert signals["vtor_expected"] == "0x08008400"
    assert "0x08008400" in signals["vtor_failure_reason"]
    assert "0x08008200" in signals["vtor_failure_reason"]
    assert signals["failure_reason"] == signals["vtor_failure_reason"]


def test_vtor_in_slot_without_vector_table_offset_keeps_in_slot_behavior() -> None:
    for captured_vtor in (0x08008000, 0x08008200, 0x08008400):
        ns = _build_runtime_outcome_harness(
            vtor_slot="exec",
            vector_table_offset=0,
        )
        ns["on_vtor_write"](captured_vtor)
        outcome, slot, signals = ns["evaluate_boot_outcome"](captured_vtor, 0x08009131)
        assert outcome == "success"
        assert slot == "exec"
        assert signals["vtor_ok"] is True
        assert "failure_reason" not in signals

    ns_wrong_slot = _build_runtime_outcome_harness(
        vtor_slot="exec",
        vector_table_offset=0,
    )
    ns_wrong_slot["on_vtor_write"](0x08040200)
    outcome, slot, signals = ns_wrong_slot["evaluate_boot_outcome"](0x08040200, 0x08041131)
    assert outcome == "wrong_image"
    assert slot == "staging"
    assert signals["vtor_ok"] is False
    assert "0x08008000" in signals["vtor_failure_reason"]
    assert "0x08040000" in signals["vtor_failure_reason"]
    assert "0x08040200" in signals["vtor_failure_reason"]


def test_pc_in_slot_enforces_declared_vector_table_offset() -> None:
    slots = {"exec": (0x10002000, 0x10025000), "staging": (0x10025000, 0x10048000)}
    ns_ok = _build_runtime_outcome_harness(
        pc_slot="exec",
        vector_table_offset=0x200,
        slot_ranges=slots,
    )
    ns_ok["capture_sticky_pc"](0x10002241)
    outcome, slot, signals = ns_ok["evaluate_boot_outcome"](0x0, 0x0)
    assert outcome == "success"
    assert slot == "exec"
    assert signals["pc_ok"] is True
    assert signals["pc_expected_range"] == ["0x10002200", "0x10025000"]
    assert "failure_reason" not in signals

    ns_header_pc = _build_runtime_outcome_harness(
        pc_slot="exec",
        vector_table_offset=0x200,
        slot_ranges=slots,
    )
    ns_header_pc["capture_sticky_pc"](0x10002101)
    outcome, slot, signals = ns_header_pc["evaluate_boot_outcome"](0x0, 0x0)
    assert outcome == "wrong_pc"
    assert slot == "exec"
    assert signals["pc_ok"] is False
    assert "0x10002200" in signals["pc_failure_reason"]
    assert "0x10025000" in signals["pc_failure_reason"]
    assert "0x10002100" in signals["pc_failure_reason"]
    assert signals["failure_reason"] == signals["pc_failure_reason"]


def test_pc_in_slot_without_vector_table_offset_keeps_in_slot_behavior() -> None:
    slots = {"exec": (0x10002000, 0x10025000), "staging": (0x10025000, 0x10048000)}
    for captured_pc in (0x10002001, 0x10002101, 0x10002241):
        ns = _build_runtime_outcome_harness(
            pc_slot="exec",
            vector_table_offset=0,
            slot_ranges=slots,
        )
        ns["capture_sticky_pc"](captured_pc)
        outcome, slot, signals = ns["evaluate_boot_outcome"](0x0, 0x0)
        assert outcome == "success"
        assert slot == "exec"
        assert signals["pc_ok"] is True
        assert "failure_reason" not in signals

    ns_outside = _build_runtime_outcome_harness(
        pc_slot="exec",
        vector_table_offset=0,
        slot_ranges=slots,
    )
    ns_outside["on_vtor_write"](0x10002000)
    outcome, slot, signals = ns_outside["evaluate_boot_outcome"](0x10002000, 0x10025041)
    assert outcome == "wrong_pc"
    assert slot == "exec"
    assert signals["pc_ok"] is False
    assert "0x10002000" in signals["pc_failure_reason"]
    assert "0x10025000" in signals["pc_failure_reason"]
    assert "0x10025040" in signals["pc_failure_reason"]

