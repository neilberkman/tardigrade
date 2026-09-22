#!/usr/bin/env python3
"""Regression tests for runtime budget and liveness classification."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"
ALLOWED_HASH = "11" * 32
UNKNOWN_HASH = "22" * 32


def _runtime_evaluator():
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"recovery_failure_outcome", "evaluate_boot_outcome"}
    ]
    state = {
        "image_hash": ALLOWED_HASH,
        "structured": {"requested": True, "all_ok": True},
    }

    def execution_evidence(_vtor, _pc, _slot, status):
        if status is None:
            return {}
        evidence = {
            "stop_reason": status.get("reason", ""),
            "hardfault_observed": bool(status.get("hardfault_observed", False)),
        }
        if "reset_vector_valid" in status:
            evidence["reset_vector_valid"] = status["reset_vector_valid"]
        return evidence

    namespace = {
        "success_vtor_slot": "exec",
        "success_image_hash": True,
        "success_image_hash_slot": "exec",
        "success_pc_slot": "exec",
        "slot_ranges": {
            "exec": (0x1000, 0x2000),
            "staging": (0x2000, 0x3000),
        },
        "sticky_vtor": {"captured": False, "value": 0, "slot": None},
        "sticky_pc": {"captured": False, "value": 0, "slot": None},
        "allowed_image_hashes": [
            {"name": "allowed", "sha256": ALLOWED_HASH},
        ],
        "expected_exec_sha256": "",
        "expected_image_name": "expected",
        "image_exec_sha256": "",
        "image_staging_sha256": "",
        "success_marker_addr": 0,
        "success_marker_value": 0,
        "security_anti_rollback": False,
        "success_otadata_expect": {},
        "success_otadata_expect_scope": "all",
        "max_reset_vector_offset": None,
        "compute_slot_hash": lambda _slot: state["image_hash"],
        "_match_configured_image_hash": (
            lambda digest: "allowed" if digest == ALLOWED_HASH else None
        ),
        "collect_otadata_signals": lambda: {},
        "evaluate_structured_success_checks": lambda: state["structured"],
        "normalize_signal_token": lambda value: str(value),
        "capture_boot_registers": lambda: None,
        "collect_recovery_execution_evidence": execution_evidence,
        "boot_outcome_after_stop": lambda outcome, _reason: outcome,
        "fmt_u32": lambda value: "0x{:08X}".format(value & 0xFFFFFFFF),
        "as_int": int,
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(RUNTIME), "exec"),
        namespace,
        namespace,
    )
    return namespace["evaluate_boot_outcome"], state


def _evaluate(*, fault_injected=False, status=None, vtor=0x1000, pc=0x1101):
    evaluate, state = _runtime_evaluator()
    result = evaluate(
        vtor,
        pc,
        fault_injected=fault_injected,
        p2_status=status or {"reason": "budget"},
    )
    return result, state


def test_clean_control_at_budget_remains_incomplete() -> None:
    (outcome, slot, signals), _state = _evaluate()

    assert outcome == "timeout"
    assert slot == "exec"
    assert signals["liveness_established"] is True
    assert signals["expectations_met"] is True


def test_faulted_run_at_budget_with_passing_liveness_remains_incomplete() -> None:
    (outcome, _slot, signals), _state = _evaluate(fault_injected=True)

    assert outcome == "timeout"
    assert signals["liveness_established"] is True


def test_content_mismatch_at_budget_is_supporting_incomplete_evidence() -> None:
    evaluate, state = _runtime_evaluator()
    state["image_hash"] = UNKNOWN_HASH

    outcome, _slot, signals = evaluate(
        0x1000, 0x1101, p2_status={"reason": "budget"}
    )

    assert outcome == "timeout"
    assert signals["liveness_established"] is True
    assert signals["content_mismatch"] is True
    assert signals["supporting_outcomes"] == ["wrong_image"]


def test_budget_with_failed_structured_check_is_incomplete_not_no_boot() -> None:
    evaluate, state = _runtime_evaluator()
    state["structured"] = {"requested": True, "all_ok": False}

    outcome, _slot, signals = evaluate(
        0x1000, 0x1101, p2_status={"reason": "budget"}
    )

    assert outcome == "timeout"
    assert signals["liveness_established"] is True
    assert signals["content_mismatch"] is True
    assert signals["supporting_outcomes"] == ["wrong_image"]


def test_budget_without_observed_execution_is_timeout() -> None:
    (outcome, slot, signals), _state = _evaluate(vtor=0, pc=0)

    assert outcome == "timeout"
    assert slot is None
    assert signals["execution_observed"] is False


def test_instruction_limit_is_timeout_even_with_observed_execution() -> None:
    (outcome, slot, signals), _state = _evaluate(
        status={"reason": "instruction_limit(500000)"}
    )

    assert outcome == "timeout"
    assert slot == "exec"
    assert signals["liveness_established"] is True


def test_runtime_loop_enforces_the_configured_instruction_limit() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "cpu_ref.ExecutedInstructions" in source
    assert "instructions_executed >= max_step_limit" in source
    assert "reason = 'instruction_limit({})'" in source


def test_hardfault_and_invalid_vector_override_content_failure() -> None:
    evaluate, state = _runtime_evaluator()
    state["image_hash"] = UNKNOWN_HASH

    hardfault, _slot, hardfault_signals = evaluate(
        0x1000,
        0x1101,
        p2_status={"reason": "budget", "hardfault_observed": True},
    )
    invalid_vector, _slot, vector_signals = evaluate(
        0x1000,
        0x1101,
        p2_status={"reason": "budget", "reset_vector_valid": False},
    )

    assert hardfault == "hard_fault"
    assert invalid_vector == "hard_fault"
    assert hardfault_signals["supporting_outcomes"] == ["wrong_image"]
    assert vector_signals["supporting_outcomes"] == ["wrong_image"]
