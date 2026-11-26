#!/usr/bin/env python3
"""Regression tests for two-cycle recovery reporting, verdict sums, and recovery writes."""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import compute_verdict, summarize_runtime_sweep  # noqa: E402
from boot_cycle_analysis import analyze_boot_cycles  # noqa: E402
from fault_classification import (  # noqa: E402
    _effective_boot_result,
    _effective_boot_signals,
    classify_failure_class,
    classify_issue_category,
    result_has_issues,
    result_is_brick,
    result_is_recovery,
    result_issue_reasons,
    result_recovered_after_failure,
)
from profile_loader import ExpectConfig, load_profile  # noqa: E402


RUNTIME_PATH = SCRIPTS / "run_runtime_fault_sweep.py"


def _load_runtime_functions(*names: str, extra_ns: dict | None = None) -> dict:
    tree = ast.parse(RUNTIME_PATH.read_text(encoding="utf-8"), filename=str(RUNTIME_PATH))
    wanted = set(names)
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    if len(nodes) != len(wanted):
        found = {node.name for node in nodes}
        raise AssertionError(f"Missing runtime functions: {wanted - found}")
    namespace = dict(extra_ns or {})
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNTIME_PATH), "exec"), namespace)
    return namespace


def _parse_verdict_breakdown(verdict: str) -> tuple[int, dict[str, int]]:
    match = re.match(r"^FAIL — found (\d+) issue points \((.+)\)$", verdict)
    if not match:
        raise AssertionError(f"Unexpected FAIL verdict format: {verdict!r}")
    total = int(match.group(1))
    parts: dict[str, int] = {}
    for item in match.group(2).split(", "):
        count_str, label = item.split(" ", 1)
        parts[label] = int(count_str)
    return total, parts


def _control_result() -> dict:
    return {
        "fault_at": 0,
        "fault_type": "w",
        "is_control": True,
        "fault_injected": False,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "initial_boot_outcome": "success",
        "initial_boot_slot": "exec",
        "final_boot_outcome": "success",
        "final_boot_slot": "exec",
        "signals": {
            "expectations_met": True,
            "vtor_ok": True,
            "pc_ok": True,
            "memory_checks_ok": True,
        },
        "boot_cycles": [
            {
                "cycle": 0,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": True,
                    "vtor_ok": True,
                    "pc_ok": True,
                    "memory_checks_ok": True,
                },
            },
            {
                "cycle": 1,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": True,
                    "vtor_ok": True,
                    "pc_ok": True,
                    "memory_checks_ok": True,
                },
            },
        ],
        "multi_boot_analysis": {
            "status": "converged",
            "converged_at_cycle": 0,
            "requested_cycles": 2,
            "completed_cycles": 2,
            "initial_outcome": "success",
            "final_outcome": "success",
            "initial_slot": "exec",
            "final_slot": "exec",
        },
    }


def _two_cycle_recovered_result(
    fault_at: int,
    *,
    initial_outcome: str = "hard_fault",
    initial_memory_checks_ok: bool = False,
) -> dict:
    cycles = [
        {
            "cycle": 0,
            "boot_outcome": initial_outcome,
            "boot_slot": None if initial_outcome == "hard_fault" else "exec",
            "signals": {
                "expectations_met": False,
                "vtor_ok": False,
                "pc_ok": False,
                "memory_checks_ok": initial_memory_checks_ok,
                "unmet_memory_checks": ["record_valid"] if not initial_memory_checks_ok else [],
            },
        },
        {
            "cycle": 1,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {
                "expectations_met": True,
                "vtor_ok": True,
                "pc_ok": True,
                "memory_checks_ok": True,
            },
        },
    ]
    analysis = analyze_boot_cycles(cycles, requested_cycles=2)
    return {
        "fault_at": fault_at,
        "fault_type": "w",
        "is_control": False,
        "fault_injected": True,
        "boot_outcome": initial_outcome,
        "boot_slot": cycles[0]["boot_slot"],
        "initial_boot_outcome": initial_outcome,
        "initial_boot_slot": cycles[0]["boot_slot"],
        "final_boot_outcome": "success",
        "final_boot_slot": "exec",
        "signals": dict(cycles[0]["signals"]),
        "boot_cycles": cycles,
        "multi_boot_analysis": analysis,
    }


def _brick_result(fault_at: int) -> dict:
    cycles = [
        {
            "cycle": 0,
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "signals": {"expectations_met": False, "memory_checks_ok": False},
        },
        {
            "cycle": 1,
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "signals": {"expectations_met": False, "memory_checks_ok": False},
        },
    ]
    return {
        "fault_at": fault_at,
        "fault_type": "w",
        "is_control": False,
        "fault_injected": True,
        "boot_outcome": "hard_fault",
        "boot_slot": None,
        "initial_boot_outcome": "hard_fault",
        "initial_boot_slot": None,
        "final_boot_outcome": "hard_fault",
        "final_boot_slot": None,
        "signals": dict(cycles[0]["signals"]),
        "boot_cycles": cycles,
        "multi_boot_analysis": analyze_boot_cycles(cycles, requested_cycles=2),
    }


class SignalCycleConsistencyTests(unittest.TestCase):
    def test_effective_signals_follow_final_cycle_when_promoted(self) -> None:
        result = _two_cycle_recovered_result(2)
        self.assertEqual(result["multi_boot_analysis"]["status"], "recovered_after_failure")
        self.assertEqual(_effective_boot_result(result), ("success", "exec"))
        self.assertTrue(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertFalse(result_is_brick(result))
        self.assertTrue(result_recovered_after_failure(result, "success"))
        self.assertEqual(result_issue_reasons(result, "success"), ["recovered_after_failure"])
        self.assertEqual(classify_issue_category(result, "success"), "recovered_after_failure")
        self.assertFalse(result_is_recovery(result, "success"))

    def test_memory_checks_unmet_on_cycle_0_then_success_is_not_stale_memory_check(
        self,
    ) -> None:
        result = _two_cycle_recovered_result(3, initial_outcome="memory_checks_unmet")
        self.assertEqual(result["multi_boot_analysis"]["status"], "recovered_after_failure")
        self.assertEqual(result_issue_reasons(result, "success"), ["recovered_after_failure"])
        self.assertEqual(classify_issue_category(result, "success"), "recovered_after_failure")

    def test_final_cycle_memory_check_failure_still_counts_as_boot_mismatch(self) -> None:
        result = _two_cycle_recovered_result(4)
        result["boot_cycles"][1]["signals"]["memory_checks_ok"] = False
        reasons = result_issue_reasons(result, "success")
        self.assertIn("memory_check", reasons)
        self.assertIn("recovered_after_failure", reasons)
        self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")

    def test_rollback_converged_is_not_classified_as_recovered_after_failure(self) -> None:
        cycles = [
            {
                "cycle": 0,
                "boot_outcome": "success",
                "boot_slot": "staging",
                "signals": {"expectations_met": True, "vtor_ok": True},
            },
            {
                "cycle": 1,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"expectations_met": True, "vtor_ok": True},
            },
            {
                "cycle": 2,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"expectations_met": True, "vtor_ok": True},
            },
        ]
        result = {
            "fault_at": 1,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "staging",
            "initial_boot_outcome": "success",
            "initial_boot_slot": "staging",
            "final_boot_outcome": "success",
            "final_boot_slot": "exec",
            "signals": dict(cycles[0]["signals"]),
            "boot_cycles": cycles,
            "multi_boot_analysis": analyze_boot_cycles(
                cycles,
                requested_cycles=3,
                target_slot="exec",
                expected_rollback_at_cycle=1,
            ),
        }
        self.assertEqual(result["multi_boot_analysis"]["status"], "rollback_converged")
        self.assertFalse(result_recovered_after_failure(result, "success"))
        self.assertEqual(result_issue_reasons(result, "success"), [])
        self.assertFalse(result_has_issues(result, "success"))
        self.assertTrue(result_is_recovery(result, "success"))

    def test_followup_timeout_keeps_cycle_0_signals_authoritative(self) -> None:
        cycles = [
            {
                "cycle": 0,
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "signals": {"expectations_met": False, "memory_checks_ok": False},
            },
            {
                "cycle": 1,
                "boot_outcome": "timeout",
                "boot_slot": None,
                "stop_reason": "wall_timeout(10s)",
                "signals": {"expectations_met": True, "memory_checks_ok": True},
            },
        ]
        result = {
            "fault_at": 5,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "initial_boot_outcome": "hard_fault",
            "initial_boot_slot": None,
            "final_boot_outcome": "timeout",
            "final_boot_slot": None,
            "signals": dict(cycles[0]["signals"]),
            "boot_cycles": cycles,
            "multi_boot_analysis": analyze_boot_cycles(cycles, requested_cycles=2),
        }
        self.assertEqual(_effective_boot_result(result), ("hard_fault", None))
        self.assertFalse(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertTrue(result_is_brick(result))
        self.assertFalse(result_recovered_after_failure(result, "success"))

    def test_four_cycle_oscillating_ending_in_success_is_not_promoted_and_stays_brick(
        self,
    ) -> None:
        cycles = [
            {
                "cycle": 0,
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "signals": {"expectations_met": False, "memory_checks_ok": False},
            },
            {
                "cycle": 1,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"expectations_met": True, "memory_checks_ok": True},
            },
            {
                "cycle": 2,
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "signals": {"expectations_met": False},
            },
            {
                "cycle": 3,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"expectations_met": True},
            },
        ]
        analysis = analyze_boot_cycles(cycles, requested_cycles=4)
        self.assertEqual(analysis["status"], "oscillating")
        result = {
            "fault_at": 2,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "initial_boot_outcome": "hard_fault",
            "initial_boot_slot": None,
            "final_boot_outcome": "success",
            "final_boot_slot": "exec",
            "signals": dict(cycles[0]["signals"]),
            "boot_cycles": cycles,
            "multi_boot_analysis": analysis,
        }
        self.assertEqual(_effective_boot_result(result), ("hard_fault", None))
        self.assertFalse(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertTrue(result_is_brick(result))
        self.assertFalse(result_recovered_after_failure(result, "success"))
        self.assertEqual(
            result_issue_reasons(result, "success"),
            ["boot_outcome", "memory_check"],
        )
        self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")

    def test_two_cycle_success_then_hard_fault_is_brick_and_boot_mismatch(self) -> None:
        cycles = [
            {
                "cycle": 0,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": True,
                    "vtor_ok": True,
                    "pc_ok": True,
                    "memory_checks_ok": True,
                },
            },
            {
                "cycle": 1,
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "signals": {
                    "expectations_met": False,
                    "vtor_ok": False,
                    "pc_ok": False,
                    "memory_checks_ok": False,
                    "unmet_memory_checks": ["scheduler_flag", "tick_count"],
                },
            },
        ]
        analysis = analyze_boot_cycles(cycles, requested_cycles=2)
        self.assertEqual(analysis["status"], "failed_after_success")
        self.assertEqual(analysis["failed_at_cycle"], 1)
        result = {
            "fault_at": 2,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "recoverable",
            "initial_boot_outcome": "success",
            "initial_boot_slot": "exec",
            "final_boot_outcome": "hard_fault",
            "final_boot_slot": None,
            "signals": dict(cycles[0]["signals"]),
            "boot_cycles": cycles,
            "multi_boot_analysis": analysis,
        }
        self.assertEqual(_effective_boot_result(result), ("hard_fault", None))
        self.assertFalse(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertTrue(result_is_brick(result))
        self.assertFalse(result_recovered_after_failure(result, "success"))
        self.assertFalse(result_is_recovery(result, "success"))
        self.assertEqual(
            result_issue_reasons(result, "success"),
            ["boot_outcome", "memory_check", "vtor_expectation", "pc_expectation"],
        )
        self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")
        self.assertEqual(classify_failure_class(result), "unrecoverable")

        summary = summarize_runtime_sweep(
            [_control_result(), _brick_result(1), result],
            expected_fault_points=2,
        )
        self.assertEqual(summary["bricks"], 2)
        self.assertEqual(summary["issue_points"], 2)
        self.assertEqual(summary["recoveries"], 0)
        self.assertEqual(summary["issue_breakdown"]["boot_mismatch"], 2)
        self.assertEqual(sum(summary["issue_breakdown"].values()), 2)
        verdict = compute_verdict(summary, ExpectConfig(should_find_issues=False))
        self.assertEqual(
            verdict,
            "FAIL — found 2 issue points (2 boot mismatches, 0 semantic, 0 invariant)",
        )

    def test_two_cycle_success_then_memory_checks_unmet_is_boot_mismatch(self) -> None:
        cycles = [
            {
                "cycle": 0,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": True,
                    "vtor_ok": True,
                    "pc_ok": True,
                    "memory_checks_ok": True,
                },
            },
            {
                "cycle": 1,
                "boot_outcome": "memory_checks_unmet",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": False,
                    "vtor_ok": True,
                    "pc_ok": True,
                    "memory_checks_ok": False,
                    "unmet_memory_checks": ["scheduler_flag", "tick_count"],
                },
            },
        ]
        analysis = analyze_boot_cycles(cycles, requested_cycles=2)
        self.assertEqual(analysis["status"], "failed_after_success")
        self.assertEqual(analysis["failed_at_cycle"], 1)
        result = {
            "fault_at": 3,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "recoverable",
            "initial_boot_outcome": "success",
            "initial_boot_slot": "exec",
            "final_boot_outcome": "memory_checks_unmet",
            "final_boot_slot": "exec",
            "signals": dict(cycles[0]["signals"]),
            "boot_cycles": cycles,
            "multi_boot_analysis": analysis,
        }
        self.assertEqual(_effective_boot_result(result), ("memory_checks_unmet", "exec"))
        self.assertFalse(_effective_boot_signals(result)["memory_checks_ok"])
        self.assertFalse(result_is_brick(result))
        self.assertFalse(result_recovered_after_failure(result, "success"))
        self.assertFalse(result_is_recovery(result, "success"))
        self.assertEqual(
            result_issue_reasons(result, "success"),
            ["boot_outcome", "memory_check"],
        )
        self.assertEqual(classify_issue_category(result, "success"), "boot_mismatch")
        self.assertEqual(classify_failure_class(result), "memory_checks_unmet")

        summary = summarize_runtime_sweep(
            [_control_result(), _brick_result(1), result],
            expected_fault_points=2,
        )
        self.assertEqual(summary["bricks"], 1)
        self.assertEqual(summary["issue_points"], 2)
        self.assertEqual(summary["recoveries"], 0)
        self.assertEqual(summary["issue_breakdown"]["boot_mismatch"], 2)
        self.assertEqual(
            summary["failure_outcomes"],
            {"hard_fault": 1, "memory_checks_unmet": 1},
        )
        self.assertEqual(
            summary["failure_classes"],
            {"unrecoverable": 1, "memory_checks_unmet": 1},
        )
        self.assertEqual(sum(summary["issue_breakdown"].values()), 2)
        verdict = compute_verdict(summary, ExpectConfig(should_find_issues=False))
        self.assertEqual(
            verdict,
            "FAIL — found 2 issue points (2 boot mismatches, 0 semantic, 0 invariant)",
        )

    def test_two_cycle_unconfirmed_revert_remains_unchanged(self) -> None:
        for final_outcome in ("success", "wrong_image"):
            with self.subTest(final_outcome=final_outcome):
                cycles = [
                    {
                        "cycle": 0,
                        "boot_outcome": "success",
                        "boot_slot": "staging",
                        "signals": {"expectations_met": True, "vtor_ok": True},
                    },
                    {
                        "cycle": 1,
                        "boot_outcome": final_outcome,
                        "boot_slot": "exec",
                        "signals": {
                            "expectations_met": final_outcome == "success",
                            "vtor_ok": final_outcome == "success",
                        },
                    },
                ]
                analysis = analyze_boot_cycles(cycles, requested_cycles=2)
                self.assertEqual(analysis["status"], "changed_unconfirmed")
                result = {
                    "fault_at": 1,
                    "fault_type": "w",
                    "is_control": False,
                    "fault_injected": True,
                    "boot_outcome": "success",
                    "boot_slot": "staging",
                    "initial_boot_outcome": "success",
                    "initial_boot_slot": "staging",
                    "final_boot_outcome": final_outcome,
                    "final_boot_slot": "exec",
                    "signals": dict(cycles[0]["signals"]),
                    "boot_cycles": cycles,
                    "multi_boot_analysis": analysis,
                }
                self.assertEqual(_effective_boot_result(result), ("success", "staging"))
                self.assertTrue(_effective_boot_signals(result)["vtor_ok"])
                self.assertFalse(result_is_brick(result))
                self.assertFalse(result_has_issues(result, "success"))
                self.assertTrue(result_is_recovery(result, "success"))


class VerdictBreakdownSumTests(unittest.TestCase):
    def test_verdict_breakdown_sums_with_bricks_and_recovered_after_failure(self) -> None:
        results = [
            _control_result(),
            _brick_result(1),
            _two_cycle_recovered_result(2),
            _two_cycle_recovered_result(3),
            _two_cycle_recovered_result(4),
        ]
        summary = summarize_runtime_sweep(results, expected_fault_points=4)
        self.assertEqual(summary["bricks"], 1)
        self.assertEqual(summary["recovered_after_failure_points"], 3)
        self.assertEqual(summary["issue_points"], 4)
        self.assertEqual(sum(summary["issue_breakdown"].values()), summary["issue_points"])

        verdict = compute_verdict(summary, ExpectConfig(should_find_issues=False))
        self.assertEqual(
            verdict,
            "FAIL — found 4 issue points (1 boot mismatches, 3 recovered after failure, 0 semantic, 0 invariant)",
        )
        total, parsed = _parse_verdict_breakdown(verdict)
        self.assertEqual(total, 4)
        self.assertEqual(sum(parsed.values()), total)

    def test_verdict_breakdown_sums_across_all_issue_categories_without_double_counting(
        self,
    ) -> None:
        def _clean_point(fault_at: int, **extra: object) -> dict:
            base = {
                "fault_at": fault_at,
                "fault_type": "w",
                "is_control": False,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {"expectations_met": True},
            }
            base.update(extra)
            return base

        # Include overlapping reasons (e.g., brick + invariant) plus every distinct
        # non-brick category to verify exact partition summing to issue_points.
        brick_and_inv = _brick_result(1)
        brick_and_inv["invariant_violations"] = [{"name": "no_brick_after_recovery"}]
        wrong_image = _clean_point(2, boot_outcome="wrong_image")
        recovered = _two_cycle_recovered_result(3)
        semantic_only = _clean_point(4, semantic_assertion_failures=[{"path": "a"}])
        invariant_only = _clean_point(5, invariant_violations=[{"name": "inv"}])
        metadata_only = _clean_point(6, metadata_delta_violations=[{"field": "boot_count"}])
        confirm_only = _clean_point(7, confirm_cycle={"confirm_incomplete": True})
        escape_only = _clean_point(
            8,
            signals={"expectations_met": True, "terminal_error_escaped": True},
        )
        results = [
            _control_result(),
            brick_and_inv,
            wrong_image,
            recovered,
            semantic_only,
            invariant_only,
            metadata_only,
            confirm_only,
            escape_only,
        ]
        summary = summarize_runtime_sweep(results, expected_fault_points=8)
        self.assertEqual(summary["issue_points"], 8)
        self.assertEqual(sum(summary["issue_breakdown"].values()), 8)
        self.assertEqual(summary["issue_breakdown"]["boot_mismatch"], 2)
        self.assertEqual(summary["issue_breakdown"]["recovered_after_failure"], 1)
        self.assertEqual(summary["issue_breakdown"]["semantic"], 1)
        self.assertEqual(summary["issue_breakdown"]["invariant"], 1)
        self.assertEqual(summary["issue_breakdown"]["metadata_delta"], 1)
        self.assertEqual(summary["issue_breakdown"]["confirm_cycle"], 1)
        self.assertEqual(summary["issue_breakdown"]["terminal_error_escape"], 1)

        verdict = compute_verdict(summary, ExpectConfig(should_find_issues=False))
        total, parsed = _parse_verdict_breakdown(verdict)
        self.assertEqual(total, 8)
        self.assertEqual(sum(parsed.values()), total)
        self.assertEqual(parsed["boot mismatches"], 2)
        self.assertEqual(parsed["recovered after failure"], 1)
        self.assertEqual(parsed["semantic"], 1)
        self.assertEqual(parsed["invariant"], 1)
        self.assertEqual(parsed["metadata_delta"], 1)
        self.assertEqual(parsed["confirm_cycle"], 1)
        self.assertEqual(parsed["terminal_error_escape"], 1)

    def test_verdict_breakdown_includes_multi_fault_and_partial_staging_issues(
        self,
    ) -> None:
        summary = summarize_runtime_sweep(
            [_control_result(), _two_cycle_recovered_result(2)],
            expected_fault_points=1,
        )
        verdict = compute_verdict(
            summary,
            ExpectConfig(should_find_issues=False),
            multi_fault_summary={"bricks": 1, "issue_points": 2},
            partial_staging_summary={
                "total_points": 2,
                "partial_image_points": 1,
                "complete_image_points": 1,
                "complete_image_ok": 1,
                "complete_image_failed": 0,
                "issue_count": 1,
            },
        )
        total, parsed = _parse_verdict_breakdown(verdict)
        self.assertEqual(total, 4)
        self.assertEqual(sum(parsed.values()), total)
        self.assertEqual(parsed["recovered after failure"], 1)
        self.assertEqual(parsed["multi-fault"], 2)
        self.assertEqual(parsed["partial staging"], 1)


class RecoveryWriteTrackingGateTests(unittest.TestCase):
    def test_recovery_reset_bypasses_native_and_python_tracking_gates(self) -> None:
        class Data:
            def __init__(self) -> None:
                self.TrackingStartAddress = 0x20000400
                self.TrackingStarted = False
                self.StartHookInstalled = True
                self.MemoryAccessHookInstalled = False
                self.NativeTrackingStartReliable = False
                self.PreserveCountersAcrossReset = True
                self.TotalWordWrites = 5
                self.LastFaultInjected = False
                self.FaultEverFired = False
                self.WriteFaultMode = 0
                self.DriverErrorFired = False
                self.FaultAtWordWrite = 3

            def WriteTraceClear(self) -> None:
                pass

            def ProgramTraceClear(self) -> None:
                pass

            def InvalidateShadow(self) -> None:
                pass

        class Cpu:
            def __init__(self) -> None:
                self.hooks: list[int] = []

            def AddHook(self, address, _callback) -> None:
                self.hooks.append(address)

            def RemoveHook(self, address, _callback) -> None:
                if address in self.hooks:
                    self.hooks.remove(address)

        data = Data()
        cpu = Cpu()
        machine = {"sysbus.cpu": cpu}
        monitor = SimpleNamespace(
            Machine=machine,
            Parse=lambda _cmd: setattr(data, "TrackingStartAddress", 0x20000400),
        )
        gate_state = {"address": 0, "cpu": None, "installed": False, "started": False}
        ns = _load_runtime_functions(
            "_apply_tracking_start_address",
            "_configure_tracking_start_address",
            "_configure_python_tracking_gate",
            "_set_preserve_counters_across_reset",
            "_machine_reset",
            "disarm_fault",
            "reset_nvmc_for_sweep",
            "reset_nvmc_for_recovery",
            extra_ns={
                "backend": {
                    "kind": "mram",
                    "data": data,
                    "controller": None,
                    "backend_sysbus_name": "sysbus.mramTracker",
                },
                "monitor": monitor,
                "tracking_start_address_config": 0x20000400,
                "_python_tracking_gate": gate_state,
                "_python_tracking_gate_hook": lambda *_args: None,
                "_apply_mram_torn_word_mode": lambda: None,
                "_require_mram_torn_word_support": lambda: None,
                "refresh_runtime_handles": lambda: None,
                "reset_sticky_handoff_state": lambda: None,
                "_DISARM_SENTINEL": 0x7FFFFFFF,
                "disarm_controller_fault": lambda: None,
                "disarm_i2c_fault": lambda: None,
                "log": lambda _msg: None,
            },
        )

        # Phase 1 reset applies the tracking gate (both backend property and CPU hook).
        ns["_machine_reset"]()
        self.assertEqual(data.TrackingStartAddress, 0x20000400)
        self.assertEqual(cpu.hooks, [0x20000400])
        self.assertTrue(gate_state["installed"])
        self.assertFalse(gate_state["started"])

        # Phase 2 recovery reset clears both backend TrackingStartAddress and Python hook.
        ns["_machine_reset"](apply_tracking_gate=False)
        self.assertEqual(data.TrackingStartAddress, 0)
        self.assertEqual(cpu.hooks, [])
        self.assertFalse(gate_state["installed"])
        self.assertTrue(gate_state["started"])

        # Re-enabling for a new Phase 1 sweep restores the gate.
        ns["reset_nvmc_for_sweep"]()
        self.assertEqual(data.TrackingStartAddress, 0x20000400)
        self.assertEqual(cpu.hooks, [0x20000400])

        # reset_nvmc_for_recovery disables both gates by default and zeroes counters.
        data.TotalWordWrites = 9
        ns["reset_nvmc_for_recovery"]()
        self.assertEqual(data.TrackingStartAddress, 0)
        self.assertEqual(cpu.hooks, [])
        self.assertEqual(data.TotalWordWrites, 0)
        self.assertTrue(gate_state["started"])

        # Passing enable_tracking_gate=True (used by clean control Phase 1) keeps
        # both backend and Python CPU tracking gates armed while zeroing counters.
        data.TotalWordWrites = 6
        ns["reset_nvmc_for_recovery"](enable_tracking_gate=True)
        self.assertEqual(data.TrackingStartAddress, 0x20000400)
        self.assertEqual(cpu.hooks, [0x20000400])
        self.assertEqual(data.TotalWordWrites, 0)
        self.assertTrue(gate_state["installed"])
        self.assertFalse(gate_state["started"])

    def test_control_phase1_is_gated_like_calibration_while_recovery_counts_ungated(
        self,
    ) -> None:
        """Control Phase 1 excludes pre-gate NVM writes while recovery stays ungated."""
        gate_addr = 0x20000400

        class SimulatedMram:
            def __init__(self) -> None:
                self.Size = 64
                self._tracking_start_address = 0
                self.TrackingStarted = True
                self.TotalWordWrites = 0
                self.FaultAtWordWrite = 0x7FFFFFFF
                self.LastFaultInjected = False
                self.FaultEverFired = False
                self.WriteFaultMode = 0
                self.DriverErrorFired = False
                self.PreserveCountersAcrossReset = False
                self.PassthroughMode = False
                self.SkipShadowScan = True
                self.DiffLookahead = 32
                self.backing = bytearray(64)

            @property
            def TrackingStartAddress(self) -> int:
                return self._tracking_start_address

            @TrackingStartAddress.setter
            def TrackingStartAddress(self, value: int) -> None:
                self._tracking_start_address = int(value)
                self.TrackingStarted = self._tracking_start_address == 0

            def write_nvm(self) -> bool:
                """Simulate one firmware NVM write; returns True if fault fired."""
                if not self.TrackingStarted:
                    return False
                self.TotalWordWrites += 1
                if self.TotalWordWrites == self.FaultAtWordWrite:
                    self.LastFaultInjected = True
                    self.FaultEverFired = True
                    return True
                return False

            def ReadBytes(self, offset: int, size: int) -> bytes:
                return bytes(self.backing[offset : offset + size])

            def WriteBytes(self, offset: int, buf: bytes, src: int, length: int) -> None:
                self.backing[offset : offset + length] = buf[src : src + length]

            def WriteTraceClear(self) -> None:
                pass

            def ProgramTraceClear(self) -> None:
                pass

            def InvalidateShadow(self) -> None:
                pass

        class SimulatedCpu:
            def __init__(self) -> None:
                self.IsHalted = False
                self.hooks: dict[int, list] = {}

            def AddHook(self, address: int, callback) -> None:
                self.hooks.setdefault(int(address), []).append(callback)

            def RemoveHook(self, address: int, callback) -> None:
                cbs = self.hooks.get(int(address), [])
                if callback in cbs:
                    cbs.remove(callback)
                if not cbs and int(address) in self.hooks:
                    del self.hooks[int(address)]

            def step_to(self, address: int) -> None:
                for cb in list(self.hooks.get(int(address), ())):
                    cb(self, address)

            def GetRegisterUnsafe(self, _reg: int) -> int:
                return 0x10100100

        data = SimulatedMram()
        cpu = SimulatedCpu()
        machine = {"sysbus.cpu": cpu}
        gate_state = {"address": 0, "cpu": None, "installed": False, "started": False}
        observed_phases: list[dict] = []

        def fake_parse(cmd: str) -> None:
            if cmd == "machine Reset":
                cpu.hooks.clear()
                if not data.PreserveCountersAcrossReset:
                    data.TotalWordWrites = 0
                data.TrackingStartAddress = gate_addr

        def run_firmware_boot(*, label: str, pre_gate_writes: int, post_gate_writes: int, hit_gate: bool) -> dict:
            observed_phases.append(
                {
                    "label": label,
                    "tracking_start": data.TrackingStartAddress,
                    "tracking_started": data.TrackingStarted,
                    "hook_installed": gate_addr in cpu.hooks,
                }
            )
            for _ in range(pre_gate_writes):
                if data.write_nvm():
                    return {"reason": "fault_fired", "emulated_s": 0.01, "iters": 1}
            if hit_gate:
                cpu.step_to(gate_addr)
            for _ in range(post_gate_writes):
                if data.write_nvm():
                    return {"reason": "fault_fired", "emulated_s": 0.02, "iters": 2}
            return {"reason": "pc_captured", "emulated_s": 0.05, "iters": 3}

        def fake_run_control_phase1(_cpu_ref, label="control_p1", **_kwargs) -> dict:
            # Firmware writes 1 pre-gate word (e.g. UPDATE_TRIGGER = 0) before
            # entering gate_addr, then 5 post-gate record writes.
            return run_firmware_boot(
                label=label, pre_gate_writes=1, post_gate_writes=5, hit_gate=True
            )

        def fake_run_until_done(_cpu_ref, label="run", **_kwargs) -> dict:
            if label.endswith("_p1"):
                return run_firmware_boot(
                    label=label, pre_gate_writes=1, post_gate_writes=5, hit_gate=True
                )
            if label.endswith("_p2"):
                # Recovery boot writes 3 repair words without ever hitting gate_addr.
                status = run_firmware_boot(
                    label=label, pre_gate_writes=3, post_gate_writes=0, hit_gate=False
                )
                return status
            # Control / fault follow-up boot writes 2 words without hitting gate_addr.
            status = run_firmware_boot(
                label=label, pre_gate_writes=2, post_gate_writes=0, hit_gate=False
            )
            observed_phases[-1]["writes_after_boot"] = data.TotalWordWrites
            return status

        def fake_restore_phase1_baseline() -> None:
            ns["_machine_reset"]()

        def fake_restore_flash_and_boot(saved_flash: bytes) -> None:
            ns["_machine_reset"](apply_tracking_gate=False)
            data.WriteBytes(0, saved_flash, 0, len(saved_flash))

        def fake_build_fault_result(
            fault_at,
            fault_type,
            fault_injected,
            fault_address,
            actual_writes,
            signals,
            boot_outcome=None,
            boot_slot=None,
            eff_criteria=None,
            p2_status=None,
            followup_label="followup",
            extra_fields=None,
            **_kwargs,
        ):
            cycles, analysis, _ms = ns["run_followup_boot_cycles"](
                boot_outcome,
                boot_slot,
                signals,
                initial_status=p2_status,
                fault_injected=fault_injected,
                label=followup_label,
                effective_criteria=eff_criteria,
            )
            res = {
                "fault_at": fault_at,
                "fault_type": fault_type,
                "fault_injected": fault_injected,
                "fault_address": fault_address,
                "actual_writes": actual_writes,
                "boot_outcome": boot_outcome,
                "boot_slot": boot_slot,
                "signals": signals,
                "boot_cycles": cycles,
                "multi_boot_analysis": analysis,
            }
            if extra_fields:
                res.update(extra_fields)
            return res

        ns = _load_runtime_functions(
            "_base_fault_type_code",
            "_apply_tracking_start_address",
            "_configure_tracking_start_address",
            "_python_tracking_gate_hook",
            "_configure_python_tracking_gate",
            "_set_preserve_counters_across_reset",
            "_machine_reset",
            "get_total_writes",
            "arm_fault",
            "disarm_fault",
            "disarm_erase_fault",
            "was_fault_injected",
            "was_controller_fault_injected",
            "reset_nvmc_for_sweep",
            "reset_nvmc_for_recovery",
            "_boot_followup_cycle",
            "_continue_followup_boot_cycles",
            "run_followup_boot_cycles",
            "run_execute_fault",
            extra_ns={
                "backend": {
                    "kind": "mram",
                    "data": data,
                    "controller": None,
                    "backend_sysbus_name": "sysbus.mramTracker",
                },
                "monitor": SimpleNamespace(Machine=machine, Parse=fake_parse),
                "bus": SimpleNamespace(ReadDoubleWord=lambda _addr: 0x20000100),
                "as_int": int,
                "fmt_u32": lambda value: "0x{:08X}".format(int(value)),
                "_time": SimpleNamespace(time=lambda: 0.0),
                "tracking_start_address_config": gate_addr,
                "_python_tracking_gate": gate_state,
                "_last_phase1_setup_detail": None,
                "_last_recovery_setup_detail": None,
                "_apply_mram_torn_word_mode": lambda: None,
                "_require_mram_torn_word_support": lambda: None,
                "refresh_runtime_handles": lambda: None,
                "reset_sticky_handoff_state": lambda: None,
                "_DISARM_SENTINEL": 0x7FFFFFFF,
                "_WRITE_FAULT_MODE": {"w": 0},
                "_I2C_WIRE_CODE_TO_FAULT_TYPE": {},
                "_OTP_WIRE_CODES": frozenset(),
                "max_writes_cap": 32,
                "boot_cycles": 2,
                "phase2_wall_timeout_s": 5.0,
                "phase2_time_slice": "0.02",
                "slot_staging_base": 0x10101000,
                "slot_staging_size": 0x1000,
                "effective_page_size": lambda: 0x1000,
                "success_marker_addr": 0,
                "zero_point_execute_control": False,
                "boundary_setup_env": "",
                "boundary_durable_state_file": "",
                "calibration_mode": False,
                "boundary_phase": "",
                "_hash_bypass_active": False,
                "apply_hash_bypass": lambda: None,
                "writeback_active": lambda: False,
                "get_effective_criteria": lambda _ft: None,
                "reset_verification_probes": lambda: None,
                "restore_phase1_baseline": fake_restore_phase1_baseline,
                "restore_flash_and_boot": fake_restore_flash_and_boot,
                "capture_pre_boot_state_debug": lambda: None,
                "capture_slot_header_debug": lambda _addr: None,
                "capture_metadata_delta_snapshot": lambda: None,
                "reset_rc_injection_state": lambda **_kw: None,
                "_fault_uses_rc_injection_return_hook": lambda _ft: False,
                "disarm_controller_fault": lambda: None,
                "disarm_i2c_fault": lambda: None,
                "arm_vtor_watchpoint": lambda: None,
                "disarm_vtor_watchpoint": lambda: None,
                "_copy_on_boot_vtor_settle_iters": lambda: 0,
                "phase1_wall_timeout": lambda default_s=4.0: default_s,
                "phase1_max_iters": lambda default_s=4.0: 10,
                "run_control_phase1": fake_run_control_phase1,
                "run_until_done": fake_run_until_done,
                "get_last_write_address": lambda: 0x10102008,
                "collect_mram_fault_evidence": lambda _fp, _idx: (
                    {"exact": True, "program_address": "0x10102008"},
                    bytes(data.backing),
                    bytes(data.backing),
                ),
                "_snapshot_mram_fault_uncorrectable_offsets": lambda: [],
                "_snapshot_mram_fault_uncorrectable_addresses": lambda: [],
                "_snapshot_mram_uncorrectable_offsets": lambda: [],
                "_snapshot_mram_uncorrectable_addresses": lambda: [],
                "_restore_mram_uncorrectable_offsets": lambda _offs: None,
                "_clear_mram_uncorrectable_read_log": lambda: None,
                "collect_semantic_state": lambda _ctx: None,
                "evaluate_boot_outcome": lambda *_args, **_kwargs: (
                    "success",
                    "exec",
                    {},
                ),
                "_attach_uncorrectable_read_signals": lambda *_args, **_kwargs: None,
                "merge_verification_probe_signals": lambda _signals: None,
                "merge_stop_status_signals": lambda *_args, **_kwargs: None,
                "add_boundary_contract_signals": lambda _signals: None,
                "run_boot_cycle_hook": lambda _idx, _records: None,
                "build_cycle_record": lambda idx, outcome, slot, signals, **_kw: {
                    "cycle": idx,
                    "boot_outcome": outcome,
                    "boot_slot": slot,
                    "signals": signals,
                },
                "analyze_boot_cycles": lambda records: {
                    "status": "converged",
                    "completed_cycles": len(records),
                },
                "_build_fault_result": fake_build_fault_result,
                "log": lambda _msg: None,
            },
        )

        # 1. Calibration-equivalent Phase 1 setup: gated, counts only the 5 post-gate writes.
        ns["_machine_reset"]()
        ns["reset_nvmc_for_sweep"]()
        ns["disarm_fault"]()
        run_firmware_boot(
            label="calibration_p1", pre_gate_writes=1, post_gate_writes=5, hit_gate=True
        )
        calibration_writes = ns["get_total_writes"]()
        self.assertEqual(calibration_writes, 5)

        # 2. Clean control run (fault_at = -1): Phase 1 must stay behind the gate
        #    (matching calibration) while its follow-up recovery boot runs ungated.
        control_result = ns["run_execute_fault"](-1, "control")
        self.assertEqual(control_result["actual_writes"], calibration_writes)
        self.assertEqual(control_result["signals"]["phase1_ops_total"], calibration_writes)

        # 3. Fault point (fault_at = 2): Phase 1 stays gated (fault hits the 3rd
        #    post-gate write), and Phase 2 recovery still counts all 3 recovery writes.
        fault_result = ns["run_execute_fault"](2, "w")
        self.assertTrue(fault_result["fault_injected"])
        self.assertEqual(fault_result["actual_writes"], 2)
        self.assertEqual(fault_result["signals"]["phase1_ops_total"], 3)
        self.assertEqual(fault_result["recovery_writes"], 3)

        by_label = {entry["label"]: entry for entry in observed_phases}
        self.assertEqual(by_label["calibration_p1"]["tracking_start"], gate_addr)
        self.assertTrue(by_label["calibration_p1"]["hook_installed"])

        self.assertEqual(by_label["control_p1"]["tracking_start"], gate_addr)
        self.assertFalse(by_label["control_p1"]["tracking_started"])
        self.assertTrue(by_label["control_p1"]["hook_installed"])

        self.assertEqual(by_label["control_followup_1"]["tracking_start"], 0)
        self.assertTrue(by_label["control_followup_1"]["tracking_started"])
        self.assertFalse(by_label["control_followup_1"]["hook_installed"])
        self.assertEqual(by_label["control_followup_1"]["writes_after_boot"], 2)

        self.assertEqual(by_label["fp2_p1"]["tracking_start"], gate_addr)
        self.assertTrue(by_label["fp2_p1"]["hook_installed"])
        self.assertEqual(by_label["fp2_p2"]["tracking_start"], 0)
        self.assertTrue(by_label["fp2_p2"]["tracking_started"])
        self.assertFalse(by_label["fp2_p2"]["hook_installed"])

    def test_trace_replay_paths_record_recovery_writes(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(RUNTIME_PATH))
        for fn_name in ("run_trace_replay_fault_native", "run_trace_replay_fault"):
            fn = next(
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == fn_name
            )
            segment = ast.get_source_segment(source, fn) or ""
            self.assertIn("recovery_writes = get_total_writes()", segment)
            self.assertIn("'recovery_writes': recovery_writes", segment)


class TwoCycleRecoveryFixtureTests(unittest.TestCase):
    def test_profiles_load_strictly_and_match_compiled_tracking_address(self) -> None:
        if shutil.which("arm-none-eabi-gcc") is None or shutil.which("arm-none-eabi-nm") is None:
            self.skipTest("arm-none-eabi toolchain is not installed")
        fixture_dir = ROOT / "examples" / "two_cycle_recovery"
        subprocess.run(
            ["make", "-C", str(fixture_dir), "all"],
            check=True,
            capture_output=True,
            text=True,
        )
        profile = load_profile(fixture_dir / "profile.yaml", strict=True)
        self.assertEqual(profile.fault_sweep.boot_cycles, 2)
        self.assertEqual(profile.fault_sweep.tracking_start_address, 0x20000400)
        self.assertFalse(profile.expect.should_find_issues)

        osc_profile = load_profile(fixture_dir / "profile_oscillating.yaml", strict=True)
        self.assertEqual(osc_profile.fault_sweep.boot_cycles, 3)
        self.assertEqual(osc_profile.fault_sweep.tracking_start_address, 0x20000400)

        osc4_profile = load_profile(
            fixture_dir / "profile_oscillating_4cycle.yaml", strict=True
        )
        self.assertEqual(osc4_profile.fault_sweep.boot_cycles, 4)
        self.assertEqual(osc4_profile.fault_sweep.tracking_start_address, 0x20000400)

        fail2_profile = load_profile(
            fixture_dir / "profile_fail_second_boot.yaml", strict=True
        )
        self.assertEqual(fail2_profile.fault_sweep.boot_cycles, 2)
        self.assertEqual(fail2_profile.fault_sweep.tracking_start_address, 0x20000400)

        unmet2_profile = load_profile(
            fixture_dir / "profile_unmet_checks_second_boot.yaml", strict=True
        )
        self.assertEqual(unmet2_profile.fault_sweep.boot_cycles, 2)
        self.assertEqual(unmet2_profile.fault_sweep.tracking_start_address, 0x20000400)

        for elf_name in (
            "app.elf",
            "oscillating.elf",
            "fail_second_boot.elf",
            "unmet_checks_second_boot.elf",
        ):
            nm = subprocess.run(
                ["arm-none-eabi-nm", "-n", str(fixture_dir / elf_name)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertRegex(
                nm.stdout,
                r"(?m)^20000400 [tT] write_record$",
                msg=f"{elf_name}:\n{nm.stdout}",
            )


if __name__ == "__main__":
    unittest.main()
