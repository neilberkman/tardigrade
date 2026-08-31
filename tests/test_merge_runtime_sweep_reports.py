from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from merge_runtime_sweep_reports import merge_runtime_sweep_payloads


def _base_payload() -> dict:
    return {
        "engine": "renode-test",
        "profile": "test-profile",
        "profile_path": None,
        "schema_version": 1,
        "calibrated_writes": 10,
        "calibrated_erases": 0,
        "setup_writes": 2,
        "quick": False,
        "heuristic": {},
        "heuristic_config": {},
        "multi_fault": None,
        "verdict": "FAIL",
        "expect": {"should_find_issues": True},
        "security_policy": {},
        "git": {"commit": "deadbeef"},
        "runtime_sweep_results": [],
    }


def test_merge_runtime_sweep_payloads_recomputes_summary() -> None:
    payload_a = _base_payload()
    payload_a["runtime_sweep_results"] = [
        {"is_control": True, "boot_outcome": "success", "boot_slot": "exec"},
        {
            "fault_at": 10,
            "fault_type": "i",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
        },
    ]
    payload_b = _base_payload()
    payload_b["runtime_sweep_results"] = [
        {"is_control": True, "boot_outcome": "success", "boot_slot": "exec"},
        {
            "fault_at": 20,
            "fault_type": "i",
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        },
    ]

    merged = merge_runtime_sweep_payloads([payload_a, payload_b])

    assert merged["fault_points_tested"] == 2
    assert len(merged["runtime_sweep_results"]) == 3
    assert sum(1 for row in merged["runtime_sweep_results"] if row.get("is_control")) == 1
    summary = merged["summary"]["runtime_sweep"]
    assert summary["total_fault_points"] == 2
    assert summary["issue_points"] == 1
    assert summary["recoveries"] == 1
    assert summary["control"]["effective_outcome"] == "success"


def test_merge_runtime_sweep_payloads_dedupes_duplicate_fault_rows() -> None:
    payload = _base_payload()
    row = {
        "fault_at": 42,
        "fault_type": "i",
        "fault_injected": True,
        "boot_outcome": "wrong_image",
        "boot_slot": "staging",
    }
    payload["runtime_sweep_results"] = [
        {"is_control": True, "boot_outcome": "success", "boot_slot": "exec"},
        row,
    ]

    merged = merge_runtime_sweep_payloads([payload, json.loads(json.dumps(payload))])

    assert merged["fault_points_tested"] == 1
    non_control = [r for r in merged["runtime_sweep_results"] if not r.get("is_control")]
    assert non_control == [row]


def test_merge_runtime_sweep_payloads_preserves_explicit_target_source() -> None:
    payload_a = _base_payload()
    payload_b = _base_payload()
    target_source = {
        "name": "example-target",
        "repository": "https://example.invalid/target",
        "revision": "4f8c0d3e2a1b9876543210fedcba0123456789ab",
    }
    payload_a["target_source"] = target_source
    payload_b["target_source"] = dict(target_source)

    merged = merge_runtime_sweep_payloads([payload_a, payload_b])

    assert merged["target_source"] == target_source


def test_merge_runtime_sweep_payloads_rejects_mismatched_target_sources() -> None:
    payload_a = _base_payload()
    payload_b = _base_payload()
    payload_a["target_source"] = {"revision": "source-a"}
    payload_b["target_source"] = {"revision": "source-b"}

    with pytest.raises(ValueError, match="different target sources"):
        merge_runtime_sweep_payloads([payload_a, payload_b])
