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
        "expect": {"should_find_issues": True, "control_outcome": "success"},
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


def test_merge_runtime_sweep_payloads_preserves_rc_injection_policy() -> None:
    payload_a = _base_payload()
    payload_b = _base_payload()
    policy = {"severity_model": "availability", "return_value": 0xFFFFFFFB}
    payload_a["rc_injection_config"] = policy
    payload_b["rc_injection_config"] = dict(policy)

    merged = merge_runtime_sweep_payloads([payload_a, payload_b])

    assert merged["rc_injection_config"] == policy


def test_merge_runtime_sweep_payloads_applies_embedded_rc_availability_policy() -> None:
    payload = _base_payload()
    payload["rc_injection_config"] = {
        "severity_model": "availability",
        "require_applied": False,
    }
    payload["runtime_sweep_results"] = [
        {
            "fault_at": 1,
            "fault_type": "x",
            "fault_injected": True,
            "boot_outcome": "bus_fault",
        }
    ]

    merged = merge_runtime_sweep_payloads([payload])
    summary = merged["summary"]["runtime_sweep"]

    assert summary["issue_points"] == 1
    assert summary["bricks"] == 1


def test_merge_availability_policy_overrides_stale_dos_only_validation() -> None:
    payload = _base_payload()
    payload["rc_injection_config"] = {
        "severity_model": "availability",
        "require_applied": False,
    }
    payload["runtime_sweep_results"] = [
        {
            "fault_at": 1,
            "fault_type": "x",
            "fault_injected": True,
            "boot_outcome": "no_boot",
            "finding_validation": {
                "stage": "dismissed",
                "disposition": "dos_only",
            },
        }
    ]

    merged = merge_runtime_sweep_payloads([payload])
    summary = merged["summary"]["runtime_sweep"]

    assert summary["issue_points"] == 1
    assert summary["bricks"] == 1


def test_merge_runtime_sweep_payloads_applies_embedded_expected_outcome() -> None:
    payload = _base_payload()
    payload["expect"]["control_outcome"] = "wrong_image"
    payload["runtime_sweep_results"] = [
        {
            "fault_at": 1,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "exec",
        }
    ]

    merged = merge_runtime_sweep_payloads([payload])
    summary = merged["summary"]["runtime_sweep"]

    assert summary["issue_points"] == 0
    assert summary["recoveries"] == 1


def test_merge_runtime_sweep_payloads_rejects_mismatched_rc_policy() -> None:
    payload_a = _base_payload()
    payload_b = _base_payload()
    payload_a["rc_injection_config"] = {"severity_model": "security"}
    payload_b["rc_injection_config"] = {"severity_model": "availability"}

    with pytest.raises(ValueError, match="different RC injection policies"):
        merge_runtime_sweep_payloads([payload_a, payload_b])


def test_merge_runtime_sweep_payloads_rejects_mismatched_expectations() -> None:
    payload_a = _base_payload()
    payload_b = _base_payload()
    payload_b["expect"]["control_outcome"] = "wrong_image"

    with pytest.raises(ValueError, match="different expectations"):
        merge_runtime_sweep_payloads([payload_a, payload_b])
