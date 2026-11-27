"""Tests for the one-command demo summary and smoke-test gate."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from run_demo import (  # noqa: E402
    DemoResult,
    format_summary,
    result_from_report,
    smoke_test_exit_code,
    smoke_test_failures,
)
from profile_loader import load_profile  # noqa: E402


def _payload(*, profile: str, findings: int, outcome: str = "success"):
    failures = []
    results = [
        {
            "is_control": True,
            "fault_at": -1,
            "boot_outcome": "success",
        }
    ]
    if findings:
        failures.append(
            {
                "fault_at": 7,
                "fault_address": "0x10000038",
                "outcome": outcome,
            }
        )
        results.append(
            {
                "fault_at": 7,
                "fault_address": "0x10000038",
                "fault_injected": True,
                "initial_boot_outcome": outcome,
                "initial_boot_slot": "exec",
                "boot_outcome": "success",
            }
        )
    return {
        "profile": profile,
        "summary": {
            "runtime_sweep": {
                "returned_fault_points": 3,
                "issue_points": findings,
                "failures": failures,
            }
        },
        "runtime_sweep_results": results,
    }


def test_summary_formats_counts_first_cut_and_next_boot() -> None:
    broken_path = ROOT / "results/demo/naive_bare_copy.json"
    recovering_path = ROOT / "results/demo/demo_mcuboot_offset_upgrade.json"
    broken = result_from_report(
        _payload(profile="naive_bare_copy", findings=1, outcome="no_boot"),
        label="broken",
        report_path=broken_path,
    )
    recovering = result_from_report(
        _payload(profile="demo_mcuboot_offset_upgrade", findings=0),
        label="recovering",
        report_path=recovering_path,
    )

    rendered = format_summary([broken, recovering], repo_root=ROOT)

    assert "naive_bare_copy [broken]: 3 points run, 1 finding" in rendered
    assert (
        "first finding: cut operation 7 at 0x10000038; "
        "next boot did not boot (slot exec)"
    ) in rendered
    assert "demo_mcuboot_offset_upgrade [recovering]: 3 points run, 0 findings" in rendered
    assert "broken: results/demo/naive_bare_copy.json" in rendered
    assert "scripts/render_results_html.py" in rendered
    assert rendered.endswith("Smoke test: PASS")


def test_points_run_falls_back_to_point_count_totals_without_control() -> None:
    payload = {
        "profile": "fallback",
        "summary": {
            "runtime_sweep": {
                "issue_points": 0,
                "point_counts": {
                    "totals": {"run": 4},
                    "kinds": {"control": {"run": 1}},
                },
            }
        },
    }

    result = result_from_report(
        payload, label="recovering", report_path=Path("fallback.json")
    )

    assert result.points_run == 3


def test_smoke_gate_requires_findings_only_from_broken_profile() -> None:
    broken = DemoResult("broken", "broken", Path("broken.json"), 3, 1)
    recovering = DemoResult(
        "recovering", "recovering", Path("recovering.json"), 3, 0
    )

    assert smoke_test_failures([broken, recovering]) == []
    assert smoke_test_exit_code([broken, recovering]) == 0

    no_broken_finding = DemoResult(
        "broken", "broken", Path("broken.json"), 3, 0
    )
    unexpected_recovering_finding = DemoResult(
        "recovering", "recovering", Path("recovering.json"), 3, 2
    )
    failures = smoke_test_failures(
        [no_broken_finding, unexpected_recovering_finding]
    )

    assert failures == [
        "the broken profile showed no finding",
        "the recovering profile showed 2 finding(s)",
    ]
    assert smoke_test_exit_code(
        [no_broken_finding, unexpected_recovering_finding]
    ) == 1


def test_recovering_demo_profile_limits_quick_run_to_power_loss() -> None:
    profile = load_profile(
        ROOT / "profiles/demo_mcuboot_offset_upgrade.yaml",
        strict=True,
        repo_root=ROOT,
    )

    assert profile.name == "demo_mcuboot_offset_upgrade"
    assert profile.fault_sweep.evaluation_mode == "execute"
    assert profile.fault_sweep.fault_types == ["power_loss"]
    assert profile.expect.should_find_issues is False
