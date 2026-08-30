#!/usr/bin/env python3
"""Regression tests for fail-closed runtime campaign accounting."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from audit_report import compute_verdict, summarize_runtime_sweep  # noqa: E402
from renode_runner import (  # noqa: E402
    RenodeProtocolError,
    _run_batch_with_fallback,
    _validate_batch_results,
    run_batch,
    run_single_point,
)


def _expect(*, should_find_issues: bool = False, allow_control_only: bool = False):
    return SimpleNamespace(
        should_find_issues=should_find_issues,
        control_outcome="success",
        allow_control_only_issues=allow_control_only,
    )


def _control(*, zero_point: bool = False) -> dict:
    return {
        "is_control": True,
        "fault_injected": False,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "signals": {"zero_point_execute_control": zero_point},
    }


def test_arbitrary_runner_failure_cannot_satisfy_expected_findings() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 7,
            "fault_requested": 7,
            "fault_injected": False,
            "boot_outcome": "infra_error",
            "infrastructure_error": True,
            "error_kind": "runner_error",
            "error": "invalid JSON result",
        },
    ]
    summary = summarize_runtime_sweep(results)

    assert summary["infrastructure_error_points"] == 1
    assert summary["incomplete_fault_points"] == 1
    verdict = compute_verdict(summary, _expect(should_find_issues=True))
    assert verdict.startswith("FAIL")
    assert "infrastructure error" in verdict


def test_verified_timeout_is_incomplete_not_a_recovery() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 9,
            "fault_requested": 9,
            "fault_injected": False,
            "boot_outcome": "timeout",
            "timeout": True,
            "error_kind": "wall_timeout",
        },
    ]
    summary = summarize_runtime_sweep(results)

    assert summary["timeout_points"] == 1
    assert summary["recoveries"] == 0
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "timed out" in verdict


@pytest.mark.parametrize(
    ("final_outcome", "summary_key", "verdict_text"),
    [
        ("infra_error", "infrastructure_error_points", "infrastructure error"),
        ("timeout", "timeout_points", "timed out"),
        ("skipped", "skipped_fault_points", "were skipped"),
    ],
)
def test_nested_runner_status_cannot_become_an_expected_finding_pass(
    final_outcome,
    summary_key,
    verdict_text,
) -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 9,
            "fault_requested": 9,
            "fault_injected": True,
            "boot_outcome": "success",
            "final_boot_outcome": final_outcome,
        },
    ]

    summary = summarize_runtime_sweep(results, expected_fault_points=1)

    assert summary[summary_key] == 1
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect(should_find_issues=True))
    assert verdict.startswith("FAIL")
    assert verdict_text in verdict


def test_string_false_fault_injected_cannot_complete_campaign() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 4,
            "fault_requested": 4,
            "fault_type": "w",
            "fault_injected": "false",
            "boot_outcome": "success",
        },
    ]
    summary = summarize_runtime_sweep(results, expected_fault_points=1)

    assert summary["malformed_result_points"] == 1
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "malformed" in verdict


def test_faulted_control_cannot_be_accepted_as_clean_baseline() -> None:
    control = _control()
    control["fault_injected"] = True
    results = [
        control,
        {
            "is_control": False,
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "success",
        },
    ]
    summary = summarize_runtime_sweep(results, expected_fault_points=1)

    assert summary["faulted_control_points"] == 1
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "control run reported that fault injection fired" in verdict


def test_implicit_power_loss_batch_rejects_wrong_runtime_fault_type() -> None:
    with pytest.raises(RenodeProtocolError, match="fault type mismatch"):
        _validate_batch_results(
            [
                {
                    "fault_requested": 3,
                    "fault_at": 3,
                    "fault_type": "b",
                    "fault_injected": True,
                    "boot_outcome": "success",
                }
            ],
            [3],
            None,
        )


def test_result_protocol_rejects_non_boolean_fault_injected() -> None:
    with pytest.raises(RenodeProtocolError, match="fault_injected must be a boolean"):
        _validate_batch_results(
            [
                {
                    "fault_requested": 3,
                    "fault_at": 3,
                    "fault_type": "w",
                    "fault_injected": "false",
                    "boot_outcome": "success",
                }
            ],
            [3],
            ["w"],
        )


@pytest.mark.parametrize(
    "boot_outcome",
    [None, 7, "", "   ", "unknown", "UNKNOWN", "protocol_typo", " success", "SUCCESS"],
)
def test_result_protocol_rejects_invalid_boot_outcome(boot_outcome) -> None:
    with pytest.raises(RenodeProtocolError, match="boot_outcome"):
        _validate_batch_results(
            [
                {
                    "fault_requested": 3,
                    "fault_at": 3,
                    "fault_type": "w",
                    "fault_injected": True,
                    "boot_outcome": boot_outcome,
                }
            ],
            [3],
            ["w"],
        )


@pytest.mark.parametrize(
    "result_update",
    [
        {"initial_boot_outcome": "protocol_typo"},
        {"final_boot_outcome": "protocol_typo"},
        {"boot_cycles": [{"boot_outcome": "protocol_typo"}]},
        {"multi_boot_analysis": {"final_outcome": "protocol_typo"}},
        {
            "multi_boot_analysis": {
                "outcomes_observed": ["success", "protocol_typo"]
            }
        },
    ],
)
def test_result_protocol_rejects_invalid_nested_boot_outcomes(result_update) -> None:
    result = {
        "fault_requested": 3,
        "fault_at": 3,
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "success",
    }
    result.update(result_update)
    with pytest.raises(RenodeProtocolError, match="boot_outcome|outcome"):
        _validate_batch_results([result], [3], ["w"])


def test_faults_that_never_fire_make_campaign_incomplete() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 11,
            "fault_requested": 11,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "skip_reason": "target_not_reached",
        },
    ]
    summary = summarize_runtime_sweep(results)

    assert summary["requested_fault_points"] == 1
    assert summary["injected_fault_points"] == 0
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict == "FAIL \u2014 campaign injected none of 1 requested fault point(s)"


def test_probability_gate_is_an_intentional_exclusion_when_coverage_fires() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 10,
            "fault_requested": 10,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        },
        {
            "is_control": False,
            "fault_at": 11,
            "fault_requested": 11,
            "fault_injected": False,
            "boot_outcome": "skipped",
            "skip_reason": "probability_gate",
        },
    ]

    summary = summarize_runtime_sweep(results, expected_fault_points=2)

    assert summary["intentionally_skipped_fault_points"] == 1
    assert summary["discarded_no_fault_fired"] == 1
    assert summary["skip_reasons"] == {"probability_gate": 1}
    assert summary["campaign_complete"] is True
    assert compute_verdict(summary, _expect()) == "PASS"


def test_probability_gate_still_requires_nonzero_fired_coverage() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 11,
            "fault_requested": 11,
            "fault_injected": False,
            "boot_outcome": "skipped",
            "skip_reason": "probability_gate",
        },
    ]

    summary = summarize_runtime_sweep(results, expected_fault_points=1)

    assert summary["campaign_complete"] is False
    assert compute_verdict(summary, _expect()) == (
        "FAIL \u2014 campaign injected none of 1 requested fault point(s)"
    )


def test_unexpected_empty_campaign_fails() -> None:
    summary = summarize_runtime_sweep([_control()])

    assert summary["campaign_intentionally_control_only"] is False
    assert compute_verdict(summary, _expect()) == (
        "FAIL \u2014 campaign executed no fault points"
    )


def test_fault_campaign_without_clean_control_fails() -> None:
    summary = summarize_runtime_sweep(
        [{
            "is_control": False,
            "fault_at": 1,
            "fault_requested": 1,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        }],
        expected_fault_points=1,
    )
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict == "FAIL — campaign requires 1 clean control point(s), observed 0"


def test_duplicate_clean_controls_fail() -> None:
    summary = summarize_runtime_sweep(
        [
            _control(),
            _control(),
            {
                "is_control": False,
                "fault_at": 1,
                "fault_requested": 1,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
            },
        ],
        expected_fault_points=1,
    )
    assert summary["campaign_complete"] is False
    assert compute_verdict(summary, _expect()).startswith(
        "FAIL — campaign requires 1 clean control point(s), observed 2"
    )


def test_explicit_zero_point_control_remains_supported() -> None:
    summary = summarize_runtime_sweep([_control(zero_point=True)])

    assert summary["campaign_intentionally_control_only"] is True
    assert summary["campaign_complete"] is True
    assert compute_verdict(summary, _expect()) == "PASS"


def test_explicit_zero_point_control_does_not_require_calibration_activity() -> None:
    summary = summarize_runtime_sweep(
        [_control(zero_point=True)],
        expected_fault_points=0,
        calibration_coverage={
            "status": "no_nvm_activity",
            "reason": "Calibration produced no NVM writes or erases.",
        },
    )

    assert compute_verdict(summary, _expect()) == "PASS"


def test_control_only_expectation_opt_in_remains_supported() -> None:
    expect = _expect(should_find_issues=True, allow_control_only=True)
    profile = SimpleNamespace(
        expect=expect,
        fault_sweep=None,
        metadata_fault_regions=[],
    )
    summary = summarize_runtime_sweep([_control()], profile=profile)

    assert summary["campaign_intentionally_control_only"] is True
    assert compute_verdict(summary, expect) == "PASS \u2014 control exhibits expected success"


def test_timed_out_control_cannot_validate_control_only_campaign() -> None:
    control = _control(zero_point=True)
    control.update({"boot_outcome": "no_boot", "timeout": True})
    summary = summarize_runtime_sweep([control], expected_fault_points=0)

    assert summary["control_timeout_points"] == 1
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "control run timed out" in verdict


def test_batch_cardinality_mismatch_becomes_protocol_error_result() -> None:
    with tempfile.TemporaryDirectory() as td:
        with mock.patch("renode_runner.run_batch", return_value=[]):
            results = _run_batch_with_fallback(
                repo_root=ROOT,
                renode_test="renode-test",
                robot_suite="tests/ota_fault_point.robot",
                profile=SimpleNamespace(name="open_source_fixture"),
                fault_points=[13],
                robot_vars=[],
                work_dir=Path(td),
                renode_remote_server_dir="",
                fault_types_list=["w"],
            )

    assert len(results) == 1
    assert results[0]["fault_requested"] == 13
    assert results[0]["fault_injected"] is False
    assert results[0]["infrastructure_error"] is True
    assert results[0]["error_kind"] == "protocol_error"
    assert "cardinality mismatch" in results[0]["error"]


def test_batch_fault_type_mismatch_becomes_protocol_error_result() -> None:
    returned = [{
        "fault_at": 17,
        "fault_requested": 17,
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "success",
    }]
    with tempfile.TemporaryDirectory() as td:
        with mock.patch("renode_runner.run_batch", return_value=returned):
            results = _run_batch_with_fallback(
                repo_root=ROOT,
                renode_test="renode-test",
                robot_suite="tests/ota_fault_point.robot",
                profile=SimpleNamespace(name="open_source_fixture"),
                fault_points=[17],
                robot_vars=[],
                work_dir=Path(td),
                renode_remote_server_dir="",
                fault_types_list=["on"],
            )

    assert results[0]["fault_injected"] is False
    assert results[0]["error_kind"] == "protocol_error"
    assert "fault type mismatch" in results[0]["error"]


def test_missing_top_level_planner_result_blocks_pass() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 21,
            "fault_requested": 21,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        },
    ]
    summary = summarize_runtime_sweep(results, expected_fault_points=2)

    assert summary["requested_fault_points"] == 2
    assert summary["returned_fault_points"] == 1
    assert summary["missing_result_points"] == 1
    assert summary["campaign_complete"] is False
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "requested 2, returned 1" in verdict


def test_control_only_opt_in_cannot_hide_missing_planner_results() -> None:
    expect = _expect(should_find_issues=True, allow_control_only=True)
    profile = SimpleNamespace(
        expect=expect,
        fault_sweep=None,
        metadata_fault_regions=[],
    )
    summary = summarize_runtime_sweep(
        [_control()],
        profile=profile,
        expected_fault_points=1,
    )

    assert summary["campaign_intentionally_control_only"] is False
    assert summary["campaign_complete"] is False
    assert compute_verdict(summary, expect).startswith("FAIL")


def test_extra_top_level_runner_result_blocks_pass() -> None:
    results = [
        _control(),
        {
            "is_control": False,
            "fault_at": 31,
            "fault_requested": 31,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        },
        {
            "is_control": False,
            "fault_at": 32,
            "fault_requested": 32,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
        },
    ]
    summary = summarize_runtime_sweep(results, expected_fault_points=1)

    assert summary["extra_result_points"] == 1
    verdict = compute_verdict(summary, _expect())
    assert verdict.startswith("FAIL")
    assert "requested 1, returned 2" in verdict


def test_incomplete_multi_fault_campaign_blocks_clean_main_campaign() -> None:
    main_summary = summarize_runtime_sweep(
        [
            _control(),
            {
                "is_control": False,
                "fault_at": 41,
                "fault_requested": 41,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
            },
        ],
        expected_fault_points=1,
    )
    multi_summary = summarize_runtime_sweep(
        [], expected_fault_points=1, expected_control_points=0
    )

    verdict = compute_verdict(
        main_summary,
        _expect(),
        multi_fault_summary=multi_summary,
    )
    assert verdict.startswith("FAIL")
    assert "multi-fault campaign incomplete" in verdict


def test_compound_fault_results_validate_semantically_and_restore_wire_type() -> None:
    cases = [
        (
            1,
            "mf:1:2",
            {
                "fault_at": 1,
                "fault_requested": 1,
                "fault_type": "mf",
                "fault_sequence": [1, 2],
            },
        ),
        (
            3,
            "p2:3:4:w:b",
            {
                "fault_at": 3,
                "fault_requested": 3,
                "fault_type": "p2",
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 4,
                    "p1_fault_type": "w",
                    "p2_fault_type": "b",
                },
            },
        ),
        (
            5,
            "h:5:k",
            {
                "fault_at": 5,
                "fault_requested": 5,
                "fault_type": "h:k",
                "hook_fault": {"hook_fault_at": 5, "hook_fault_type": "k"},
            },
        ),
        (
            6,
            "cc:6:w",
            {
                "fault_at": 6,
                "fault_requested": 6,
                "fault_type": "cc:w",
                "confirm_cycle": {"cc_fault_at": 6, "cc_fault_type": "w"},
            },
        ),
        (
            0x1000,
            "i:0x1000",
            {
                "fault_at": 0x1000,
                "fault_requested": 0x1000,
                "fault_type": "i",
                "signals": {"skip_address": "0x00001000"},
            },
        ),
        (
            8,
            "tb:0x1010:0x2020:3",
            {
                "fault_at": 8,
                "fault_requested": 8,
                "fault_type": "tb:0x1010:0x2020",
                "signals": {"timed_bit_flip_count": 3},
            },
        ),
        (
            9,
            "b:123",
            {
                "fault_at": 9,
                "fault_requested": 9,
                "fault_type": "b",
                "signals": {"corruption_seed": 123},
            },
        ),
        (
            10,
            "m:w",
            {
                "fault_at": 10,
                "fault_requested": 10,
                "fault_type": "w",
                "signals": {
                    "metadata_fault_applied": 10,
                    "metadata_fault_total": 20,
                },
            },
        ),
        (
            11,
            "c:11:2",
            {
                "fault_at": 11,
                "fault_requested": 11,
                "fault_type": "cascade",
                "cascade": {"write_fault_at": 11, "erase_fault_at": 2},
            },
        ),
    ]

    for point, expected_type, raw_result in cases:
        raw_result["fault_injected"] = True
        raw_result["boot_outcome"] = "success"
        observed_type = raw_result["fault_type"]
        validated = _validate_batch_results(
            [raw_result], [point], [expected_type]
        )[0]
        assert validated["fault_type"] == expected_type
        assert validated["fault_requested_type"] == expected_type
        assert validated["fault_observed_type"] == observed_type


def test_compound_fault_metadata_mismatch_is_protocol_error() -> None:
    with pytest.raises(RenodeProtocolError, match="fault type mismatch"):
        _validate_batch_results(
            [{
                "fault_at": 1,
                "fault_requested": 1,
                "fault_type": "mf",
                "fault_injected": True,
                "fault_sequence": [1, 3],
                "boot_outcome": "success",
            }],
            [1],
            ["mf:1:2"],
        )


def test_compound_fault_runtime_telemetry_contract() -> None:
    runtime_source = (SCRIPTS / "run_runtime_fault_sweep.py").read_text(
        encoding="utf-8"
    )

    assert "result_signals['corruption_seed'] = int(cseed)" in runtime_source
    assert "signals['timed_bit_flip_count'] = int(bit_flips)" in runtime_source
    assert "signals['trigger_armed'] = _tb_active['armed']" in runtime_source
    assert "_tb_state['armed']" not in runtime_source


def test_state_mode_clean_control_preserves_control_identity() -> None:
    runtime_source = (SCRIPTS / "run_runtime_fault_sweep.py").read_text(
        encoding="utf-8"
    )

    assert "requested_fault_type = 'control' if int(fault_at) < 0 else 'w'" in runtime_source
    assert "'fault_type': requested_fault_type" in runtime_source


def test_single_point_cannot_reuse_stale_result_file() -> None:
    profile = SimpleNamespace(name="stale", fault_sweep=None)
    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        stale_result = work_dir / "stale_fault_7" / "result.json"
        stale_result.parent.mkdir(parents=True)
        stale_result.write_text(
            '{"fault_at":7,"fault_requested":7,"boot_outcome":"success"}',
            encoding="utf-8",
        )
        with mock.patch(
            "renode_runner.run_renode_subprocess",
            return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
        ):
            with pytest.raises(RuntimeError, match="did not produce"):
                run_single_point(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_at=7,
                    robot_vars=[],
                    work_dir=work_dir,
                    renode_remote_server_dir="",
                )


def test_single_point_rejects_mismatched_result_identity() -> None:
    profile = SimpleNamespace(name="identity", fault_sweep=None)

    def fake_run(cmd, *, cwd, env, timeout_s):
        result_token = next(
            cmd[index + 1]
            for index, token in enumerate(cmd[:-1])
            if token == "--variable"
            and cmd[index + 1].startswith("RESULT_FILE:")
        )
        result_path = Path(result_token.split(":", 1)[1])
        result_path.write_text(
            '{"fault_at":8,"fault_requested":8,"boot_outcome":"success"}',
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with tempfile.TemporaryDirectory() as td:
        with mock.patch("renode_runner.run_renode_subprocess", side_effect=fake_run):
            with pytest.raises(RenodeProtocolError, match="request mismatch"):
                run_single_point(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_at=7,
                    robot_vars=[],
                    work_dir=Path(td),
                    renode_remote_server_dir="",
                )


def test_batch_cannot_reuse_stale_result_file() -> None:
    profile = SimpleNamespace(
        name="stale_batch_profile",
        fault_sweep=None,
        has_update_sequence=False,
    )
    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        stale_result = work_dir / "stale_batch_profile_batch" / "result.json"
        stale_result.parent.mkdir(parents=True)
        stale_result.write_text(
            '[{"fault_at":7,"fault_requested":7,"fault_type":"w"}]',
            encoding="utf-8",
        )
        with mock.patch(
            "renode_runner.run_renode_subprocess",
            return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
        ):
            with pytest.raises(RuntimeError, match="did not produce"):
                run_batch(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[7],
                    fault_types_list=["w"],
                    robot_vars=[],
                    work_dir=work_dir,
                    renode_remote_server_dir="",
                )
