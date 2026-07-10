from __future__ import annotations

import sys
import textwrap
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import audit_bootloader  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from state_fuzz import (  # noqa: E402
    extract_state_fuzz_result,
    generate_state_scenarios,
    resolve_metadata_model,
    summarize_state_campaign,
)


BASE_PROFILE_YAML = textwrap.dedent(
    """\
    schema_version: 1
    name: state_fuzz_test
    description: "State fuzz profile"
    platform: platforms/cortex_m0_nvm.repl
    flash_backend: nvm_ctrl
    bootloader:
      elf: examples/vulnerable_ota/firmware.elf
      entry: 0x10000000
    memory:
      sram: { start: 0x20000000, end: 0x20020000 }
      write_granularity: 8
      slots:
        exec:    { base: 0x10000000, size: 0x38000 }
        staging: { base: 0x00040000, size: 0x38000 }
    images:
      staging: examples/vulnerable_ota/firmware.bin
    success_criteria:
      vtor_in_slot: exec
    fault_sweep:
      mode: runtime
      max_writes: 8
    state_fuzzer:
      enabled: true
      iterations: 6
      seed: 7
      metadata_model:
        base_address: 0x00080000
        fields:
          - { name: active_slot, offset: 0, size: 1, valid: [0, 1] }
          - { name: seq, offset: 4, size: 4, type: uint32 }
          - { name: boot_count, offset: 8, size: 1, valid_range: [0, 10] }
          - { name: crc, offset: 12, size: 4, type: computed_crc32 }
    expect:
      should_find_issues: false
    """
)


def _write_profile(tmp_path: Path, body: str = BASE_PROFILE_YAML) -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_state_fuzzer_profile_parses_structured_model(tmp_path: Path) -> None:
    profile = load_profile(_write_profile(tmp_path))
    assert profile.state_fuzzer.enabled is True
    assert profile.state_fuzzer.iterations == 6
    assert profile.state_fuzzer.seed == 7
    model = profile.state_fuzzer.metadata_model
    assert isinstance(model, dict)
    assert model["base_address"] == 0x00080000
    assert model["fields"][0]["name"] == "active_slot"
    assert model["fields"][-1]["type"] == "computed_crc32"


def test_generate_state_scenarios_cycles_modes_and_crc() -> None:
    model = resolve_metadata_model(
        {
            "base_address": 0x00080000,
            "fields": [
                {"name": "active_slot", "offset": 0, "size": 1, "valid": [0, 1]},
                {"name": "seq", "offset": 4, "size": 4, "type": "uint32"},
                {"name": "crc", "offset": 8, "size": 4, "type": "computed_crc32"},
            ],
        },
        default_base=0x00080000,
    )
    scenarios = generate_state_scenarios(model, iterations=6, seed=1)
    assert [s["mode"] for s in scenarios[:3]] == [
        "random_bytes",
        "structured_random",
        "boundary",
    ]
    assert scenarios[0]["pre_boot_state"][0][0] == 0x00080000

    first_blob = scenarios[0]["blob"]
    first_crc = int.from_bytes(first_blob[8:12], "little")
    assert first_crc == (zlib.crc32(first_blob[:8]) & 0xFFFFFFFF)

    second_blob = scenarios[1]["blob"]
    second_crc = int.from_bytes(second_blob[8:12], "little")
    assert second_crc != (zlib.crc32(second_blob[:8]) & 0xFFFFFFFF)


def test_state_fuzzer_rejects_non_terminal_crc_field(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        schema_version: 1
        name: state_fuzz_test
        description: "State fuzz profile"
        platform: platforms/cortex_m0_nvm.repl
        flash_backend: nvm_ctrl
        bootloader:
          elf: examples/vulnerable_ota/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20020000 }
          write_granularity: 8
          slots:
            exec:    { base: 0x10000000, size: 0x38000 }
            staging: { base: 0x00040000, size: 0x38000 }
        images:
          staging: examples/vulnerable_ota/firmware.bin
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          mode: runtime
          max_writes: 8
        state_fuzzer:
          enabled: true
          metadata_model:
            base_address: 0x00080000
            fields:
              - { name: active_slot, offset: 0, size: 1, valid: [0, 1] }
              - { name: crc, offset: 8, size: 4, type: computed_crc32 }
              - { name: trailing, offset: 12, size: 1, valid: [0, 1] }
        expect:
          should_find_issues: false
        """
    )
    with pytest.raises(Exception, match="computed_crc32 field must be the final field"):
        load_profile(_write_profile(tmp_path, body))


def _dummy_result(
    index: int, *, outcome: str, slot: str, finding: bool = False
) -> dict:
    return {
        "scenario_index": index,
        "boot_outcome": outcome,
        "boot_slot": slot,
        "effective_outcome": outcome,
        "effective_slot": slot,
        "issue_count": 1 if finding else 0,
        "issue_reasons": {"wrong_image": 1} if finding else {},
        "finding": finding,
    }


def test_summary_warns_when_all_scenarios_collapse_to_one_outcome() -> None:
    results = [
        _dummy_result(i, outcome="recovery", slot="exec") for i in range(50)
    ]
    summary = summarize_state_campaign(
        results,
        expected_outcome="success",
        metadata_model={"magic": 0xDEADBEEF},
        iterations=50,
    )
    assert "warnings" in summary
    assert any(
        "single effective" in w and "misconfigured" in w
        for w in summary["warnings"]
    )
    assert summary["iterations_completed"] == 50


def test_summary_has_no_warning_when_outcomes_diverge() -> None:
    results = [
        _dummy_result(i, outcome="success", slot="staging")
        for i in range(10)
    ] + [
        _dummy_result(10, outcome="recovery", slot="exec"),
    ]
    summary = summarize_state_campaign(
        results,
        expected_outcome="success",
        metadata_model={},
        iterations=11,
    )
    assert "warnings" not in summary


def test_summary_has_no_warning_below_diversity_floor() -> None:
    # Small smoke runs can legitimately land on a single effective tuple;
    # do not warn until we have enough samples to claim a funnel collapse.
    summary0 = summarize_state_campaign([], "success", {}, iterations=0)
    summary1 = summarize_state_campaign(
        [_dummy_result(0, outcome="success", slot="staging")],
        "success",
        {},
        iterations=1,
    )
    summary_under_floor = summarize_state_campaign(
        [
            _dummy_result(i, outcome="recovery", slot="exec")
            for i in range(9)
        ],
        "success",
        {},
        iterations=9,
    )
    assert "warnings" not in summary0
    assert "warnings" not in summary1
    assert "warnings" not in summary_under_floor


def test_summary_distinguishes_effective_from_raw_slot() -> None:
    # effective_outcome/slot can differ from boot_outcome when a fault is
    # classified as a "recovery" convergence; the diversity check must use
    # the effective pair so it doesn't false-positive on raw noise.
    results = [
        {"boot_outcome": raw, "boot_slot": None,
         "effective_outcome": "recovery", "effective_slot": "exec",
         "issue_reasons": {}, "finding": False}
        for raw in (
            ["bus_fault"] * 5 + ["timeout"] * 5
        )
    ]
    summary = summarize_state_campaign(
        results, "success", {}, iterations=len(results)
    )
    assert "warnings" in summary


def test_extract_state_fuzz_result_suppresses_baseline_slot_mismatch_for_invalid_scenario() -> None:
    model = resolve_metadata_model(
        {
            "base_address": 0x00080000,
            "fields": [
                {"name": "active_slot", "offset": 0, "size": 1, "valid": [1]},
                {"name": "seq", "offset": 4, "size": 4, "type": "uint32"},
                {"name": "boot_count", "offset": 8, "size": 1, "valid_range": [0, 2]},
                {"name": "crc", "offset": 12, "size": 4, "type": "computed_crc32"},
            ],
        },
        default_base=0x00080000,
    )
    scenario = {
        "index": 2,
        "mode": "boundary",
        "crc_mode": "valid",
        "blob_sha256": "deadbeef",
        "field_values": {
            "active_slot": 0,
            "seq": 1,
            "boot_count": 1,
            "crc": 0,
        },
    }
    result = {
        "boot_outcome": "wrong_pc",
        "boot_slot": "exec",
        "effective_outcome": "wrong_pc",
        "effective_slot": "exec",
        "effective_success_criteria": {"vtor_slot": "staging"},
        "signals": {"expectations_met": False, "vtor_ok": False, "pc_ok": False},
    }

    extracted = extract_state_fuzz_result(
        scenario=scenario,
        result=result,
        expected_outcome="success",
        metadata_model=model,
    )

    assert extracted["scenario_matches_model"] is False
    assert extracted["finding"] is False
    assert extracted["issue_reasons"] == {}


def test_extract_state_fuzz_result_keeps_slot_mismatch_for_valid_scenario() -> None:
    model = resolve_metadata_model(
        {
            "base_address": 0x00080000,
            "fields": [
                {"name": "active_slot", "offset": 0, "size": 1, "valid": [1]},
                {"name": "seq", "offset": 4, "size": 4, "type": "uint32"},
                {"name": "boot_count", "offset": 8, "size": 1, "valid_range": [0, 2]},
                {"name": "crc", "offset": 12, "size": 4, "type": "computed_crc32"},
            ],
        },
        default_base=0x00080000,
    )
    scenario = {
        "index": 3,
        "mode": "structured_random",
        "crc_mode": "valid",
        "blob_sha256": "feedface",
        "field_values": {
            "active_slot": 1,
            "seq": 1,
            "boot_count": 1,
            "crc": 0,
        },
    }
    result = {
        "boot_outcome": "wrong_pc",
        "boot_slot": "exec",
        "effective_outcome": "wrong_pc",
        "effective_slot": "exec",
        "effective_success_criteria": {"vtor_slot": "staging"},
        "signals": {"expectations_met": False, "vtor_ok": False, "pc_ok": False},
    }

    extracted = extract_state_fuzz_result(
        scenario=scenario,
        result=result,
        expected_outcome="success",
        metadata_model=model,
    )

    assert extracted["scenario_matches_model"] is True
    assert extracted["finding"] is True
    assert extracted["issue_reasons"] == {
        "boot_outcome": 1,
        "pc_expectation": 1,
        "vtor_expectation": 1,
    }


def test_state_fuzz_preserves_infrastructure_error_without_counting_finding() -> None:
    scenario = {
        "index": 4,
        "mode": "structured_random",
        "crc_mode": "valid",
        "blob_sha256": "infra",
        "field_values": {},
    }
    result = {
        "boot_outcome": "success",
        "boot_slot": "exec",
        "infrastructure_error": True,
        "error_kind": "invariant_evaluation_error",
        "invariant_violations": [{"name": "invariant_evaluation_error"}],
        "signals": {},
    }

    extracted = extract_state_fuzz_result(
        scenario=scenario,
        result=result,
        expected_outcome="success",
        metadata_model=None,
    )
    summary = summarize_state_campaign(
        [extracted],
        expected_outcome="success",
        metadata_model={},
        iterations=1,
    )

    assert extracted["infrastructure_error"] is True
    assert extracted["error_kind"] == "invariant_evaluation_error"
    assert extracted["finding"] is False
    assert summary["infrastructure_errors"] == 1
    assert summary["findings"] == 0


def test_run_state_fuzz_campaign_builds_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = load_profile(_write_profile(tmp_path))
    captured_robot_vars = []

    def fake_run_single_point(**kwargs):
        captured_robot_vars.extend(kwargs["robot_vars"])
        return {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "signals": {"marker_ok": False},
        }

    monkeypatch.setattr(audit_bootloader, "run_single_point", fake_run_single_point)

    results, summary = audit_bootloader.run_state_fuzz_campaign(
        profile,
        repo_root=ROOT,
        renode_test="renode-test",
        robot_suite="tests/ota_fault_point.robot",
        work_dir=tmp_path / "work",
        renode_remote_server_dir="",
        evaluation_mode="state",
        stall_timeout=5.0,
        extra_robot_vars=[],
        keep_run_artifacts=False,
    )

    assert len(results) == profile.state_fuzzer.iterations
    assert summary["iterations_completed"] == profile.state_fuzzer.iterations
    assert summary["findings"] == profile.state_fuzzer.iterations
    assert any(rv.startswith("PRE_BOOT_STATE_BIN:") for rv in captured_robot_vars)
    assert "EVALUATION_MODE:state" in captured_robot_vars
