from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_bootloader import (  # noqa: E402
    _aggregate_auxiliary_verdict,
    _compute_calibration_cache_key,
    _initial_state_child_command,
    _is_pass_verdict,
    _multi_component_campaign_robot_vars,
    _multi_component_verdict,
    _renode_cache_identity,
    _run_initial_state_matrix,
    _validate_profile_asset_containment,
)
from fault_inject import FaultResult  # noqa: E402
from fault_classification import result_issue_reasons  # noqa: E402
from invariants import run_invariants  # noqa: E402
from profile_loader import load_profile  # noqa: E402


class _Component:
    def __init__(self, name: str, expected: str = "success") -> None:
        self.name = name
        self.expected = expected

    def to_profile_config(self, _parent):
        return SimpleNamespace(
            expect=SimpleNamespace(control_outcome=self.expected)
        )


def _profile(*, should_find_issues: bool = False):
    return SimpleNamespace(
        expect=SimpleNamespace(should_find_issues=should_find_issues),
        multi_component=SimpleNamespace(
            components=[_Component("app"), _Component("radio")]
        ),
    )


def _component_data(
    *,
    issue_points: int = 0,
    timeout_points: int = 0,
    infrastructure_error_points: int = 0,
    planned: int = 1,
    campaign_complete: bool = True,
):
    return {
        "fault_points_tested": planned,
        "summary": {
            "campaign_complete": campaign_complete,
            "issue_points": issue_points,
            "bricks": issue_points,
            "timeout_points": timeout_points,
            "infrastructure_error_points": infrastructure_error_points,
            "control": {
                "effective_outcome": "success",
                "issue_count": 0,
            },
        },
    }


def test_multi_component_all_failed_is_not_ignored() -> None:
    result = {
        "per_component": {
            "app": _component_data(),
            "radio": _component_data(),
        },
        "combined_summary": {
            "split_brain": 0,
            "all_failed": 1,
            "degraded": 0,
        },
    }
    assert _multi_component_verdict(result, _profile()).startswith("FAIL")


def test_multi_component_timeout_is_inconclusive() -> None:
    result = {
        "per_component": {
            "app": _component_data(timeout_points=1),
            "radio": _component_data(),
        },
        "combined_summary": {},
    }
    assert _multi_component_verdict(result, _profile()).startswith("INCONCLUSIVE")


def test_multi_component_infrastructure_error_is_inconclusive() -> None:
    result = {
        "per_component": {
            "app": _component_data(infrastructure_error_points=1),
            "radio": _component_data(),
        },
        "combined_summary": {},
    }
    assert _multi_component_verdict(result, _profile()).startswith("INCONCLUSIVE")


def test_each_multi_component_must_plan_faults() -> None:
    result = {
        "per_component": {
            "app": _component_data(planned=0),
            "radio": _component_data(),
        },
        "combined_summary": {},
    }
    verdict = _multi_component_verdict(result, _profile())
    assert verdict == "INCONCLUSIVE -- component 'app' planned no fault points"


def test_multi_component_incomplete_campaign_is_inconclusive() -> None:
    result = {
        "per_component": {
            "app": _component_data(campaign_complete=False),
            "radio": _component_data(),
        },
        "combined_summary": {},
    }

    verdict = _multi_component_verdict(result, _profile())
    assert verdict == "INCONCLUSIVE -- component 'app' campaign was incomplete"


def test_multi_component_missing_configured_component_is_inconclusive() -> None:
    result = {
        "per_component": {"app": _component_data()},
        "combined_summary": {},
    }

    verdict = _multi_component_verdict(result, _profile())
    assert verdict.startswith("INCONCLUSIVE")
    assert "missing radio" in verdict


def test_multi_component_unexpected_component_is_inconclusive() -> None:
    result = {
        "per_component": {
            "app": _component_data(),
            "radio": _component_data(),
            "extra": _component_data(),
        },
        "combined_summary": {},
    }

    verdict = _multi_component_verdict(result, _profile())
    assert verdict.startswith("INCONCLUSIVE")
    assert "unexpected extra" in verdict


def test_state_fuzz_findings_affect_clean_profile_verdict() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "PASS",
        _profile(),
        state_fuzz_results=[{"boot_outcome": "success", "finding": True}],
        state_fuzz_summary={
            "iterations_requested": 1,
            "iterations_completed": 1,
            "findings": 1,
        },
        fuzz_crash_results=None,
        fuzz_crash_summary=None,
        geometry_preflight=None,
    )
    assert verdict.startswith("FAIL")


def test_state_fuzz_can_satisfy_expected_finding_policy() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "FAIL — expected to find issues but found none",
        _profile(should_find_issues=True),
        state_fuzz_results=[{"boot_outcome": "success", "finding": True}],
        state_fuzz_summary={
            "iterations_requested": 1,
            "iterations_completed": 1,
            "findings": 1,
        },
        fuzz_crash_results=None,
        fuzz_crash_summary=None,
        geometry_preflight=None,
    )
    assert verdict == "PASS"


def test_state_fuzz_infrastructure_error_cannot_satisfy_expected_findings() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "FAIL — expected to find issues but found none",
        _profile(should_find_issues=True),
        state_fuzz_results=[{
            "boot_outcome": "success",
            "infrastructure_error": True,
            "error_kind": "invariant_evaluation_error",
            "finding": False,
        }],
        state_fuzz_summary={
            "iterations_requested": 1,
            "iterations_completed": 1,
            "findings": 0,
            "infrastructure_errors": 1,
        },
        fuzz_crash_results=None,
        fuzz_crash_summary=None,
        geometry_preflight=None,
    )
    assert verdict.startswith("INCONCLUSIVE")


def test_fuzz_crash_requires_at_least_one_generated_regression() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "PASS",
        _profile(),
        state_fuzz_results=None,
        state_fuzz_summary=None,
        fuzz_crash_results=[],
        fuzz_crash_summary={
            "generated_profiles": 0,
            "results": 0,
            "security_findings": 0,
        },
        geometry_preflight=None,
    )
    assert verdict == "INCONCLUSIVE -- fuzz-crash campaign generated no regressions"


def test_fuzz_crash_requires_successful_child_exit() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "PASS",
        _profile(),
        state_fuzz_results=None,
        state_fuzz_summary=None,
        fuzz_crash_results=[{
            "returncode": 2,
            "verdict": "PASS",
            "security_finding": True,
        }],
        fuzz_crash_summary={
            "generated_profiles": 1,
            "results": 1,
            "security_findings": 1,
        },
        geometry_preflight=None,
    )
    assert verdict == "INCONCLUSIVE -- fuzz-crash child exited with status 2"


def test_geometry_mismatch_is_inconclusive() -> None:
    verdict = _aggregate_auxiliary_verdict(
        "PASS",
        _profile(),
        state_fuzz_results=None,
        state_fuzz_summary=None,
        fuzz_crash_results=None,
        fuzz_crash_summary=None,
        geometry_preflight={"status": "mismatch", "reason": "slot differs"},
    )
    assert verdict.startswith("INCONCLUSIVE")


def test_initial_state_child_command_replaces_parent_output(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit_bootloader.py",
            "--profile",
            "profile.yaml",
            "--output",
            "parent.json",
            "--quick",
        ],
    )
    child_output = tmp_path / "child.json"
    command = _initial_state_child_command("damaged_copy", child_output)
    assert "parent.json" not in command
    assert command[command.index("--output") + 1] == str(child_output)
    assert command[command.index("--initial-state") + 1] == "damaged_copy"
    assert "--no-assert-verdict" in command
    assert "--no-assert-control-boots" in command


@pytest.mark.parametrize(
    ("verdict", "accepted"),
    [
        ("PASS", True),
        (" PASS — details ", True),
        ("PASS details", True),
        ("PASSFAIL", False),
        ("PASS\nFAIL", False),
        ("PASS \nFAIL", False),
        ("PASS \rFAIL", False),
        ("PASS \tFAIL", False),
        ("PASS\x00FAIL", False),
        ("", False),
        (None, False),
        (1, False),
    ],
)
def test_initial_state_pass_verdict_protocol(verdict, accepted) -> None:
    assert _is_pass_verdict(verdict) is accepted


def test_initial_state_matrix_rejects_pass_prefix_garbage(
    monkeypatch, tmp_path
) -> None:
    output = tmp_path / "matrix.json"
    args = SimpleNamespace(
        repo_root=str(ROOT),
        output=str(output),
        no_assert_verdict=False,
    )
    profile = SimpleNamespace(
        name="matrix_fixture",
        profile_path=tmp_path / "profile.yaml",
        schema_version=1,
        initial_states=[
            SimpleNamespace(name="state_a", description="fixture state")
        ],
    )

    def fake_run(command, **_kwargs):
        if command and command[0] == "git":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        child_output = Path(command[command.index("--output") + 1])
        child_output.write_text(
            '{"verdict":"PASSFAIL","summary":{}}',
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("audit_bootloader.subprocess.run", fake_run)
    assert _run_initial_state_matrix(args, profile) == 1
    payload = __import__("json").loads(output.read_text(encoding="utf-8"))
    assert payload["verdict"].startswith("FAIL")
    assert payload["summary"]["initial_states"]["passed"] == 0


def test_multi_component_base_vars_exclude_parent_profile_contracts() -> None:
    variables = _multi_component_campaign_robot_vars(
        ["CALLER_FLAG:enabled"],
        12.5,
    )
    assert variables == [
        "CALLER_FLAG:enabled",
        "PROGRESS_STALL_TIMEOUT_S:12.500000",
    ]
    assert not any(value.startswith("SUCCESS_") for value in variables)


def test_invariant_evaluation_error_is_recorded() -> None:
    result = FaultResult(
        fault_at=1,
        boot_outcome="success",
        boot_slot="exec",
        nvm_state={},
        raw_log="",
    )

    def broken_invariant(_result, **_context):
        raise ValueError("unparseable observation")

    violations = run_invariants(result, invariants=[broken_invariant])
    assert len(violations) == 1
    assert violations[0].invariant_name == "invariant_evaluation_error"


def test_structured_success_check_reasons_are_reported() -> None:
    reasons = result_issue_reasons(
        {
            "boot_outcome": "wrong_image",
            "signals": {
                "memory_checks_ok": False,
                "config_checks_ok": False,
                "bootloader_integrity_ok": False,
            },
        },
        expected_outcome="success",
    )
    assert "memory_check" in reasons
    assert "config_check" in reasons
    assert "bootloader_integrity" in reasons


def test_calibration_key_includes_success_criteria() -> None:
    profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
    before = _compute_calibration_cache_key(profile, ROOT)
    profile.success_criteria.marker_value = 0xA5A5A5A5
    after = _compute_calibration_cache_key(profile, ROOT)
    assert before != after


def test_calibration_key_includes_effective_robot_overrides() -> None:
    profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
    first = _compute_calibration_cache_key(
        profile,
        ROOT,
        robot_vars=["CALLER_OVERRIDE:first"],
    )
    second = _compute_calibration_cache_key(
        profile,
        ROOT,
        robot_vars=["CALLER_OVERRIDE:second"],
    )
    assert first != second


def test_calibration_key_hashes_file_valued_robot_override(tmp_path) -> None:
    profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
    external_input = tmp_path / "input.bin"
    external_input.write_bytes(b"first")
    robot_vars = ["CALLER_FILE:{}".format(external_input)]
    first = _compute_calibration_cache_key(
        profile,
        ROOT,
        robot_vars=robot_vars,
    )
    external_input.write_bytes(b"second")
    second = _compute_calibration_cache_key(
        profile,
        ROOT,
        robot_vars=robot_vars,
    )
    assert first != second


def test_calibration_key_hashes_secondary_profile_inputs(tmp_path) -> None:
    profile = load_profile(ROOT / "profiles" / "naive_bare_copy.yaml")
    firmware = tmp_path / "firmware.elf"
    nvs_snapshot = tmp_path / "nvs.bin"
    prior_image = tmp_path / "prior.bin"
    firmware.write_bytes(b"firmware-one")
    nvs_snapshot.write_bytes(b"nvs-one")
    prior_image.write_bytes(b"prior-one")
    profile.firmware_elf = str(firmware)
    profile.nvs_region = SimpleNamespace(
        address=0x10000000,
        size=0x100,
        snapshot=str(nvs_snapshot),
    )
    profile.residual_image = SimpleNamespace(
        slot="staging",
        prior_image=str(prior_image),
        fill_pattern=None,
    )
    baseline = _compute_calibration_cache_key(profile, ROOT)
    for path, replacement in (
        (firmware, b"firmware-two"),
        (nvs_snapshot, b"nvs-two"),
        (prior_image, b"prior-two"),
    ):
        original = path.read_bytes()
        path.write_bytes(replacement)
        try:
            assert _compute_calibration_cache_key(profile, ROOT) != baseline
        finally:
            path.write_bytes(original)


def test_failed_renode_version_probe_is_not_tool_identity(tmp_path) -> None:
    runner = tmp_path / "renode-test"
    runner.write_text("#!/bin/sh\n", encoding="utf-8")

    with mock.patch(
        "audit_bootloader.subprocess.run",
        return_value=SimpleNamespace(returncode=2, stdout="usage: first", stderr=""),
    ):
        first = _renode_cache_identity(str(runner))
    with mock.patch(
        "audit_bootloader.subprocess.run",
        return_value=SimpleNamespace(returncode=2, stdout="usage: changed", stderr=""),
    ):
        second = _renode_cache_identity(str(runner))
    assert first == second


def test_mutable_docker_cache_identity_requires_local_image_digest() -> None:
    with mock.patch(
        "audit_bootloader.subprocess.run",
        return_value=SimpleNamespace(returncode=1, stdout="", stderr="missing"),
    ), pytest.raises(RuntimeError, match="inspectable image ID"):
        _renode_cache_identity("docker://renode-patched:test")

    with mock.patch(
        "audit_bootloader.subprocess.run",
        return_value=SimpleNamespace(
            returncode=0,
            stdout="sha256:" + ("a" * 64) + "\n",
            stderr="",
        ),
    ):
        identity = _renode_cache_identity("docker://renode-patched:test")
    assert "sha256:" + ("a" * 64) in identity


def test_calibration_key_hashes_transitive_platform_surface(tmp_path) -> None:
    platforms = tmp_path / "platforms"
    platforms.mkdir()
    (platforms / "main.repl").write_text(
        'using "included.repl"\n', encoding="utf-8"
    )
    included = platforms / "included.repl"
    included.write_text("first revision\n", encoding="utf-8")
    (tmp_path / "boot.elf").write_bytes(b"ELF")
    (tmp_path / "image.bin").write_bytes(b"image")
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            name: cache_transitive_platform
            platform: platforms/main.repl
            bootloader: { elf: boot.elf, entry: 0x10000000 }
            memory:
              sram: { start: 0x20000000, end: 0x20010000 }
              write_granularity: 4
              slots:
                exec: { base: 0x10000000, size: 0x1000 }
                staging: { base: 0x10001000, size: 0x1000 }
            images: { staging: image.bin }
            success_criteria: { vtor_in_slot: exec }
            fault_sweep: { mode: runtime, max_writes: 1, fault_types: [power_loss] }
            expect: { should_find_issues: false }
            """
        ),
        encoding="utf-8",
    )
    profile = load_profile(profile_path)
    first = _compute_calibration_cache_key(profile, tmp_path)
    included.write_text("second revision\n", encoding="utf-8")
    second = _compute_calibration_cache_key(profile, tmp_path)
    assert first != second


def test_strict_runtime_containment_rejects_asset_symlink(tmp_path) -> None:
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "platform.repl").write_text("mach create\n", encoding="utf-8")
    (root / "platform.repl").symlink_to(outside / "platform.repl")
    (root / "firmware.elf").write_bytes(b"ELF")
    (root / "image.bin").write_bytes(b"image")
    profile_path = root / "profile.yaml"
    profile_path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            name: containment
            platform: platform.repl
            bootloader: { elf: firmware.elf, entry: 0x10000000 }
            memory:
              sram: { start: 0x20000000, end: 0x20010000 }
              write_granularity: 4
              slots:
                exec: { base: 0x10000000, size: 0x1000 }
                staging: { base: 0x10001000, size: 0x1000 }
            images: { staging: image.bin }
            success_criteria: { vtor_in_slot: exec }
            fault_sweep: { mode: runtime, max_writes: 1, fault_types: [power_loss] }
            expect: { should_find_issues: false }
            """
        ),
        encoding="utf-8",
    )
    profile = load_profile(profile_path, strict=True)
    with pytest.raises(RuntimeError, match="escapes repository root"):
        _validate_profile_asset_containment(profile, root)


def test_strict_runtime_containment_rejects_partial_staging_symlink(
    tmp_path,
) -> None:
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "platform.repl").write_text("mach create\n", encoding="utf-8")
    (root / "firmware.elf").write_bytes(b"ELF")
    (root / "image.bin").write_bytes(b"image")
    (outside / "partial.bin").write_bytes(b"partial")
    (root / "partial.bin").symlink_to(outside / "partial.bin")
    profile_path = root / "profile.yaml"
    profile_path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            name: partial_staging_containment
            platform: platform.repl
            bootloader: { elf: firmware.elf, entry: 0x10000000 }
            memory:
              sram: { start: 0x20000000, end: 0x20010000 }
              write_granularity: 4
              slots:
                exec: { base: 0x10000000, size: 0x1000 }
                staging: { base: 0x10001000, size: 0x1000 }
            images: { staging: image.bin }
            success_criteria: { vtor_in_slot: exec }
            fault_sweep:
              mode: runtime
              max_writes: 1
              fault_types: [power_loss]
              partial_staging: { staging_image: partial.bin }
            expect: { should_find_issues: false }
            """
        ),
        encoding="utf-8",
    )
    profile = load_profile(profile_path, strict=True)
    with pytest.raises(RuntimeError, match="escapes repository root"):
        _validate_profile_asset_containment(profile, root)
