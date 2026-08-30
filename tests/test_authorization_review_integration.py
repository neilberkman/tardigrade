"""Integration coverage for vendor-neutral authorization-review plumbing."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit_bootloader  # noqa: E402
import profile_loader  # noqa: E402
from authorization_review_analyzer import (  # noqa: E402
    analyze_authorization_review,
    authorization_review_model_digest,
    load_trace,
)
from profile_loader import ProfileError, load_profile  # noqa: E402
from render_results_html import render_authorization_review_panel  # noqa: E402


def _authorization_review() -> dict:
    return {
        "scalars": {
            "value": {
                "path": "request.value",
                "type": "bytes",
                "max_bytes": 32,
                "review": "required",
                "authorization": "required",
            }
        },
        "digests": {"auth": {"algorithm": "sha256", "covers": ["value"]}},
        "events": {
            "parse": {"kind": "parse", "produces": ["value"]},
            "review": {"kind": "user_review", "reviews": ["value"]},
            "digest": {"kind": "digest", "digest": "auth"},
            "signature": {"kind": "signature", "digest": "auth"},
            "authorize": {"kind": "authorization", "requires": ["value"]},
        },
        "sequences": [{"name": "normal", "events": [
            "parse", "review", "digest", "signature", "authorize",
        ]}],
    }


def _profile(*, name: str = "authorization-integration", authorization: bool = True) -> dict:
    data = {
        "schema_version": 1,
        "name": name,
        "description": "authorization integration fixture",
        "platform": "platforms/cortex_m0_nvm.repl",
        "flash_backend": "nvm_ctrl",
        "bootloader": {
            "elf": "examples/vulnerable_ota/firmware.elf",
            "entry": 0x10000000,
        },
        "memory": {
            "sram": {"start": 0x20000000, "end": 0x20020000},
            "write_granularity": 8,
            "slots": {
                "exec": {"base": 0x10000000, "size": 0x38000},
                "staging": {"base": 0x10038000, "size": 0x38000},
            },
        },
        "images": {"staging": "examples/vulnerable_ota/firmware.bin"},
        "success_criteria": {
            "vtor_in_slot": "exec",
            "image_hash": True,
            "expected_image": "staging",
        },
        "fault_sweep": {
            "mode": "runtime",
            "max_writes": 1,
            "max_writes_cap": 1,
            "run_duration": "0.01",
        },
        "expect": {"should_find_issues": False},
    }
    if authorization:
        data["authorization_review"] = _authorization_review()
    return data


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _evidence(digest_char: str = "1") -> dict:
    return {
        "canonical_type": "bytes",
        "cardinality": 1,
        "digest": "sha256:" + digest_char * 64,
    }


def _trace(model, *, review_digest: str = "1", include_signature: bool = True) -> dict:
    value = _evidence("1")
    reviewed = _evidence(review_digest)
    events = [
        {"name": "parse", "occurrence": 0, "complete": True, "produced": {"value": value}},
        {"name": "review", "occurrence": 0, "complete": True, "reviewed": {"value": reviewed}},
    ]
    if include_signature:
        events.extend([
            {
                "name": "digest", "occurrence": 0, "complete": True,
                "accepted": True, "digest_values": {"value": value},
            },
            {
                "name": "signature", "occurrence": 0, "complete": True,
                "accepted": True, "covered": ["value"],
                "covered_values": {"value": value},
            },
        ])
    events.append({
        "name": "authorize", "occurrence": 0, "complete": True,
        "authorized": {"value": value},
    })
    return {
        "model_digest": authorization_review_model_digest(model),
        "sequence": "normal",
        "events": events,
    }


def test_profile_loading_inherits_and_overrides_authorization_review(tmp_path):
    base_path = _write_json(tmp_path / "base.yaml", _profile(name="base"))
    child = {
        "base_profile": base_path.name,
        "name": "child",
        "authorization_review": {
            "scalars": {"value": {"path": "request.amount"}},
        },
    }
    child_path = _write_json(tmp_path / "child.yaml", child)

    profile = load_profile(child_path, strict=True)

    assert profile.name == "child"
    assert profile.authorization_review is not None
    assert profile.authorization_review.scalars["value"].path == "request.amount"
    assert profile.authorization_review.events["signature"].digest == "auth"


def test_profile_loading_rejects_unknown_authorization_review_keys_in_strict_mode(tmp_path):
    raw = _profile()
    raw["authorization_review"]["scalars"]["value"]["typo"] = True
    path = _write_json(tmp_path / "unknown.yaml", raw)

    with pytest.raises(ProfileError, match=r"authorization_review\.scalars\.value.*unknown field"):
        load_profile(path, strict=True)


def test_profile_loading_rejects_trusted_exemptions_in_v1(tmp_path):
    raw = _profile()
    raw["authorization_review"]["scalars"]["value"]["review"] = "hidden"
    raw["authorization_review"]["scalars"]["value"]["trusted_binding"] = "forged"
    raw["authorization_review"]["trusted_bindings"] = {
        "forged": {
            "covers": ["value"],
            "authority": "arbitrary_untrusted_provider",
            "rule": "arbitrary_forged_rule",
        }
    }
    path = _write_json(tmp_path / "trusted.yaml", raw)

    with pytest.raises(ProfileError, match="no enforceable trusted-rule verifier"):
        load_profile(path, strict=True)


def test_profile_info_serializes_authorization_review_analysis(tmp_path, monkeypatch, capsys):
    path = _write_json(tmp_path / "profile.yaml", _profile())
    profile = load_profile(path)
    expected_digest = authorization_review_model_digest(profile.authorization_review)

    monkeypatch.setattr(sys, "argv", ["profile_loader.py", str(path)])
    assert profile_loader.main() == 0
    info = json.loads(capsys.readouterr().out)

    assert info["authorization_review_analysis"]["model_digest"] == expected_digest
    assert info["authorization_review_analysis"]["variants_analyzed"] == 1
    assert info["authorization_review_analysis"]["verdict"] == "INCONCLUSIVE"


@pytest.fixture
def cheap_audit(monkeypatch):
    """Stub the unrelated runtime campaign while retaining CLI/report wiring."""
    monkeypatch.setattr(audit_bootloader, "ensure_tool", lambda value: value)
    monkeypatch.setattr(audit_bootloader, "_common_robot_vars", lambda *args, **kwargs: [])
    monkeypatch.setattr(audit_bootloader, "validate_runtime_fault_mode_compat", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        audit_bootloader,
        "validate_compiled_flash_map",
        lambda *args, **kwargs: {"status": "ok"},
    )
    monkeypatch.setattr(
        audit_bootloader,
        "build_fault_plan",
        lambda **kwargs: SimpleNamespace(
            fault_points=[],
            fault_types_list=[],
            heuristic_summary={},
            swap_progress_summary=None,
            security_state_erase_summary=None,
            clustered_bit_count=0,
        ),
    )
    monkeypatch.setattr(
        audit_bootloader,
        "run_runtime_sweep",
        lambda **kwargs: [{
            "is_control": True,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
        }],
    )
    monkeypatch.setattr(audit_bootloader, "annotate_clean_trace", lambda *args, **kwargs: None)
    monkeypatch.setattr(audit_bootloader, "summarize_calibration_coverage", lambda *args, **kwargs: {})
    monkeypatch.setattr(audit_bootloader, "annotate_result_checks", lambda *args, **kwargs: None)
    monkeypatch.setattr(audit_bootloader, "validate_runtime_findings", lambda *args, **kwargs: None)
    monkeypatch.setattr(audit_bootloader, "report_skip_reasons", lambda *args, **kwargs: None)
    monkeypatch.setattr(audit_bootloader, "run_multi_fault_phase", lambda **kwargs: audit_bootloader.MultiFaultPhaseResult())
    monkeypatch.setattr(audit_bootloader, "compute_verdict", lambda *args, **kwargs: "PASS")
    monkeypatch.setattr(audit_bootloader, "git_metadata", lambda *args, **kwargs: {})


def test_audit_cli_rejects_trace_without_authorization_review(tmp_path, monkeypatch, capsys):
    profile_path = _write_json(tmp_path / "profile.yaml", _profile(authorization=False))
    trace_path = _write_json(tmp_path / "trace.json", {"events": []})
    output_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", [
        "audit_bootloader.py", "--profile", str(profile_path),
        "--output", str(output_path), "--trace", str(trace_path),
    ])

    assert audit_bootloader.main() == audit_bootloader.EXIT_INFRA_FAILURE
    assert "traces were provided but profile has no authorization_review block" in capsys.readouterr().err
    assert not output_path.exists()


@pytest.mark.parametrize(
    ("trace_kwargs", "expected_analysis", "expected_exit", "expected_verdict"),
    [
        ({}, "PASS", 0, "PASS"),
        ({"review_digest": "f"}, "FAIL", 1, "FAIL -- authorization review analysis found a mismatch"),
        ({"include_signature": False}, "INCONCLUSIVE", 1, "INCONCLUSIVE -- authorization review evidence incomplete"),
    ],
)
def test_audit_cli_propagates_authorization_verdict_to_exit_and_json(
    tmp_path,
    monkeypatch,
    capsys,
    cheap_audit,
    trace_kwargs,
    expected_analysis,
    expected_exit,
    expected_verdict,
):
    profile_path = _write_json(tmp_path / "profile.yaml", _profile())
    profile = load_profile(profile_path)
    trace_path = _write_json(
        tmp_path / "trace.json",
        _trace(profile.authorization_review, **trace_kwargs),
    )
    output_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", [
        "audit_bootloader.py", "--profile", str(profile_path),
        "--output", str(output_path), "--trace", str(trace_path),
    ])

    assert audit_bootloader.main() == expected_exit
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["authorization_review_analysis"]["verdict"] == expected_analysis
    assert payload["verdict"] == expected_verdict
    assert json.loads(capsys.readouterr().out)["verdict"] == expected_verdict


def test_authorization_html_renders_semantic_findings_and_infrastructure_status():
    html = render_authorization_review_panel({
        "authorization_review_analysis": {
            "variants_analyzed": 2,
            "traces_analyzed": 1,
            "verdict": "INCONCLUSIVE",
            "findings": [
                {
                    "id": "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE",
                    "sequence": "normal",
                    "evidence": {"field": "value"},
                    "message": "reviewed value differs",
                },
                {
                    "id": "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR",
                    "sequence": "normal",
                    "evidence": {"event": "signature"},
                    "message": "trace evidence is incomplete",
                },
            ],
        }
    })

    assert "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE" in html
    assert "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR" in html
    assert "signature" in html
    assert "INCONCLUSIVE" in html


@pytest.mark.parametrize(
    ("profile_name", "trace_name", "expected_verdict", "expected_finding"),
    [
        (
            "authorization_review_vulnerable.yaml",
            "vulnerable_trace.json",
            "FAIL",
            "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE",
        ),
        (
            "authorization_review_fixed.yaml",
            "fixed_trace.json",
            "PASS",
            None,
        ),
    ],
)
def test_vendor_neutral_example_profiles_and_traces(
    profile_name, trace_name, expected_verdict, expected_finding
):
    profile = load_profile(ROOT / "profiles" / profile_name)
    trace = load_trace(ROOT / "examples" / "authorization_review" / trace_name)

    report = analyze_authorization_review(profile.authorization_review, [trace])

    assert report["verdict"] == expected_verdict
    finding_ids = {finding["id"] for finding in report["findings"]}
    if expected_finding is None:
        assert finding_ids == set()
    else:
        assert expected_finding in finding_ids
