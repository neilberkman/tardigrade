"""Focused tests for the synthetic pre-authentication bounds oracle."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.preauth_bounds_oracle import (  # noqa: E402
    BoundsModel,
    FieldSpec,
    OracleError,
    evaluate_bounds,
    load_config,
    run_campaign,
    _mutations,
)


EXAMPLE = ROOT / "examples" / "preauth_bounds_oracle"


def test_independent_model_catches_nested_auth_extent() -> None:
    config = load_config(EXAMPLE / "fixed.yaml")
    data = bytes.fromhex(config["input_hex"])
    layout = config["layout"]
    mutated = bytearray(data)
    # Signature length is relative to the nested authentication header.
    mutated[8:10] = (13).to_bytes(2, "little")
    result = evaluate_bounds(bytes(mutated), layout)
    assert result["safe"] is False
    assert "signature_key_extent_exceeds_authentication" in result["violations"]


def test_vulnerable_fixture_reports_pre_auth_escape_and_fixed_passes() -> None:
    vulnerable = run_campaign(load_config(EXAMPLE / "vulnerable.yaml"))
    assert vulnerable["status"] == "FINDINGS"
    assert vulnerable["findings"]
    assert all(item["id"] == "PREAUTH_BOUNDS_ESCAPE" for item in vulnerable["findings"])
    assert any("total_length_exceeds_component" in item["violations"] for item in vulnerable["findings"])
    assert any("signature_key_extent_exceeds_authentication" in item["violations"] for item in vulnerable["findings"])

    fixed = run_campaign(load_config(EXAMPLE / "fixed.yaml"))
    assert fixed["status"] == "PASS"
    assert fixed["findings"] == []
    assert any(not item["bounds"]["safe"] for item in fixed["mutants"])
    assert all(
        not item["outcome"]["auth_attempted"]
        for item in fixed["mutants"]
        if not item["bounds"]["safe"]
    )


def test_canonical_input_must_be_safe() -> None:
    config = load_config(EXAMPLE / "fixed.yaml")
    config["input_hex"] = (
        "290018005348523108000400415554484b455930313233343536373839"
        "4142434445464748494a4b4c4d4e4f505152"
    )
    with pytest.raises(OracleError, match="canonical input is outside declared bounds"):
        run_campaign(config)


def test_non_overlapping_layout_can_use_nonzero_component_offset() -> None:
    layout = BoundsModel(
        component_offset=4,
        component_length=24,
        authentication_offset=12,
        authentication_length=12,
        authentication_header_size=4,
        fields={
            "total_length": FieldSpec(0, 2),
            "used_length": FieldSpec(2, 2),
            "signature_length": FieldSpec(4, 2),
            "key_length": FieldSpec(6, 2),
        },
        byteorder="little",
    )
    data = (
        b"xxxx"
        + (20).to_bytes(2, "little")
        + (16).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + b"payload-padding!"
    )
    assert evaluate_bounds(data, layout)["safe"] is True


def test_unrepresentable_safe_edges_are_skipped_for_narrow_fields() -> None:
    layout = BoundsModel(
        component_offset=0,
        component_length=300,
        authentication_offset=8,
        authentication_length=16,
        authentication_header_size=4,
        fields={
            "total_length": FieldSpec(0, 1),
            "used_length": FieldSpec(1, 1),
            "signature_length": FieldSpec(4, 1),
            "key_length": FieldSpec(5, 1),
        },
        byteorder="little",
    )
    data = bytearray(300)
    data[0] = 20
    data[1] = 16
    data[4] = 8
    data[5] = 4
    mutations = _mutations(
        bytes(data),
        layout,
        {"mutations": {"max_mutants": 32, "include_safe_edges": True}},
    )
    assert mutations
    assert all(
        all(0 <= mutation.fields[name] <= 255 for name in mutation.fields)
        for mutation in mutations
    )
    assert all(mutation.fields["total_length"] != 300 for mutation in mutations)


def test_combined_extent_overflow_uses_two_narrow_fields() -> None:
    layout = BoundsModel(
        component_offset=0,
        component_length=400,
        authentication_offset=8,
        authentication_length=304,
        authentication_header_size=4,
        fields={
            "total_length": FieldSpec(0, 1),
            "used_length": FieldSpec(1, 1),
            "signature_length": FieldSpec(4, 1),
            "key_length": FieldSpec(5, 1),
        },
        byteorder="little",
    )
    data = bytearray(400)
    data[0] = 200
    data[1] = 180
    data[4] = 100
    data[5] = 100
    mutations = _mutations(
        bytes(data),
        layout,
        {"mutations": {"max_mutants": 32, "include_safe_edges": True}},
    )
    combined = [
        mutation
        for mutation in mutations
        if mutation.fields["signature_length"] + mutation.fields["key_length"] == 301
    ]
    assert combined
    assert combined[0].fields["signature_length"] == 255
    assert combined[0].fields["key_length"] == 46
    assert "signature_key_extent_exceeds_authentication" in evaluate_bounds(
        combined[0].data, layout
    )["violations"]


def test_reaching_authentication_is_a_finding_even_after_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(EXAMPLE / "fixed.yaml")
    from scripts import preauth_bounds_oracle as oracle

    def fake_harness(_config, path, mutation_id, _index):
        if mutation_id == "base":
            return {
                "accepted": True,
                "committed": True,
                "auth_attempted": True,
                "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        return {
            "accepted": False,
            "committed": False,
            "auth_attempted": True,
            "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    monkeypatch.setattr(oracle, "_run_harness", fake_harness)
    report = run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert report["findings"]
    assert all(item["id"] == "PREAUTH_BOUNDS_ESCAPE" for item in report["findings"])
