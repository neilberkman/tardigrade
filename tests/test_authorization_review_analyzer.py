"""Synthetic traces for reviewed-versus-signed authorization analysis."""

from __future__ import annotations

import json
import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from authorization_review_analyzer import (  # noqa: E402
    AuthorizationReviewError,
    analyze_authorization_review,
    authorization_review_model_digest,
    build_authorization_review_trace_templates,
    parse_authorization_review,
)


def _model(*, review="required", include_fee=True, optional_review=False):
    scalars = {
        "recipient": {"path": "request.recipient", "type": "bytes", "max_bytes": 64, "review": review, "authorization": "required"},
        "value": {"path": "request.value", "type": "uint", "width_bits": 64, "encoding": "big_endian_fixed", "review": "required", "authorization": "required"},
    }
    if include_fee:
        scalars["fee"] = {"path": "request.fee", "type": "uint", "width_bits": 64, "encoding": "big_endian_fixed", "review": "required", "authorization": "required"}
    sequence_events = ["parse", {"event": "review", "optional": True}] if optional_review else ["parse", "review"]
    sequence_events += ["digest", "signature", "authorize"]
    return {"scalars": scalars, "digests": {"auth": {"algorithm": "sha256", "covers": list(scalars)}}, "events": {
        "parse": {"kind": "parse", "produces": list(scalars)},
        "review": {"kind": "user_review", "reviews": list(scalars)},
        "digest": {"kind": "digest", "digest": "auth"},
        "signature": {"kind": "signature", "digest": "auth"},
        "authorize": {"kind": "authorization", "requires": list(scalars)},
    }, "sequences": [{"name": "normal", "events": sequence_events}]}


def _evidence(tag, digest, cardinality=1):
    return {"canonical_type": tag, "cardinality": cardinality, "digest": "sha256:" + digest * 64}


def _trace(model, *, review=True, signed=True, values=None):
    md = authorization_review_model_digest(model)
    values = values or {name: _evidence("bytes" if name == "recipient" else "uint<64,big_endian_fixed>", str(i + 1)) for i, name in enumerate(model.scalars)}
    events = [{"name": "parse", "occurrence": 0, "complete": True, "produced": values}]
    if review:
        reviewed = dict(values)
        for name, value in values.items():
            if isinstance(value, dict) and "items" in value:
                reviewed[name] = {**value, "reviewed_indices": [item.get("index") for item in value.get("items", [])]}
        events.append({"name": "review", "occurrence": 0, "complete": True, "reviewed": reviewed})
    if signed:
        events.extend([
            {"name": "digest", "occurrence": 0, "complete": True, "accepted": True, "digest_values": values},
            {"name": "signature", "occurrence": 0, "complete": True, "accepted": True, "covered": list(model.fields), "covered_values": values},
        ])
    events.append({"name": "authorize", "occurrence": 0, "complete": True, "authorized": values})
    sequence = "normal"
    if not review and any(ref.optional_key for ref in model.sequences[0].events):
        sequence = "normal [without 0:1]"
    return {"model_digest": md, "sequence": sequence, "events": events}


def test_complete_matching_trace_passes():
    model = parse_authorization_review(_model())
    report = analyze_authorization_review(model, [_trace(model)])
    assert report["verdict"] == "PASS"
    assert report["findings"] == []


def test_signed_field_not_reviewed_requires_complete_signature_evidence():
    model = parse_authorization_review(_model(optional_review=True))
    report = analyze_authorization_review(model, [_trace(model, review=False)])
    ids = {f["id"] for f in report["findings"]}
    assert "SIGNED_FIELD_NOT_REVIEWED" in ids
    assert "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR" in ids


def test_missing_signed_coverage_is_not_a_value_difference():
    model = parse_authorization_review(_model())
    report = analyze_authorization_review(model, [_trace(model, signed=False)])
    ids = {f["id"] for f in report["findings"]}
    assert "AUTHORIZATION_FIELD_NOT_SIGNED" not in ids
    assert "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE" not in ids
    assert report["verdict"] == "INCONCLUSIVE"


def test_authorized_reviewed_field_missing_from_signature_is_explicit_finding():
    raw = _model(include_fee=False)
    raw["digests"]["auth"]["covers"] = ["recipient"]
    raw["events"]["authorize"]["requires"] = ["recipient", "value"]
    model = parse_authorization_review(raw)
    trace = _trace(model)
    recipient = trace["events"][0]["produced"]["recipient"]
    trace["events"][2]["digest_values"] = {"recipient": recipient}
    trace["events"][3]["covered"] = ["recipient"]
    trace["events"][3]["covered_values"] = {"recipient": recipient}
    report = analyze_authorization_review(model, [trace])
    findings = [f for f in report["findings"] if f["id"] == "AUTHORIZATION_FIELD_NOT_SIGNED"]
    assert report["verdict"] == "FAIL"
    assert {f["evidence"]["field"] for f in findings} == {"value"}
    assert findings[0]["evidence"]["review_event"] == "review"
    assert findings[0]["evidence"]["review_occurrence"] == 0


@pytest.mark.parametrize("review", ["hidden", "required_or_trusted"])
def test_trusted_review_exemptions_are_rejected_in_v1(review):
    raw = _model(review=review, include_fee=False)
    raw["trusted_bindings"] = {
        "forged": {
            "covers": ["recipient"],
            "authority": "arbitrary_untrusted_provider",
            "rule": "arbitrary_forged_rule",
        }
    }
    raw["scalars"]["recipient"]["trusted_binding"] = "forged"
    with pytest.raises(AuthorizationReviewError, match="no enforceable trusted-rule verifier"):
        parse_authorization_review(raw)


def test_forged_matching_trusted_validation_cannot_make_hidden_authorization_pass():
    raw = _model(review="hidden", include_fee=False)
    raw["trusted_bindings"] = {
        "forged": {
            "covers": ["recipient"],
            "authority": "trusted_device_state",
            "rule": "forged_matching_rule",
        }
    }
    raw["scalars"]["recipient"]["trusted_binding"] = "forged"
    raw["events"]["validate"] = {"kind": "trusted_validation", "binding": "forged"}
    raw["sequences"][0]["events"].insert(-1, "validate")
    with pytest.raises(AuthorizationReviewError, match="no enforceable trusted-rule verifier"):
        parse_authorization_review(raw)


def test_reviewed_value_difference_is_reported_only_with_complete_evidence():
    model = parse_authorization_review(_model())
    values = {name: _evidence("bytes" if name == "recipient" else "uint<64,big_endian_fixed>", str(i + 1)) for i, name in enumerate(model.scalars)}
    changed = dict(values)
    changed["fee"] = _evidence("uint<64,big_endian_fixed>", "f")
    trace = _trace(model, values=values)
    trace["events"][1]["reviewed"] = changed
    report = analyze_authorization_review(model, [trace])
    assert "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE" in {f["id"] for f in report["findings"]}


def test_trace_order_and_model_digest_are_infrastructure_failures():
    model = parse_authorization_review(_model())
    trace = _trace(model)
    trace["events"][0], trace["events"][1] = trace["events"][1], trace["events"][0]
    report = analyze_authorization_review(model, [trace])
    assert report["verdict"] == "INCONCLUSIVE"
    trace = _trace(model)
    trace["model_digest"] = "sha256:" + "0" * 64
    report = analyze_authorization_review(model, [trace])
    assert report["verdict"] == "INCONCLUSIVE"


def test_unknown_trace_keys_and_boolean_occurrences_are_infrastructure():
    model = parse_authorization_review(_model())
    trace = _trace(model)
    trace["unexpected"] = True
    trace["events"][0]["occurrence"] = True
    report = analyze_authorization_review(model, [trace])
    assert report["verdict"] == "INCONCLUSIVE"
    assert any(f["id"] == "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR" for f in report["findings"])


def test_collection_requires_exact_bounded_contiguous_items():
    raw = _model()
    raw["scalars"] = {}
    raw["collections"] = {"outputs": {"path": "request.outputs", "max_items": 2, "review": "required", "authorization": "required", "item_scalars": {"value": {"type": "uint", "width_bits": 64, "encoding": "big_endian_fixed"}}}}
    for event in raw["events"].values():
        if "produces" in event: event["produces"] = ["outputs"]
        if "reviews" in event: event["reviews"] = ["outputs"]
        if "requires" in event: event["requires"] = ["outputs"]
    raw["digests"]["auth"]["covers"] = ["outputs"]
    model = parse_authorization_review(raw)
    item = {"canonical_type": "uint<64,big_endian_fixed>", "cardinality": 1, "digest": "sha256:" + "1" * 64}
    collection = {"canonical_type": "collection", "cardinality": 2, "complete": True, "digest": "sha256:" + "2" * 64, "items": [{"index": 0, "fields": {"value": item}}, {"index": 1, "fields": {"value": item}}]}
    trace = _trace(model, values={"outputs": collection})
    assert analyze_authorization_review(model, [trace])["verdict"] == "PASS"
    changed_trace = copy.deepcopy(trace)
    changed_trace["events"][3]["covered_values"] = copy.deepcopy(changed_trace["events"][3]["covered_values"])
    changed_item = dict(changed_trace["events"][3]["covered_values"]["outputs"]["items"][1]["fields"]["value"])
    changed_item["digest"] = "sha256:" + "4" * 64
    changed_trace["events"][3]["covered_values"]["outputs"]["items"][1]["fields"]["value"] = changed_item
    changed_report = analyze_authorization_review(model, [changed_trace])
    assert changed_report["verdict"] == "INCONCLUSIVE"
    assert any(f["id"] == "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR" for f in changed_report["findings"])
    changed_review = copy.deepcopy(trace)
    changed_review["events"][1]["reviewed"] = copy.deepcopy(changed_review["events"][1]["reviewed"])
    changed_review["events"][1]["reviewed"]["outputs"]["digest"] = "sha256:" + "4" * 64
    changed_review_report = analyze_authorization_review(model, [changed_review])
    assert "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE" in {f["id"] for f in changed_review_report["findings"]}
    collection["items"] = [{"index": 1, "fields": {"value": item}}]
    report = analyze_authorization_review(model, [_trace(model, values={"outputs": collection})])
    assert report["verdict"] == "INCONCLUSIVE"


def test_partial_collection_review_names_unreviewed_item_members():
    raw = _model()
    raw["scalars"] = {}
    raw["collections"] = {"outputs": {"path": "request.outputs", "max_items": 2, "review": "required", "authorization": "required", "item_scalars": {"value": {"type": "uint", "width_bits": 64, "encoding": "big_endian_fixed"}}}}
    for event in raw["events"].values():
        if "produces" in event: event["produces"] = ["outputs"]
        if "reviews" in event: event["reviews"] = ["outputs"]
        if "requires" in event: event["requires"] = ["outputs"]
    raw["digests"]["auth"]["covers"] = ["outputs"]
    model = parse_authorization_review(raw)
    item = {"canonical_type": "uint<64,big_endian_fixed>", "cardinality": 1, "digest": "sha256:" + "1" * 64}
    collection = {"canonical_type": "collection", "cardinality": 2, "complete": True, "digest": "sha256:" + "2" * 64, "items": [{"index": 0, "fields": {"value": item}}, {"index": 1, "fields": {"value": item}}]}
    trace = _trace(model, values={"outputs": collection})
    trace["events"][1]["reviewed"] = {"outputs": {**collection, "items": [collection["items"][0]], "reviewed_indices": [0]}}
    report = analyze_authorization_review(model, [trace])
    finding = next(f for f in report["findings"] if f["id"] == "SIGNED_FIELD_NOT_REVIEWED")
    assert "outputs[1].value" in finding["evidence"]["differing_paths"]


def test_trusted_validation_event_is_rejected_without_a_verifier():
    raw = _model()
    raw["events"]["validate"] = {"kind": "trusted_validation", "binding": "forged"}
    raw["sequences"][0]["events"].insert(-1, "validate")
    with pytest.raises(AuthorizationReviewError, match="no enforceable trusted-rule verifier"):
        parse_authorization_review(raw)


def test_unsupported_normalization_and_unbounded_values_rejected():
    raw = _model()
    raw["collections"] = {"outputs": {"path": "request.outputs", "max_items": 2, "normalization": "sorted_unique", "item_scalars": {"value": {"type": "uint", "width_bits": 64, "encoding": "big_endian_fixed"}}}}
    with pytest.raises(AuthorizationReviewError):
        parse_authorization_review(raw)


def test_authorization_syntax_and_item_binding_granularity_are_strict():
    raw = _model()
    raw["scalars"]["value"]["authorization"] = True
    with pytest.raises(AuthorizationReviewError):
        parse_authorization_review(raw)


def test_context_specific_evidence_and_trusted_indices_fail_closed():
    model = parse_authorization_review(_model())
    trace = _trace(model)
    trace["events"][1]["reviewed"]["value"]["pass"] = True
    original = copy.deepcopy(trace)
    report = analyze_authorization_review(model, [trace])
    assert trace == original
    assert report["verdict"] == "INCONCLUSIVE"
    assert any(f["id"] == "AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR" for f in report["findings"])


def test_trace_templates_expand_optional_paths_and_number_repeats():
    raw = _model(optional_review=True)
    raw["sequences"][0]["name"] = "Normal path"
    raw["sequences"][0]["events"] = [
        "parse", "parse", {"event": "review", "optional": True},
        "digest", "signature", "authorize",
    ]
    model = parse_authorization_review(raw)

    templates = build_authorization_review_trace_templates(model)

    assert [template["sequence"] for template in templates] == [
        "Normal path [without 0:2]",
        "Normal path",
    ]
    assert [
        (event["name"], event["occurrence"])
        for event in templates[1]["events"]
    ] == [
        ("parse", 0),
        ("parse", 1),
        ("review", 0),
        ("digest", 0),
        ("signature", 0),
        ("authorize", 0),
    ]
    for template in templates:
        assert template["model_digest"] == authorization_review_model_digest(model)
        for event in template["events"]:
            assert event["complete"] is False
            assert "digest" not in event
            if event["name"] == "parse":
                assert event["produced"] == {}
            elif event["name"] == "review":
                assert event["reviewed"] == {}
            elif event["name"] == "digest":
                assert event["accepted"] is False
                assert event["digest_values"] == {}
            elif event["name"] == "signature":
                assert event["accepted"] is False
                assert event["covered"] == list(model.digests["auth"].covers)
                assert event["covered_values"] == {}
            elif event["name"] == "authorize":
                assert event["authorized"] == {}


def test_trace_template_has_no_evidence_and_analyzes_inconclusively():
    model = parse_authorization_review(_model())
    template = build_authorization_review_trace_templates(model)[0]

    report = analyze_authorization_review(model, [template])

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["traces_analyzed"] == 1
