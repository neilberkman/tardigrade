#!/usr/bin/env python3
"""Fail-closed reviewed-versus-signed authorization analysis.

The declaration describes values which a device parses, displays, signs, and
authorizes.  Runtime trace records provide the value identity at each stage;
declarations alone are never evidence of a safe authorization flow.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from update_protocol_analyzer import (
    MAX_SEQUENCE_VARIANTS,
    SequenceEvent,
    ProtocolSequence,
    iter_sequence_variants,
)

# When invoked as a script, profile_loader must resolve this same module
# object; otherwise its model classes are duplicated under a second import
# name and collection/type checks fail at the CLI boundary.
if __name__ == "__main__":
    sys.modules.setdefault("authorization_review_analyzer", sys.modules[__name__])


MAX_COLLECTION_ITEMS = 4096
MAX_TRACE_EVENTS = 4096
MAX_FINDING_PATHS = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuthorizationReviewError(ValueError):
    """Raised when an authorization-review declaration is malformed."""


def _reject_trusted_exemption(context: str) -> None:
    raise AuthorizationReviewError(
        "{}: trusted exemptions are unavailable in v1; no enforceable "
        "trusted-rule verifier exists; use review: required and ordinary "
        "user review".format(context)
    )


@dataclass(frozen=True)
class Scalar:
    name: str
    path: str
    type: str
    review: str
    authorization: bool
    trusted_binding: Optional[str]
    options: Mapping[str, Any]

    def type_tag(self) -> str:
        if self.type in {"uint", "int"}:
            return "{}<{},{}>".format(
                self.type, self.options["width_bits"], self.options["encoding"]
            )
        return self.type

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "path": self.path,
            "type": self.type,
            "review": self.review,
        }
        if self.authorization:
            out["authorization"] = "required"
        if self.trusted_binding is not None:
            out["trusted_binding"] = self.trusted_binding
        out.update(self.options)
        return out


@dataclass(frozen=True)
class Collection:
    name: str
    path: str
    max_items: int
    review: str
    authorization: bool
    item_scalars: Mapping[str, Scalar]
    normalization: Optional[str]
    trusted_binding: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "path": self.path,
            "max_items": self.max_items,
            "review": self.review,
            "item_scalars": {
                name: scalar.to_dict() for name, scalar in self.item_scalars.items()
            },
        }
        if self.authorization:
            out["authorization"] = "required"
        if self.normalization is not None:
            out["normalization"] = self.normalization
        if self.trusted_binding is not None:
            out["trusted_binding"] = self.trusted_binding
        return out


@dataclass(frozen=True)
class Digest:
    name: str
    algorithm: str
    covers: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "covers": list(self.covers)}


@dataclass(frozen=True)
class TrustedBinding:
    name: str
    covers: Tuple[str, ...]
    authority: str
    rule: str
    granularity: str = "field"
    additional_defense: bool = False

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "covers": list(self.covers),
            "authority": self.authority,
            "rule": self.rule,
            "granularity": self.granularity,
        }
        if self.additional_defense:
            out["additional_defense"] = True
        return out


@dataclass(frozen=True)
class ReviewEvent:
    name: str
    kind: str
    values: Tuple[str, ...] = ()
    digest: Optional[str] = None
    binding: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind}
        if self.values:
            out["produces" if self.kind == "parse" else "reviews" if self.kind == "user_review" else "requires"] = list(self.values)
        if self.digest is not None:
            out["digest"] = self.digest
        if self.binding is not None:
            out["binding"] = self.binding
        return out


@dataclass(frozen=True)
class AuthorizationReviewModel:
    scalars: Mapping[str, Scalar]
    collections: Mapping[str, Collection]
    digests: Mapping[str, Digest]
    trusted_bindings: Mapping[str, TrustedBinding]
    events: Mapping[str, ReviewEvent]
    sequences: Tuple[ProtocolSequence, ...]

    @property
    def fields(self) -> Tuple[str, ...]:
        return tuple(self.scalars) + tuple(self.collections)

    def field(self, name: str) -> Scalar | Collection:
        if name in self.scalars:
            return self.scalars[name]
        if name in self.collections:
            return self.collections[name]
        raise KeyError(name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scalars": {name: item.to_dict() for name, item in self.scalars.items()},
            "collections": {
                name: item.to_dict() for name, item in self.collections.items()
            },
            "digests": {name: item.to_dict() for name, item in self.digests.items()},
            "trusted_bindings": {
                name: item.to_dict() for name, item in self.trusted_bindings.items()
            },
            "events": {name: item.to_dict() for name, item in self.events.items()},
            "sequences": [
                {
                    "name": seq.name,
                    "events": [
                        (
                            {"event": ref.event, "optional_group": ref.optional_key[6:]}
                            if ref.optional_key and ref.optional_key.startswith("group:")
                            else ({"event": ref.event, "optional": True} if ref.optional_key else ref.event)
                        )
                        for ref in seq.events
                    ],
                }
                for seq in self.sequences
            ],
        }


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationReviewError("{}: expected mapping".format(context))
    return value


def _name(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationReviewError("{}: expected non-empty string".format(context))
    return value.strip()


def _reject_unknown(value: Mapping[str, Any], allowed: Iterable[str], context: str) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise AuthorizationReviewError(
            "{}: unknown field(s): {}".format(context, ", ".join(unknown))
        )


def _bool(value: Any, context: str, default: Optional[bool] = None) -> bool:
    if value is None and default is not None:
        return default
    if type(value) is not bool:
        raise AuthorizationReviewError("{}: expected boolean".format(context))
    return value


def _positive(value: Any, context: str, maximum: int = 0x7FFFFFFF) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        raise AuthorizationReviewError("{}: expected positive bounded integer".format(context))
    return value


def _path(value: Any, context: str) -> str:
    text = _name(value, context)
    if text.startswith(".") or text.endswith(".") or ".." in text:
        raise AuthorizationReviewError("{}: ambiguous path {!r}".format(context, text))
    if any(ch in text for ch in "[]*\\"):
        raise AuthorizationReviewError("{}: unsupported path syntax".format(context))
    return text


def _parse_scalar(raw: Any, context: str, *, name: str, collection_item: bool = False) -> Scalar:
    item = _mapping(raw, context)
    allowed = {
        "path", "type", "review", "authorization", "trusted_binding",
        "max_bytes", "width_bits", "encoding", "max_chars", "enum_values",
        "max_encoded_bytes",
    }
    if collection_item:
        allowed -= {"path"}
        if "authorization" in item:
            raise AuthorizationReviewError(context + ".authorization: item-level authorization is unsupported")
    _reject_unknown(item, allowed, context)
    path = _path(item.get("path", name), context + ".path")
    scalar_type = _name(item.get("type"), context + ".type").lower()
    if scalar_type not in {"uint", "int", "bool", "string", "bytes", "enum"}:
        raise AuthorizationReviewError("{}: unsupported scalar type {!r}".format(context, scalar_type))
    review = item.get("review", "required")
    if review != "required":
        _reject_trusted_exemption(context + ".review")
    authorization_raw = item.get("authorization")
    if authorization_raw is None:
        authorization = False
    elif authorization_raw == "required":
        authorization = True
    else:
        raise AuthorizationReviewError(context + ".authorization: expected 'required' or omission")
    if "trusted_binding" in item:
        _reject_trusted_exemption(context + ".trusted_binding")
    trusted_name = None
    options: Dict[str, Any] = {}
    if scalar_type in {"uint", "int"}:
        width = _positive(item.get("width_bits"), context + ".width_bits", 128)
        if width not in {8, 16, 32, 64, 128}:
            raise AuthorizationReviewError("{}.width_bits: unsupported width".format(context))
        encoding = _name(item.get("encoding"), context + ".encoding")
        if encoding not in {"big_endian_fixed", "little_endian_fixed", "varint"}:
            raise AuthorizationReviewError("{}.encoding: unsupported encoding".format(context))
        options.update({"width_bits": width, "encoding": encoding})
        if encoding == "varint":
            options["max_encoded_bytes"] = _positive(
                item.get("max_encoded_bytes"), context + ".max_encoded_bytes", 32
            )
    elif scalar_type in {"bytes", "string"}:
        bound_key = "max_bytes" if scalar_type == "bytes" else "max_chars"
        options[bound_key] = _positive(item.get(bound_key), context + "." + bound_key, MAX_COLLECTION_ITEMS)
    elif scalar_type == "enum":
        values = item.get("enum_values")
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
            raise AuthorizationReviewError("{}.enum_values: expected non-empty strings".format(context))
        if len(set(values)) != len(values):
            raise AuthorizationReviewError("{}.enum_values: duplicate value".format(context))
        options["enum_values"] = list(values)
    return Scalar(name=name, path=path, type=scalar_type, review=review,
                  authorization=authorization, trusted_binding=trusted_name, options=options)


def _all_fields(model_scalars: Mapping[str, Scalar], model_collections: Mapping[str, Collection]) -> set[str]:
    return set(model_scalars) | set(model_collections)


def parse_authorization_review(raw: Any) -> Optional[AuthorizationReviewModel]:
    if raw is None:
        return None
    root = _mapping(raw, "authorization_review")
    _reject_unknown(root, {"scalars", "collections", "digests", "trusted_bindings", "events", "sequences"}, "authorization_review")
    if "trusted_bindings" in root:
        _reject_trusted_exemption("authorization_review.trusted_bindings")
    scalars: Dict[str, Scalar] = {}
    for raw_name, raw_scalar in _mapping(root.get("scalars", {}), "authorization_review.scalars").items():
        name = _name(raw_name, "authorization_review.scalars key")
        if name in scalars:
            raise AuthorizationReviewError("duplicate scalar {!r}".format(name))
        scalars[name] = _parse_scalar(raw_scalar, "authorization_review.scalars." + name, name=name)
    collections: Dict[str, Collection] = {}
    for raw_name, raw_collection in _mapping(root.get("collections", {}), "authorization_review.collections").items():
        name = _name(raw_name, "authorization_review.collections key")
        if name in scalars or name in collections:
            raise AuthorizationReviewError("duplicate field {!r}".format(name))
        context = "authorization_review.collections." + name
        item = _mapping(raw_collection, context)
        _reject_unknown(item, {"path", "max_items", "review", "authorization", "item_scalars", "normalization", "trusted_binding"}, context)
        review = item.get("review", "required")
        if review != "required":
            _reject_trusted_exemption(context + ".review")
        normalization = item.get("normalization")
        if normalization is not None and normalization != "ordered":
            raise AuthorizationReviewError(context + ".normalization: unsupported normalization")
        item_fields: Dict[str, Scalar] = {}
        for raw_item_name, raw_field in _mapping(item.get("item_scalars"), context + ".item_scalars").items():
            item_name = _name(raw_item_name, context + ".item_scalars key")
            if item_name in item_fields:
                raise AuthorizationReviewError("duplicate item field {!r}".format(item_name))
            item_fields[item_name] = _parse_scalar(raw_field, context + ".item_scalars." + item_name, name=item_name, collection_item=True)
        if not item_fields:
            raise AuthorizationReviewError(context + ".item_scalars: expected non-empty mapping")
        authorization_raw = item.get("authorization")
        if authorization_raw is None:
            collection_authorization = False
        elif authorization_raw == "required":
            collection_authorization = True
        else:
            raise AuthorizationReviewError(context + ".authorization: expected 'required' or omission")
        if "trusted_binding" in item:
            _reject_trusted_exemption(context + ".trusted_binding")
        collection_binding = None
        # A collection's item-member binding is the default for its members.
        # Explicit member bindings are permitted only when they agree with it.
        if any(member.review != "required" for member in item_fields.values()):
            _reject_trusted_exemption(context + ".item_scalars.review")
        collections[name] = Collection(
            name=name, path=_path(item.get("path"), context + ".path"),
            max_items=_positive(item.get("max_items"), context + ".max_items", MAX_COLLECTION_ITEMS),
            review=review,
            authorization=collection_authorization,
            item_scalars=item_fields, normalization=normalization,
            trusted_binding=collection_binding,
        )
    field_names = _all_fields(scalars, collections)
    digests: Dict[str, Digest] = {}
    for raw_name, raw_digest in _mapping(root.get("digests", {}), "authorization_review.digests").items():
        name = _name(raw_name, "authorization_review.digests key")
        if name in digests:
            raise AuthorizationReviewError("duplicate digest {!r}".format(name))
        context = "authorization_review.digests." + name
        item = _mapping(raw_digest, context)
        _reject_unknown(item, {"algorithm", "covers"}, context)
        if item.get("algorithm") != "sha256":
            raise AuthorizationReviewError(context + ".algorithm: unsupported algorithm")
        covers = item.get("covers")
        if not isinstance(covers, list) or not covers:
            raise AuthorizationReviewError(context + ".covers: expected non-empty list")
        refs = tuple(_name(ref, context + ".covers") for ref in covers)
        if len(set(refs)) != len(refs) or any(ref not in field_names for ref in refs):
            raise AuthorizationReviewError(context + ".covers: duplicate or unknown field")
        digests[name] = Digest(name, "sha256", refs)
    bindings: Dict[str, TrustedBinding] = {}
    for field in list(scalars.values()) + list(collections.values()):
        if field.trusted_binding:
            _reject_trusted_exemption("field {!r}.trusted_binding".format(field.name))
    for collection in collections.values():
        for item_name, item_field in collection.item_scalars.items():
            if item_field.trusted_binding:
                _reject_trusted_exemption("collection item {!r}.{}.trusted_binding".format(collection.name, item_name))
    events: Dict[str, ReviewEvent] = {}
    allowed_kinds = {"parse", "user_review", "digest", "signature", "trusted_validation", "authorization"}
    event_allowed = {"kind", "produces", "reviews", "digest", "binding", "requires"}
    for raw_name, raw_event in _mapping(root.get("events"), "authorization_review.events").items():
        name = _name(raw_name, "authorization_review.events key")
        if name in events:
            raise AuthorizationReviewError("duplicate event {!r}".format(name))
        context = "authorization_review.events." + name
        item = _mapping(raw_event, context)
        _reject_unknown(item, event_allowed, context)
        kind = _name(item.get("kind"), context + ".kind")
        if kind not in allowed_kinds:
            raise AuthorizationReviewError(context + ".kind: unsupported event kind")
        if kind == "trusted_validation":
            _reject_trusted_exemption(context + ".kind")
        list_key = {"parse": "produces", "user_review": "reviews", "authorization": "requires"}.get(kind)
        values: Tuple[str, ...] = ()
        if list_key:
            raw_values = item.get(list_key)
            if not isinstance(raw_values, list) or any(not isinstance(value, str) for value in raw_values):
                raise AuthorizationReviewError(context + "." + list_key + ": expected list")
            values = tuple(_name(value, context + "." + list_key) for value in raw_values)
            if len(set(values)) != len(values) or any(value not in field_names for value in values):
                raise AuthorizationReviewError(context + "." + list_key + ": duplicate or unknown field")
        for key in ("produces", "reviews", "requires"):
            if key != list_key and key in item:
                raise AuthorizationReviewError(context + ".{} is invalid for {} events".format(key, kind))
        digest = item.get("digest")
        binding = item.get("binding")
        if kind in {"digest", "signature"}:
            digest = _name(digest, context + ".digest")
            if digest not in digests:
                raise AuthorizationReviewError(context + ".digest: unknown digest")
        elif digest is not None:
            raise AuthorizationReviewError(context + ".digest is invalid for {} events".format(kind))
        if kind == "trusted_validation":
            binding = _name(binding, context + ".binding")
            if binding not in bindings:
                raise AuthorizationReviewError(context + ".binding: unknown binding")
        elif binding is not None:
            raise AuthorizationReviewError(context + ".binding is invalid for {} events".format(kind))
        events[name] = ReviewEvent(name, kind, values, digest, binding)
    if not events:
        raise AuthorizationReviewError("authorization_review.events: expected non-empty mapping")
    sequences_raw = root.get("sequences")
    if not isinstance(sequences_raw, list) or not sequences_raw:
        raise AuthorizationReviewError("authorization_review.sequences: expected non-empty list")
    sequences: List[ProtocolSequence] = []
    names = set()
    for index, raw_sequence in enumerate(sequences_raw):
        context = "authorization_review.sequences[{}]".format(index)
        item = _mapping(raw_sequence, context)
        _reject_unknown(item, {"name", "events"}, context)
        seq_name = _name(item.get("name"), context + ".name")
        if seq_name in names:
            raise AuthorizationReviewError("duplicate sequence {!r}".format(seq_name))
        names.add(seq_name)
        raw_events = item.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            raise AuthorizationReviewError(context + ".events: expected non-empty list")
        refs: List[SequenceEvent] = []
        for event_index, raw_ref in enumerate(raw_events):
            ref_context = "{}.events[{}]".format(context, event_index)
            optional_key = None
            if isinstance(raw_ref, str):
                event_name = _name(raw_ref, ref_context)
            else:
                ref = _mapping(raw_ref, ref_context)
                _reject_unknown(ref, {"event", "optional", "optional_group"}, ref_context)
                event_name = _name(ref.get("event"), ref_context + ".event")
                optional = _bool(ref.get("optional", False), ref_context + ".optional", False)
                group = ref.get("optional_group")
                if optional and group is not None:
                    raise AuthorizationReviewError(ref_context + ": optional and optional_group are exclusive")
                optional_key = "group:" + _name(group, ref_context + ".optional_group") if group is not None else ("event:{}:{}".format(index, event_index) if optional else None)
            if event_name not in events:
                raise AuthorizationReviewError(ref_context + ": unknown event")
            refs.append(SequenceEvent(event_name, optional_key))
        sequences.append(ProtocolSequence(seq_name, tuple(refs)))
    model = AuthorizationReviewModel(scalars, collections, digests, bindings, events, tuple(sequences))
    try:
        list(iter_sequence_variants(model))
    except ValueError as exc:
        raise AuthorizationReviewError("authorization_review: optional paths exceed maximum") from exc
    # Require authorization to include all explicitly authorized values.
    required_auth = {name for name, field in scalars.items() if field.authorization} | {name for name, field in collections.items() if field.authorization}
    for event in events.values():
        if event.kind == "authorization" and not required_auth.issubset(set(event.values)):
            raise AuthorizationReviewError("authorization event {!r} omits required input".format(event.name))
    return model


def authorization_review_model_digest(model: AuthorizationReviewModel) -> str:
    encoded = json.dumps(model.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_authorization_review_trace_templates(
    model: AuthorizationReviewModel,
) -> List[Dict[str, Any]]:
    """Build incomplete trace placeholders for every expanded sequence path.

    The returned mappings contain declaration identity and event structure only;
    they deliberately contain no observed value evidence.  This function does
    not mutate *model* and performs no analysis.
    """
    templates: List[Dict[str, Any]] = []
    model_digest = authorization_review_model_digest(model)
    payload_keys = {
        "parse": ("produced",),
        "user_review": ("reviewed",),
        "digest": ("digest_values",),
        "signature": ("covered", "covered_values"),
        "authorization": ("authorized",),
    }
    for sequence_name, event_names in iter_sequence_variants(model):
        occurrences: Dict[str, int] = {}
        events: List[Dict[str, Any]] = []
        for event_name in event_names:
            occurrence = occurrences.get(event_name, 0)
            occurrences[event_name] = occurrence + 1
            event = model.events[event_name]
            item: Dict[str, Any] = {
                "name": event_name,
                "occurrence": occurrence,
                "complete": False,
            }
            for key in payload_keys.get(event.kind, ()):
                if key == "covered":
                    digest = model.digests.get(event.digest or "")
                    item[key] = list(digest.covers) if digest is not None else []
                else:
                    item[key] = {}
            if event.kind in {"digest", "signature"}:
                item["accepted"] = False
            events.append(item)
        templates.append({
            "model_digest": model_digest,
            "sequence": sequence_name,
            "events": events,
        })
    return templates


def _trace_template_slug(sequence_name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", sequence_name).strip("-").lower()
    return slug or "sequence"


def _emit_authorization_review_trace_templates(
    model: AuthorizationReviewModel, directory: str | Path
) -> List[Path]:
    target = Path(directory)
    if target.exists() and not target.is_dir():
        raise AuthorizationReviewError(
            "trace template output target {} is not a directory".format(target)
        )
    target.mkdir(parents=True, exist_ok=True)
    templates = build_authorization_review_trace_templates(model)
    paths = [
        target / "{:04d}-{}.json".format(index, _trace_template_slug(template["sequence"]))
        for index, template in enumerate(templates)
    ]
    existing = [path for path in paths if path.exists()]
    if existing:
        raise AuthorizationReviewError(
            "trace template output file already exists: {}".format(existing[0])
        )
    for path, template in zip(paths, templates):
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(template, handle, indent=2, sort_keys=True, ensure_ascii=False)
                handle.write("\n")
        except FileExistsError as exc:
            raise AuthorizationReviewError(
                "trace template output file already exists: {}".format(path)
            ) from exc
    return paths


def _finding(code: str, sequence: str, auth: str, message: str, **evidence: Any) -> Dict[str, Any]:
    return {"id": code, "severity": "high" if code in {"AUTHORIZATION_FIELD_NOT_SIGNED", "SIGNED_FIELD_NOT_REVIEWED", "UNVERIFIED_HIDDEN_VALUE", "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE"} else "configuration", "sequence": sequence, "events": [], "message": message, "evidence": evidence}


def _infra(sequence: str, auth: str, message: str, **evidence: Any) -> Dict[str, Any]:
    return _finding("AUTHORIZATION_REVIEW_INFRASTRUCTURE_ERROR", sequence, auth, message, authorization=auth, **evidence)


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.fullmatch(value))


def _expected_tag(model: AuthorizationReviewModel, ref: str, item_name: Optional[str] = None) -> str:
    field = model.field(ref)
    if isinstance(field, Scalar):
        return field.type_tag()
    if item_name is None:
        return "collection"
    return field.item_scalars[item_name].type_tag()


def _validate_evidence(model: AuthorizationReviewModel, ref: str, evidence: Any, *, item_name: Optional[str] = None, allow_partial_collection: bool = False, evidence_context: str = "value") -> Tuple[bool, str, int, str]:
    if not isinstance(evidence, dict):
        return False, "missing evidence", 0, ""
    allowed_evidence_keys = {"canonical_type", "cardinality", "digest"}
    if evidence_context == "validation":
        allowed_evidence_keys.update({"pass", "binding", "authority", "rule"})
    if item_name is None and isinstance(model.field(ref), Collection):
        allowed_evidence_keys.update({"complete", "items"})
        if evidence_context == "review":
            allowed_evidence_keys.add("reviewed_indices")
        elif evidence_context == "validation":
            allowed_evidence_keys.add("validated_indices")
    if set(evidence) - allowed_evidence_keys:
        return False, "evidence has unknown fields", 0, str(evidence.get("canonical_type") or "")
    if evidence.get("canonical_type") != _expected_tag(model, ref, item_name):
        return False, "canonical type mismatch", 0, str(evidence.get("canonical_type") or "")
    cardinality = evidence.get("cardinality")
    if isinstance(cardinality, bool) or not isinstance(cardinality, int) or cardinality < 0:
        return False, "invalid cardinality", 0, str(evidence.get("canonical_type") or "")
    if not _valid_digest(evidence.get("digest")):
        return False, "missing or malformed digest", 0, str(evidence.get("canonical_type") or "")
    if isinstance(model.field(ref), Scalar) and cardinality != 1:
        return False, "scalar cardinality must be one", cardinality, str(evidence.get("canonical_type") or "")
    if isinstance(model.field(ref), Collection) and item_name is None:
        field = model.collections[ref]
        if cardinality > field.max_items or evidence.get("complete") is not True:
            return False, "collection cardinality or completeness mismatch", cardinality, "collection"
        items = evidence.get("items")
        indices = [item.get("index") for item in items if isinstance(item, dict)] if isinstance(items, list) else []
        if not isinstance(items, list) or (allow_partial_collection and cardinality > 0 and not items) or (not allow_partial_collection and len(items) != cardinality) or any(type(index) is not int or index < 0 or index >= cardinality for index in indices) or len(set(indices)) != len(indices) or indices != sorted(indices) or (not allow_partial_collection and indices != list(range(cardinality))):
            return False, "collection items are not contiguous", cardinality, "collection"
        if allow_partial_collection:
            index_key = "reviewed_indices"
            reviewed_indices = evidence.get(index_key)
            if not isinstance(reviewed_indices, list) or any(type(index) is not int for index in reviewed_indices) or reviewed_indices != indices:
                return False, "collection is missing exact reviewed_indices", cardinality, "collection"
        for item in items:
            if not isinstance(item, dict) or set(item) - {"index", "fields"}:
                return False, "collection item has unknown fields", cardinality, "collection"
            fields = item.get("fields") if isinstance(item, dict) else None
            if not isinstance(fields, dict) or not fields or (not allow_partial_collection and set(fields) != set(field.item_scalars)) or set(fields) - set(field.item_scalars):
                return False, "collection item fields are incomplete", cardinality, "collection"
            for item_name, item_value in fields.items():
                ok, reason, _, _ = _validate_evidence(
                    model, ref, item_value, item_name=item_name, evidence_context=evidence_context
                )
                if not ok:
                    return False, "collection item {}: {}".format(item_name, reason), cardinality, "collection"
    return True, "", cardinality, str(evidence["canonical_type"])


def _event_map(trace: Mapping[str, Any]) -> Tuple[Optional[Dict[Tuple[str, int], Mapping[str, Any]]], Optional[str], List[Tuple[str, int]]]:
    raw_events = trace.get("events")
    if not isinstance(raw_events, list) or len(raw_events) > MAX_TRACE_EVENTS:
        return None, "events must be a bounded list", []
    out: Dict[Tuple[str, int], Mapping[str, Any]] = {}
    order: List[Tuple[str, int]] = []
    for item in raw_events:
        if not isinstance(item, dict) or type(item.get("occurrence")) is not int or item.get("occurrence") < 0:
            return None, "event occurrence is invalid", []
        name = item.get("name")
        key = (name, item["occurrence"])
        if not isinstance(name, str) or key in out:
            return None, "duplicate or invalid event occurrence", []
        out[key] = item
        order.append(key)
    return out, None, order


def _refs_from_payload(payload: Any, key: str) -> Mapping[str, Any]:
    value = payload.get(key) if isinstance(payload, dict) else None
    return value if isinstance(value, dict) else {}


def _compare_ref(model: AuthorizationReviewModel, ref: str, reviewed: Any, signed: Any) -> Tuple[bool, List[str]]:
    mismatches: List[str] = []
    if isinstance(model.field(ref), Scalar):
        if reviewed.get("digest") != signed.get("digest") or reviewed.get("canonical_type") != signed.get("canonical_type") or reviewed.get("cardinality") != signed.get("cardinality"):
            mismatches.append(ref)
        return bool(mismatches), mismatches
    if reviewed.get("digest") != signed.get("digest") or reviewed.get("canonical_type") != signed.get("canonical_type") or reviewed.get("cardinality") != signed.get("cardinality"):
        mismatches.append(ref)
    ritems = reviewed.get("items") or []
    sitems = signed.get("items") or []
    for index in range(max(len(ritems), len(sitems))):
        ritem = ritems[index] if index < len(ritems) else None
        sitem = sitems[index] if index < len(sitems) else None
        if not isinstance(ritem, dict) or not isinstance(sitem, dict):
            mismatches.append("{}[{}]".format(ref, index)); continue
        rfields, sfields = ritem.get("fields"), sitem.get("fields")
        if not isinstance(rfields, dict) or not isinstance(sfields, dict):
            mismatches.append("{}[{}]".format(ref, index)); continue
        for item_name in model.collections[ref].item_scalars:
            rv, sv = rfields.get(item_name), sfields.get(item_name)
            if not isinstance(rv, dict) or not isinstance(sv, dict) or rv.get("digest") != sv.get("digest") or rv.get("canonical_type") != sv.get("canonical_type") or rv.get("cardinality") != sv.get("cardinality"):
                mismatches.append("{}[{}].{}".format(ref, index, item_name))
    return bool(mismatches), mismatches[:MAX_FINDING_PATHS]


def _collection_review_gaps(
    model: AuthorizationReviewModel, ref: str, reviewed: Mapping[str, Any], signed: Mapping[str, Any]
) -> Tuple[List[str], List[str]]:
    """Return (unreviewed paths, differing paths) for a partial collection review."""
    collection = model.collections[ref]
    reviewed_items = {
        item.get("index"): item
        for item in (reviewed.get("items") or [])
        if isinstance(item, dict)
    }
    signed_items = {
        item.get("index"): item
        for item in (signed.get("items") or [])
        if isinstance(item, dict)
    }
    gaps: List[str] = []
    differences: List[str] = []
    if any(reviewed.get(key) != signed.get(key) for key in ("canonical_type", "cardinality", "digest")):
        differences.append(ref)
    for index, signed_item in signed_items.items():
        reviewed_item = reviewed_items.get(index)
        for item_name in collection.item_scalars:
            if collection.item_scalars[item_name].review not in {"required", "required_or_trusted"}:
                continue
            path = "{}[{}].{}".format(ref, index, item_name)
            if reviewed_item is None or not isinstance(reviewed_item.get("fields"), dict) or item_name not in reviewed_item["fields"]:
                gaps.append(path)
                continue
            rv = reviewed_item["fields"][item_name]
            sv = (signed_item.get("fields") or {}).get(item_name)
            if not isinstance(rv, dict) or not isinstance(sv, dict) or rv.get("digest") != sv.get("digest") or rv.get("canonical_type") != sv.get("canonical_type") or rv.get("cardinality") != sv.get("cardinality"):
                differences.append(path)
    return gaps[:MAX_FINDING_PATHS], differences[:MAX_FINDING_PATHS]


def _trusted_collection_paths(
    model: AuthorizationReviewModel,
    ref: str,
    validation: Any,
    signed: Mapping[str, Any],
    binding: TrustedBinding,
) -> Tuple[List[str], Optional[str]]:
    """Return reviewed gaps covered by an exact trusted item validation.

    A collection-level trusted assertion is not enough to authorize an
    undisplayed member.  The assertion must carry the same collection
    identity as the signature and include that member's complete evidence.
    """
    if not isinstance(validation, dict):
        return [], None
    if any(validation.get(key) != signed.get(key) for key in ("canonical_type", "cardinality", "digest")):
        return [], "trusted collection identity differs"
    if validation.get("complete") is not True:
        return [], "trusted collection evidence is incomplete"
    signed_items = {
        item.get("index"): item
        for item in (signed.get("items") or [])
        if isinstance(item, dict)
    }
    raw_validation_items = validation.get("items")
    if not isinstance(raw_validation_items, list):
        return [], "trusted collection items are missing"
    raw_validation_indices = [item.get("index") for item in raw_validation_items if isinstance(item, dict)]
    validation_items = {
        item.get("index"): item
        for item in raw_validation_items
        if isinstance(item, dict)
    }
    validation_indices = list(validation_items)
    if any(type(index) is not int for index in raw_validation_indices) or len(set(raw_validation_indices)) != len(raw_validation_indices) or raw_validation_indices != sorted(raw_validation_indices):
        return [], "trusted collection indices are invalid: {}".format(raw_validation_indices)
    if validation.get("validated_indices") != raw_validation_indices:
        return [], "trusted collection validated_indices do not match items"
    paths: List[str] = []
    collection = model.collections[ref]
    for index, item in validation_items.items():
        signed_item = signed_items.get(index)
        if signed_item is None:
            return [], "trusted collection index {} is out of range".format(index)
        if set(item) - {"index", "fields"}:
            return [], "trusted collection item {} has unknown fields".format(index)
        fields = item.get("fields")
        signed_fields = signed_item.get("fields")
        if not isinstance(fields, dict) or not isinstance(signed_fields, dict) or set(fields) - set(collection.item_scalars):
            return [], "trusted collection item {} fields are invalid".format(index)
        for item_name in collection.item_scalars:
            item_field = collection.item_scalars[item_name]
            if item_field.review not in {"hidden", "required_or_trusted"} or item_field.trusted_binding != binding.name:
                continue
            value = fields.get(item_name)
            expected = signed_fields.get(item_name)
            if not isinstance(value, dict) or not isinstance(expected, dict):
                continue
            valid_member, _, _, _ = _validate_evidence(model, ref, value, item_name=item_name, evidence_context="validation")
            if not valid_member:
                return [], "trusted collection member evidence is invalid at {}[{}].{}".format(ref, index, item_name)
            if (
                value.get("canonical_type") == expected.get("canonical_type")
                and value.get("cardinality") == expected.get("cardinality")
                and value.get("digest") == expected.get("digest")
            ):
                paths.append("{}[{}].{}".format(ref, index, item_name))
    return paths[:MAX_FINDING_PATHS], None


def analyze_authorization_review(model: AuthorizationReviewModel, traces: Optional[Sequence[Mapping[str, Any]]] = None) -> Dict[str, Any]:
    expected_model_digest = authorization_review_model_digest(model)
    variants = list(iter_sequence_variants(model))
    # Keep the runtime boundary fail-closed even for callers that construct a
    # model directly instead of going through parse_authorization_review().
    trusted_fields = [
        field.name
        for field in list(model.scalars.values()) + list(model.collections.values())
        if field.trusted_binding
    ]
    trusted_fields.extend(
        "{}.{}".format(collection.name, item_name)
        for collection in model.collections.values()
        for item_name, field in collection.item_scalars.items()
        if field.trusted_binding
    )
    trusted_events = [
        name for name, event in model.events.items() if event.kind == "trusted_validation"
    ]
    if model.trusted_bindings or trusted_fields or trusted_events:
        return {
            "verdict": "INCONCLUSIVE",
            "model_digest": expected_model_digest,
            "variants_analyzed": len(variants),
            "traces_analyzed": 0,
            "findings": [_infra(
                "model",
                "unknown",
                "trusted exemptions are unavailable in v1; no enforceable trusted-rule verifier exists",
                model_digest=expected_model_digest,
                trusted_fields=trusted_fields,
                trusted_events=trusted_events,
            )],
        }
    trace_map: Dict[str, Mapping[str, Any]] = {}
    infrastructure: List[Dict[str, Any]] = []
    for trace in traces or []:
        if not isinstance(trace, dict):
            infrastructure.append(_infra("unknown", "unknown", "trace must be an object")); continue
        sequence = trace.get("sequence")
        unknown_trace_keys = set(trace) - {"model_digest", "sequence", "events"}
        if unknown_trace_keys:
            infrastructure.append(_infra(str(sequence or "unknown"), "unknown", "trace has unknown top-level field(s)", unknown=sorted(unknown_trace_keys)))
        if not isinstance(sequence, str) or sequence in trace_map:
            infrastructure.append(_infra(str(sequence or "unknown"), "unknown", "duplicate or missing trace sequence")); continue
        if trace.get("model_digest") != expected_model_digest:
            infrastructure.append(_infra(sequence, "unknown", "trace model digest does not match declaration", model_digest=expected_model_digest, trace_model_digest=trace.get("model_digest"))); continue
        trace_map[sequence] = copy.deepcopy(trace)
    # Malformed, duplicate, or model-mismatched traces are findings too.  A
    # good trace must never hide an invalid extra trace from the verdict.
    findings: List[Dict[str, Any]] = list(infrastructure)
    expected_sequences = {name for name, _ in variants}
    for sequence_name, event_names in variants:
        trace = trace_map.get(sequence_name)
        auth_names = [name for name in event_names if model.events[name].kind == "authorization"]
        if len(auth_names) != 1:
            findings.append(_infra(sequence_name, auth_names[0] if auth_names else "unknown", "each analyzed path must contain exactly one authorization event")); continue
        auth_name = auth_names[0]
        if trace is None:
            findings.append(_infra(sequence_name, auth_name, "complete authorization trace is missing", model_digest=expected_model_digest)); continue
        event_map, error, observed_order = _event_map(trace)
        if error:
            findings.append(_infra(sequence_name, auth_name, error, model_digest=expected_model_digest)); continue
        occurrence_by_name: Dict[str, int] = {}
        payloads: Dict[Tuple[str, int], Mapping[str, Any]] = {}
        bad_order = False
        expected_order: List[Tuple[str, int]] = []
        produced: set[str] = set()
        ordered_payloads: List[Tuple[int, str, int, Mapping[str, Any]]] = []
        authorization_position = next((idx for idx, name in enumerate(event_names) if name == auth_name), len(event_names))
        for position, event_name in enumerate(event_names):
            occurrence = occurrence_by_name.get(event_name, 0); occurrence_by_name[event_name] = occurrence + 1
            expected_order.append((event_name, occurrence))
            event = model.events[event_name]
            item = event_map.get((event_name, occurrence))
            if item is None:
                if event.kind in {"parse", "user_review", "digest", "signature", "trusted_validation", "authorization"}:
                    findings.append(_infra(sequence_name, auth_name, "missing event occurrence {!r}".format(event_name), model_digest=expected_model_digest, event=event_name, occurrence=occurrence)); bad_order = True
                continue
            if position > authorization_position:
                findings.append(_infra(sequence_name, auth_name, "evidence event occurs after authorization", model_digest=expected_model_digest, event=event_name, occurrence=occurrence)); bad_order = True
            if item.get("complete") is not True:
                findings.append(_infra(sequence_name, auth_name, "event occurrence is incomplete", model_digest=expected_model_digest, event=event_name, occurrence=occurrence)); bad_order = True
            payload_key = {
                "parse": "produced",
                "user_review": "reviewed",
                "digest": "digest_values",
                "signature": "covered_values",
                "trusted_validation": "validated",
                "authorization": "authorized",
            }.get(event.kind)
            allowed_trace_keys = {"name", "occurrence", "complete"}
            if event.kind == "digest":
                allowed_trace_keys.add("accepted")
            elif event.kind == "signature":
                allowed_trace_keys.update({"accepted", "covered"})
            elif event.kind == "trusted_validation":
                allowed_trace_keys.update({"pass", "binding", "authority", "rule"})
            if payload_key:
                allowed_trace_keys.add(payload_key)
                if payload_key not in item:
                    findings.append(_infra(sequence_name, auth_name, "event evidence is missing", model_digest=expected_model_digest, event=event_name, evidence_key=payload_key)); bad_order = True
            unknown_trace_keys = set(item) - allowed_trace_keys
            if unknown_trace_keys:
                findings.append(_infra(sequence_name, auth_name, "event evidence has unknown field(s)", model_digest=expected_model_digest, event=event_name, unknown=sorted(unknown_trace_keys))); bad_order = True
            payloads[(event_name, occurrence)] = item
            ordered_payloads.append((position, event_name, occurrence, item))
            refs = {
                "parse": event.values,
                "user_review": event.values,
                "authorization": event.values,
                "digest": model.digests[event.digest].covers if event.digest else (),
                "signature": model.digests[event.digest].covers if event.digest else (),
                "trusted_validation": model.trusted_bindings[event.binding].covers if event.binding else (),
            }.get(event.kind, ())
            if event.kind != "parse" and not set(refs).issubset(produced):
                findings.append(_infra(sequence_name, auth_name, "event {!r} precedes production of its inputs".format(event_name), model_digest=expected_model_digest, event=event_name, required=list(refs), produced=sorted(produced))); bad_order = True
            if event.kind == "parse":
                produced.update(refs)
            if event.kind == "digest" and item.get("accepted") is not True:
                findings.append(_infra(sequence_name, auth_name, "digest event was not accepted", model_digest=expected_model_digest, event=event_name)); bad_order = True
        if observed_order != expected_order:
            findings.append(_infra(sequence_name, auth_name, "trace event order does not match expanded sequence", model_digest=expected_model_digest, expected_events=expected_order, observed_events=observed_order)); continue
        if bad_order:
            continue
        parse_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "parse"]
        parse_events = [name for _, name, _, _ in parse_entries]
        auth_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "authorization"]
        auth_key = (auth_entries[0][1], auth_entries[0][2]) if auth_entries else None
        authorization_occurrence = auth_entries[0][2] if auth_entries else None
        parse_payload: Dict[str, Any] = {}
        parse_invalid = False
        for _, parse_name, parse_occurrence, parse_event_payload in parse_entries:
            parse_refs = _refs_from_payload(parse_event_payload, "produced")
            if set(parse_refs) != set(model.events[parse_name].values):
                findings.append(_infra(sequence_name, auth_name, "parse evidence does not match declared outputs", model_digest=expected_model_digest, parse_event=parse_name, occurrence=parse_occurrence)); parse_invalid = True; continue
            for ref, value in parse_refs.items():
                if ref in parse_payload and parse_payload[ref] != value:
                    findings.append(_infra(sequence_name, auth_name, "repeated parse evidence conflicts", model_digest=expected_model_digest, parse_event=parse_name, occurrence=parse_occurrence, field=ref)); parse_invalid = True
                else:
                    parse_payload[ref] = value
        auth_payload = _refs_from_payload(payloads.get(auth_key, {}), "authorized") if auth_key else {}
        if not parse_entries or parse_invalid:
            continue
        parse_occurrence = parse_entries[-1][2]
        digest_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "digest"]
        digest_invalid = False
        digest_seen: Dict[str, Mapping[str, Any]] = {}
        for _, digest_name, digest_occurrence, digest_event_payload in digest_entries:
            digest_decl = model.digests[model.events[digest_name].digest or ""]
            digest_values = _refs_from_payload(digest_event_payload, "digest_values")
            if set(digest_values) != set(digest_decl.covers):
                findings.append(_infra(sequence_name, auth_name, "digest evidence does not match declared coverage", model_digest=expected_model_digest, digest_event=digest_name, occurrence=digest_occurrence)); digest_invalid = True; continue
            if digest_decl.name in digest_seen and digest_seen[digest_decl.name] != digest_values:
                findings.append(_infra(sequence_name, auth_name, "repeated digest evidence conflicts", model_digest=expected_model_digest, digest_event=digest_name, occurrence=digest_occurrence, digest= digest_decl.name)); digest_invalid = True
            else:
                digest_seen[digest_decl.name] = digest_values
        if digest_invalid:
            continue
        if set(auth_payload) != set(model.events[auth_name].values):
            findings.append(_infra(sequence_name, auth_name, "authorization evidence does not match declared inputs", model_digest=expected_model_digest, authorization_event=auth_name)); continue
        # Digest/signature acceptance is explicit and cannot be inferred from
        # the declaration or from a containing-object digest.
        signed_payload: Dict[str, Any] = {}
        signature_invalid = False
        signature_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "signature"]
        signature_names = [name for _, name, _, _ in signature_entries]
        signature_occurrences = [occurrence for _, _, occurrence, _ in signature_entries]
        for signature_position, signature_name, signature_occurrence, payload in signature_entries:
            event = model.events[signature_name]
            covered = payload.get("covered")
            digest = model.digests[event.digest] if event.digest else None
            prior_digest_entry = next((entry for entry in reversed(ordered_payloads) if entry[0] < signature_position and model.events[entry[1]].kind == "digest" and model.events[entry[1]].digest == event.digest), None)
            prior_digest = prior_digest_entry[1] if prior_digest_entry else None
            prior_digest_key = (prior_digest_entry[1], prior_digest_entry[2]) if prior_digest_entry else None
            digest_payload = payloads.get(prior_digest_key, {}) if prior_digest_key else {}
            if payload.get("accepted") is not True or not isinstance(covered, list) or digest is None or covered != list(digest.covers) or prior_digest is None or digest_payload.get("accepted") is not True:
                findings.append(_infra(sequence_name, auth_name, "signature coverage is missing or differs from declared digest", model_digest=expected_model_digest, signature_event=signature_name, digest=event.digest)); signature_invalid = True; continue
            covered_values = _refs_from_payload(payload, "covered_values")
            digest_values = _refs_from_payload(digest_payload, "digest_values")
            if list(covered_values) != covered or list(digest_values) != covered:
                findings.append(_infra(sequence_name, auth_name, "accepted signature lacks complete digest/value evidence", model_digest=expected_model_digest, signature_event=signature_name, digest_event=prior_digest)); signature_invalid = True; continue
            invalid_digest_value = next(
                (
                    ref for ref in covered
                    if not _validate_evidence(model, ref, digest_values.get(ref), evidence_context="digest")[0]
                ),
                None,
            )
            if invalid_digest_value is not None:
                findings.append(_infra(sequence_name, auth_name, "digest evidence is incomplete or malformed", model_digest=expected_model_digest, digest_event=prior_digest, field=invalid_digest_value)); signature_invalid = True; continue
            invalid_covered_value = next((ref for ref in covered if not _validate_evidence(model, ref, covered_values.get(ref), evidence_context="signature")[0]), None)
            if invalid_covered_value is not None:
                findings.append(_infra(sequence_name, auth_name, "signature value evidence is incomplete or malformed", model_digest=expected_model_digest, signature_event=signature_name, field=invalid_covered_value)); signature_invalid = True; continue
            for ref in covered:
                differs, differing_paths = _compare_ref(model, ref, digest_values[ref], covered_values[ref])
                if differs:
                    findings.append(_infra(sequence_name, auth_name, "signature collection/member evidence differs from accepted digest evidence", model_digest=expected_model_digest, digest_event=prior_digest, signature_event=signature_name, field=ref, differing_paths=differing_paths)); signature_invalid = True; break
            if signature_invalid:
                continue
            if any(
                any(digest_values[ref].get(key) != covered_values[ref].get(key) for key in ("digest", "canonical_type", "cardinality"))
                for ref in covered
                if isinstance(digest_values.get(ref), dict) and isinstance(covered_values.get(ref), dict)
            ):
                findings.append(_infra(sequence_name, auth_name, "signature value evidence differs from accepted digest evidence", model_digest=expected_model_digest, digest_event=prior_digest, signature_event=signature_name)); signature_invalid = True; continue
            for ref, value in covered_values.items():
                if ref in signed_payload and signed_payload[ref] != value:
                    findings.append(_infra(sequence_name, auth_name, "repeated signature evidence conflicts", model_digest=expected_model_digest, signature_event=signature_name, occurrence=signature_occurrence, field=ref)); signature_invalid = True
                else:
                    signed_payload[ref] = value
        if not signature_names:
            findings.append(_infra(sequence_name, auth_name, "no accepted signature event on path", model_digest=expected_model_digest)); continue
        if signature_invalid:
            continue
        review_payload: Dict[str, Any] = {}
        review_provenance: Dict[str, Tuple[str, int]] = {}
        review_invalid = False
        review_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "user_review"]
        for _, review_name, occurrence, payload in review_entries:
            refs = _refs_from_payload(payload, "reviewed")
            if set(refs) - set(model.events[review_name].values):
                findings.append(_infra(sequence_name, auth_name, "review evidence contains undeclared fields", model_digest=expected_model_digest, review_event=review_name)); review_invalid = True; continue
            for ref, value in refs.items():
                if ref in review_payload:
                    findings.append(_infra(sequence_name, auth_name, "repeated review evidence is ambiguous", model_digest=expected_model_digest, review_event=review_name, occurrence=occurrence, field=ref)); review_invalid = True
                else:
                    review_payload[ref] = value
                    review_provenance[ref] = (review_name, occurrence)
        validation_payload: Dict[str, Any] = {}
        validation_provenance: Dict[str, Tuple[str, int]] = {}
        validation_invalid = False
        validation_entries = [(pos, name, occurrence, payload) for pos, name, occurrence, payload in ordered_payloads if model.events[name].kind == "trusted_validation"]
        for _, validation_name, occurrence, payload in validation_entries:
            refs = _refs_from_payload(payload, "validated")
            binding = model.trusted_bindings[model.events[validation_name].binding]
            if set(refs) != set(binding.covers):
                findings.append(_infra(sequence_name, auth_name, "trusted-validation evidence contains undeclared fields", model_digest=expected_model_digest, validation_event=validation_name)); validation_invalid = True; continue
            normalized_refs: Dict[str, Any] = {}
            for ref, value in refs.items():
                if isinstance(value, dict):
                    normalized_value = dict(value)
                    for key in ("pass", "binding", "authority", "rule"):
                        if key in payload and key not in normalized_value:
                            normalized_value[key] = payload[key]
                    normalized_refs[ref] = normalized_value
                else:
                    normalized_refs[ref] = value
            for ref, value in normalized_refs.items():
                if ref in validation_payload and validation_payload[ref] != value:
                    findings.append(_infra(sequence_name, auth_name, "repeated trusted-validation evidence conflicts", model_digest=expected_model_digest, validation_event=validation_name, occurrence=occurrence, field=ref)); validation_invalid = True
                else:
                    validation_payload[ref] = value
                    validation_provenance[ref] = (validation_name, occurrence)
        if review_invalid or validation_invalid:
            continue
        for field_name in model.fields:
            field = model.field(field_name)
            review_required = field.review in {"required", "required_or_trusted"}
            if isinstance(field, Collection):
                review_required = review_required or any(item.review in {"required", "required_or_trusted"} for item in field.item_scalars.values())
            signed = signed_payload.get(field_name)
            review_declared = any(
                field_name in model.events[name].values
                for name in event_names
                if model.events[name].kind == "user_review"
            )
            if field_name not in parse_payload or (
                field.authorization and field_name not in auth_payload
            ) or (signed is None and not field.authorization and not review_declared):
                findings.append(_infra(sequence_name, auth_name, "authorization or parse evidence omits {!r}".format(field_name), model_digest=expected_model_digest, field=field_name)); continue
            ok_parse, why, card, tag = _validate_evidence(model, field_name, parse_payload[field_name], evidence_context="parse")
            ok_auth, why_auth, auth_card, auth_tag = (
                _validate_evidence(model, field_name, auth_payload[field_name], evidence_context="authorization")
                if field.authorization
                else (True, "", 0, "")
            )
            if not ok_parse or not ok_auth:
                findings.append(_infra(sequence_name, auth_name, "incomplete {} evidence for {!r}".format("parse" if not ok_parse else "authorization", field_name), model_digest=expected_model_digest, field=field_name, parse_reason=why, authorization_reason=why_auth)); continue
            if signed is None:
                if not field.authorization:
                    continue
                supported_paths: List[str] = []
                supported_provenance: Dict[str, Tuple[str, int, str]] = {}
                review_value = review_payload.get(field_name)
                if review_value is not None and field.review != "hidden":
                    review_ok, review_reason, _, _ = _validate_evidence(model, field_name, review_value, allow_partial_collection=isinstance(field, Collection), evidence_context="review")
                    if not review_ok:
                        findings.append(_infra(sequence_name, auth_name, "invalid review evidence for {!r}".format(field_name), model_digest=expected_model_digest, field=field_name, reason=review_reason)); continue
                    if isinstance(field, Collection):
                        source_items = parse_payload[field_name].get("items", [])
                        reviewed_gaps, _ = _collection_review_gaps(model, field_name, review_value, parse_payload[field_name])
                        gap_set = set(reviewed_gaps)
                        for item in source_items:
                            if isinstance(item, dict):
                                for item_name, item_field in field.item_scalars.items():
                                    path = "{}[{}].{}".format(field_name, item.get("index"), item_name)
                                    if item_field.review in {"required", "required_or_trusted"} and path not in gap_set:
                                        supported_paths.append(path)
                                        if field_name in review_provenance:
                                            supported_provenance[path] = (review_provenance[field_name][0], review_provenance[field_name][1], "review")
                    else:
                        supported_paths.append(field_name)
                        if field_name in review_provenance:
                            supported_provenance[field_name] = (review_provenance[field_name][0], review_provenance[field_name][1], "review")
                binding = model.trusted_bindings.get(field.trusted_binding or "")
                validation = validation_payload.get(field_name)
                trusted_metadata = (
                    binding is not None and isinstance(validation, dict)
                    and validation.get("pass") is True
                    and validation.get("binding") == binding.name
                    and validation.get("authority") == binding.authority
                    and validation.get("rule") == binding.rule
                    and validation.get("canonical_type") == parse_payload[field_name].get("canonical_type")
                    and validation.get("cardinality") == parse_payload[field_name].get("cardinality")
                    and validation.get("digest") == parse_payload[field_name].get("digest")
                )
                if trusted_metadata:
                    if isinstance(field, Collection):
                        trusted_paths, trusted_error = _trusted_collection_paths(model, field_name, validation, parse_payload[field_name], binding)
                        if trusted_error:
                            validation_source = validation_provenance.get(field_name)
                            findings.append(_infra(sequence_name, auth_name, trusted_error, model_digest=expected_model_digest, field=field_name, validation_event=validation_source[0] if validation_source else None, validation_occurrence=validation_source[1] if validation_source else None, reason=trusted_error)); trusted_paths = []
                        supported_paths.extend(path for path in trusted_paths if path not in supported_paths)
                        if field_name in validation_provenance:
                            for path in trusted_paths:
                                supported_provenance[path] = (validation_provenance[field_name][0], validation_provenance[field_name][1], "validation")
                    elif _validate_evidence(model, field_name, validation, evidence_context="validation")[0]:
                        differs, _ = _compare_ref(model, field_name, validation, parse_payload[field_name])
                        if not differs:
                            supported_paths.append(field_name)
                            if field_name in validation_provenance:
                                supported_provenance[field_name] = (validation_provenance[field_name][0], validation_provenance[field_name][1], "validation")
                if not supported_paths:
                    findings.append(_infra(sequence_name, auth_name, "authorization-required value lacks complete review or trusted evidence before missing signature coverage", model_digest=expected_model_digest, field=field_name))
                else:
                    for affected_path in supported_paths:
                        provenance = supported_provenance.get(affected_path)
                        provenance_evidence = {}
                        if provenance:
                            if provenance[2] == "review":
                                provenance_evidence.update(review_event=provenance[0], review_occurrence=provenance[1])
                            else:
                                provenance_evidence.update(validation_event=provenance[0], validation_occurrence=provenance[1])
                        findings.append(_finding("AUTHORIZATION_FIELD_NOT_SIGNED", sequence_name, auth_name, "authorization input {!r} is not covered by accepted signature".format(affected_path), model_digest=expected_model_digest, field=affected_path, authorization_event=auth_name, authorization_occurrence=authorization_occurrence, parse_event=parse_entries[-1][1], parse_occurrence=parse_occurrence, parse_evidence=parse_payload[field_name], review_evidence=review_payload.get(field_name), signature_events=signature_names, signature_occurrences=signature_occurrences, **provenance_evidence))
                continue
            ok_signed, signed_reason, signed_card, signed_tag = _validate_evidence(model, field_name, signed, evidence_context="signature")
            if not ok_signed:
                findings.append(_infra(sequence_name, auth_name, "invalid signed evidence for {!r}".format(field_name), model_digest=expected_model_digest, field=field_name, reason=signed_reason)); continue
            identity_sources = [("parse", parse_payload.get(field_name))]
            if field.authorization:
                identity_sources.append(("authorization", auth_payload.get(field_name)))
            identity_mismatch = False
            for source_name, source_value in identity_sources:
                if not isinstance(source_value, dict):
                    continue
                differs, identity_paths = _compare_ref(model, field_name, source_value, signed)
                if differs:
                    findings.append(_infra(sequence_name, auth_name, "{} evidence identity differs from signed value for {!r}".format(source_name, field_name), model_digest=expected_model_digest, field=field_name, source=source_name, differing_paths=identity_paths, source_digest=source_value.get("digest"), signed_digest=signed.get("digest"))); identity_mismatch = True
            if identity_mismatch:
                continue
            trusted_review_ok = False
            trusted_collection_paths: List[str] = []
            uses_trusted_items = isinstance(field, Collection) and any(item.review in {"hidden", "required_or_trusted"} for item in field.item_scalars.values())
            if field.review == "required_or_trusted" or uses_trusted_items:
                binding = model.trusted_bindings.get(field.trusted_binding or "")
                validation = validation_payload.get(field_name)
                trusted_review_ok = (
                    binding is not None and isinstance(validation, dict)
                    and validation.get("pass") is True
                    and validation.get("binding") == binding.name
                    and validation.get("authority") == binding.authority
                    and validation.get("rule") == binding.rule
                    and validation.get("digest") == signed.get("digest")
                    and validation.get("cardinality") == signed.get("cardinality")
                    and validation.get("canonical_type") == signed.get("canonical_type")
                )
                if isinstance(field, Collection) and isinstance(validation, dict) and binding is not None:
                    candidate_trusted_paths, trusted_error = _trusted_collection_paths(model, field_name, validation, signed, binding)
                    if trusted_error:
                        validation_source = validation_provenance.get(field_name)
                        findings.append(_infra(sequence_name, auth_name, trusted_error, model_digest=expected_model_digest, field=field_name, validation_event=validation_source[0] if validation_source else None, validation_occurrence=validation_source[1] if validation_source else None, reason=trusted_error)); continue
                    if trusted_review_ok:
                        trusted_collection_paths = candidate_trusted_paths
            collection_gaps: List[str] = []
            if isinstance(field, Collection) and review_required:
                if field_name in review_payload:
                    collection_gaps, _ = _collection_review_gaps(model, field_name, review_payload[field_name], signed)
                else:
                    collection_gaps = [
                        "{}[{}].{}".format(field_name, index, item_name)
                        for index in range(signed_card)
                        for item_name in field.item_scalars
                    ][:MAX_FINDING_PATHS]
            untrusted_collection_gaps = [path for path in collection_gaps if path not in trusted_collection_paths]
            if review_required and field_name not in review_payload and ((not isinstance(field, Collection) and not trusted_review_ok) or (isinstance(field, Collection) and untrusted_collection_gaps)):
                findings.append(_finding("SIGNED_FIELD_NOT_REVIEWED", sequence_name, auth_name, "signed field {!r} was not reviewed".format(field_name), model_digest=expected_model_digest, field=field_name, authorization_event=auth_name, authorization_occurrence=authorization_occurrence, parse_event=parse_entries[-1][1] if parse_entries else None, parse_occurrence=parse_occurrence if parse_entries else None, review_event=None, signature_events=signature_names, signature_occurrences=signature_occurrences, canonical_type=signed_tag, cardinality=signed_card, signed_digest=signed.get("digest")))
            elif review_required and field_name in review_payload:
                ok_review, review_reason, review_card, review_tag = _validate_evidence(
                    model,
                    field_name,
                    review_payload[field_name],
                    allow_partial_collection=isinstance(field, Collection),
                    evidence_context="review",
                )
                if not ok_review:
                    findings.append(_infra(sequence_name, auth_name, "invalid review evidence for {!r}".format(field_name), model_digest=expected_model_digest, field=field_name, reason=review_reason)); continue
                if isinstance(field, Collection):
                    gaps, paths = _collection_review_gaps(model, field_name, review_payload[field_name], signed)
                    gaps = [path for path in gaps if path not in trusted_collection_paths]
                    differs = bool(paths)
                    if gaps:
                        review_event_name, review_event_occurrence = review_provenance.get(field_name, (None, None))
                        findings.append(_finding("SIGNED_FIELD_NOT_REVIEWED", sequence_name, auth_name, "signed collection members were not reviewed for {!r}".format(field_name), model_digest=expected_model_digest, field=field_name, differing_paths=gaps, authorization_event=auth_name, authorization_occurrence=authorization_occurrence, parse_event=parse_entries[-1][1] if parse_entries else None, parse_occurrence=parse_occurrence if parse_entries else None, review_event=review_event_name, review_occurrence=review_event_occurrence, signature_events=signature_names, signature_occurrences=signature_occurrences, canonical_type=signed_tag, cardinality=signed_card, signed_digest=signed.get("digest")))
                else:
                    differs, paths = _compare_ref(model, field_name, review_payload[field_name], signed)
                if differs:
                    review_event_name, review_event_occurrence = review_provenance.get(field_name, (None, None))
                    findings.append(_finding("REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE", sequence_name, auth_name, "reviewed and signed values differ for {!r}".format(field_name), model_digest=expected_model_digest, field=field_name, differing_paths=paths, authorization_event=auth_name, authorization_occurrence=authorization_occurrence, parse_event=parse_entries[-1][1] if parse_entries else None, parse_occurrence=parse_occurrence if parse_entries else None, review_event=review_event_name, review_occurrence=review_event_occurrence, signature_events=signature_names, signature_occurrences=signature_occurrences, canonical_type_reviewed=review_tag, canonical_type_signed=signed_tag, cardinality_reviewed=review_card, cardinality_signed=signed_card, reviewed_digest=review_payload[field_name].get("digest"), signed_digest=signed.get("digest")))
            if isinstance(field, Collection) and uses_trusted_items:
                signed_items = signed.get("items") if isinstance(signed, dict) else []
                hidden_paths = [
                    "{}[{}].{}".format(field_name, item.get("index"), item_name)
                    for item in (signed_items or []) if isinstance(item, dict)
                    for item_name, item_field in field.item_scalars.items()
                    if item_field.review == "hidden"
                ]
                for hidden_path in [path for path in hidden_paths if path not in trusted_collection_paths]:
                    findings.append(_finding("UNVERIFIED_HIDDEN_VALUE", sequence_name, auth_name, "hidden collection member {!r} lacks an observed trusted binding".format(hidden_path), model_digest=expected_model_digest, field=hidden_path, authorization_event=auth_name, parse_event=parse_events[-1] if parse_events else None, signature_events=signature_names, trusted_binding=field.trusted_binding, canonical_type=signed_tag, cardinality=signed_card, signed_digest=signed.get("digest")))
            if field.review == "hidden":
                binding_name = field.trusted_binding
                binding = model.trusted_bindings.get(binding_name or "")
                validation = validation_payload.get(field_name)
                valid_validation = (
                    binding is not None
                    and isinstance(validation, dict)
                    and validation.get("pass") is True
                    and validation.get("binding") == binding.name
                    and validation.get("authority") == binding.authority
                    and validation.get("rule") == binding.rule
                    and _validate_evidence(model, field_name, validation, evidence_context="validation")[0]
                    and validation.get("digest") == signed.get("digest")
                    and validation.get("cardinality") == signed.get("cardinality")
                    and validation.get("canonical_type") == signed.get("canonical_type")
                )
                if not valid_validation:
                    findings.append(_finding("UNVERIFIED_HIDDEN_VALUE", sequence_name, auth_name, "hidden value {!r} lacks an observed trusted binding".format(field_name), model_digest=expected_model_digest, field=field_name, authorization_event=auth_name, parse_event=parse_events[-1] if parse_events else None, signature_events=signature_names, trusted_binding=binding_name, validation_event=next((name for name in event_names if model.events[name].kind == "trusted_validation" and model.events[name].binding == binding_name), None), canonical_type=signed_tag, cardinality=signed_card, signed_digest=signed.get("digest")))
        # Unknown trace fields are rejected so evidence cannot silently drift.
        known_names = set(event_names)
        if any(name not in known_names for name, _ in (event_map or {})):
            findings.append(_infra(sequence_name, auth_name, "trace contains event not present in expanded path", model_digest=expected_model_digest))
    extras = sorted(set(trace_map) - expected_sequences)
    for sequence in extras:
        findings.append(_infra(sequence, "unknown", "trace names unknown expanded sequence", model_digest=expected_model_digest))
    semantic = [item for item in findings if item["id"] in {"AUTHORIZATION_FIELD_NOT_SIGNED", "SIGNED_FIELD_NOT_REVIEWED", "UNVERIFIED_HIDDEN_VALUE", "REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE"}]
    return {
        "verdict": "FAIL" if semantic else ("INCONCLUSIVE" if findings else "PASS"),
        "model_digest": expected_model_digest,
        "variants_analyzed": len(variants),
        "traces_analyzed": len(trace_map),
        "findings": findings,
    }


def load_trace(path: str | Path) -> Mapping[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AuthorizationReviewError("trace {} must contain a JSON object".format(path))
    return value


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze reviewed versus signed authorization content")
    parser.add_argument("--profile", required=True, help="YAML profile containing authorization_review")
    trace_group = parser.add_mutually_exclusive_group()
    trace_group.add_argument("--trace", action="append", default=[], help="authorization_review_trace JSON (repeatable)")
    trace_group.add_argument(
        "--emit-trace-template-dir",
        metavar="DIRECTORY",
        help="write incomplete authorization-review trace templates to DIRECTORY",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)
    try:
        from profile_loader import ProfileError, load_profile
        profile = load_profile(args.profile)
        if profile.authorization_review is None:
            raise AuthorizationReviewError("profile has no authorization_review block")
        if args.emit_trace_template_dir is not None:
            _emit_authorization_review_trace_templates(
                profile.authorization_review, args.emit_trace_template_dir
            )
            print(
                "WARNING: emitted trace template files are incomplete observations; "
                "collect runtime evidence before analysis."
            )
            return 0
        traces = [load_trace(path) for path in args.trace]
        report = analyze_authorization_review(profile.authorization_review, traces)
    except (OSError, ValueError, ProfileError) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Authorization review analysis: {}".format(profile.name))
        print("Verdict: {} ({} variants, {} traces)".format(report["verdict"], report["variants_analyzed"], report["traces_analyzed"]))
        for finding in report["findings"]:
            print("- {} [{}]: {}".format(finding["id"], finding.get("sequence") or "model", finding["message"]))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
