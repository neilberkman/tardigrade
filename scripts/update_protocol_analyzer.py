#!/usr/bin/env python3
"""Static security-path analysis for declarative firmware update protocols.

The analyzer complements Tardigrade's runtime fault injection.  It enumerates
declared update-message paths, including optional event groups, and verifies
that every path to a commit event is dominated by the required security gates
and metadata bindings.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


MAX_SEQUENCE_VARIANTS = 256


class UpdateProtocolError(ValueError):
    """Raised when an update_protocol declaration is invalid."""


@dataclass(frozen=True)
class MetadataField:
    name: str
    source: str
    semantic: str
    authenticated: bool
    available_after: str


@dataclass(frozen=True)
class ContentItem:
    name: str
    semantic: str
    size: Optional[int] = None


@dataclass(frozen=True)
class Destination:
    name: str
    role: str
    require_modeled_content: bool = False


@dataclass(frozen=True)
class ContentReference:
    """A whole content item or a half-open byte interval within one."""

    content: str
    offset: Optional[int] = None
    size: Optional[int] = None

    @property
    def is_whole(self) -> bool:
        return self.offset is None


@dataclass(frozen=True)
class ContentBinding:
    name: str
    authenticated_parent: str
    child: str
    method: str


@dataclass(frozen=True)
class ProtocolEvent:
    name: str
    kind: str
    policy: Optional[str] = None
    metadata: Optional[str] = None
    binding: Optional[str] = None
    covers: Tuple[ContentReference, ...] = ()
    content: Optional[ContentReference] = None
    content_binding: Optional[str] = None
    destinations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ExpectedBinding:
    name: str
    fields: Tuple[str, ...]
    before: str
    required: bool = True


@dataclass(frozen=True)
class SequenceEvent:
    event: str
    optional_key: Optional[str] = None


@dataclass(frozen=True)
class ProtocolSequence:
    name: str
    events: Tuple[SequenceEvent, ...]


@dataclass(frozen=True)
class UpdateProtocolModel:
    metadata: Mapping[str, MetadataField]
    content: Mapping[str, ContentItem]
    destinations: Mapping[str, Destination]
    content_bindings: Mapping[str, ContentBinding]
    events: Mapping[str, ProtocolEvent]
    bindings: Mapping[str, ExpectedBinding]
    sequences: Tuple[ProtocolSequence, ...]
    required_policies: Tuple[str, ...] = ()


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise UpdateProtocolError("{}: expected mapping".format(context))
    return value


def _nonempty_name(value: Any, context: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise UpdateProtocolError("{}: expected non-empty string".format(context))
    return text


def _reject_unknown(value: Mapping[str, Any], allowed: Iterable[str], context: str) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise UpdateProtocolError(
            "{}: unknown field(s): {}".format(context, ", ".join(unknown))
        )


def _strict_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise UpdateProtocolError("{}: expected boolean".format(context))
    return value


def _strict_nonnegative_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise UpdateProtocolError("{}: expected non-negative integer".format(context))
    return value


def _strict_positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise UpdateProtocolError("{}: expected positive integer".format(context))
    return value


def _parse_content_reference(
    raw: Any, context: str, content: Mapping[str, ContentItem]
) -> ContentReference:
    if isinstance(raw, str):
        name = _nonempty_name(raw, context)
        if name not in content:
            raise UpdateProtocolError("{}: unknown content {!r}".format(context, name))
        return ContentReference(name)
    ref = _mapping(raw, context)
    _reject_unknown(ref, {"content", "offset", "size"}, context)
    name = _nonempty_name(ref.get("content"), context + ".content")
    if name not in content:
        raise UpdateProtocolError("{}.content: unknown content {!r}".format(context, name))
    if ("offset" in ref) != ("size" in ref):
        raise UpdateProtocolError("{}: range references require both offset and size".format(context))
    if "offset" not in ref:
        return ContentReference(name)
    offset = _strict_nonnegative_int(ref["offset"], context + ".offset")
    size = _strict_positive_int(ref["size"], context + ".size")
    declared_size = content[name].size
    if declared_size is None:
        raise UpdateProtocolError(
            "{}: ranges are valid only for content with a known size".format(context)
        )
    if offset > declared_size or size > declared_size - offset:
        raise UpdateProtocolError(
            "{}: range [{}, {}) is outside declared size {}".format(
                context, offset, offset + size, declared_size
            )
        )
    return ContentReference(name, offset, size)


def parse_update_protocol(raw: Any) -> Optional[UpdateProtocolModel]:
    """Validate and parse an optional ``update_protocol`` profile block."""
    if raw is None:
        return None
    root = _mapping(raw, "update_protocol")
    _reject_unknown(
        root,
        {
            "metadata", "content", "destinations", "content_bindings",
            "events", "bindings", "sequences", "required_policies",
        },
        "update_protocol",
    )

    content_raw = _mapping(root.get("content", {}), "update_protocol.content")
    content: Dict[str, ContentItem] = {}
    for raw_name, raw_item in content_raw.items():
        name = _nonempty_name(raw_name, "update_protocol.content key")
        context = "update_protocol.content.{}".format(name)
        item = _mapping(raw_item, context)
        _reject_unknown(item, {"semantic", "size"}, context)
        size = (
            _strict_nonnegative_int(item["size"], context + ".size")
            if "size" in item else None
        )
        content[name] = ContentItem(
            name=name,
            semantic=_nonempty_name(item.get("semantic"), context + ".semantic"),
            size=size,
        )

    destinations_raw = _mapping(root.get("destinations", {}), "update_protocol.destinations")
    destinations: Dict[str, Destination] = {}
    for raw_name, raw_destination in destinations_raw.items():
        name = _nonempty_name(raw_name, "update_protocol.destinations key")
        context = "update_protocol.destinations.{}".format(name)
        destination = _mapping(raw_destination, context)
        _reject_unknown(destination, {"role", "require_modeled_content"}, context)
        destinations[name] = Destination(
            name=name,
            role=_nonempty_name(destination.get("role"), context + ".role"),
            require_modeled_content=_strict_bool(
                destination.get("require_modeled_content", False),
                context + ".require_modeled_content",
            ),
        )

    content_bindings_raw = _mapping(
        root.get("content_bindings", {}), "update_protocol.content_bindings"
    )
    content_bindings: Dict[str, ContentBinding] = {}
    for raw_name, raw_binding in content_bindings_raw.items():
        name = _nonempty_name(raw_name, "update_protocol.content_bindings key")
        context = "update_protocol.content_bindings.{}".format(name)
        binding = _mapping(raw_binding, context)
        _reject_unknown(binding, {"authenticated_parent", "child", "method"}, context)
        parent = _nonempty_name(binding.get("authenticated_parent"), context + ".authenticated_parent")
        child = _nonempty_name(binding.get("child"), context + ".child")
        if parent not in content:
            raise UpdateProtocolError("{}.authenticated_parent: unknown content {!r}".format(context, parent))
        if child not in content:
            raise UpdateProtocolError("{}.child: unknown content {!r}".format(context, child))
        content_bindings[name] = ContentBinding(
            name=name,
            authenticated_parent=parent,
            child=child,
            method=_nonempty_name(binding.get("method"), context + ".method"),
        )

    metadata_raw = _mapping(root.get("metadata", {}), "update_protocol.metadata")
    metadata: Dict[str, MetadataField] = {}
    for raw_name, raw_field in metadata_raw.items():
        name = _nonempty_name(raw_name, "update_protocol.metadata key")
        context = "update_protocol.metadata.{}".format(name)
        field = _mapping(raw_field, context)
        _reject_unknown(
            field,
            {"source", "semantic", "authenticated", "available_after"},
            context,
        )
        metadata[name] = MetadataField(
            name=name,
            source=_nonempty_name(field.get("source"), context + ".source"),
            semantic=_nonempty_name(field.get("semantic"), context + ".semantic"),
            authenticated=_strict_bool(
                field.get("authenticated"), context + ".authenticated"
            ),
            available_after=_nonempty_name(
                field.get("available_after"), context + ".available_after"
            ),
        )

    events_raw = _mapping(root.get("events"), "update_protocol.events")
    if not events_raw:
        raise UpdateProtocolError("update_protocol.events: expected at least one event")
    valid_kinds = {
        "message", "authentication", "security_gate", "binding",
        "content_binding", "write", "commit", "other"
    }
    events: Dict[str, ProtocolEvent] = {}
    for raw_name, raw_event in events_raw.items():
        name = _nonempty_name(raw_name, "update_protocol.events key")
        context = "update_protocol.events.{}".format(name)
        event = _mapping(raw_event, context)
        _reject_unknown(
            event,
            {
                "kind", "policy", "metadata", "binding", "covers", "content",
                "content_binding", "destination", "destinations",
            },
            context,
        )
        kind = _nonempty_name(event.get("kind"), context + ".kind")
        if kind not in valid_kinds:
            raise UpdateProtocolError(
                "{}.kind: expected one of {}, got {!r}".format(
                    context, sorted(valid_kinds), kind
                )
            )
        policy = event.get("policy")
        metadata_name = event.get("metadata")
        binding_name = event.get("binding")
        content_binding_name = event.get("content_binding")
        content_ref = None
        covers_raw = event.get("covers", [])
        destinations_ref = tuple()
        if not isinstance(covers_raw, list):
            raise UpdateProtocolError(context + ".covers: expected list")
        covers = tuple(
            _parse_content_reference(value, context + ".covers[{}]".format(index), content)
            for index, value in enumerate(covers_raw)
        )
        if "content" in event:
            content_ref = _parse_content_reference(event["content"], context + ".content", content)
        if "destination" in event and "destinations" in event:
            raise UpdateProtocolError(
                "{}: use destination or destinations, not both".format(context)
            )
        if "destination" in event:
            destinations_ref = (_nonempty_name(event["destination"], context + ".destination"),)
        elif "destinations" in event:
            destinations_raw = event["destinations"]
            if not isinstance(destinations_raw, list):
                raise UpdateProtocolError(context + ".destinations: expected list")
            destinations_ref = tuple(
                _nonempty_name(value, context + ".destinations")
                for value in destinations_raw
            )
        if len(set(destinations_ref)) != len(destinations_ref):
            raise UpdateProtocolError(
                "{}.destinations: duplicate destination reference".format(context)
            )
        for destination_name in destinations_ref:
            if destination_name not in destinations:
                raise UpdateProtocolError(
                    "{}.destination: unknown destination {!r}".format(
                        context, destination_name
                    )
                )
        if kind == "security_gate":
            policy = _nonempty_name(policy, context + ".policy")
            metadata_name = _nonempty_name(metadata_name, context + ".metadata")
        elif policy is not None or metadata_name is not None:
            raise UpdateProtocolError(
                "{}: policy and metadata are valid only for security_gate events".format(
                    context
                )
            )
        if kind == "binding":
            binding_name = _nonempty_name(binding_name, context + ".binding")
        elif binding_name is not None:
            raise UpdateProtocolError(
                "{}.binding is valid only for binding events".format(context)
                )
        if kind == "authentication":
            if content_ref is not None or content_binding_name is not None or destinations_ref:
                raise UpdateProtocolError(
                    "{}: content, content_binding, and destinations are invalid for "
                    "authentication events".format(context)
                )
        elif covers:
            raise UpdateProtocolError("{}.covers is valid only for authentication events".format(context))
        if kind == "content_binding":
            content_binding_name = _nonempty_name(
                content_binding_name, context + ".content_binding"
            )
        elif content_binding_name is not None:
            raise UpdateProtocolError(
                "{}.content_binding is valid only for content_binding events".format(context)
            )
        if kind == "write":
            if content_ref is None:
                raise UpdateProtocolError("{}.content: required for write events".format(context))
            if len(destinations_ref) != 1:
                raise UpdateProtocolError(
                    "{}.destinations: write events require exactly one destination".format(context)
                )
            # The singular spelling is the concise write-event form; the
            # plural spelling remains accepted for compatibility with models
            # that use one uniform destination field.
        elif "destination" in event:
            raise UpdateProtocolError("{}.destination is valid only for write events".format(context))
        elif content_ref is not None:
            raise UpdateProtocolError("{}.content is valid only for write events".format(context))
        if kind == "commit":
            if "destinations" in event and not destinations_ref:
                raise UpdateProtocolError("{}.destinations: expected at least one destination".format(context))
        elif destinations_ref and kind != "write":
            raise UpdateProtocolError(
                "{}.destinations is valid only for write or commit events".format(context)
            )
        if kind == "content_binding" and content_binding_name not in content_bindings:
            raise UpdateProtocolError(
                "{}.content_binding: unknown content binding {!r}".format(
                    context, content_binding_name
                )
            )
        events[name] = ProtocolEvent(
            name=name,
            kind=kind,
            policy=str(policy) if policy is not None else None,
            metadata=str(metadata_name) if metadata_name is not None else None,
            binding=str(binding_name) if binding_name is not None else None,
            covers=covers,
            content=content_ref,
            content_binding=(
                str(content_binding_name) if content_binding_name is not None else None
            ),
            destinations=destinations_ref,
        )

    bindings_raw = root.get("bindings", {})
    bindings_map = _mapping(bindings_raw, "update_protocol.bindings")
    bindings: Dict[str, ExpectedBinding] = {}
    for raw_name, raw_binding in bindings_map.items():
        name = _nonempty_name(raw_name, "update_protocol.bindings key")
        context = "update_protocol.bindings.{}".format(name)
        binding = _mapping(raw_binding, context)
        _reject_unknown(binding, {"fields", "before", "required"}, context)
        fields_raw = binding.get("fields")
        if not isinstance(fields_raw, list) or len(fields_raw) < 2:
            raise UpdateProtocolError(
                "{}.fields: expected at least two field names".format(context)
            )
        fields = tuple(_nonempty_name(v, context + ".fields") for v in fields_raw)
        if len(set(fields)) != len(fields):
            raise UpdateProtocolError("{}.fields: duplicate field name".format(context))
        bindings[name] = ExpectedBinding(
            name=name,
            fields=fields,
            before=_nonempty_name(binding.get("before"), context + ".before"),
            required=_strict_bool(binding.get("required", True), context + ".required"),
        )

    sequences_raw = root.get("sequences")
    if not isinstance(sequences_raw, list) or not sequences_raw:
        raise UpdateProtocolError("update_protocol.sequences: expected non-empty list")
    sequences: List[ProtocolSequence] = []
    sequence_names = set()
    for index, raw_sequence in enumerate(sequences_raw):
        context = "update_protocol.sequences[{}]".format(index)
        sequence = _mapping(raw_sequence, context)
        _reject_unknown(sequence, {"name", "events"}, context)
        name = _nonempty_name(sequence.get("name"), context + ".name")
        if name in sequence_names:
            raise UpdateProtocolError("update_protocol.sequences: duplicate name {!r}".format(name))
        sequence_names.add(name)
        sequence_events_raw = sequence.get("events")
        if not isinstance(sequence_events_raw, list) or not sequence_events_raw:
            raise UpdateProtocolError("{}.events: expected non-empty list".format(context))
        sequence_events: List[SequenceEvent] = []
        for event_index, raw_ref in enumerate(sequence_events_raw):
            ref_context = "{}.events[{}]".format(context, event_index)
            optional_key: Optional[str] = None
            if isinstance(raw_ref, str):
                event_name = _nonempty_name(raw_ref, ref_context)
            else:
                ref = _mapping(raw_ref, ref_context)
                _reject_unknown(
                    ref, {"event", "optional", "optional_group"}, ref_context
                )
                event_name = _nonempty_name(ref.get("event"), ref_context + ".event")
                optional = _strict_bool(
                    ref.get("optional", False), ref_context + ".optional"
                )
                optional_group = ref.get("optional_group")
                if optional and optional_group is not None:
                    raise UpdateProtocolError(
                        "{}: use optional or optional_group, not both".format(ref_context)
                    )
                if optional_group is not None:
                    optional_key = "group:" + _nonempty_name(
                        optional_group, ref_context + ".optional_group"
                    )
                elif optional:
                    optional_key = "event:{}:{}".format(index, event_index)
            sequence_events.append(SequenceEvent(event_name, optional_key))
        sequences.append(ProtocolSequence(name, tuple(sequence_events)))

    required_raw = root.get("required_policies", [])
    if not isinstance(required_raw, list):
        raise UpdateProtocolError("update_protocol.required_policies: expected list")
    required_policies = tuple(
        _nonempty_name(value, "update_protocol.required_policies")
        for value in required_raw
    )
    if len(set(required_policies)) != len(required_policies):
        raise UpdateProtocolError("update_protocol.required_policies: duplicate policy")

    model = UpdateProtocolModel(
        metadata=metadata,
        content=content,
        destinations=destinations,
        content_bindings=content_bindings,
        events=events,
        bindings=bindings,
        sequences=tuple(sequences),
        required_policies=required_policies,
    )
    _validate_model_references(model)
    # Validate the expansion bound during loading rather than surprising a CI run.
    list(iter_sequence_variants(model))
    return model


def _validate_model_references(model: UpdateProtocolModel) -> None:
    for field in model.metadata.values():
        if field.available_after not in model.events:
            raise UpdateProtocolError(
                "update_protocol.metadata.{}.available_after: unknown event {!r}".format(
                    field.name, field.available_after
                )
            )
    for event in model.events.values():
        if event.metadata is not None and event.metadata not in model.metadata:
            raise UpdateProtocolError(
                "update_protocol.events.{}.metadata: unknown field {!r}".format(
                    event.name, event.metadata
                )
            )
        if event.binding is not None and event.binding not in model.bindings:
            raise UpdateProtocolError(
                "update_protocol.events.{}.binding: unknown binding {!r}".format(
                    event.name, event.binding
                )
            )
    for binding in model.bindings.values():
        for field in binding.fields:
            if field not in model.metadata:
                raise UpdateProtocolError(
                    "update_protocol.bindings.{}.fields: unknown field {!r}".format(
                        binding.name, field
                    )
                )
        if binding.before not in model.events:
            raise UpdateProtocolError(
                "update_protocol.bindings.{}.before: unknown event {!r}".format(
                    binding.name, binding.before
                )
            )
        if model.events[binding.before].kind != "commit":
            raise UpdateProtocolError(
                "update_protocol.bindings.{}.before: event {!r} is not a commit".format(
                    binding.name, binding.before
                )
            )
    for sequence in model.sequences:
        for ref in sequence.events:
            if ref.event not in model.events:
                raise UpdateProtocolError(
                    "update_protocol.sequences.{}: unknown event {!r}".format(
                        sequence.name, ref.event
                    )
                )


def iter_sequence_variants(
    model: UpdateProtocolModel,
) -> Iterable[Tuple[str, Tuple[str, ...]]]:
    """Yield explicit and optional-event variants in deterministic order."""
    total = 0
    for sequence in model.sequences:
        optional_keys = sorted(
            {ref.optional_key for ref in sequence.events if ref.optional_key is not None}
        )
        variant_count = 1 << len(optional_keys)
        if total + variant_count > MAX_SEQUENCE_VARIANTS:
            raise UpdateProtocolError(
                "update_protocol: optional paths expand to more than {} variants".format(
                    MAX_SEQUENCE_VARIANTS
                )
            )
        total += variant_count
        for choices in itertools.product((False, True), repeat=len(optional_keys)):
            enabled = dict(zip(optional_keys, choices))
            events = tuple(
                ref.event
                for ref in sequence.events
                if ref.optional_key is None or enabled[ref.optional_key]
            )
            omitted = [key.split(":", 1)[-1] for key in optional_keys if not enabled[key]]
            variant_name = sequence.name
            if omitted:
                variant_name += " [without {}]".format(", ".join(omitted))
            yield variant_name, events


def _security_policy_names(security_policy: Any) -> Tuple[str, ...]:
    required: List[str] = []
    if security_policy is None:
        return ()
    if isinstance(security_policy, dict):
        anti_rollback = security_policy.get("anti_rollback", False)
    else:
        anti_rollback = getattr(security_policy, "anti_rollback", False)
    if anti_rollback:
        required.append("anti_rollback")
    return tuple(required)


def _binding_connects(binding: ExpectedBinding, left: str, right: str) -> bool:
    return left in binding.fields and right in binding.fields


def _binding_is_enforced(
    model: UpdateProtocolModel,
    binding: ExpectedBinding,
    event_names: Sequence[str],
) -> bool:
    """Return whether a binding occurs after all of its inputs are available."""
    for index, event_name in enumerate(event_names):
        event = model.events[event_name]
        if event.kind != "binding" or event.binding != binding.name:
            continue
        prior = set(event_names[:index])
        if all(
            model.metadata[field].available_after in prior for field in binding.fields
        ):
            return True
    return False


def _add_interval(intervals: List[Tuple[int, int]], start: int, end: int) -> None:
    """Add an interval and keep the union normalized."""
    if start >= end:
        return
    merged: List[Tuple[int, int]] = []
    for left, right in sorted(intervals + [(start, end)]):
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    intervals[:] = merged


def _coverage_covers(
    model: UpdateProtocolModel,
    coverage: Mapping[str, Tuple[bool, Tuple[Tuple[int, int], ...]]],
    reference: ContentReference,
) -> bool:
    whole, intervals = coverage.get(reference.content, (False, ()))
    if whole:
        return True
    item = model.content[reference.content]
    if reference.is_whole:
        if item.size is None:
            return False
        start, end = 0, item.size
    else:
        assert reference.offset is not None and reference.size is not None
        start, end = reference.offset, reference.offset + reference.size
    cursor = start
    for left, right in intervals:
        if right <= cursor:
            continue
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return cursor >= end


def _content_coverage_at(
    model: UpdateProtocolModel,
    event_names: Sequence[str],
    stop: int,
) -> Tuple[Dict[str, Tuple[bool, Tuple[Tuple[int, int], ...]]], List[str]]:
    """Compute coverage before ``stop``, applying content bindings in order."""
    whole: Dict[str, bool] = {}
    intervals: Dict[str, List[Tuple[int, int]]] = {}
    authentication_events: List[str] = []

    def add_reference(reference: ContentReference) -> None:
        if reference.is_whole:
            whole[reference.content] = True
            return
        assert reference.offset is not None and reference.size is not None
        _add_interval(
            intervals.setdefault(reference.content, []),
            reference.offset,
            reference.offset + reference.size,
        )

    for index, event_name in enumerate(event_names[:stop]):
        event = model.events[event_name]
        if event.kind == "authentication":
            authentication_events.append(event.name)
            for reference in event.covers:
                add_reference(reference)
        elif event.kind == "content_binding":
            binding = model.content_bindings[event.content_binding]  # validated at load
            parent = ContentReference(binding.authenticated_parent)
            current = {
                name: (whole.get(name, False), tuple(intervals.get(name, [])))
                for name in model.content
            }
            if _coverage_covers(model, current, parent):
                whole[binding.child] = True

    return (
        {
            name: (whole.get(name, False), tuple(intervals.get(name, [])))
            for name in model.content
        },
        authentication_events,
    )


def analyze_update_protocol(
    model: UpdateProtocolModel,
    security_policy: Any = None,
) -> Dict[str, Any]:
    """Analyze every declared path to commit and return a JSON-ready report."""
    required_policies = tuple(
        dict.fromkeys(model.required_policies + _security_policy_names(security_policy))
    )
    findings: List[Dict[str, Any]] = []
    variants_analyzed = 0
    commit_paths = 0

    def add(
        finding_id: str,
        sequence: str,
        event_names: Sequence[str],
        message: str,
        **evidence: Any
    ) -> None:
        findings.append(
            {
                "id": finding_id,
                "severity": "high",
                "sequence": sequence,
                "events": list(event_names),
                "message": message,
                "evidence": evidence,
            }
        )

    for sequence_name, event_names in iter_sequence_variants(model):
        variants_analyzed += 1

        # Every write into a non-staging destination must be governed by a
        # later commit that explicitly names that destination.  Checking only
        # the prefixes of commits leaves two blind spots: a separate path can
        # write executable content and end without a commit, or a write can
        # occur after the last relevant commit.  A staging-only preparation
        # path remains valid because staging is not an activation boundary.
        for write_index, write_name in enumerate(event_names):
            write_event = model.events[write_name]
            if write_event.kind != "write":
                continue
            non_staging_destinations = [
                destination_name
                for destination_name in write_event.destinations
                if model.destinations[destination_name].role != "staging"
            ]
            for destination_name in non_staging_destinations:
                governing_commits = [
                    later_name
                    for later_name in event_names[write_index + 1:]
                    if model.events[later_name].kind == "commit"
                    and destination_name in model.events[later_name].destinations
                ]
                if governing_commits:
                    continue
                findings.append(
                    {
                        "id": "WRITE_WITHOUT_GOVERNING_COMMIT",
                        "severity": "configuration",
                        "sequence": sequence_name,
                        "events": list(event_names),
                        "message": (
                            "Write {!r} reaches non-staging destination {!r} "
                            "without a later commit naming that destination."
                        ).format(write_name, destination_name),
                        "evidence": {
                            "write_event": write_name,
                            "destination": destination_name,
                            "later_governing_commits": governing_commits,
                        },
                    }
                )

        for commit_index, event_name in enumerate(event_names):
            commit_event = model.events[event_name]
            if commit_event.kind != "commit":
                continue
            commit_paths += 1
            prefix_names = event_names[:commit_index]
            prefix = [model.events[name] for name in prefix_names]
            prefix_name_set = set(prefix_names)

            for prefix_index, event in enumerate(prefix):
                if event.kind != "security_gate" or event.metadata is None:
                    continue
                field = model.metadata[event.metadata]
                if field.available_after not in set(prefix_names[:prefix_index]):
                    add(
                        "GATE_METADATA_UNAVAILABLE",
                        sequence_name,
                        event_names,
                        "Security gate {!r} can run before metadata {!r} is available.".format(
                            event.name, field.name
                        ),
                        gate=event.name,
                        metadata=field.name,
                        available_after=field.available_after,
                        commit=event_name,
                    )

            for policy in required_policies:
                gates = [
                    event
                    for index, event in enumerate(prefix)
                    if event.kind == "security_gate"
                    and event.policy == policy
                    and event.metadata is not None
                    and model.metadata[event.metadata].available_after
                    in set(prefix_names[:index])
                ]
                if not gates:
                    add(
                        "SECURITY_GATE_BYPASS",
                        sequence_name,
                        event_names,
                        "Path reaches commit {!r} without required {!r} gate.".format(
                            event_name, policy
                        ),
                        policy=policy,
                        commit=event_name,
                    )
                    continue

                for gate in gates:
                    if gate.metadata is None:
                        continue
                    checked = model.metadata[gate.metadata]
                    if checked.authenticated:
                        continue
                    authenticated_peers = [
                        field
                        for field in model.metadata.values()
                        if field.semantic == checked.semantic
                        and field.authenticated
                        and field.available_after in prefix_name_set
                    ]
                    if not authenticated_peers:
                        add(
                            "UNAUTHENTICATED_SECURITY_METADATA",
                            sequence_name,
                            event_names,
                            "Gate {!r} checks unauthenticated {!r}; no authenticated "
                            "metadata with semantic {!r} is available before commit.".format(
                                gate.name, checked.name, checked.semantic
                            ),
                            policy=policy,
                            gate=gate.name,
                            checked_metadata=checked.name,
                            authenticated_metadata=[],
                            commit=event_name,
                        )
                        continue
                    protected = any(
                        other.kind == "security_gate"
                        and other.policy == policy
                        and other.metadata in {field.name for field in authenticated_peers}
                        for other in gates
                    )
                    if not protected:
                        for binding in model.bindings.values():
                            if not any(
                                _binding_connects(binding, checked.name, peer.name)
                                for peer in authenticated_peers
                            ):
                                continue
                            if _binding_is_enforced(model, binding, prefix_names):
                                protected = True
                                break
                    if not protected:
                        add(
                            "UNAUTHENTICATED_SECURITY_METADATA",
                            sequence_name,
                            event_names,
                            "Gate {!r} checks unauthenticated {!r}, but authenticated {} "
                            "is neither checked nor bound before commit.".format(
                                gate.name,
                                checked.name,
                                ", ".join(repr(field.name) for field in authenticated_peers),
                            ),
                            policy=policy,
                            gate=gate.name,
                            checked_metadata=checked.name,
                            authenticated_metadata=[field.name for field in authenticated_peers],
                            commit=event_name,
                        )

            for binding in model.bindings.values():
                if not binding.required or binding.before != event_name:
                    continue
                # A binding is conditional when one of its fields comes from an
                # optional message absent from this path.
                if not all(
                    model.metadata[field].available_after in prefix_name_set
                    for field in binding.fields
                ):
                    continue
                enforced = _binding_is_enforced(model, binding, prefix_names)
                if not enforced:
                    add(
                        "MISSING_EXPECTED_BINDING",
                        sequence_name,
                        event_names,
                        "Expected metadata binding {!r} is not enforced before commit {!r}.".format(
                            binding.name, event_name
                        ),
                        binding=binding.name,
                        fields=list(binding.fields),
                        commit=event_name,
                    )

            # Content coverage is deliberately evaluated on the same expanded
            # path as the metadata checks above.  Authentication of a manifest
            # does not implicitly authenticate any other content item.
            # A commit without destinations is retained for backwards
            # compatibility with metadata-only protocols.  Once the model
            # declares a non-staging destination, however, omitting the
            # destination list would make the content checks unreachable and
            # therefore silently turn an incomplete model into a pass.
            modeled_committed_destinations = [
                destination.name
                for destination in model.destinations.values()
                if destination.role != "staging"
            ]
            if not commit_event.destinations and modeled_committed_destinations:
                findings.append(
                    {
                        "id": "COMMIT_WITHOUT_DECLARED_DESTINATIONS",
                        "severity": "configuration",
                        "sequence": sequence_name,
                        "events": list(event_names),
                        "message": (
                            "Commit {!r} omits destinations while the model declares "
                            "committed destinations; content coverage cannot be assessed."
                        ).format(event_name),
                        "evidence": {
                            "commit": event_name,
                            "commit_event": event_name,
                            "declared_committed_destinations": (
                                modeled_committed_destinations
                            ),
                            "authentication_events": [],
                        },
                    }
                )
            if commit_event.destinations:
                coverage, authentication_events = _content_coverage_at(
                    model, event_names, commit_index
                )
                eventual_coverage, eventual_authentication_events = _content_coverage_at(
                    model, event_names, len(event_names)
                )
                for destination_name in commit_event.destinations:
                    destination = model.destinations[destination_name]
                    writes = [
                        event
                        for event in prefix
                        if event.kind == "write"
                        and destination_name in event.destinations
                        and event.content is not None
                    ]
                    if not writes:
                        if destination.require_modeled_content:
                            add(
                                "COMMIT_DESTINATION_WITH_UNKNOWN_CONTENT",
                                sequence_name,
                                event_names,
                                "Commit {!r} reaches destination {!r} without a modeled write."
                                .format(event_name, destination_name),
                                content=None,
                                destination=destination_name,
                                write_event=None,
                                commit=event_name,
                                commit_event=event_name,
                                authentication_events=authentication_events,
                            )
                        continue
                    if destination.role == "staging":
                        # Staging is an intermediate store.  It is intentionally
                        # outside the authenticated executable-destination rule.
                        continue
                    for write in writes:
                        assert write.content is not None
                        if _coverage_covers(model, coverage, write.content):
                            continue
                        if _coverage_covers(model, eventual_coverage, write.content):
                            finding_id = "CONTENT_AUTHENTICATED_AFTER_COMMIT"
                            message = (
                                "Content {!r} written by {!r} to destination {!r} is "
                                "authenticated only after commit {!r}."
                            ).format(
                                write.content.content,
                                write.name,
                                destination_name,
                                event_name,
                            )
                        else:
                            finding_id = "UNAUTHENTICATED_COMMITTED_CONTENT"
                            message = (
                                "Content {!r} written by {!r} to destination {!r} lacks "
                                "coverage before commit {!r}."
                            ).format(
                                write.content.content,
                                write.name,
                                destination_name,
                                event_name,
                            )
                        add(
                            finding_id,
                            sequence_name,
                            event_names,
                            message,
                            content=write.content.content,
                            content_reference={
                                "offset": write.content.offset,
                                "size": write.content.size,
                            },
                            destination=destination_name,
                            write_event=write.name,
                            commit=event_name,
                            commit_event=event_name,
                            authentication_events=(
                                eventual_authentication_events
                                if finding_id == "CONTENT_AUTHENTICATED_AFTER_COMMIT"
                                else authentication_events
                            ),
                        )

    # A staging-only preparation path is intentionally allowed to end before
    # activation.  It has no committed destination to assess, so it should not
    # be turned into a spurious no-commit security failure.
    staging_only_write_path = bool(model.content) and all(
        event.kind != "write"
        or all(
            model.destinations[destination].role == "staging"
            for destination in event.destinations
        )
        for sequence in model.sequences
        for event_name in sequence.events
        for event in [model.events[event_name.event]]
    ) and any(
        event.kind == "write"
        for sequence in model.sequences
        for event_name in sequence.events
        for event in [model.events[event_name.event]]
    )
    if commit_paths == 0 and not staging_only_write_path:
        findings.append(
            {
                "id": "NO_COMMIT_PATH",
                "severity": "configuration",
                "sequence": None,
                "events": [],
                "message": "No declared sequence reaches a commit event.",
                "evidence": {},
            }
        )

    return {
        "verdict": "FAIL" if findings else "PASS",
        "required_policies": list(required_policies),
        "variants_analyzed": variants_analyzed,
        "commit_paths_analyzed": commit_paths,
        "findings": findings,
    }


def _human_report(profile_name: str, report: Mapping[str, Any]) -> str:
    lines = [
        "Update protocol analysis: {}".format(profile_name),
        "Verdict: {} ({} variants, {} commit paths)".format(
            report["verdict"],
            report["variants_analyzed"],
            report["commit_paths_analyzed"],
        ),
    ]
    for finding in report["findings"]:
        lines.append(
            "- {} [{}]: {}".format(
                finding["id"], finding.get("sequence") or "model", finding["message"]
            )
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze update-protocol security gates and artifact bindings"
    )
    parser.add_argument("--profile", required=True, help="Tardigrade profile YAML")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)

    try:
        # Imported lazily so this module remains usable by profile_loader.
        from profile_loader import ProfileError, load_profile

        profile = load_profile(Path(args.profile))
        if profile.update_protocol is None:
            raise UpdateProtocolError("profile has no update_protocol block")
        report = analyze_update_protocol(profile.update_protocol, profile.security_policy)
    except (OSError, ProfileError, UpdateProtocolError, ValueError) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_human_report(profile.name, report))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
