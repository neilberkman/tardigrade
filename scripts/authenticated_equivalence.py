#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Grammar-aware authenticated-equivalence campaign runner.

The campaign mutates only records after a declared authentication-boundary
TLV, then executes a black-box parser/harness for the base stream and each
mutant.  A harness must report the authenticated bytes and signature bytes in
addition to semantic acceptance/commit/rollback outcomes.  Missing or
inconsistent evidence is an infrastructure failure, never a finding.

This module intentionally does not classify crashes.  A non-zero exit,
malformed JSON, timeout, missing semantic field, authentication digest drift,
or an empty mutation set fails the campaign closed.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only in minimal installs
    yaml = None


SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_MUTATION_FILE_BYTES = 16 * 1024 * 1024
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
IDENTITY_FIELDS = (
    "authenticated_bytes_b64",
    "authenticated_digest",
    "signature_bytes_b64",
)
INPUT_DIGEST_FIELD = "input_sha256"
EVIDENCE_FIELDS = IDENTITY_FIELDS + (INPUT_DIGEST_FIELD,)
REQUIRED_OUTCOME_FIELDS = ("accepted", "committed")
# These fields are the security outcomes this campaign is intended to compare
# across inputs that retain the same authenticated bytes and signature. A
# target may add more outcome fields, but it may not omit one of these or the
# campaign could silently miss a version/target/install-state divergence.
REQUIRED_SEMANTIC_OUTCOME_FIELDS = (
    "rollback_outcome",
    "version",
    "target",
    "size",
    "installed_payload_digest",
    "security_state",
)
ALLOWED_PLACEHOLDERS = ("{input}", "{mutation_id}", "{mutation_index}", "{mode}")


class CampaignError(ValueError):
    """Raised for malformed configuration, harness evidence, or campaign data."""


@dataclass(frozen=True)
class Record:
    """A parsed TLV record, retaining its exact encoded bytes."""

    type: int
    value: bytes
    encoded: bytes


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    operation: str
    record_index: int | None
    second_record_index: int | None
    records: tuple[Record, ...]


@dataclass(frozen=True)
class MutationCase:
    case_id: str
    operations: tuple[Mapping[str, Any], ...]


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CampaignError("{} must be a mapping".format(context))
    return value


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CampaignError("{} must be a non-empty string".format(context))
    return value.strip()


def _strict_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CampaignError("{} must be an integer".format(context))
    return value


def _reject_unknown(mapping: Mapping[str, Any], allowed: Iterable[str], context: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise CampaignError("{} has unknown field(s): {}".format(context, ", ".join(unknown)))


def _parse_config(raw: Mapping[str, Any]) -> dict[str, Any]:
    root = _mapping(raw, "config")
    _reject_unknown(
        root,
        {"schema_version", "name", "input", "input_hex", "grammar", "authentication", "mutations", "harness", "outcomes", "mode", "_config_dir"},
        "config",
    )
    version = _strict_int(root.get("schema_version", SCHEMA_VERSION), "schema_version")
    if version not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
        raise CampaignError("unsupported schema_version {}".format(version))
    name = _nonempty_string(root.get("name"), "name")
    has_input = root.get("input") is not None
    has_hex = root.get("input_hex") is not None
    if has_input == has_hex:
        raise CampaignError("config must declare exactly one of input or input_hex")

    grammar = _mapping(root.get("grammar"), "grammar")
    _reject_unknown(grammar, {"kind", "type_width", "length_width", "byteorder", "max_records", "max_record_length"}, "grammar")
    if grammar.get("kind", "tlv") != "tlv":
        raise CampaignError("grammar.kind must be 'tlv'")
    type_width = _strict_int(grammar.get("type_width", 1), "grammar.type_width")
    length_width = _strict_int(grammar.get("length_width", 2), "grammar.length_width")
    if type_width not in (1, 2, 4) or length_width not in (1, 2, 4):
        raise CampaignError("grammar type_width and length_width must be 1, 2, or 4")
    byteorder = grammar.get("byteorder", "little")
    if byteorder not in ("little", "big"):
        raise CampaignError("grammar.byteorder must be 'little' or 'big'")
    max_records = _strict_int(grammar.get("max_records", 256), "grammar.max_records")
    max_record_length = _strict_int(grammar.get("max_record_length", 65535), "grammar.max_record_length")
    if max_records <= 0 or max_record_length < 0:
        raise CampaignError("grammar bounds must be positive")

    auth = _mapping(root.get("authentication"), "authentication")
    _reject_unknown(
        auth,
        {"boundary_type", "signature_type", "include_boundary", "coverage"},
        "authentication",
    )
    max_type = (1 << (8 * type_width)) - 1
    boundary_type = _strict_int(auth.get("boundary_type"), "authentication.boundary_type")
    signature_type = _strict_int(auth.get("signature_type"), "authentication.signature_type")
    if not 0 <= boundary_type <= max_type or not 0 <= signature_type <= max_type:
        raise CampaignError("authentication record types exceed grammar.type_width")
    include_boundary = auth.get("include_boundary", True)
    if not isinstance(include_boundary, bool):
        raise CampaignError("authentication.include_boundary must be boolean")
    coverage = auth.get("coverage", "prefix_through_boundary")
    if coverage not in ("prefix_through_boundary", "signature_before_boundary"):
        raise CampaignError(
            "authentication.coverage must be 'prefix_through_boundary' or 'signature_before_boundary'"
        )
    if coverage == "signature_before_boundary" and boundary_type == signature_type:
        raise CampaignError(
            "authentication.coverage signature_before_boundary requires distinct boundary and signature types"
        )
    if version == LEGACY_SCHEMA_VERSION and coverage != "prefix_through_boundary":
        raise CampaignError("schema_version 1 supports only prefix_through_boundary coverage")

    mutations = _mapping(root.get("mutations"), "mutations")
    _reject_unknown(
        mutations,
        {"duplicate_types", "reorder_types", "max_mutants", "cases"},
        "mutations",
    )
    duplicate_types = _parse_type_list(mutations.get("duplicate_types", []), max_type, "mutations.duplicate_types")
    reorder_types = _parse_type_list(mutations.get("reorder_types", []), max_type, "mutations.reorder_types")
    max_mutants = _strict_int(mutations.get("max_mutants", 64), "mutations.max_mutants")
    if max_mutants <= 0:
        raise CampaignError("mutations.max_mutants must be positive")
    raw_cases = mutations.get("cases", [])
    if version == LEGACY_SCHEMA_VERSION and raw_cases:
        raise CampaignError("schema_version 1 does not support mutations.cases")
    if raw_cases and all(isinstance(case, MutationCase) for case in raw_cases):
        cases = list(raw_cases)
    else:
        cases = _parse_mutation_cases(raw_cases, max_type, "mutations.cases")
    if cases and (duplicate_types or reorder_types):
        raise CampaignError("mutations.cases cannot be combined with legacy type mutations")

    harness = _mapping(root.get("harness"), "harness")
    _reject_unknown(harness, {"command", "timeout_seconds", "cwd"}, "harness")
    command = harness.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise CampaignError("harness.command must be a non-empty list of strings")
    if any("\x00" in item for item in command):
        raise CampaignError("harness.command must not contain NUL characters")
    if not any("{input}" in token for token in command):
        raise CampaignError("harness.command must include the {input} placeholder")
    placeholder_pattern = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
    allowed_names = {placeholder[1:-1] for placeholder in ALLOWED_PLACEHOLDERS}
    for token in command:
        for placeholder_name in placeholder_pattern.findall(token):
            if placeholder_name not in allowed_names:
                raise CampaignError("harness.command contains an unknown placeholder")
    timeout_seconds = harness.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise CampaignError("harness.timeout_seconds must be finite and positive")
    try:
        timeout_value = float(timeout_seconds)
    except (OverflowError, ValueError) as exc:
        raise CampaignError("harness.timeout_seconds must be finite and positive") from exc
    if not math.isfinite(timeout_value) or timeout_value <= 0:
        raise CampaignError("harness.timeout_seconds must be finite and positive")
    if "cwd" not in harness:
        cwd = None
    elif not isinstance(harness["cwd"], str) or not harness["cwd"].strip():
        raise CampaignError("harness.cwd must be absent or a non-empty string")
    elif "\x00" in harness["cwd"]:
        raise CampaignError("harness.cwd must not contain NUL characters")
    else:
        cwd = harness["cwd"].strip()

    outcome_fields = root.get("outcomes")
    if not isinstance(outcome_fields, list) or not outcome_fields:
        raise CampaignError("outcomes must be a non-empty list")
    if not all(isinstance(item, str) and item.strip() for item in outcome_fields):
        raise CampaignError("outcomes must contain non-empty strings")
    outcome_fields = [item.strip() for item in outcome_fields]
    if len(set(outcome_fields)) != len(outcome_fields):
        raise CampaignError("outcomes contains duplicate fields")
    for required in REQUIRED_OUTCOME_FIELDS:
        if required not in outcome_fields:
            raise CampaignError("outcomes must include '{}'".format(required))
    if version == SCHEMA_VERSION:
        for required in REQUIRED_SEMANTIC_OUTCOME_FIELDS:
            if required not in outcome_fields:
                raise CampaignError("outcomes must include semantic field '{}'".format(required))
    if any(item in EVIDENCE_FIELDS for item in outcome_fields):
        raise CampaignError("outcomes cannot contain authentication evidence fields")

    mode = _nonempty_string(root.get("mode", "default"), "mode")
    normalized_harness = {
        "command": command,
        "timeout_seconds": timeout_value,
    }
    if cwd is not None:
        normalized_harness["cwd"] = cwd
    return {
        "schema_version": version,
        "name": name,
        "input": root.get("input"),
        "input_hex": root.get("input_hex"),
        "grammar": {
            "type_width": type_width,
            "length_width": length_width,
            "byteorder": byteorder,
            "max_records": max_records,
            "max_record_length": max_record_length,
        },
        "authentication": {
            "boundary_type": boundary_type,
            "signature_type": signature_type,
            "include_boundary": include_boundary,
            "coverage": coverage,
        },
        "mutations": {
            "duplicate_types": duplicate_types,
            "reorder_types": reorder_types,
            "max_mutants": max_mutants,
            "cases": [
                {"id": case.case_id, "operations": [dict(operation) for operation in case.operations]}
                for case in cases
            ],
        },
        "harness": normalized_harness,
        "outcomes": outcome_fields,
        "mode": mode,
    }


def _parse_type_list(value: Any, max_type: int, context: str) -> list[int]:
    if not isinstance(value, list):
        raise CampaignError("{} must be a list".format(context))
    result = []
    for index, item in enumerate(value):
        number = _strict_int(item, "{}[{}]".format(context, index))
        if not 0 <= number <= max_type:
            raise CampaignError("{}[{}] exceeds grammar type width".format(context, index))
        if number not in result:
            result.append(number)
    return result


def _parse_selector(value: Any, max_type: int, context: str) -> dict[str, Any]:
    selector = _mapping(value, context)
    _reject_unknown(selector, {"index", "type", "occurrence"}, context)
    has_index = "index" in selector
    has_type = "type" in selector
    has_occurrence = "occurrence" in selector
    if has_index == has_type:
        raise CampaignError("{} must contain exactly one of index or type".format(context))
    if has_index and has_occurrence:
        raise CampaignError("{} occurrence is not valid with index".format(context))
    if has_type != has_occurrence:
        raise CampaignError("{} type selectors require occurrence".format(context))
    if has_index:
        index = _strict_int(selector["index"], context + ".index")
        if index < 0:
            raise CampaignError("{}.index must be non-negative".format(context))
        return {"index": index}
    type_value = _strict_int(selector["type"], context + ".type")
    if not 0 <= type_value <= max_type:
        raise CampaignError("{}.type exceeds grammar type width".format(context))
    occurrence = _strict_int(selector["occurrence"], context + ".occurrence")
    if occurrence <= 0:
        raise CampaignError("{}.occurrence must be positive".format(context))
    return {"type": type_value, "occurrence": occurrence}


def _parse_file_reference(value: Any, context: str) -> str:
    path = _nonempty_string(value, context)
    if "\x00" in path:
        raise CampaignError("{} must not contain NUL characters".format(context))
    if Path(path).is_absolute():
        raise CampaignError("{} must be config-relative".format(context))
    return path


def _parse_case_id(value: Any, context: str) -> str:
    case_id = _nonempty_string(value, context)
    if case_id.casefold() in (".", "..", "base") or not CASE_ID_RE.fullmatch(case_id):
        raise CampaignError(
            "{} must be a portable identifier matching [A-Za-z0-9][A-Za-z0-9._-]{{0,127}} and not 'base'".format(
                context
            )
        )
    return case_id


def _parse_hex_bytes(value: Any, context: str) -> str:
    text = _nonempty_string(value, context)
    try:
        decoded = bytes.fromhex(text)
    except ValueError as exc:
        raise CampaignError("{} is not valid hexadecimal".format(context)) from exc
    if not decoded:
        raise CampaignError("{} must not be empty".format(context))
    if len(decoded) > MAX_MUTATION_FILE_BYTES:
        raise CampaignError("{} exceeds mutation size limit".format(context))
    return text


def _parse_replacement(value: Mapping[str, Any], context: str) -> dict[str, str]:
    has_hex = "bytes_hex" in value
    has_file = "bytes_file" in value
    if has_hex == has_file:
        raise CampaignError("{} must declare exactly one of bytes_hex or bytes_file".format(context))
    if has_hex:
        return {"bytes_hex": _parse_hex_bytes(value["bytes_hex"], context + ".bytes_hex")}
    return {"bytes_file": _parse_file_reference(value["bytes_file"], context + ".bytes_file")}


def _parse_patches(value: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise CampaignError("{} must be a non-empty list".format(context))
    patches = []
    for index, raw_patch in enumerate(value):
        patch_context = "{}[{}]".format(context, index)
        patch = _mapping(raw_patch, patch_context)
        _reject_unknown(patch, {"offset", "bytes_hex", "bytes_file"}, patch_context)
        offset = _strict_int(patch.get("offset"), patch_context + ".offset")
        if offset < 0:
            raise CampaignError("{}.offset must be non-negative".format(patch_context))
        parsed = {"offset": offset}
        parsed.update(_parse_replacement(patch, patch_context))
        patches.append(parsed)
    return patches


def _parse_mutation_cases(value: Any, max_type: int, context: str) -> list[MutationCase]:
    if not isinstance(value, list):
        raise CampaignError("{} must be a list".format(context))
    cases: list[MutationCase] = []
    seen_ids: set[str] = set()
    for index, raw_case in enumerate(value):
        case_context = "{}[{}]".format(context, index)
        case = _mapping(raw_case, case_context)
        _reject_unknown(case, {"id", "operations"}, case_context)
        case_id = _parse_case_id(case.get("id"), case_context + ".id")
        case_key = case_id.casefold()
        if case_key in seen_ids:
            raise CampaignError("{} duplicate id '{}'".format(context, case_id))
        seen_ids.add(case_key)
        operations = case.get("operations")
        if not isinstance(operations, list) or not operations:
            raise CampaignError("{}.operations must be a non-empty list".format(case_context))
        parsed_operations: list[Mapping[str, Any]] = []
        for op_index, raw_operation in enumerate(operations):
            op_context = "{}.operations[{}]".format(case_context, op_index)
            operation = _mapping(raw_operation, op_context)
            kind = _nonempty_string(operation.get("operation"), op_context + ".operation")
            if kind == "duplicate":
                _reject_unknown(
                    operation,
                    {"operation", "source", "insert_index", "insert_after", "patches"},
                    op_context,
                )
                source = _parse_selector(operation.get("source"), max_type, op_context + ".source")
                has_index = "insert_index" in operation
                has_after = "insert_after" in operation
                if has_index and has_after:
                    raise CampaignError("{} may declare only one insertion destination".format(op_context))
                if has_index:
                    insert_index = _strict_int(operation["insert_index"], op_context + ".insert_index")
                    if insert_index < 0:
                        raise CampaignError("{}.insert_index must be non-negative".format(op_context))
                    destination: dict[str, Any] = {"insert_index": insert_index}
                elif has_after:
                    destination = {
                        "insert_after": _parse_selector(
                            operation["insert_after"], max_type, op_context + ".insert_after"
                        )
                    }
                else:
                    destination = {}
                parsed = {"operation": kind, "source": source, **destination}
                if "patches" in operation:
                    parsed["patches"] = _parse_patches(operation["patches"], op_context + ".patches")
                parsed_operations.append(parsed)
            elif kind == "replace":
                _reject_unknown(
                    operation,
                    {"operation", "target", "value_hex", "value_file"},
                    op_context,
                )
                target = _parse_selector(operation.get("target"), max_type, op_context + ".target")
                has_hex = "value_hex" in operation
                has_file = "value_file" in operation
                if has_hex == has_file:
                    raise CampaignError("{} must declare exactly one of value_hex or value_file".format(op_context))
                parsed = {"operation": kind, "target": target}
                if has_hex:
                    parsed["value_hex"] = _parse_hex_bytes(operation["value_hex"], op_context + ".value_hex")
                else:
                    parsed["value_file"] = _parse_file_reference(operation["value_file"], op_context + ".value_file")
                parsed_operations.append(parsed)
            elif kind == "patch":
                _reject_unknown(operation, {"operation", "target", "patches"}, op_context)
                parsed_operations.append(
                    {
                        "operation": kind,
                        "target": _parse_selector(operation.get("target"), max_type, op_context + ".target"),
                        "patches": _parse_patches(operation.get("patches"), op_context + ".patches"),
                    }
                )
            else:
                raise CampaignError("{} has unsupported operation '{}'".format(op_context, kind))
        cases.append(MutationCase(case_id, tuple(parsed_operations)))
    return cases


def load_config(path: Path) -> dict[str, Any]:
    """Load and strictly validate a YAML or JSON campaign config."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CampaignError("cannot read config '{}': {}".format(path, exc)) from exc
    try:
        if yaml is not None:
            raw = yaml.safe_load(text)
        else:
            raw = json.loads(text)
    except Exception as exc:
        raise CampaignError("config is not valid YAML/JSON: {}".format(exc)) from exc
    config = _parse_config(raw)
    config["_config_dir"] = path.resolve().parent
    return config


def _decode_hex(value: str, context: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise CampaignError("{} must be a non-empty hexadecimal string".format(context))
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise CampaignError("{} is not valid hexadecimal".format(context)) from exc


def _resolve_input(config: Mapping[str, Any]) -> bytes:
    if config.get("input_hex") is not None:
        return _decode_hex(config["input_hex"], "input_hex")
    source = _nonempty_string(config.get("input"), "input")
    path = Path(source)
    if not path.is_absolute():
        path = Path(config.get("_config_dir") or Path.cwd()) / path
    try:
        data = path.resolve().read_bytes()
    except OSError as exc:
        raise CampaignError("cannot read input '{}': {}".format(path, exc)) from exc
    if not data:
        raise CampaignError("input stream is empty")
    return data


def parse_tlv_stream(data: bytes, grammar: Mapping[str, Any]) -> tuple[Record, ...]:
    """Parse a bounded TLV stream while retaining exact record encodings."""

    type_width = grammar["type_width"]
    length_width = grammar["length_width"]
    byteorder = grammar["byteorder"]
    max_records = grammar["max_records"]
    max_record_length = grammar["max_record_length"]
    cursor = 0
    records: list[Record] = []
    header_width = type_width + length_width
    while cursor < len(data):
        if len(records) >= max_records:
            raise CampaignError("TLV stream exceeds grammar.max_records")
        if len(data) - cursor < header_width:
            raise CampaignError("TLV stream ends with a partial header")
        type_value = int.from_bytes(data[cursor:cursor + type_width], byteorder)
        length_start = cursor + type_width
        length = int.from_bytes(data[length_start:length_start + length_width], byteorder)
        if length > max_record_length:
            raise CampaignError("TLV record length exceeds grammar.max_record_length")
        record_end = cursor + header_width + length
        if record_end > len(data):
            raise CampaignError("TLV record extends beyond input")
        encoded = data[cursor:record_end]
        value = data[cursor + header_width:record_end]
        records.append(Record(type=type_value, value=value, encoded=encoded))
        cursor = record_end
    if not records:
        raise CampaignError("TLV stream contains no records")
    return tuple(records)


def _encode_record(record: Record) -> bytes:
    # Exact encodings from the base stream are reused by mutations.  This
    # helper is retained as a guard for future record-producing mutators.
    return record.encoded


def _auth_identity(records: Sequence[Record], auth: Mapping[str, Any]) -> tuple[bytes, bytes]:
    boundary_type = auth["boundary_type"]
    signature_type = auth["signature_type"]
    boundary_indexes = [index for index, record in enumerate(records) if record.type == boundary_type]
    signature_records = [record for record in records if record.type == signature_type]
    if len(boundary_indexes) != 1:
        raise CampaignError("authentication boundary must occur exactly once")
    if len(signature_records) != 1:
        raise CampaignError("signature record must occur exactly once")
    boundary_index = boundary_indexes[0]
    signature_index = next(index for index, record in enumerate(records) if record.type == signature_type)
    coverage = auth.get("coverage", "prefix_through_boundary")
    if coverage == "signature_before_boundary":
        if signature_index >= boundary_index:
            raise CampaignError("signature record must occur strictly before authentication boundary")
        start = signature_index + 1
        end = boundary_index + (1 if auth["include_boundary"] else 0)
        authenticated_records = records[start:end]
    else:
        if signature_index < boundary_index:
            raise CampaignError("signature record must occur at or after authentication boundary")
        if auth["include_boundary"]:
            authenticated_records = records[:boundary_index + 1]
        else:
            authenticated_records = records[:boundary_index]
    if not authenticated_records:
        raise CampaignError("authenticated region is empty")
    return b"".join(_encode_record(record) for record in authenticated_records), signature_records[0].value


def _resolve_mutation_file(config_dir: Path, reference: str, context: str) -> bytes:
    root = config_dir.resolve()
    path = (root / reference).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise CampaignError("{} must remain under the config directory".format(context)) from exc
    try:
        if not path.is_file():
            raise CampaignError("{} is not a regular file".format(context))
        size = path.stat().st_size
        if size <= 0 or size > MAX_MUTATION_FILE_BYTES:
            raise CampaignError("{} exceeds mutation size limit".format(context))
        return path.read_bytes()
    except OSError as exc:
        raise CampaignError("cannot read {}: {}".format(context, exc)) from exc


def _replacement_bytes(spec: Mapping[str, Any], config_dir: Path, context: str) -> bytes:
    if "bytes_hex" in spec:
        try:
            value = bytes.fromhex(spec["bytes_hex"])
        except ValueError as exc:
            raise CampaignError("{} is not valid hexadecimal".format(context)) from exc
        if not value:
            raise CampaignError("{} must not be empty".format(context))
        return value
    if "bytes_file" in spec:
        return _resolve_mutation_file(config_dir, spec["bytes_file"], context + ".bytes_file")
    raise CampaignError("{} is missing replacement bytes".format(context))


def _apply_patches(value: bytes, patches: Sequence[Mapping[str, Any]], config_dir: Path, context: str) -> bytes:
    result = bytearray(value)
    intervals: list[tuple[int, int]] = []
    for index, patch in enumerate(patches):
        patch_context = "{}[{}]".format(context, index)
        offset = patch["offset"]
        replacement = _replacement_bytes(patch, config_dir, patch_context)
        end = offset + len(replacement)
        if end > len(result):
            raise CampaignError("{} patch is out of bounds".format(patch_context))
        if any(offset < prior_end and prior_start < end for prior_start, prior_end in intervals):
            raise CampaignError("{} patch overlaps another patch".format(patch_context))
        intervals.append((offset, end))
        result[offset:end] = replacement
    if bytes(result) == value:
        raise CampaignError("{} is a no-op".format(context))
    return bytes(result)


def _selector_index(records: Sequence[Record], selector: Mapping[str, Any], context: str) -> int:
    if "index" in selector:
        index = selector["index"]
        if index >= len(records):
            raise CampaignError("{} index is out of range".format(context))
        return index
    matches = [index for index, record in enumerate(records) if record.type == selector["type"]]
    occurrence = selector["occurrence"]
    if occurrence > len(matches):
        raise CampaignError("{} occurrence does not exist".format(context))
    return matches[occurrence - 1]


def _tail_start(records: Sequence[Record], boundary_record: Record, signature_record: Record) -> int:
    try:
        boundary_index = next(index for index, record in enumerate(records) if record is boundary_record)
        signature_index = next(index for index, record in enumerate(records) if record is signature_record)
    except StopIteration as exc:
        raise CampaignError("mutation removed an authentication delimiter") from exc
    return max(boundary_index, signature_index) + 1


def _encode_mutated_record(record: Record, value: bytes, grammar: Mapping[str, Any]) -> Record:
    if len(value) > grammar["max_record_length"]:
        raise CampaignError("mutated TLV value exceeds grammar.max_record_length")
    type_bytes = record.type.to_bytes(grammar["type_width"], grammar["byteorder"])
    length_width = grammar["length_width"]
    try:
        length_bytes = len(value).to_bytes(length_width, grammar["byteorder"])
    except OverflowError as exc:
        raise CampaignError("mutated TLV value exceeds grammar length width") from exc
    encoded = type_bytes + length_bytes + value
    return Record(type=record.type, value=value, encoded=encoded)


def _case_mutation(
    base: Sequence[Record],
    case: MutationCase,
    auth: Mapping[str, Any],
    grammar: Mapping[str, Any],
    config_dir: Path,
) -> Mutation:
    records = list(base)
    boundary_indexes = [index for index, record in enumerate(records) if record.type == auth["boundary_type"]]
    signature_indexes = [index for index, record in enumerate(records) if record.type == auth["signature_type"]]
    if len(boundary_indexes) != 1 or len(signature_indexes) != 1:
        raise CampaignError("authentication delimiters must be unique before mutation")
    boundary_record = records[boundary_indexes[0]]
    signature_record = records[signature_indexes[0]]
    changed = False
    first_index: int | None = None
    second_index: int | None = None
    operation_names: list[str] = []
    for op_index, operation in enumerate(case.operations):
        context = "mutation case '{}' operation {}".format(case.case_id, op_index)
        kind = operation["operation"]
        operation_names.append(kind)
        tail_start = _tail_start(records, boundary_record, signature_record)
        if kind == "duplicate":
            source_index = _selector_index(records, operation["source"], context + ".source")
            if "insert_index" in operation:
                insert_index = operation["insert_index"]
            elif "insert_after" in operation:
                anchor_index = _selector_index(records, operation["insert_after"], context + ".insert_after")
                if anchor_index < tail_start:
                    raise CampaignError("{} insertion anchor is not in the post-auth tail".format(context))
                insert_index = anchor_index + 1
            else:
                insert_index = len(records)
            if insert_index < tail_start or insert_index > len(records):
                raise CampaignError("{} insertion destination is not strictly in the post-auth tail".format(context))
            source = records[source_index]
            value = source.value
            if "patches" in operation:
                value = _apply_patches(value, operation["patches"], config_dir, context + ".patches")
            copied = _encode_mutated_record(source, value, grammar)
            records.insert(insert_index, copied)
            first_index = insert_index if first_index is None else first_index
            changed = True
        elif kind in ("replace", "patch"):
            target_index = _selector_index(records, operation["target"], context + ".target")
            if target_index < tail_start:
                raise CampaignError("{} target is not strictly in the post-auth tail".format(context))
            target = records[target_index]
            if kind == "replace":
                if "value_hex" in operation:
                    value = bytes.fromhex(operation["value_hex"])
                else:
                    value = _resolve_mutation_file(config_dir, operation["value_file"], context + ".value_file")
                if not value:
                    raise CampaignError("{} replacement value must not be empty".format(context))
                if value == target.value:
                    raise CampaignError("{} replacement is a no-op".format(context))
            else:
                value = _apply_patches(target.value, operation["patches"], config_dir, context + ".patches")
            records[target_index] = _encode_mutated_record(target, value, grammar)
            first_index = target_index if first_index is None else first_index
            changed = True
        else:  # pragma: no cover - parser validation makes this unreachable
            raise CampaignError("{} has unsupported operation '{}'".format(context, kind))
    if not changed or tuple(records) == tuple(base):
        raise CampaignError("mutation case '{}' is empty or a no-op".format(case.case_id))
    mutant = tuple(records)
    expected_auth, expected_signature = _auth_identity(base, auth)
    actual_auth, actual_signature = _auth_identity(mutant, auth)
    if actual_auth != expected_auth or actual_signature != expected_signature:
        raise CampaignError("mutation case '{}' changed authenticated identity".format(case.case_id))
    return Mutation(
        case.case_id,
        "+".join(operation_names),
        first_index,
        second_index,
        mutant,
    )


def _mutation_records(
    base: Sequence[Record],
    mutation_config: Mapping[str, Any],
    auth: Mapping[str, Any],
    grammar: Mapping[str, Any] | None = None,
    config_dir: Path | None = None,
) -> list[Mutation]:
    if mutation_config.get("cases"):
        if grammar is None:
            raise CampaignError("grammar is required for declarative mutation cases")
        root = config_dir or Path.cwd()
        cases = mutation_config["cases"]
        if len(cases) > mutation_config["max_mutants"]:
            raise CampaignError("mutations.cases exceeds mutations.max_mutants")
        if cases and isinstance(cases[0], Mapping):
            max_type = (1 << (8 * grammar["type_width"])) - 1
            cases = _parse_mutation_cases(cases, max_type, "mutations.cases")
        mutations: list[Mutation] = []
        seen_streams: set[bytes] = set()
        for case in cases:
            mutation = _case_mutation(base, case, auth, grammar, root)
            stream = b"".join(record.encoded for record in mutation.records)
            if stream in seen_streams:
                raise CampaignError("mutation case '{}' duplicates another case output".format(case.case_id))
            seen_streams.add(stream)
            mutations.append(mutation)
        if not mutations:
            raise CampaignError("mutation set is empty")
        return mutations

    boundary_type = auth["boundary_type"]
    boundary_indexes = [index for index, record in enumerate(base) if record.type == boundary_type]
    if len(boundary_indexes) != 1:
        raise CampaignError("authentication boundary must occur exactly once before mutation")
    boundary_index = boundary_indexes[0]
    signature_type = auth["signature_type"]
    if sum(record.type == signature_type for record in base) != 1:
        raise CampaignError("signature record must occur exactly once before mutation")
    signature_index = next(index for index, record in enumerate(base) if record.type == signature_type)
    if auth.get("coverage", "prefix_through_boundary") == "signature_before_boundary":
        if signature_index >= boundary_index:
            raise CampaignError("signature record must occur strictly before authentication boundary")
    elif signature_index < boundary_index:
        raise CampaignError("signature record must occur at or after authentication boundary")
    # The mutation region must be outside both authentication delimiters.  In
    # particular, records between the boundary and a later signature remain
    # untouched even when their type is configured as mutation-eligible.
    tail_start = max(boundary_index, signature_index) + 1
    tail = [index for index in range(tail_start, len(base)) if base[index].type != signature_type]
    max_mutants = mutation_config["max_mutants"]
    mutations: list[Mutation] = []

    base_stream = b"".join(record.encoded for record in base)
    seen_streams = {base_stream}

    def add_legacy_mutation(operation: str, first_index: int, second_index: int | None, records: tuple[Record, ...]) -> bool:
        stream = b"".join(record.encoded for record in records)
        if stream in seen_streams:
            return False
        seen_streams.add(stream)
        mutations.append(Mutation("m{:04d}".format(len(mutations) + 1), operation, first_index, second_index, records))
        return True

    for index in tail:
        if base[index].type not in mutation_config["duplicate_types"]:
            continue
        records = tuple(base[:index + 1]) + (base[index],) + tuple(base[index + 1:])
        add_legacy_mutation("duplicate", index, None, records)
        if len(mutations) >= max_mutants:
            return mutations

    reorder_types = set(mutation_config["reorder_types"])
    for first_position, first_index in enumerate(tail[:-1]):
        if base[first_index].type not in reorder_types:
            continue
        for second_index in tail[first_position + 1:]:
            if base[second_index].type not in reorder_types:
                continue
            records_list = list(base)
            records_list[first_index], records_list[second_index] = records_list[second_index], records_list[first_index]
            add_legacy_mutation("reorder", first_index, second_index, tuple(records_list))
            if len(mutations) >= max_mutants:
                return mutations
    if not mutations:
        raise CampaignError("mutation set is empty")
    return mutations


def _render_command(command: Sequence[str], *, input_path: Path, mutation_id: str, mutation_index: int, mode: str) -> list[str]:
    replacements = {
        "{input}": str(input_path),
        "{mutation_id}": mutation_id,
        "{mutation_index}": str(mutation_index),
        "{mode}": mode,
    }
    rendered: list[str] = []
    for token in command:
        current = token
        for placeholder, replacement in replacements.items():
            current = current.replace(placeholder, replacement)
        if any(name not in replacements for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", current)):
            raise CampaignError("harness.command contains an unresolved placeholder")
        rendered.append(current)
    return rendered


def _decode_b64(value: Any, context: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise CampaignError("{} must be a non-empty base64 string".format(context))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CampaignError("{} is not valid base64".format(context)) from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-standard JSON constant {}".format(value))


def _validate_digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise CampaignError("{} must be a lowercase SHA-256 hex digest".format(context))
    if value.lower() != value:
        raise CampaignError("{} must be lowercase".format(context))
    try:
        int(value, 16)
    except ValueError as exc:
        raise CampaignError("{} must be a lowercase SHA-256 hex digest".format(context)) from exc
    return value


def _run_harness(config: Mapping[str, Any], input_path: Path, mutation_id: str, mutation_index: int) -> dict[str, Any]:
    command = _render_command(
        config["harness"]["command"],
        input_path=input_path,
        mutation_id=mutation_id,
        mutation_index=mutation_index,
        mode=config["mode"],
    )
    cwd_value = config["harness"].get("cwd")
    cwd = Path(cwd_value) if cwd_value else Path(config.get("_config_dir") or Path.cwd())
    if not cwd.is_absolute():
        cwd = Path(config.get("_config_dir") or Path.cwd()) / cwd
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd.resolve()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=config["harness"]["timeout_seconds"],
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CampaignError("harness timed out for {}".format(mutation_id)) from exc
    except OSError as exc:
        raise CampaignError("harness could not start for {}: {}".format(mutation_id, exc)) from exc
    if result.returncode != 0:
        raise CampaignError("harness returned {} for {}".format(result.returncode, mutation_id))
    try:
        output = json.loads(
            result.stdout,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise CampaignError("harness output for {} is not JSON".format(mutation_id)) from exc
    if not isinstance(output, dict):
        raise CampaignError("harness output for {} must be a JSON object".format(mutation_id))
    return output


def _validate_harness_output(
    output: Mapping[str, Any],
    *,
    schema_version: int = SCHEMA_VERSION,
    outcome_fields: Sequence[str],
    expected_authenticated: bytes,
    expected_signature: bytes,
    expected_input: bytes,
    context: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    for field in (*IDENTITY_FIELDS, INPUT_DIGEST_FIELD, *outcome_fields):
        if field not in output:
            raise CampaignError("{} is missing output field '{}'".format(context, field))
    authenticated_bytes = _decode_b64(output["authenticated_bytes_b64"], context + ".authenticated_bytes_b64")
    signature_bytes = _decode_b64(output["signature_bytes_b64"], context + ".signature_bytes_b64")
    input_digest = _validate_digest(output[INPUT_DIGEST_FIELD], context + ".input_sha256")
    expected_input_digest = hashlib.sha256(expected_input).hexdigest()
    if input_digest != expected_input_digest:
        raise CampaignError("{} input_sha256 does not match supplied input bytes".format(context))
    digest = _validate_digest(output["authenticated_digest"], context + ".authenticated_digest")
    computed_digest = hashlib.sha256(authenticated_bytes).hexdigest()
    if digest != computed_digest:
        raise CampaignError("{} authenticated_digest does not hash authenticated_bytes_b64".format(context))
    expected_digest = hashlib.sha256(expected_authenticated).hexdigest()
    if authenticated_bytes != expected_authenticated or digest != expected_digest:
        raise CampaignError("{} authenticated bytes/digest drifted".format(context))
    if signature_bytes != expected_signature:
        raise CampaignError("{} signature bytes drifted".format(context))
    outcome = {field: output[field] for field in outcome_fields}
    if not isinstance(outcome["accepted"], bool) or not isinstance(outcome["committed"], bool):
        raise CampaignError("{} accepted and committed must be boolean".format(context))
    if outcome["committed"] and not outcome["accepted"]:
        raise CampaignError("{} committed cannot be true when accepted is false".format(context))
    if schema_version >= SCHEMA_VERSION:
        if not isinstance(outcome["rollback_outcome"], str) or not outcome["rollback_outcome"].strip():
            raise CampaignError("{} rollback_outcome must be a non-empty string".format(context))
        if not isinstance(outcome["security_state"], dict):
            raise CampaignError("{} security_state must be a JSON object".format(context))
        if outcome["accepted"]:
            for field in ("version", "target"):
                value = outcome[field]
                if value is None or isinstance(value, bool) or (isinstance(value, str) and not value.strip()):
                    raise CampaignError("{} {} must be meaningful when accepted".format(context, field))
            size = outcome["size"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise CampaignError("{} size must be a non-negative integer when accepted".format(context))
        if outcome["committed"]:
            _validate_digest(
                outcome["installed_payload_digest"],
                context + ".installed_payload_digest",
            )
    return outcome, authenticated_bytes, signature_bytes


def run_campaign(config: Mapping[str, Any]) -> dict[str, Any]:
    """Run a validated authenticated-equivalence campaign and return a report."""

    normalized = _parse_config(config)
    normalized["_config_dir"] = config.get("_config_dir", Path.cwd())
    data = _resolve_input({**normalized, "_config_dir": config.get("_config_dir", Path.cwd())})
    base_records = parse_tlv_stream(data, normalized["grammar"])
    expected_authenticated, expected_signature = _auth_identity(base_records, normalized["authentication"])
    mutations = _mutation_records(
        base_records,
        normalized["mutations"],
        normalized["authentication"],
        normalized["grammar"],
        Path(config.get("_config_dir", Path.cwd())),
    )
    if not mutations:
        raise CampaignError("mutation set is empty")

    report: dict[str, Any] = {
        "schema_version": normalized["schema_version"],
        "campaign": normalized["name"],
        "status": "PASS",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "configuration": {
            key: value for key, value in normalized.items() if key != "_config_dir"
        },
        # Keep the configured placeholder rather than recording the temporary
        # path used for a particular invocation.
        "harness_argv": list(normalized["harness"]["command"]),
        "authenticated_identity": {
            "authenticated_digest": hashlib.sha256(expected_authenticated).hexdigest(),
            "authenticated_bytes_sha256": hashlib.sha256(expected_authenticated).hexdigest(),
            "signature_bytes_b64": base64.b64encode(expected_signature).decode("ascii"),
        },
        "base": None,
        "mutants": [],
        "findings": [],
    }

    with tempfile.TemporaryDirectory(prefix="tardigrade-auth-equiv-") as temp_dir:
        temp_path = Path(temp_dir)
        base_path = temp_path / "base.bin"
        base_path.write_bytes(data)
        base_output = _run_harness(normalized, base_path, "base", 0)
        base_outcome, _, _ = _validate_harness_output(
            base_output,
            schema_version=normalized["schema_version"],
            outcome_fields=normalized["outcomes"],
            expected_authenticated=expected_authenticated,
            expected_signature=expected_signature,
            expected_input=data,
            context="base harness output",
        )
        if not base_outcome["accepted"]:
            raise CampaignError("canonical base harness outcome is not accepted")
        report["base"] = {"outcome": base_outcome}

        for index, mutation in enumerate(mutations, start=1):
            mutant_data = b"".join(record.encoded for record in mutation.records)
            mutant_records = parse_tlv_stream(mutant_data, normalized["grammar"])
            mutant_authenticated, mutant_signature = _auth_identity(mutant_records, normalized["authentication"])
            if mutant_authenticated != expected_authenticated or mutant_signature != expected_signature:
                raise CampaignError("mutation {} changed authenticated identity".format(mutation.mutation_id))
            # Keep filesystem names independent of attacker/configuration IDs;
            # the ID is still passed to the harness and recorded in the report.
            mutant_path = temp_path / "mutant-{:04d}.bin".format(index)
            mutant_path.write_bytes(mutant_data)
            output = _run_harness(normalized, mutant_path, mutation.mutation_id, index)
            outcome, _, _ = _validate_harness_output(
                output,
                schema_version=normalized["schema_version"],
                outcome_fields=normalized["outcomes"],
                expected_authenticated=expected_authenticated,
                expected_signature=expected_signature,
                expected_input=mutant_data,
                context="{} harness output".format(mutation.mutation_id),
            )
            # A parser that safely rejects a mutant is not an equivalence
            # finding.  For accepted mutants, accepted/committed are control
            # gates; compare protected fields and any commit-state divergence.
            differing = {
                field: {"base": base_outcome[field], "mutant": outcome[field]}
                for field in normalized["outcomes"]
                if field not in ("accepted", "committed")
                and outcome["accepted"]
                and outcome[field] != base_outcome[field]
            }
            if (
                outcome["accepted"]
                and outcome["committed"] != base_outcome["committed"]
            ):
                differing["committed"] = {
                    "base": base_outcome["committed"],
                    "mutant": outcome["committed"],
                }
            mutant_report: dict[str, Any] = {
                "mutation_id": mutation.mutation_id,
                "operation": mutation.operation,
                "record_index": mutation.record_index,
                "second_record_index": mutation.second_record_index,
                "input_sha256": hashlib.sha256(mutant_data).hexdigest(),
                "input_size": len(mutant_data),
                "outcome": outcome,
            }
            if differing:
                report["findings"].append(
                    {
                        "id": "AUTHENTICATED_EQUIVALENCE_DIVERGENCE",
                        "mutation_id": mutation.mutation_id,
                        "differing_outcomes": differing,
                    }
                )
            report["mutants"].append(mutant_report)

    if report["findings"]:
        report["status"] = "FINDINGS"
    return report


def write_report(report: Mapping[str, Any], path: Path | None = None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(text)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report_schema_version = SCHEMA_VERSION
    try:
        config = load_config(args.config)
        loaded_schema_version = config.get("schema_version", SCHEMA_VERSION)
        if loaded_schema_version in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
            report_schema_version = loaded_schema_version
        report = run_campaign(config)
        write_report(report, args.report)
        return 1 if report["status"] == "FINDINGS" else 0
    except CampaignError as exc:
        report = {
            "schema_version": report_schema_version,
            "status": "FAIL_CLOSED",
            "error": str(exc),
        }
        write_report(report, args.report)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
