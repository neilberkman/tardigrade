#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic pre-authentication nested-header bounds oracle.

This campaign is deliberately target-neutral.  It mutates four declaratively
named integer fields in a small binary header and asks a black-box harness
whether the parser began consuming signature/key material or cryptographic
verification.  A finding is reported when an input which the independent
bounds model classifies as unsafe reaches that stage (or is accepted/committed)
instead of being rejected first.

The utility does not parse, import, or reproduce any vendor bootloader code.
It is intended for minimal synthetic fixtures and black-box parser harnesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - JSON remains available
    yaml = None


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 10.0
REQUIRED_HARNESS_FIELDS = ("accepted", "committed", "auth_attempted")
ALLOWED_PLACEHOLDERS = ("{input}", "{mutation_id}", "{mutation_index}", "{mode}")
FIELD_NAMES = ("total_length", "used_length", "signature_length", "key_length")


class OracleError(ValueError):
    """Raised when configuration, input, or harness evidence is invalid."""


@dataclass(frozen=True)
class FieldSpec:
    offset: int
    width: int


@dataclass(frozen=True)
class BoundsModel:
    component_offset: int
    component_length: int
    authentication_offset: int
    authentication_length: int
    authentication_header_size: int
    fields: Mapping[str, FieldSpec]
    byteorder: str


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    fields: Mapping[str, int]
    data: bytes


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OracleError("{} must be a mapping".format(context))
    return value


def _strict_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OracleError("{} must be an integer".format(context))
    return value


def _nonnegative(value: Any, context: str) -> int:
    number = _strict_int(value, context)
    if number < 0:
        raise OracleError("{} must be non-negative".format(context))
    return number


def _positive(value: Any, context: str) -> int:
    number = _strict_int(value, context)
    if number <= 0:
        raise OracleError("{} must be positive".format(context))
    return number


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise OracleError("{} has unknown field(s): {}".format(context, ", ".join(unknown)))


def _parse_field(raw: Any, context: str) -> FieldSpec:
    item = _mapping(raw, context)
    _reject_unknown(item, {"offset", "width"}, context)
    offset = _nonnegative(item.get("offset"), context + ".offset")
    width = _strict_int(item.get("width"), context + ".width")
    if width not in (1, 2, 4, 8):
        raise OracleError("{}.width must be 1, 2, 4, or 8".format(context))
    return FieldSpec(offset, width)


def _parse_config(raw: Mapping[str, Any]) -> dict[str, Any]:
    root = _mapping(raw, "config")
    _reject_unknown(
        root,
        {"schema_version", "name", "input", "input_hex", "layout", "mutations", "harness", "mode", "_config_dir"},
        "config",
    )
    version = _strict_int(root.get("schema_version", SCHEMA_VERSION), "schema_version")
    if version != SCHEMA_VERSION:
        raise OracleError("unsupported schema_version {}".format(version))
    name = root.get("name")
    if not isinstance(name, str) or not name.strip():
        raise OracleError("name must be a non-empty string")
    has_input = root.get("input") is not None
    has_hex = root.get("input_hex") is not None
    if has_input == has_hex:
        raise OracleError("config must declare exactly one of input or input_hex")

    layout = _mapping(root.get("layout"), "layout")
    _reject_unknown(
        layout,
        {"byteorder", "component_offset", "component_length", "authentication_offset",
         "authentication_length", "authentication_header_size", "fields"},
        "layout",
    )
    byteorder = layout.get("byteorder", "little")
    if byteorder not in ("little", "big"):
        raise OracleError("layout.byteorder must be 'little' or 'big'")
    component_offset = _nonnegative(layout.get("component_offset"), "layout.component_offset")
    component_length = _positive(layout.get("component_length"), "layout.component_length")
    auth_offset = _nonnegative(layout.get("authentication_offset"), "layout.authentication_offset")
    auth_length = _positive(layout.get("authentication_length"), "layout.authentication_length")
    auth_header_size = _nonnegative(
        layout.get("authentication_header_size", 0), "layout.authentication_header_size"
    )
    fields_raw = _mapping(layout.get("fields"), "layout.fields")
    if set(fields_raw) != set(FIELD_NAMES):
        missing = sorted(set(FIELD_NAMES) - set(fields_raw))
        extra = sorted(set(fields_raw) - set(FIELD_NAMES))
        bits = []
        if missing:
            bits.append("missing {}".format(", ".join(missing)))
        if extra:
            bits.append("unknown {}".format(", ".join(extra)))
        raise OracleError("layout.fields: " + "; ".join(bits))
    fields = {name: _parse_field(fields_raw[name], "layout.fields." + name) for name in FIELD_NAMES}
    intervals = [(spec.offset, spec.offset + spec.width, name) for name, spec in fields.items()]
    for start, end, field_name in intervals:
        if end > component_length:
            raise OracleError("layout.fields.{} lies outside component length".format(field_name))
    for index, (start, end, field_name) in enumerate(intervals):
        for other_start, other_end, other_name in intervals[index + 1:]:
            if start < other_end and other_start < end:
                raise OracleError("layout fields {} and {} overlap".format(field_name, other_name))
    if auth_offset < component_offset or auth_offset + auth_length > component_offset + component_length:
        raise OracleError("authentication extent must lie within component extent")
    if auth_header_size > auth_length:
        raise OracleError("authentication_header_size exceeds authentication_length")

    mutations = _mapping(root.get("mutations", {}), "mutations")
    _reject_unknown(mutations, {"max_mutants", "include_safe_edges"}, "mutations")
    max_mutants = _positive(mutations.get("max_mutants", 32), "mutations.max_mutants")
    include_safe_edges = mutations.get("include_safe_edges", True)
    if not isinstance(include_safe_edges, bool):
        raise OracleError("mutations.include_safe_edges must be boolean")

    harness = _mapping(root.get("harness"), "harness")
    _reject_unknown(harness, {"command", "timeout_seconds", "cwd"}, "harness")
    command = harness.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
        raise OracleError("harness.command must be a non-empty list of strings")
    if any("\x00" in x for x in command):
        raise OracleError("harness.command must not contain NUL characters")
    if not any("{input}" in x for x in command):
        raise OracleError("harness.command must include the {input} placeholder")
    names = {item[1:-1] for item in ALLOWED_PLACEHOLDERS}
    for token in command:
        for placeholder in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", token):
            if placeholder not in names:
                raise OracleError("harness.command contains an unknown placeholder")
    timeout = harness.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0
    ):
        raise OracleError("harness.timeout_seconds must be finite and positive")
    cwd = harness.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip() or "\x00" in cwd):
        raise OracleError("harness.cwd must be absent or a non-empty string")
    mode = root.get("mode", "default")
    if not isinstance(mode, str) or not mode.strip():
        raise OracleError("mode must be a non-empty string")
    return {
        "schema_version": version,
        "name": name.strip(),
        "input": root.get("input"),
        "input_hex": root.get("input_hex"),
        "layout": BoundsModel(
            component_offset,
            component_length,
            auth_offset,
            auth_length,
            auth_header_size,
            fields,
            byteorder,
        ),
        "mutations": {"max_mutants": max_mutants, "include_safe_edges": include_safe_edges},
        "harness": {
            "command": list(command),
            "timeout_seconds": float(timeout),
            "cwd": cwd.strip() if isinstance(cwd, str) else None,
        },
        "mode": mode.strip(),
    }


def load_config(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text) if yaml is not None else json.loads(text)
    except Exception as exc:
        raise OracleError("config is not valid YAML/JSON: {}".format(exc)) from exc
    config = _parse_config(raw)
    config["_config_dir"] = path.resolve().parent
    return config


def _resolve_input(config: Mapping[str, Any]) -> bytes:
    if config.get("input_hex") is not None:
        value = config["input_hex"]
        if not isinstance(value, str) or not value.strip():
            raise OracleError("input_hex must be a non-empty hexadecimal string")
        try:
            data = bytes.fromhex(value)
        except ValueError as exc:
            raise OracleError("input_hex is not valid hexadecimal") from exc
    else:
        source = config.get("input")
        if not isinstance(source, str) or not source.strip():
            raise OracleError("input must be a non-empty path")
        path = Path(source)
        if not path.is_absolute():
            path = Path(config.get("_config_dir") or Path.cwd()) / path
        try:
            data = path.resolve().read_bytes()
        except OSError as exc:
            raise OracleError("cannot read input '{}': {}".format(path, exc)) from exc
    if not data:
        raise OracleError("input is empty")
    return data


def _field_value(data: bytes, spec: FieldSpec, byteorder: str) -> int:
    if spec.offset + spec.width > len(data):
        raise OracleError("input is shorter than a declared field")
    return int.from_bytes(data[spec.offset:spec.offset + spec.width], byteorder)


def evaluate_bounds(data: bytes, layout: BoundsModel) -> dict[str, Any]:
    """Independently evaluate nested component/authentication extents."""
    values = {
        name: _field_value(
            data[layout.component_offset:], layout.fields[name], layout.byteorder
        )
        for name in FIELD_NAMES
    }
    component_end = layout.component_offset + layout.component_length
    auth_end = layout.authentication_offset + layout.authentication_length
    total_end = layout.component_offset + values["total_length"]
    used_end = layout.component_offset + values["used_length"]
    material_end = (
        layout.authentication_offset + layout.authentication_header_size
        + values["signature_length"] + values["key_length"]
    )
    violations: list[str] = []
    if layout.component_offset + layout.component_length > len(data):
        violations.append("component_extent_exceeds_input")
    if values["total_length"] > layout.component_length:
        violations.append("total_length_exceeds_component")
    if values["used_length"] > values["total_length"]:
        violations.append("used_length_exceeds_total")
    if material_end > auth_end:
        violations.append("signature_key_extent_exceeds_authentication")
    if material_end > component_end:
        violations.append("signature_key_extent_exceeds_component")
    if used_end > component_end:
        violations.append("used_extent_exceeds_component")
    return {
        "safe": not violations,
        "values": values,
        "component_end": component_end,
        "authentication_end": auth_end,
        "total_end": total_end,
        "used_end": used_end,
        "signature_key_end": material_end,
        "violations": violations,
    }


def _write_field(data: bytes, spec: FieldSpec, value: int, byteorder: str) -> bytes:
    maximum = (1 << (8 * spec.width)) - 1
    if not 0 <= value <= maximum:
        raise OracleError("mutation value exceeds field width")
    result = bytearray(data)
    result[spec.offset:spec.offset + spec.width] = value.to_bytes(spec.width, byteorder)
    return bytes(result)


def _mutations(data: bytes, layout: BoundsModel, config: Mapping[str, Any]) -> list[Mutation]:
    base = evaluate_bounds(data, layout)
    if not base["safe"]:
        raise OracleError("canonical input is outside declared bounds")
    max_mutants = config["mutations"]["max_mutants"]
    values = base["values"]
    candidates: list[dict[str, int]] = []
    # Each individual edge is useful for distinguishing which bound is absent.
    for name in FIELD_NAMES:
        spec = layout.fields[name]
        maximum = (1 << (8 * spec.width)) - 1
        if name == "total_length":
            edge = layout.component_length + 1
        elif name == "used_length":
            edge = values["total_length"] + 1
        else:
            available = layout.authentication_length - layout.authentication_header_size
            edge = available + 1
        if edge <= maximum:
            candidate = dict(values)
            candidate[name] = edge
            candidates.append(candidate)
    # Include a safe boundary edge and a combined nested overflow when space allows.
    if config["mutations"]["include_safe_edges"]:
        for name in FIELD_NAMES:
            candidate = dict(values)
            if name == "total_length":
                candidate[name] = layout.component_length
            elif name == "used_length":
                candidate[name] = values["total_length"]
            elif name == "signature_length":
                candidate[name] = max(
                    0,
                    layout.authentication_length
                    - layout.authentication_header_size
                    - values["key_length"],
                )
            else:
                candidate[name] = max(
                    0,
                    layout.authentication_length
                    - layout.authentication_header_size
                    - values["signature_length"],
                )
            candidates.append(candidate)
    available = layout.authentication_length - layout.authentication_header_size
    signature_max = (1 << (8 * layout.fields["signature_length"].width)) - 1
    key_max = (1 << (8 * layout.fields["key_length"].width)) - 1
    target_sum = available + 1
    if target_sum <= signature_max + key_max:
        # Prefer the largest representable signature and put the remainder in
        # the key field.  This is deterministic and handles capacities larger
        # than either narrow field (for example 255 + 46 for uint8 fields).
        combo = dict(values)
        combo["signature_length"] = min(signature_max, target_sum)
        combo["key_length"] = target_sum - combo["signature_length"]
        if 0 <= combo["key_length"] <= key_max:
            candidates.append(combo)
    mutations: list[Mutation] = []
    seen: set[tuple[tuple[str, int], ...]] = set()
    for candidate in candidates:
        # A safe-edge can itself be unrepresentable (for example, a 300-byte
        # component with a one-byte total-length field).  Such a candidate is
        # not a valid encoded input and must be skipped, not allowed to fail
        # the entire campaign.
        if any(
            not 0 <= candidate[name] <= (1 << (8 * layout.fields[name].width)) - 1
            for name in FIELD_NAMES
        ):
            continue
        key = tuple((name, candidate[name]) for name in FIELD_NAMES)
        if key in seen or candidate == values:
            continue
        seen.add(key)
        mutated = data
        for name in FIELD_NAMES:
            if candidate[name] != values[name]:
                spec = layout.fields[name]
                absolute = FieldSpec(layout.component_offset + spec.offset, spec.width)
                mutated = _write_field(mutated, absolute, candidate[name], layout.byteorder)
        mutations.append(Mutation("m{:04d}".format(len(mutations) + 1), candidate, mutated))
        if len(mutations) >= max_mutants:
            break
    if not mutations:
        raise OracleError("mutation set is empty")
    return mutations


def _render_command(command: Sequence[str], path: Path, mutation_id: str, index: int, mode: str) -> list[str]:
    replacements = {"{input}": str(path), "{mutation_id}": mutation_id, "{mutation_index}": str(index), "{mode}": mode}
    rendered = []
    for token in command:
        current = token
        for old, new in replacements.items():
            current = current.replace(old, new)
        rendered.append(current)
    return rendered


def _run_harness(config: Mapping[str, Any], path: Path, mutation_id: str, index: int) -> dict[str, Any]:
    harness = config["harness"]
    cwd = harness.get("cwd")
    cwd_path = Path(cwd) if cwd else Path(config.get("_config_dir") or Path.cwd())
    if not cwd_path.is_absolute():
        cwd_path = Path(config.get("_config_dir") or Path.cwd()) / cwd_path
    try:
        result = subprocess.run(
            _render_command(harness["command"], path, mutation_id, index, config["mode"]),
            cwd=str(cwd_path.resolve()), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=harness["timeout_seconds"], check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OracleError("harness timed out for {}".format(mutation_id)) from exc
    except OSError as exc:
        raise OracleError("cannot execute harness for {}: {}".format(mutation_id, exc)) from exc
    if result.returncode != 0:
        raise OracleError("harness returned {} for {}".format(result.returncode, mutation_id))
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OracleError("harness output for {} is not JSON".format(mutation_id)) from exc
    if not isinstance(output, dict):
        raise OracleError("harness output for {} must be an object".format(mutation_id))
    for field in REQUIRED_HARNESS_FIELDS:
        if field not in output or not isinstance(output[field], bool):
            raise OracleError("harness output for {} must contain boolean '{}'".format(mutation_id, field))
    if output["committed"] and not output["accepted"]:
        raise OracleError("harness committed without acceptance for {}".format(mutation_id))
    input_digest = output.get("input_sha256")
    if input_digest != hashlib.sha256(path.read_bytes()).hexdigest():
        raise OracleError("harness input_sha256 does not match supplied bytes for {}".format(mutation_id))
    return output


def run_campaign(config: Mapping[str, Any]) -> dict[str, Any]:
    # ``load_config`` already returns a typed layout.  Accepting it here keeps
    # the library API convenient while still validating direct dictionary
    # callers through the strict parser.
    if isinstance(config.get("layout"), BoundsModel):
        normalized = dict(config)
        normalized["_config_dir"] = config.get("_config_dir", Path.cwd())
    else:
        normalized = _parse_config(config)
        normalized["_config_dir"] = config.get("_config_dir", Path.cwd())
    data = _resolve_input(normalized)
    layout: BoundsModel = normalized["layout"]
    base_bounds = evaluate_bounds(data, layout)
    mutations = _mutations(data, layout, normalized)
    layout_report = {
        "byteorder": layout.byteorder,
        "component_offset": layout.component_offset,
        "component_length": layout.component_length,
        "authentication_offset": layout.authentication_offset,
        "authentication_length": layout.authentication_length,
        "authentication_header_size": layout.authentication_header_size,
        "fields": {
            name: {"offset": spec.offset, "width": spec.width}
            for name, spec in layout.fields.items()
        },
    }
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "campaign": normalized["name"],
        "status": "PASS",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "configuration": {
            "schema_version": normalized["schema_version"],
            "name": normalized["name"],
            "input": normalized.get("input"),
            "input_hex": normalized.get("input_hex"),
            "layout": layout_report,
            "mutations": dict(normalized["mutations"]),
            "harness": dict(normalized["harness"]),
            "mode": normalized["mode"],
        },
        "harness_argv": list(normalized["harness"]["command"]),
        "base_bounds": base_bounds,
        "base": None,
        "mutants": [],
        "findings": [],
    }
    with tempfile.TemporaryDirectory(prefix="tardigrade-preauth-bounds-") as temp_dir:
        directory = Path(temp_dir)
        base_path = directory / "base.bin"
        base_path.write_bytes(data)
        base_output = _run_harness(normalized, base_path, "base", 0)
        if not base_output["accepted"] or not base_output["auth_attempted"]:
            raise OracleError("canonical harness must accept and attempt authentication")
        report["base"] = {"outcome": base_output}
        for index, mutation in enumerate(mutations, 1):
            path = directory / (mutation.mutation_id + ".bin")
            path.write_bytes(mutation.data)
            bounds = evaluate_bounds(mutation.data, layout)
            output = _run_harness(normalized, path, mutation.mutation_id, index)
            item = {
                "mutation_id": mutation.mutation_id,
                "fields": dict(mutation.fields),
                "input_sha256": hashlib.sha256(mutation.data).hexdigest(),
                "input_size": len(mutation.data),
                "bounds": bounds,
                "outcome": output,
            }
            report["mutants"].append(item)
            if not bounds["safe"] and (output["auth_attempted"] or output["accepted"] or output["committed"]):
                report["findings"].append({
                    "id": "PREAUTH_BOUNDS_ESCAPE",
                    "mutation_id": mutation.mutation_id,
                    "violations": bounds["violations"],
                    "observed": {key: output[key] for key in REQUIRED_HARNESS_FIELDS},
                })
    if report["findings"]:
        report["status"] = "FINDINGS"
    return report


def write_report(report: Mapping[str, Any], path: Path | None = None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_campaign(load_config(args.config))
        write_report(report, args.report)
        return 1 if report["status"] == "FINDINGS" else 0
    except OracleError as exc:
        write_report({"schema_version": SCHEMA_VERSION, "status": "FAIL_CLOSED", "error": str(exc)}, args.report)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
