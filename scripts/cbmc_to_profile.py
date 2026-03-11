#!/usr/bin/env python3
"""Convert CBMC counterexamples to tardigrade profile YAML files.

Supports both JSON (``--json-ui``) and XML (``--xml-ui``) CBMC output
formats.  An optional *address map* file lets you map CBMC symbolic
variable names to absolute flash addresses so the generated
``pre_boot_state`` writes target the correct memory locations.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from xml.etree import ElementTree

try:
    import yaml
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit(
        "PyYAML is required for cbmc_to_profile.py (pip install pyyaml)."
    ) from exc


DEFAULT_META_SIZE = 512
ARRAY_CANDIDATES = ("meta_bytes", "nvm")


# ---------------------------------------------------------------------------
# Address-map helpers
# ---------------------------------------------------------------------------

def load_address_map(path: Optional[str]) -> Dict[str, int]:
    """Load a variable-name -> flash-address mapping from a YAML or JSON file.

    Expected format (YAML)::

        # Map CBMC array names to absolute flash base addresses.
        meta_bytes: 0x10070000
        header:     0x10038000

    Or JSON::

        {"meta_bytes": "0x10070000", "header": "0x10038000"}

    Returns a dict of ``{name: int_address}``.
    """
    if not path:
        return {}
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        raw = yaml.safe_load(text)
    else:
        raw = json.loads(text)
    if not isinstance(raw, dict):
        raise RuntimeError("Address map must be a JSON/YAML object mapping names to addresses.")
    result: Dict[str, int] = {}
    for name, addr in raw.items():
        if isinstance(addr, int):
            result[str(name)] = addr
        elif isinstance(addr, str):
            result[str(name)] = int(addr, 0)
        else:
            raise RuntimeError(
                "Address map entry '{}' has unsupported type: {}".format(name, type(addr).__name__)
            )
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert CBMC JSON or XML counterexamples into tardigrade profiles."
    )
    parser.add_argument(
        "--cbmc-output", required=True,
        help="Path to CBMC output (JSON from --json-ui, or XML from --xml-ui).",
    )
    parser.add_argument("--template", required=True, help="Template profile YAML to copy.")
    parser.add_argument("--output", required=True, help="Output profile path.")
    parser.add_argument(
        "--replay-output",
        default="",
        help="Optional output path for generic replay spec(s).",
    )
    parser.add_argument(
        "--address-map",
        default="",
        help="Optional YAML/JSON file mapping CBMC variable names to flash addresses.",
    )
    parser.add_argument(
        "--meta-size",
        type=int,
        default=DEFAULT_META_SIZE,
        help="Metadata region size in bytes (default: 512).",
    )
    parser.add_argument(
        "--meta-base",
        type=lambda v: int(v, 0),
        default=None,
        help="Optional absolute metadata base address override (e.g. 0x10070000).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be generated without writing files.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

REQUIRED_TEMPLATE_KEYS = ("schema_version", "bootloader")


def _validate_cbmc_path(path):
    """Check that the CBMC output file exists and is non-empty."""
    p = Path(path)
    if not p.exists():
        raise RuntimeError("CBMC output file does not exist: {}".format(p))
    if p.stat().st_size == 0:
        raise RuntimeError("CBMC output file is empty: {}".format(p))


def _validate_template(data, path):
    """Check that the template profile has required top-level keys."""
    if not isinstance(data, dict):
        raise RuntimeError("Template profile must be a YAML mapping/object: {}".format(path))
    missing = [k for k in REQUIRED_TEMPLATE_KEYS if k not in data]
    if missing:
        raise RuntimeError(
            "Template profile {} is missing required key(s): {}".format(
                path, ", ".join(missing)
            )
        )


def _validate_trace(trace, index):
    """Check that a counterexample trace is a non-empty list of dicts."""
    if not isinstance(trace, list):
        raise RuntimeError(
            "Counterexample {} has invalid trace: expected list, got {}.".format(
                index, type(trace).__name__
            )
        )
    if len(trace) == 0:
        raise RuntimeError(
            "Counterexample {} has an empty trace (no steps).".format(index)
        )


# ---------------------------------------------------------------------------
# JSON trace extraction (existing logic)
# ---------------------------------------------------------------------------

def _is_failure_dict(node: Dict[str, Any]) -> bool:
    for key in ("status", "result", "propertyStatus", "verificationStatus"):
        value = node.get(key)
        if isinstance(value, str) and "FAIL" in value.upper():
            return True
    if node.get("success") is False and isinstance(node.get("trace"), list):
        return True
    return False


def _collect_failure_traces(node: Any, out: List[Dict[str, Any]]) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("trace"), list) and _is_failure_dict(node):
            out.append(node)
        for value in node.values():
            _collect_failure_traces(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_failure_traces(value, out)


def _contains_verification_success(node: Any) -> bool:
    if isinstance(node, str):
        return "VERIFICATION SUCCESSFUL" in node.upper()
    if isinstance(node, dict):
        return any(_contains_verification_success(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_verification_success(v) for v in node)
    return False


def _collect_error_messages(node: Any, out: List[str]) -> None:
    if isinstance(node, dict):
        msg_type = node.get("messageType")
        msg_text = node.get("messageText")
        if isinstance(msg_type, str) and msg_type.upper() == "ERROR":
            out.append(str(msg_text or "CBMC error"))
        elif isinstance(msg_text, str) and "CONVERSION ERROR" in msg_text.upper():
            out.append(msg_text)
        for value in node.values():
            _collect_error_messages(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_error_messages(value, out)


# ---------------------------------------------------------------------------
# XML trace extraction
# ---------------------------------------------------------------------------

def _parse_xml_counterexamples(xml_path: Path) -> List[Dict[str, Any]]:
    """Parse CBMC ``--xml-ui`` output and return a list of failure dicts.

    Each returned dict has the same shape as the JSON failure dicts:
    ``{"property": str, "status": "FAILURE", "trace": [step_dict, ...]}``.

    CBMC XML structure (simplified)::

        <cprover>
          <result property="..." status="FAILURE">
            <goto_trace>
              <assignment ...>
                <full_lhs>meta_bytes[0]</full_lhs>
                <full_lhs_value>42</full_lhs_value>
                ...
              </assignment>
            </goto_trace>
          </result>
        </cprover>
    """
    tree = ElementTree.parse(str(xml_path))
    root = tree.getroot()
    failures: List[Dict[str, Any]] = []

    for result_elem in root.iter("result"):
        status = (result_elem.get("status") or "").upper()
        if "FAIL" not in status:
            continue
        prop_name = result_elem.get("property", "unknown")

        trace_steps: List[Dict[str, Any]] = []
        for goto_trace in result_elem.iter("goto_trace"):
            for child in goto_trace:
                if child.tag == "assignment":
                    step: Dict[str, Any] = {"stepType": "assignment"}
                    for field in child:
                        if field.tag == "full_lhs":
                            step["full_lhs"] = (field.text or "").strip()
                        elif field.tag == "full_lhs_value":
                            step["value"] = (field.text or "").strip()
                        elif field.tag == "lhs":
                            step["lhs"] = (field.text or "").strip()
                        elif field.tag == "value":
                            step.setdefault("value", (field.text or "").strip())
                        elif field.tag == "type":
                            step["type"] = (field.text or "").strip()
                    # Also grab attributes
                    for attr in ("identifier", "base_name", "display_name"):
                        val = child.get(attr)
                        if val:
                            step[attr] = val
                    trace_steps.append(step)
                elif child.tag == "failure":
                    step = {
                        "stepType": "failure",
                        "property": child.get("property", ""),
                        "reason": child.get("reason", ""),
                    }
                    trace_steps.append(step)

        failures.append({
            "property": prop_name,
            "status": "FAILURE",
            "trace": trace_steps,
        })

    return failures


def _xml_contains_success(xml_path: Path) -> bool:
    """Check if the XML output indicates all properties passed."""
    tree = ElementTree.parse(str(xml_path))
    root = tree.getroot()
    for result_elem in root.iter("result"):
        status = (result_elem.get("status") or "").upper()
        if "FAIL" in status:
            return False
    # If we found result elements and none failed, it's a success
    return any(True for _ in root.iter("result"))


# ---------------------------------------------------------------------------
# Scalar/value parsing
# ---------------------------------------------------------------------------

def _parse_scalar_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.startswith(("0b", "-0b")):
            try:
                return int(s, 2)
            except ValueError:
                return None
        if s.startswith(("0x", "-0x")):
            try:
                return int(s, 16)
            except ValueError:
                return None
        try:
            return int(s, 10)
        except ValueError:
            return None
    if isinstance(value, dict):
        for key in ("data", "binary", "value", "name"):
            if key in value:
                parsed = _parse_scalar_int(value[key])
                if parsed is not None:
                    return parsed
    return None


# ---------------------------------------------------------------------------
# Byte-assignment extraction from traces
# ---------------------------------------------------------------------------

def _extract_byte_assignments(
    trace: Sequence[Any],
    extra_arrays: Sequence[str] = (),
) -> Tuple[str, Dict[int, int]]:
    """Walk a CBMC trace and collect per-byte array assignments.

    *extra_arrays* allows callers to supply additional array names (e.g.
    from an address-map) beyond the built-in ``ARRAY_CANDIDATES``.
    """
    all_candidates = list(ARRAY_CANDIDATES) + [
        n for n in extra_arrays if n not in ARRAY_CANDIDATES
    ]
    captures: Dict[str, Dict[int, int]] = {name: {} for name in all_candidates}
    patterns = {
        name: re.compile(r"\b{}\[(\d+)(?:[uUlL]*)\]".format(re.escape(name)))
        for name in all_candidates
    }

    for step in trace:
        if not isinstance(step, dict):
            continue
        lhs_candidates = [
            step.get("lhs"),
            step.get("full_lhs"),
            step.get("identifier"),
        ]
        lhs = next((x for x in lhs_candidates if isinstance(x, str) and x), "")
        if not lhs:
            continue

        # CBMC may emit aggregate assignments like:
        # lhs: "meta_bytes", value: {"elements":[{"index":0,"value":...}, ...]}
        for candidate in all_candidates:
            if lhs == candidate and isinstance(step.get("value"), dict):
                elements = step["value"].get("elements")
                if isinstance(elements, list):
                    for elem in elements:
                        if not isinstance(elem, dict):
                            continue
                        raw_index = elem.get("index")
                        if isinstance(raw_index, int):
                            idx = raw_index
                        elif isinstance(raw_index, str):
                            m = re.match(r"^\s*(\d+)", raw_index)
                            if not m:
                                continue
                            idx = int(m.group(1))
                        else:
                            continue
                        value = _parse_scalar_int(elem.get("value"))
                        if value is None:
                            continue
                        captures[candidate][idx] = value & 0xFF
                continue

        array_name = None
        index = None
        for candidate, pattern in patterns.items():
            match = pattern.search(lhs)
            if match:
                array_name = candidate
                index = int(match.group(1))
                break

        if array_name is None or index is None:
            continue

        raw_value = step.get("value")
        if raw_value is None:
            raw_value = step.get("rhs")
        if raw_value is None:
            raw_value = step.get("assignedValue")
        value = _parse_scalar_int(raw_value)
        if value is None:
            continue
        captures[array_name][index] = value & 0xFF

    for name in all_candidates:
        if captures[name]:
            return name, captures[name]

    return "", {}


# ---------------------------------------------------------------------------
# Address / metadata helpers
# ---------------------------------------------------------------------------

def _derive_meta_base(
    template: Dict[str, Any],
    override: Optional[int],
    addr_map: Dict[str, int],
    array_name: str,
) -> int:
    """Determine the metadata base address.

    Priority order:
    1. Explicit ``--meta-base`` CLI override.
    2. Address-map entry for the matched *array_name*.
    3. Inferred from template slot layout (end of last slot).
    4. Hardcoded fallback ``0x10070000``.
    """
    if override is not None:
        return override
    if array_name and array_name in addr_map:
        return addr_map[array_name]
    slots = (
        template.get("memory", {}).get("slots", {})
        if isinstance(template.get("memory"), dict)
        else {}
    )
    slot_ends: List[int] = []
    if isinstance(slots, dict):
        for entry in slots.values():
            if not isinstance(entry, dict):
                continue
            base = entry.get("base")
            size = entry.get("size")
            if base is None or size is None:
                continue
            slot_ends.append(int(base, 0) + int(size, 0) if isinstance(base, str) else int(base) + (int(size, 0) if isinstance(size, str) else int(size)))
    if slot_ends:
        return max(slot_ends)
    return 0x10070000


def _normalize_metadata_indices(
    byte_map: Dict[int, int], meta_size: int
) -> Dict[int, int]:
    if not byte_map:
        return {}

    indices = sorted(byte_map.keys())
    max_idx = indices[-1]

    if max_idx < (meta_size * 2):
        base_index = 0
    else:
        base_index = indices[0]

    normalized: Dict[int, int] = {}
    for idx, value in byte_map.items():
        rel = idx - base_index
        if 0 <= rel < meta_size:
            normalized[rel] = value
    return normalized


def _bytes_to_pre_boot_state(meta_base: int, bytes_map: Dict[int, int]) -> List[Dict[str, str]]:
    word_indices = sorted({idx // 4 for idx in bytes_map.keys()})
    writes: List[Dict[str, str]] = []
    for word_idx in word_indices:
        byte_offset = word_idx * 4
        b0 = bytes_map.get(byte_offset + 0, 0)
        b1 = bytes_map.get(byte_offset + 1, 0)
        b2 = bytes_map.get(byte_offset + 2, 0)
        b3 = bytes_map.get(byte_offset + 3, 0)
        word = (b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24)
        writes.append(
            {
                "address": "0x{:08X}".format(meta_base + byte_offset),
                "u32": "0x{:08X}".format(word),
            }
        )
    return writes


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _suffix_path(path: Path, index: int) -> Path:
    stem = path.stem
    suffix = path.suffix if path.suffix else ".yaml"
    return path.with_name("{}_{:03d}{}".format(stem, index, suffix))


def _property_name(trace_entry: Dict[str, Any], index: int) -> str:
    for key in ("property", "propertyId", "name", "description"):
        value = trace_entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "cbmc_counterexample_{}".format(index)


def _build_replay_spec(
    profile: Dict[str, Any],
    failure: Dict[str, Any],
    index: int,
    normalized: Dict[int, int],
    array_name: str,
    meta_base: int,
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "replay",
        "name": profile.get("name"),
        "description": profile.get("description"),
        "source": {
            "type": "cbmc",
            "property": _property_name(failure, index),
            "array": array_name,
            "meta_base": "0x{:08X}".format(meta_base),
            "byte_count": len(normalized),
        },
        "profile_overrides": {
            "pre_boot_state": _bytes_to_pre_boot_state(meta_base, normalized),
            "expect": {
                "should_find_issues": True,
            },
        },
    }


# ---------------------------------------------------------------------------
# Input detection
# ---------------------------------------------------------------------------

def _detect_format(path: Path) -> str:
    """Return 'json' or 'xml' based on file content sniffing."""
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("<") or stripped.startswith("<?xml"):
        return "xml"
    return "json"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    cbmc_path = Path(args.cbmc_output)
    template_path = Path(args.template)
    output_path = Path(args.output)
    replay_output_path = Path(args.replay_output).resolve() if args.replay_output else None
    dry_run = args.dry_run
    addr_map = load_address_map(args.address_map or None)

    # --- Validate inputs early ---
    _validate_cbmc_path(cbmc_path)

    if not template_path.exists():
        raise RuntimeError("Template file does not exist: {}".format(template_path))

    template_data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    _validate_template(template_data, template_path)

    fmt = _detect_format(cbmc_path)

    if fmt == "xml":
        failures = _parse_xml_counterexamples(cbmc_path)
        if not failures:
            if _xml_contains_success(cbmc_path):
                print("CBMC reported VERIFICATION SUCCESSFUL. No profile generated.")
                return 0
            print("No failing CBMC traces found. No profile generated.")
            return 0
    else:
        try:
            cbmc_data = json.loads(cbmc_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "CBMC output is not valid JSON: {}".format(exc)
            ) from exc
        failures = []
        _collect_failure_traces(cbmc_data, failures)
        errors: List[str] = []
        _collect_error_messages(cbmc_data, errors)
        if not failures:
            if errors:
                first = errors[0]
                raise RuntimeError(
                    "CBMC output contains errors and no failing trace: {}".format(first)
                )
            if _contains_verification_success(cbmc_data):
                print("CBMC reported VERIFICATION SUCCESSFUL. No profile generated.")
                return 0
            print("No failing CBMC traces found. No profile generated.")
            return 0

    extra_arrays = list(addr_map.keys())
    generated_paths: List[Path] = []
    generated_replays: List[Path] = []

    for idx, failure in enumerate(failures, start=1):
        trace = failure.get("trace")
        _validate_trace(trace, idx)

        array_name, byte_map = _extract_byte_assignments(trace, extra_arrays=extra_arrays)
        if not byte_map:
            raise RuntimeError(
                "Counterexample {} does not contain array assignments for {}. "
                "Run CBMC with --trace --json-ui and keep symbolic metadata arrays visible.".format(
                    idx, ", ".join(list(ARRAY_CANDIDATES) + extra_arrays)
                )
            )

        normalized = _normalize_metadata_indices(byte_map, args.meta_size)
        if not normalized:
            raise RuntimeError(
                "Counterexample {} had array assignments, but none mapped into metadata size {} bytes.".format(
                    idx, args.meta_size
                )
            )

        meta_base = _derive_meta_base(template_data, args.meta_base, addr_map, array_name)

        profile = copy.deepcopy(template_data)
        base_name = str(profile.get("name") or "cbmc_finding")
        profile["name"] = "{}_cbmc_{:03d}".format(base_name, idx)
        profile["description"] = (
            "{} (from CBMC counterexample {})".format(
                profile.get("description", "CBMC-derived profile"),
                _property_name(failure, idx),
            )
        )
        profile["pre_boot_state"] = _bytes_to_pre_boot_state(meta_base, normalized)
        expect = profile.setdefault("expect", {})
        if isinstance(expect, dict):
            expect["should_find_issues"] = True

        if len(failures) == 1:
            dest = output_path
        else:
            dest = _suffix_path(output_path, idx)

        profile_yaml = yaml.safe_dump(profile, sort_keys=False)

        if dry_run:
            print("--- dry-run: {} ---".format(dest))
            print(profile_yaml)
            generated_paths.append(dest)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(profile_yaml, encoding="utf-8")
            generated_paths.append(dest)
            print(
                "Generated {} from property '{}' using {} byte assignments from '{}'.".format(
                    dest,
                    _property_name(failure, idx),
                    len(normalized),
                    array_name,
                )
            )

        if replay_output_path is not None:
            replay_spec = _build_replay_spec(
                profile=profile,
                failure=failure,
                index=idx,
                normalized=normalized,
                array_name=array_name,
                meta_base=meta_base,
            )
            if len(failures) == 1:
                replay_dest = replay_output_path
            else:
                replay_dest = _suffix_path(replay_output_path, idx)

            replay_yaml = yaml.safe_dump(replay_spec, sort_keys=False)

            if dry_run:
                print("--- dry-run replay: {} ---".format(replay_dest))
                print(replay_yaml)
                generated_replays.append(replay_dest)
            else:
                replay_dest.parent.mkdir(parents=True, exist_ok=True)
                replay_dest.write_text(replay_yaml, encoding="utf-8")
                generated_replays.append(replay_dest)
                print(
                    "Generated replay spec {} for property '{}'.".format(
                        replay_dest,
                        _property_name(failure, idx),
                    )
                )

    if not generated_paths:
        raise RuntimeError("No profiles were generated from the failing traces.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
