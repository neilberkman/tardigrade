"""Helpers for metadata-state fuzzing.

Generates structured metadata blobs from a declarative field model, converts
them into ``pre_boot_state`` writes, and summarizes campaign results.
"""

from __future__ import annotations

import hashlib
import random
import zlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from fault_classification import _effective_boot_result, result_issue_reasons

# Default metadata base when no slot geometry is available (512KB).
DEFAULT_METADATA_BASE = 0x00080000


@dataclass(frozen=True)
class MetadataField:
    name: str
    offset: int
    size: int
    field_type: str = ""
    valid: Tuple[int, ...] = ()
    valid_range: Optional[Tuple[int, int]] = None


@dataclass(frozen=True)
class MetadataModel:
    base_address: int
    size: int
    fill: int
    fields: Tuple[MetadataField, ...]


def derive_default_metadata_base(slots: Dict[str, Any]) -> int:
    slot_ends: List[int] = []
    for slot in slots.values():
        base = getattr(slot, "base", None)
        size = getattr(slot, "size", None)
        if base is None or size is None:
            continue
        slot_ends.append(int(base) + int(size))
    return max(slot_ends) if slot_ends else DEFAULT_METADATA_BASE


def build_legacy_ab_replica_model(base_address: int) -> Dict[str, Any]:
    return {
        "base_address": int(base_address),
        "fill": 0xFF,
        "fields": [
            {"name": "magic", "offset": 0, "size": 4, "valid": [0x4F54414D]},
            {"name": "seq", "offset": 4, "size": 4, "type": "uint32"},
            {"name": "active_slot", "offset": 8, "size": 4, "valid": [0, 1]},
            {"name": "target_slot", "offset": 12, "size": 4, "valid": [0, 1]},
            {"name": "state", "offset": 16, "size": 4, "valid_range": [0, 4]},
            {"name": "boot_count", "offset": 20, "size": 4, "valid_range": [0, 10]},
            {"name": "max_boot_count", "offset": 24, "size": 4, "valid_range": [0, 10]},
            {"name": "crc", "offset": 252, "size": 4, "type": "computed_crc32"},
        ],
    }


def resolve_metadata_model(raw: Any, default_base: int) -> MetadataModel:
    if isinstance(raw, str):
        if raw != "ab_replica":
            raise ValueError("unsupported legacy metadata model {!r}".format(raw))
        raw = build_legacy_ab_replica_model(default_base)
    if not isinstance(raw, dict):
        raise ValueError("metadata model must be a mapping or legacy model name")

    fields: List[MetadataField] = []
    size = 0
    fill = int(raw.get("fill", 0xFF)) & 0xFF
    for entry in raw.get("fields", []):
        field = MetadataField(
            name=str(entry["name"]),
            offset=int(entry["offset"]),
            size=int(entry["size"]),
            field_type=str(entry.get("type", "")),
            valid=tuple(int(v) for v in entry.get("valid", []) or []),
            valid_range=(
                (int(entry["valid_range"][0]), int(entry["valid_range"][1]))
                if entry.get("valid_range") is not None
                else None
            ),
        )
        fields.append(field)
        size = max(size, field.offset + field.size)
    if not fields:
        raise ValueError("metadata model must define at least one field")
    crc_fields = [field for field in fields if field.field_type == "computed_crc32"]
    if len(crc_fields) > 1:
        raise ValueError("metadata model supports at most one computed_crc32 field")
    if crc_fields and (crc_fields[0].offset + crc_fields[0].size != size):
        raise ValueError("computed_crc32 field must be the final field")
    return MetadataModel(
        base_address=int(raw["base_address"]),
        size=size,
        fill=fill,
        fields=tuple(sorted(fields, key=lambda f: f.offset)),
    )


def _fits(field: MetadataField, value: int) -> bool:
    return 0 <= int(value) <= ((1 << (field.size * 8)) - 1)


def _is_valid(field: MetadataField, value: int) -> bool:
    if not _fits(field, value):
        return False
    if field.valid:
        return int(value) in field.valid
    if field.valid_range is not None:
        lo, hi = field.valid_range
        return lo <= int(value) <= hi
    return True


def _scenario_matches_model(
    scenario: Dict[str, Any],
    model: Optional[MetadataModel],
) -> Optional[bool]:
    if model is None:
        return None
    if str(scenario.get("crc_mode") or "").strip().lower() == "invalid":
        return False

    field_values = scenario.get("field_values")
    if not isinstance(field_values, dict):
        return None

    for field in model.fields:
        if field.field_type == "computed_crc32":
            continue
        if field.name not in field_values:
            continue
        if not _is_valid(field, int(field_values[field.name])):
            return False
    return True


def _random_valid_value(field: MetadataField, rng: random.Random) -> int:
    if field.valid:
        return int(rng.choice(field.valid))
    if field.valid_range is not None:
        lo, hi = field.valid_range
        return rng.randint(lo, hi)
    return rng.randrange(0, 1 << (field.size * 8))


def _invalid_candidates(field: MetadataField) -> List[int]:
    max_value = (1 << (field.size * 8)) - 1
    candidates = [
        0,
        1,
        max_value,
        max_value - 1 if max_value > 0 else 0,
        int.from_bytes(b"\xA5" * field.size, "little") & max_value,
        int.from_bytes(b"\x5A" * field.size, "little") & max_value,
    ]
    if field.valid:
        hi = max(int(v) for v in field.valid)
        if hi < max_value:
            candidates.append(hi + 1)
    if field.valid_range is not None:
        lo, hi = field.valid_range
        if lo > 0:
            candidates.append(lo - 1)
        if hi < max_value:
            candidates.append(hi + 1)
    seen: set = set()
    result: List[int] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result


def _random_invalid_value(field: MetadataField, rng: random.Random) -> int:
    # Unconstrained fields have no invalid values — return random instead.
    if not field.valid and field.valid_range is None:
        return rng.randrange(0, (1 << (field.size * 8)))
    candidates = [c for c in _invalid_candidates(field) if not _is_valid(field, c)]
    if candidates:
        return int(rng.choice(candidates))
    max_value = (1 << (field.size * 8)) - 1
    for _ in range(64):
        candidate = rng.randrange(0, max_value + 1)
        if not _is_valid(field, candidate):
            return candidate
    return max_value


def _boundary_value(field: MetadataField, index: int) -> int:
    max_value = (1 << (field.size * 8)) - 1
    candidates: List[int] = [0, 1, max_value]
    if field.valid:
        sorted_valid = sorted(set(int(v) for v in field.valid))
        candidates.extend([sorted_valid[0], sorted_valid[-1]])
    if field.valid_range is not None:
        lo, hi = field.valid_range
        candidates.extend([lo, hi])
        if lo > 0:
            candidates.append(lo - 1)
        if hi < max_value:
            candidates.append(hi + 1)
    deduped: List[int] = []
    seen: set = set()
    for candidate in candidates:
        if 0 <= candidate <= max_value and candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped[index % len(deduped)] if deduped else 0


def _encode_field(blob: bytearray, field: MetadataField, value: int) -> None:
    blob[field.offset:field.offset + field.size] = int(value).to_bytes(
        field.size, byteorder="little", signed=False
    )


def _write_crc_field(blob: bytearray, field: MetadataField, *, valid_crc: bool) -> None:
    if field.size != 4:
        raise ValueError("computed_crc32 fields must be 4 bytes")
    crc = zlib.crc32(bytes(blob[:field.offset])) & 0xFFFFFFFF
    if not valid_crc:
        crc ^= 0xFFFFFFFF
    _encode_field(blob, field, crc)


def blob_to_pre_boot_words(model: MetadataModel, blob: bytes) -> List[Tuple[int, int]]:
    padded = blob
    if len(padded) % 4:
        padded += bytes([model.fill]) * (4 - (len(padded) % 4))
    writes: List[Tuple[int, int]] = []
    for idx in range(0, len(padded), 4):
        value = int.from_bytes(padded[idx:idx + 4], byteorder="little", signed=False)
        writes.append((model.base_address + idx, value))
    return writes


def _scenario_digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def generate_state_scenarios(
    model: MetadataModel,
    iterations: int,
    seed: int = 0,
) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    normal_fields = [field for field in model.fields if field.field_type != "computed_crc32"]
    crc_field = next((field for field in model.fields if field.field_type == "computed_crc32"), None)
    if not normal_fields and crc_field is not None:
        raise ValueError("metadata model must contain at least one non-CRC field")

    scenarios: List[Dict[str, Any]] = []
    # Modes cycle: 0=random_bytes, 1=structured_random, 2=boundary, ...
    # CRC alternates: even=valid, odd=invalid.  The two cycles interact:
    # idx 0 = random_bytes + valid_crc, 1 = structured + invalid, 2 = boundary + valid, etc.
    modes = ("random_bytes", "structured_random", "boundary")
    for idx in range(iterations):
        mode = modes[idx % len(modes)]
        blob = bytearray([model.fill] * model.size)
        field_values: Dict[str, int] = {}
        valid_crc = (idx % 2) == 0

        if mode == "random_bytes":
            for pos in range(model.size):
                blob[pos] = rng.randrange(0, 256)
        else:
            focus_field = normal_fields[idx % len(normal_fields)] if normal_fields else None
            boundary_index = idx // max(1, len(normal_fields))
            for field in normal_fields:
                if mode == "boundary" and field == focus_field:
                    value = _boundary_value(field, boundary_index)
                elif mode == "structured_random":
                    if field.valid or field.valid_range is not None:
                        choose_valid = rng.random() < 0.7
                        value = (
                            _random_valid_value(field, rng)
                            if choose_valid
                            else _random_invalid_value(field, rng)
                        )
                    else:
                        value = _random_valid_value(field, rng)
                else:
                    value = _random_valid_value(field, rng)
                field_values[field.name] = int(value)
                _encode_field(blob, field, value)

        if mode == "random_bytes":
            for field in normal_fields:
                raw_value = int.from_bytes(
                    blob[field.offset:field.offset + field.size],
                    byteorder="little",
                    signed=False,
                )
                field_values[field.name] = raw_value

        if crc_field is not None:
            _write_crc_field(blob, crc_field, valid_crc=valid_crc)
            field_values[crc_field.name] = int.from_bytes(
                blob[crc_field.offset:crc_field.offset + crc_field.size],
                byteorder="little",
                signed=False,
            )

        blob_bytes = bytes(blob)
        scenarios.append(
            {
                "index": idx,
                "mode": mode,
                "crc_mode": (
                    "valid" if crc_field is not None and valid_crc else
                    "invalid" if crc_field is not None else
                    "none"
                ),
                "field_values": field_values,
                "blob": blob_bytes,
                "blob_sha256": _scenario_digest(blob_bytes),
                "pre_boot_state": blob_to_pre_boot_words(model, blob_bytes),
            }
        )
    return scenarios


def summarize_state_campaign(
    results: Sequence[Dict[str, Any]],
    expected_outcome: str,
    metadata_model: Any,
    iterations: int,
) -> Dict[str, Any]:
    boot_outcomes: Dict[str, int] = {}
    issue_reasons_total: Dict[str, int] = {}
    findings = 0
    infrastructure_errors = 0
    timeouts = 0
    effective_tuples: set = set()

    for entry in results:
        outcome = str(entry.get("boot_outcome", "unknown"))
        boot_outcomes[outcome] = boot_outcomes.get(outcome, 0) + 1
        for reason, count in (entry.get("issue_reasons", {}) or {}).items():
            issue_reasons_total[str(reason)] = issue_reasons_total.get(str(reason), 0) + int(count)
        if entry.get("finding"):
            findings += 1
        if entry.get("infrastructure_error") or outcome == "infra_error":
            infrastructure_errors += 1
        if entry.get("timeout") or outcome == "timeout":
            timeouts += 1
        effective_tuples.add(
            (
                str(entry.get("effective_outcome") or entry.get("boot_outcome") or "unknown"),
                entry.get("effective_slot") if entry.get("effective_slot") is not None
                else entry.get("boot_slot"),
            )
        )

    warnings: List[str] = []
    # A state-fuzz campaign that forces many different scenarios but
    # collapses to a single observable boot result means the input
    # distribution went through a funnel somewhere (typical cause: the
    # model's ``magic`` value does not match what the firmware expects, so
    # every scenario is rejected at the same point).  Surface this loudly
    # instead of letting a "50/50 scenarios passed" line imply coverage
    # that does not exist.  We floor at 10 to avoid spurious warnings on
    # smoke runs where a small sample landing on a single tuple is not
    # yet evidence of a misconfiguration.
    if len(results) >= 10 and len(effective_tuples) == 1:
        only_tuple = next(iter(effective_tuples))
        warnings.append(
            "state_fuzz produced a single effective (outcome, slot) across all "
            "{} scenarios: {}. The metadata model may be misconfigured for this "
            "firmware (e.g. wrong ``magic`` constant) so every scenario collapses "
            "to the same path.".format(len(results), only_tuple)
        )

    summary = {
        "status": "completed",
        "iterations_requested": int(iterations),
        "iterations_completed": len(results),
        "findings": findings,
        "infrastructure_errors": infrastructure_errors,
        "timeouts": timeouts,
        "expected_control_outcome": expected_outcome,
        "boot_outcomes": boot_outcomes,
        "issue_reasons": issue_reasons_total,
        "metadata_model": metadata_model,
    }
    if warnings:
        summary["warnings"] = warnings
    return summary


def extract_state_fuzz_result(
    scenario: Dict[str, Any],
    result: Dict[str, Any],
    expected_outcome: str,
    metadata_model: Optional[MetadataModel] = None,
) -> Dict[str, Any]:
    effective_outcome, effective_slot = _effective_boot_result(result)
    issue_reason_list = result_issue_reasons(result, expected_outcome)
    scenario_matches_model = _scenario_matches_model(scenario, metadata_model)
    if scenario_matches_model is False:
        issue_reason_list = [
            reason for reason in issue_reason_list
            if reason not in {"boot_outcome", "pc_expectation", "vtor_expectation"}
        ]
    issue_reasons = {reason: 1 for reason in issue_reason_list}
    raw_outcome = str(result.get("boot_outcome", "unknown")).strip().lower()
    infrastructure_error = bool(
        result.get("infrastructure_error") or raw_outcome == "infra_error"
    )
    timeout = bool(result.get("timeout") or raw_outcome == "timeout")
    unreliable = infrastructure_error or timeout or raw_outcome == "unknown"
    finding = bool(issue_reason_list) and not unreliable
    return {
        "scenario_index": int(scenario["index"]),
        "mode": scenario["mode"],
        "crc_mode": scenario["crc_mode"],
        "blob_sha256": scenario["blob_sha256"],
        "field_values": dict(scenario["field_values"]),
        "scenario_matches_model": scenario_matches_model,
        "boot_outcome": raw_outcome,
        "boot_slot": result.get("boot_slot"),
        "effective_outcome": effective_outcome,
        "effective_slot": effective_slot,
        "issue_count": len(issue_reason_list),
        "issue_reasons": issue_reasons,
        "finding": finding,
        "infrastructure_error": infrastructure_error,
        "timeout": timeout,
        "error_kind": result.get("error_kind"),
    }
