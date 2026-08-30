"""Semantic assertion evaluation, invariant checking, and result annotation.

Extracted from audit_bootloader.py to provide a focused module for
post-sweep result validation logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_classification import _effective_boot_result
from fault_inject import FaultResult, decode_multi_fault_sequence
from invariants import resolve_invariants, run_invariants
from profile_loader import ProfileConfig

REPO_ROOT = Path(__file__).resolve().parent.parent

_MISSING = object()


def _tokenize_path(path: str) -> List[Any]:
    tokens: List[Any] = []
    current = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if current:
                tokens.append(current)
                current = ""
            i += 1
            continue
        if ch == "[":
            if current:
                tokens.append(current)
                current = ""
            end = path.find("]", i)
            if end == -1:
                raise ValueError("unterminated path index in {!r}".format(path))
            index_text = path[i + 1:end].strip()
            if not index_text:
                raise ValueError("empty path index in {!r}".format(path))
            tokens.append(int(index_text))
            i = end + 1
            continue
        current += ch
        i += 1
    if current:
        tokens.append(current)
    return tokens


def _lookup_path(data: Any, path: str) -> Any:
    current = data
    for token in _tokenize_path(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token < 0 or token >= len(current):
                return _MISSING
            current = current[token]
            continue
        if not isinstance(current, dict) or token not in current:
            return _MISSING
        current = current[token]
    return current


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def _serialize_value(value: Any) -> Any:
    if value is _MISSING:
        return "<missing>"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return value


def _result_state_payload(result: Dict[str, Any]) -> Any:
    # Prefer the final boot cycle's semantic state when multi-boot cycles exist.
    boot_cycles = result.get("boot_cycles")
    if isinstance(boot_cycles, list) and boot_cycles:
        last_cycle = boot_cycles[-1]
        if isinstance(last_cycle, dict):
            cycle_state = last_cycle.get("semantic_state")
            if isinstance(cycle_state, dict):
                return cycle_state
    if isinstance(result.get("nvm_state"), dict):
        return result.get("nvm_state")
    if isinstance(result.get("semantic_state"), dict):
        return result.get("semantic_state")
    return result.get("nvm_state") or result.get("semantic_state")


def _lookup_result_path(result: Dict[str, Any], path: str) -> Any:
    semantic_state = _result_state_payload(result)
    if path == "semantic_state":
        if semantic_state is not None:
            return semantic_state
    elif path.startswith("semantic_state."):
        if isinstance(semantic_state, dict):
            resolved = _lookup_path(semantic_state, path[len("semantic_state."):])
            if resolved is not _MISSING:
                return resolved

    nvm_state = result.get("nvm_state")
    if path == "nvm_state":
        if nvm_state is not None:
            return nvm_state
    elif path.startswith("nvm_state."):
        if isinstance(nvm_state, dict):
            resolved = _lookup_path(nvm_state, path[len("nvm_state."):])
            if resolved is not _MISSING:
                return resolved

    return _lookup_path(result, path)


def _profile_partition_ranges(profile: ProfileConfig) -> List[Tuple[int, int]]:
    return [
        (slot.base, slot.base + slot.size)
        for slot in profile.memory.slots.values()
    ]


def _evaluate_semantic_assertions(
    result: Dict[str, Any],
    profile: ProfileConfig,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    failures: List[Dict[str, Any]] = []
    observation_failures: List[Dict[str, Any]] = []
    scopes = ["always", "control" if result.get("is_control") else "faulted"]
    for scope in scopes:
        expectations = profile.semantic_assertions.get(scope, {})
        for path, expected in expectations.items():
            actual = _lookup_result_path(result, path)
            if actual is _MISSING:
                observation_failures.append(
                    {
                        "scope": scope,
                        "path": path,
                        "expected": _serialize_value(expected),
                        "actual": "<missing>",
                    }
                )
                continue
            if not _value_matches(actual, expected):
                failures.append(
                    {
                        "scope": scope,
                        "path": path,
                        "expected": _serialize_value(expected),
                        "actual": _serialize_value(actual),
                    }
                )
    return failures, observation_failures


def _evaluate_state_probe_contract(
    result: Dict[str, Any],
    profile: ProfileConfig,
) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    if (
        (getattr(profile, "invariant_config", {}) or {}).get("semantic_state_stage")
        == "fault_snapshot"
        and result.get("fault_injected")
        and not isinstance(result.get("fault_semantic_state"), dict)
    ):
        failures.append(
            {
                "scope": "contract",
                "contract": "invariant_config.semantic_state_stage",
                "path": "fault_semantic_state",
                "expected": "present",
                "actual": "<missing>",
            }
        )
    if getattr(profile, "state_probe", None) is None:
        return failures
    required_paths = list(getattr(profile.state_probe, "required_paths", []) or [])
    if not required_paths:
        return failures
    for path in required_paths:
        actual = _lookup_result_path(result, path)
        if actual is _MISSING:
            failures.append(
                {
                    "scope": "contract",
                    "contract": "state_probe.required_paths",
                    "path": path,
                    "expected": "present",
                    "actual": "<missing>",
                }
            )
    return failures


def _slot_validity_from_boot_slot(boot_slot: Optional[str]) -> Dict[str, bool]:
    token = str(boot_slot or "").strip().lower()
    slot_a_names = {"exec", "primary", "slot_a", "slot0", "a"}
    slot_b_names = {"staging", "secondary", "slot_b", "slot1", "b"}
    return {
        "slot_a_valid": token in slot_a_names,
        "slot_b_valid": token in slot_b_names,
    }


def _derive_runtime_pre_state(
    result: Dict[str, Any],
    control_result: Optional[Dict[str, Any]],
    profile: ProfileConfig,
) -> Optional[Dict[str, Any]]:
    explicit = result.get("pre_state")
    if isinstance(explicit, dict):
        return explicit
    if not isinstance(control_result, dict):
        return None
    if not result.get("is_control"):
        control_semantic = _result_state_payload(control_result)
        if isinstance(control_semantic, dict):
            return control_semantic
    expected_outcome = getattr(profile.expect, "control_outcome", "success") or "success"
    eff_outcome, eff_slot = _effective_boot_result(control_result)
    if eff_outcome != expected_outcome:
        return None
    derived = _slot_validity_from_boot_slot(eff_slot)
    if not any(derived.values()):
        derived["slot_a_valid"] = True
    derived["derived_from"] = "control_result"
    derived["control_boot_slot"] = control_result.get("boot_slot")
    derived["control_boot_outcome"] = control_result.get("boot_outcome")
    return derived


def check_write_order_constraints(
    trace: List[Dict[str, Any]],
    constraints: List[Any],
) -> List[Dict[str, Any]]:
    """Check write-order constraints against a calibration write trace.

    Each constraint specifies a ``first`` region that must be written before
    a ``then`` region.  When ``bidirectional`` is True, the constraint passes
    if either region completes all its writes before the other region's first
    write -- i.e., one region is fully written before the other starts,
    regardless of direction.  Only violates when writes are interleaved.
    Returns a list of violation dicts (empty = all OK).
    """
    violations: List[Dict[str, Any]] = []
    for c in constraints:
        first_start = c.first_start
        first_end = first_start + c.first_size
        then_start = c.then_start
        then_end = then_start + c.then_size
        bidirectional = getattr(c, "bidirectional", False)

        first_min: Optional[int] = None
        first_max: Optional[int] = None
        then_min: Optional[int] = None
        then_max: Optional[int] = None

        for entry in trace:
            addr = entry.get("flash_offset", 0)
            idx = entry.get("write_index", 0)
            if first_start <= addr < first_end:
                if first_min is None or idx < first_min:
                    first_min = idx
                if first_max is None or idx > first_max:
                    first_max = idx
            if then_start <= addr < then_end:
                if then_min is None or idx < then_min:
                    then_min = idx
                if then_max is None or idx > then_max:
                    then_max = idx

        if first_min is None and then_min is None:
            continue
        if then_min is None:
            continue
        if first_min is None:
            if bidirectional:
                # Only one region written -- no interleaving possible.
                continue
            violations.append({
                "label": c.label,
                "status": "violated",
                "reason": "first region never written, then region written at index {}".format(then_min),
                "first_write_index": None,
                "then_write_index": then_min,
            })
            continue

        if bidirectional:
            # Pass if either region completes before the other starts.
            first_before_then = first_max <= then_min  # type: ignore[operator]
            then_before_first = then_max <= first_min  # type: ignore[operator]
            if not first_before_then and not then_before_first:
                violations.append({
                    "label": c.label,
                    "status": "violated",
                    "reason": (
                        "bidirectional: writes are interleaved "
                        "(first region [{}-{}], then region [{}-{}])".format(
                            first_min, first_max, then_min, then_max
                        )
                    ),
                    "first_write_index": first_min,
                    "then_write_index": then_min,
                })
        else:
            if then_min < first_min:
                violations.append({
                    "label": c.label,
                    "status": "violated",
                    "reason": "then region written at index {} before first region at {}".format(
                        then_min, first_min
                    ),
                    "first_write_index": first_min,
                    "then_write_index": then_min,
                })
    return violations


def _evaluate_invariants(
    result: Dict[str, Any],
    profile: ProfileConfig,
    pre_state: Optional[Dict[str, Any]] = None,
    repo_root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    if not profile.invariants:
        return []
    effective_root = repo_root or REPO_ROOT
    provider_paths = [
        profile.resolve_path(effective_root, provider_path)
        for provider_path in getattr(profile, "invariant_providers", []) or []
    ]
    invariant_fns = resolve_invariants(
        profile.invariants,
        provider_paths=provider_paths,
    )
    signals = result.get("signals")
    elapsed_virtual_time_s: Optional[float] = None
    if isinstance(signals, dict):
        emulated = signals.get("phase2_emulated_s")
        if emulated is not None:
            try:
                elapsed_virtual_time_s = float(emulated)
            except (TypeError, ValueError):
                elapsed_virtual_time_s = None
    # Decode multi-fault sequence from fault_type if present.
    fault_sequence: Optional[List[int]] = None
    fault_type = result.get("fault_type", "")
    if isinstance(fault_type, str) and fault_type.startswith("mf:"):
        try:
            fault_sequence = decode_multi_fault_sequence(fault_type)
        except (ValueError, TypeError):
            fault_sequence = None
    invariant_config = getattr(profile, "invariant_config", {}) or {}
    semantic_stage = invariant_config.get("semantic_state_stage", "final")
    invariant_state = _result_state_payload(result)
    result_signals = result.get("signals") if isinstance(result.get("signals"), dict) else {}
    invariant_signals = dict(result_signals)
    if isinstance(invariant_state, dict):
        invariant_signals.setdefault("semantic_state", invariant_state)
    if semantic_stage == "fault_snapshot":
        staged = result.get("fault_semantic_state")
        if isinstance(staged, dict):
            invariant_state = staged
            # Generic invariants that consume result_signals rather than
            # FaultResult.nvm_state see the same selected stage.
            invariant_signals["semantic_state"] = staged

    fault_result = FaultResult(
        fault_at=int(result.get("fault_at", 0)),
        boot_outcome=str(result.get("boot_outcome", "unknown")),
        boot_slot=result.get("boot_slot"),
        nvm_state=invariant_state,
        raw_log="",
        is_control=bool(result.get("is_control", False)),
        elapsed_virtual_time_s=elapsed_virtual_time_s,
        fault_sequence=fault_sequence,
    )
    boot_register_values = getattr(
        profile.success_criteria, "boot_register_values", None
    ) or None
    violations = run_invariants(
        fault_result,
        invariant_fns,
        pre_state=pre_state,
        write_log=result.get("write_log"),
        partition_ranges=_profile_partition_ranges(profile),
        multi_boot_analysis=result.get("multi_boot_analysis"),
        boot_cycles=result.get("boot_cycles"),
        invariant_config=invariant_config,
        boot_register_values=boot_register_values,
        result_signals=invariant_signals,
        result_dict=result,
    )
    violation_dicts = []
    for v in violations:
        vd: Dict[str, Any] = {
            "name": v.invariant_name,
            "description": v.description,
            "details": v.details,
        }
        if isinstance(v.details, dict) and v.details.get("finding_code"):
            vd["finding"] = v.details.get("finding_code")
        if semantic_stage == "fault_snapshot" and isinstance(result.get("fault_semantic_state"), dict):
            vd["semantic_state_stage"] = "fault_snapshot"
        if fault_sequence is not None:
            vd["fault_sequence"] = fault_sequence
        violation_dicts.append(vd)
    return violation_dicts


def _marker_actually_written(signals: Dict[str, Any]) -> bool:
    """Determine if firmware actually wrote its success marker.

    The 'marker_ok' signal defaults to True when no content criterion is
    configured (no marker address, no image hash).  For metadata_delta
    'when=marker_written' checks we need to know if the marker was
    *actually* written, not just whether content criteria were skipped.
    """
    # If an image hash was computed, use that as the authoritative signal.
    hash_match = str(signals.get("image_hash_match", "") or "").strip().lower()
    if hash_match and hash_match not in ("", "skipped", "unknown"):
        return True
    if hash_match == "unknown":
        return False
    # If a marker address was configured, check whether the actual marker
    # value is non-zero (the default/unconfigured state emits '0x00000000').
    marker_actual = signals.get("marker_actual")
    if marker_actual is not None:
        try:
            val = int(str(marker_actual), 0)
        except (ValueError, TypeError):
            val = 0
        if val != 0:
            return bool(signals.get("marker_ok", False))
    # No content criterion was configured.
    return False


def _evaluate_metadata_delta(
    result: Dict[str, Any],
    profile: ProfileConfig,
) -> List[Dict[str, Any]]:
    """Re-evaluate metadata_delta assertions from result signals.

    The RESC harness attaches metadata_delta_violations during execution,
    but this function can re-check from signals when post-processing
    results outside of Renode (e.g. in unit tests or report regeneration).

    Only runs when the profile has metadata_delta.enabled and the result
    contains metadata_delta signal data.

    Note: metadata_delta is only populated by execute/trace-replay fault
    runners.  State-mode, instruction-skip, and hook-fault runners do not
    capture metadata snapshots, so this function will return [] for those
    result types (no metadata_delta signals present).
    """
    fs = getattr(profile, "fault_sweep", None)
    if fs is None:
        return []
    md = getattr(fs, "metadata_delta", None)
    if md is None or not md.enabled or not md.fields:
        return []
    signals = result.get("signals")
    if not isinstance(signals, dict):
        return []
    md_signals = signals.get("metadata_delta")
    if not isinstance(md_signals, dict):
        return []

    # Determine if firmware actually wrote its success marker.
    # marker_ok defaults to True when no content criterion is configured,
    # which does NOT mean the marker was written.  Check whether a content
    # criterion was actively verified.
    marker_written = _marker_actually_written(signals)
    violations: List[Dict[str, Any]] = []
    for field in md.fields:
        name = field.name
        delta_key = name + "_delta"
        delta = md_signals.get(delta_key)
        if delta is None:
            continue

        when = field.when or "always"
        if when == "marker_written" and not marker_written:
            continue
        if when == "marker_not_written" and marker_written:
            continue

        # Retrieve pre/post values from signals for schema parity with
        # the RESC-side evaluate_metadata_delta which includes them.
        pre_value = md_signals.get(name + "_pre")
        post_value = md_signals.get(name + "_post")

        violation = None
        if field.min_delta is not None and delta < field.min_delta:
            if "boot_count" in name:
                category = "boot_count_suppressed"
            elif "rollback" in name or "version" in name:
                category = "rollback_floor_decreased"
            else:
                category = "metadata_delta_below_min"
            violation = {
                "field": name,
                "address": "0x{:08X}".format(field.address),
                "pre_value": pre_value,
                "post_value": post_value,
                "delta": delta,
                "min_delta": field.min_delta,
                "max_delta": field.max_delta,
                "when": when,
                "finding_category": category,
            }
        elif field.max_delta is not None and delta > field.max_delta:
            if "boot_count" in name:
                category = "boot_count_exhausted"
            else:
                category = "metadata_delta_above_max"
            violation = {
                "field": name,
                "address": "0x{:08X}".format(field.address),
                "pre_value": pre_value,
                "post_value": post_value,
                "delta": delta,
                "min_delta": field.min_delta,
                "max_delta": field.max_delta,
                "when": when,
                "finding_category": category,
            }
        if violation is not None:
            violations.append(violation)
    return violations


def annotate_result_checks(
    results: List[Dict[str, Any]],
    profile: ProfileConfig,
    repo_root: Optional[Path] = None,
) -> None:
    control_result: Optional[Dict[str, Any]] = None
    for candidate in results:
        if candidate.get("is_control"):
            control_result = candidate
    for result in results:
        contract_observation_failures = _evaluate_state_probe_contract(result, profile)
        semantic_failures, observation_failures = _evaluate_semantic_assertions(
            result, profile
        )
        if semantic_failures:
            result["semantic_assertion_failures"] = semantic_failures
        combined_observation_failures = contract_observation_failures + observation_failures
        if combined_observation_failures:
            result["semantic_observation_failures"] = combined_observation_failures
        pre_state = _derive_runtime_pre_state(result, control_result, profile)
        if pre_state is not None:
            result["pre_state"] = pre_state
        invariant_failures = _evaluate_invariants(
            result,
            profile,
            pre_state=pre_state,
            repo_root=repo_root,
        )
        if invariant_failures:
            result["invariant_violations"] = invariant_failures
            evaluation_errors = [
                failure
                for failure in invariant_failures
                if failure.get("name") == "invariant_evaluation_error"
            ]
            if evaluation_errors:
                result["invariant_evaluation_errors"] = evaluation_errors
                result["infrastructure_error"] = True
                result["error_kind"] = "invariant_evaluation_error"
        # Metadata delta: only re-evaluate if not already annotated by RESC.
        if not result.get("metadata_delta_violations"):
            md_failures = _evaluate_metadata_delta(result, profile)
            if md_failures:
                result["metadata_delta_violations"] = md_failures
