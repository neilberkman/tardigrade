#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate a persisted TF-M flash snapshot with the normal Tardigrade path.

This module is deliberately a post-run evaluator.  It does not implement or
simulate TF-M's update transition and it does not inject a fault.  The input
is a byte-for-byte flash dump produced by an emulator or target, plus a small
JSON profile describing the compiled slot geometry.  The existing TF-M probe
parses trailer state and the normal invariant registry evaluates it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence


_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _ROOT / "scripts"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from fault_inject import FaultResult  # noqa: E402
from invariants import resolve_invariants, run_invariants  # noqa: E402
from targets.tf_m_bl2 import probe  # noqa: E402


class SnapshotBus:
    """Small Renode-compatible reader over a persisted flat memory dump."""

    def __init__(self, data: bytes, address_base: int = 0) -> None:
        self._data = data
        self._base = int(address_base)

    def ReadBytes(self, address: int, size: int):  # noqa: N802 - Renode API
        start = int(address) - self._base
        end = start + int(size)
        if start < 0 or end > len(self._data):
            raise ValueError(
                "snapshot read outside dump: address=0x{:X} size=0x{:X}".format(
                    int(address), int(size)
                )
            )
        return self._data[start:end]


class SnapshotMonitor:
    """Renode monitor-variable adapter backed by profile slot geometry."""

    def __init__(self, variables: Mapping[str, Any]) -> None:
        self._variables = dict(variables)

    def GetVariable(self, name: str):  # noqa: N802 - Renode API
        if name not in self._variables:
            raise KeyError(name)
        return self._variables[name]


def _integer(value: Any) -> int:
    return int(str(value), 0) if isinstance(value, str) else int(value)


def _monitor_variables(
    profile: Mapping[str, Any], snapshot_base: int, snapshot_size: int
) -> Dict[str, int]:
    slots = profile.get("slots")
    if not isinstance(slots, Mapping):
        raise ValueError("profile.slots must be a mapping")
    variables: Dict[str, int] = {
        "mcuboot_trailer_align": _integer(profile.get("trailer_align", 8)),
    }
    if variables["mcuboot_trailer_align"] <= 0:
        raise ValueError("profile.trailer_align must be positive")
    names = {
        "secure_exec": "slot_s_exec",
        "secure_staging": "slot_s_staging",
        "ns_exec": "slot_ns_exec",
        "ns_staging": "slot_ns_staging",
    }
    for slot_name, variable_prefix in names.items():
        slot = slots.get(slot_name)
        if not isinstance(slot, Mapping):
            raise ValueError("profile.slots.{} must be a mapping".format(slot_name))
        base = _integer(slot["base"])
        size = _integer(slot["size"])
        if base < snapshot_base or size < 16 + variables["mcuboot_trailer_align"]:
            raise ValueError("invalid geometry for profile.slots.{}".format(slot_name))
        if base + size > snapshot_base + snapshot_size:
            raise ValueError(
                "profile.slots.{} lies outside the persisted snapshot".format(slot_name)
            )
        variables[variable_prefix + "_base"] = base
        variables[variable_prefix + "_size"] = size
    ranges = sorted(
        (variables[p + "_base"], variables[p + "_base"] + variables[p + "_size"], name)
        for name, p in names.items()
    )
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            raise ValueError(
                "profile slot ranges overlap: {} and {}".format(
                    previous[2], current[2]
                )
            )
    return variables


def _violation_json(violation: Any) -> Dict[str, Any]:
    return {
        "name": violation.invariant_name,
        "description": violation.description,
        "details": violation.details,
    }


def evaluate_snapshot(snapshot_path: Path, profile_path: Path) -> Dict[str, Any]:
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(profile, Mapping):
        raise ValueError("snapshot profile must be a JSON object")
    data = snapshot_path.read_bytes()
    address_base = _integer(profile.get("address_base", 0))
    if address_base < 0:
        raise ValueError("profile.address_base must be non-negative")
    variables = _monitor_variables(profile, address_base, len(data))
    expected_magic = profile.get("expected_primary_magic")
    if expected_magic is not None and (
        not isinstance(expected_magic, Sequence)
        or isinstance(expected_magic, (str, bytes))
        or len(expected_magic) != 2
    ):
        raise ValueError("expected_primary_magic must contain two states")
    state = probe.collect_state(
        bus=SnapshotBus(data, address_base),
        monitor=SnapshotMonitor(variables),
        context={
            "stage": "post_fault_snapshot",
            "fault_injected": True,
        },
    )
    if expected_magic is not None:
        actual_magic = [
            state["slots"][name]["magic_state"]
            for name in ("secure_exec", "ns_exec")
        ]
        if actual_magic != list(expected_magic):
            raise ValueError(
                "primary trailer magic precondition failed: expected {}, got {}".format(
                    list(expected_magic), actual_magic
                )
            )
    result = FaultResult(
        fault_at=-1,
        boot_outcome=str(profile.get("boot_outcome", "not_evaluated")),
        boot_slot=None,
        nvm_state=state,
        raw_log="",
    )
    providers = profile.get("invariant_providers", [])
    specs_raw = profile.get("invariants", [])
    if not isinstance(providers, list) or any(
        not isinstance(item, str) or not item.strip() for item in providers
    ):
        raise ValueError("invariant_providers must be a list of non-empty strings")
    if not isinstance(specs_raw, list) or not specs_raw or any(
        not isinstance(item, str) or not item.strip() for item in specs_raw
    ):
        raise ValueError("invariants must be a non-empty list of strings")
    config = profile.get("invariant_config") or {}
    if not isinstance(config, Mapping):
        raise ValueError("invariant_config must be a mapping")
    provider_paths = []
    for provider in providers:
        provider_path = Path(str(provider))
        if not provider_path.is_absolute():
            provider_path = _ROOT / provider_path
        provider_paths.append(str(provider_path))
    specs = [str(item) for item in specs_raw]
    checks = resolve_invariants(specs, provider_paths=provider_paths)
    violations = run_invariants(result, invariants=checks, invariant_config=config)
    return {
        "source": "persisted_flash_snapshot",
        "snapshot": str(snapshot_path),
        "snapshot_size": len(data),
        "snapshot_sha256": hashlib.sha256(data).hexdigest(),
        "profile": str(profile_path),
        "semantic_state": state,
        "invariants_run": [fn.__name__ for fn in checks],
        "invariant_violations": [_violation_json(v) for v in violations],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = evaluate_snapshot(args.snapshot, args.profile)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        output = {
            "source": "persisted_flash_snapshot",
            "snapshot": str(args.snapshot),
            "profile": str(args.profile),
            "evaluation_error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
            "invariant_violations": [],
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if output["invariant_violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
