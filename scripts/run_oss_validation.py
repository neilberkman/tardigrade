#!/usr/bin/env python3
"""Run OSS validation profiles: read manifest, iterate fault points, check expectations.

Internal orchestrator for the oss-validation.yml GitHub workflow.
Not intended as a user-facing CLI -- use audit_bootloader.py for direct profile runs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fault_classification import _effective_boot_result
from layout_validation import LayoutValidationError, validate_load_plan


PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

LAYOUT_ROBOT_VARIABLES = {
    "BOOTLOADER_ENTRY",
    "BOOT_MARKER_ADDR",
    "BOOT_MARKER_OTHER_VALUE",
    "BOOT_MARKER_VALUE",
    "BOOT_OBSERVATION_TIMEOUT_S",
    "BOOT_POLL_INTERVAL_S",
    "BOOT_WALL_TIMEOUT_S",
    "EXPECTED_CONTROL_SLOT",
    "META_BASE",
    "META_BASE_0",
    "META_BASE_1",
    "META_SIZE",
    "NVM_BASE",
    "NVM_SIZE",
    "OTA_HEADER_SIZE",
    "PRE_BOOT_WRITES",
    "RUN_DURATION",
    "SLOT_A_BASE",
    "SLOT_B_BASE",
    "SLOT_SIZE",
    "WRITE_GRANULARITY",
}


def validate_profile_name(value: Any) -> str:
    """Return a safe profile identifier suitable for result path names."""
    if not isinstance(value, str) or not PROFILE_NAME_RE.fullmatch(value):
        raise ValueError(
            "OSS profile name must match {}: {!r}".format(
                PROFILE_NAME_RE.pattern,
                value,
            )
        )
    return value


def _require_contained(root: Path, candidate: Path, *, label: str) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("{} escapes {}: {}".format(label, root, candidate)) from exc
    return candidate


def source_worktree_path(repo_root: Path, profile_name: str) -> Path:
    """Return the contained worktree path for a validated profile name."""
    name = validate_profile_name(profile_name)
    worktree_root = (repo_root / "results" / "oss_validation" / "worktrees").resolve()
    return _require_contained(
        worktree_root,
        worktree_root / name,
        label="source worktree",
    )


def _worktree_marker_path(source_worktree: Path) -> Path:
    return source_worktree.parent / ".{}.tardigrade-worktree.json".format(
        source_worktree.name
    )


def _read_worktree_marker(source_worktree: Path) -> Dict[str, Any] | None:
    marker = _worktree_marker_path(source_worktree)
    if not marker.is_file():
        return None
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid managed-worktree marker: {}".format(marker)) from exc
    return payload if isinstance(payload, dict) else None


def _write_worktree_marker(source_worktree: Path, source_repo: Path) -> None:
    marker = _worktree_marker_path(source_worktree)
    payload = {
        "version": 1,
        "source_repo": str(source_repo.resolve()),
        "source_worktree": str(source_worktree.resolve()),
    }
    marker.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=".{}-".format(marker.name),
        suffix=".tmp",
        dir=str(marker.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, marker)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _is_registered_worktree(source_repo: Path, source_worktree: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(source_repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    expected = source_worktree.resolve()
    for line in proc.stdout.splitlines():
        if not line.startswith("worktree "):
            continue
        if Path(line[len("worktree "):]).resolve() == expected:
            return True
    return False


class SafeTemplateDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render(value: Any, variables: Dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(SafeTemplateDict(variables))
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    return value


def is_brick(result: Dict[str, Any]) -> bool:
    outcome, _ = _effective_boot_result(result)
    outcome = str(outcome or "unknown").strip().lower()
    return outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}


def _effective_outcome_str(result: Dict[str, Any]) -> str:
    outcome, _ = _effective_boot_result(result)
    return str(outcome or "unknown").strip().lower()


def _format_outcome_span(result: Dict[str, Any]) -> str:
    initial = str(
        result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    ).strip().lower()
    final = _effective_outcome_str(result)
    return final if final == initial else "{} -> {}".format(initial, final)


def git_ref_exists(repo: Path, ref: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "{}^{{commit}}".format(ref)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def ensure_source_worktree(
    repo_root: Path,
    profile_name: str,
    source_checkout: Dict[str, Any],
    source_worktree: Path,
) -> None:
    profile_name = validate_profile_name(profile_name)
    expected_worktree = source_worktree_path(repo_root, profile_name)
    if source_worktree.resolve() != expected_worktree:
        raise ValueError(
            "source worktree must be the managed profile path {}".format(
                expected_worktree
            )
        )
    source_worktree = expected_worktree
    source_repo = _require_contained(
        repo_root,
        repo_root / str(source_checkout["repo"]),
        label="source checkout repo",
    )
    ref = str(source_checkout["ref"])
    fetch_remote = str(source_checkout.get("fetch_remote", "")).strip()

    if not source_repo.is_dir():
        raise RuntimeError("source checkout repo not found: {}".format(source_repo))

    if not git_ref_exists(source_repo, ref):
        if not fetch_remote:
            raise RuntimeError(
                "ref '{}' missing in {} and no fetch_remote configured".format(ref, source_repo)
            )
        proc = subprocess.run(
            ["git", "-C", str(source_repo), "fetch", "--quiet", fetch_remote, ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "git fetch failed for {} {}:\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    fetch_remote, ref, proc.stdout, proc.stderr
                )
            )
        if not git_ref_exists(source_repo, ref):
            raise RuntimeError(
                "ref '{}' still missing after fetch from {}".format(ref, fetch_remote)
            )

    source_worktree.parent.mkdir(parents=True, exist_ok=True)

    if source_worktree.exists():
        marker = _read_worktree_marker(source_worktree)
        expected_marker = {
            "version": 1,
            "source_repo": str(source_repo.resolve()),
            "source_worktree": str(source_worktree.resolve()),
        }
        if marker != expected_marker:
            raise RuntimeError(
                "refusing to remove unowned worktree path: {}".format(source_worktree)
            )
        if not _is_registered_worktree(source_repo, source_worktree):
            raise RuntimeError(
                "refusing to remove path not registered as a git worktree: {}".format(
                    source_worktree
                )
            )
        proc = subprocess.run(
            ["git", "-C", str(source_repo), "worktree", "remove", "--force", str(source_worktree)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or source_worktree.exists():
            raise RuntimeError(
                "git refused to remove managed worktree {}:\n{}".format(
                    source_worktree,
                    proc.stderr,
                )
            )

    proc = subprocess.run(
        [
            "git", "-C", str(source_repo), "worktree", "add", "--detach", "--force",
            str(source_worktree), ref,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git worktree add failed for {} at {}:\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                profile_name, ref, proc.stdout, proc.stderr
            )
        )
    try:
        _write_worktree_marker(source_worktree, source_repo)
    except Exception:
        subprocess.run(
            ["git", "-C", str(source_repo), "worktree", "remove", "--force", str(source_worktree)],
            capture_output=True,
            text=True,
            check=False,
        )
        raise


class BatchProtocolError(RuntimeError):
    """The one-process campaign did not return a complete, ordered result."""


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError("{} must be an integer".format(label))
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("{} must be an integer, got {!r}".format(label, value)) from exc


def _robot_var_map(robot_vars: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for entry in robot_vars:
        key, separator, value = str(entry).partition(":")
        key = key.strip().upper()
        if not separator or not key:
            raise ValueError("invalid Robot variable {!r}".format(entry))
        if key in result:
            raise ValueError("duplicate Robot variable '{}'".format(key))
        result[key] = value
    return result


def _layout_contract(
    rendered: Dict[str, Any],
    robot_vars: List[str],
) -> Tuple[Dict[str, Any], List[str]]:
    """Validate the manifest layout and derive every address Robot receives."""
    layout = rendered.get("layout")
    if not isinstance(layout, dict) or layout.get("version") != 1:
        raise ValueError("profile requires a version 1 layout mapping")

    robot_map = _robot_var_map(robot_vars)
    duplicates = sorted(LAYOUT_ROBOT_VARIABLES.intersection(robot_map))
    if duplicates:
        raise ValueError(
            "layout-owned Robot variables must not be repeated in robot_vars: {}".format(
                ", ".join(duplicates)
            )
        )

    nvm = layout.get("nvm")
    bootloader = layout.get("bootloader")
    slots = layout.get("slots")
    if not isinstance(nvm, dict) or not isinstance(bootloader, dict):
        raise ValueError("layout.nvm and layout.bootloader must be mappings")
    if not isinstance(slots, dict) or set(slots) != {"A", "B"}:
        raise ValueError("layout.slots must define exactly A and B")

    nvm_base = _parse_int(nvm.get("base"), "layout.nvm.base")
    nvm_size = _parse_int(nvm.get("size"), "layout.nvm.size")
    bootloader_base = _parse_int(
        bootloader.get("base"), "layout.bootloader.base"
    )
    write_granularity = _parse_int(
        layout.get("write_granularity"), "layout.write_granularity"
    )
    header_size = _parse_int(
        layout.get("ota_header_size", 0), "layout.ota_header_size"
    )

    normalized_slots: Dict[str, Dict[str, int]] = {}
    for slot_name in ("A", "B"):
        definition = slots[slot_name]
        if not isinstance(definition, dict):
            raise ValueError("layout.slots.{} must be a mapping".format(slot_name))
        normalized_slots[slot_name] = {
            "base": _parse_int(
                definition.get("base"), "layout.slots.{}.base".format(slot_name)
            ),
            "size": _parse_int(
                definition.get("size"), "layout.slots.{}.size".format(slot_name)
            ),
        }
    if normalized_slots["A"]["size"] != normalized_slots["B"]["size"]:
        raise ValueError("generic A/B runner requires equal slot sizes")

    raw_metadata = layout.get("metadata", [])
    if not isinstance(raw_metadata, list) or len(raw_metadata) > 2:
        raise ValueError("layout.metadata must be a list with at most two regions")
    metadata: List[Dict[str, Any]] = []
    for index, definition in enumerate(raw_metadata):
        if not isinstance(definition, dict):
            raise ValueError("layout.metadata[{}] must be a mapping".format(index))
        metadata.append({
            "name": str(definition.get("name", "replica_{}".format(index))),
            "base": _parse_int(
                definition.get("base"), "layout.metadata[{}].base".format(index)
            ),
            "size": _parse_int(
                definition.get("size"), "layout.metadata[{}].size".format(index)
            ),
        })
    if len(metadata) == 2 and metadata[0]["size"] != metadata[1]["size"]:
        raise ValueError("generic A/B runner requires equal metadata replica sizes")

    control = layout.get("control")
    if not isinstance(control, dict):
        raise ValueError("layout.control must be a mapping")
    expected_slot = str(control.get("expected_slot", "")).upper()
    if expected_slot not in {"A", "B"}:
        raise ValueError("layout.control.expected_slot must be A or B")
    marker = control.get("marker")
    if not isinstance(marker, dict):
        raise ValueError("layout.control.marker must be a mapping")
    marker_slot = str(marker.get("address_slot", "")).upper()
    if marker_slot not in normalized_slots:
        raise ValueError("layout.control.marker.address_slot must be A or B")
    marker_offset = _parse_int(
        marker.get("offset"), "layout.control.marker.offset"
    )
    marker_value = _parse_int(
        marker.get("value"), "layout.control.marker.value"
    ) & 0xFFFFFFFF
    marker_other = _parse_int(
        marker.get("other_value"), "layout.control.marker.other_value"
    ) & 0xFFFFFFFF
    if marker_value in {0, 0xFFFFFFFF} or marker_other in {0, 0xFFFFFFFF}:
        raise ValueError("slot marker sentinels must be nonzero and non-erased")
    if marker_value == marker_other:
        raise ValueError("slot marker sentinels must be distinct")
    marker_slot_def = normalized_slots[marker_slot]
    if marker_offset < 0 or marker_offset + 4 > marker_slot_def["size"]:
        raise ValueError("layout.control.marker.offset lies outside its slot")
    marker_address = marker_slot_def["base"] + marker_offset

    expected_image_slot = str(marker.get("expected_image_slot", "")).upper()
    alternate_image_slot = str(marker.get("alternate_image_slot", "")).upper()
    if expected_image_slot not in {"A", "B"} or alternate_image_slot not in {"A", "B"}:
        raise ValueError(
            "layout control marker must name expected_image_slot and alternate_image_slot"
        )
    if expected_image_slot == alternate_image_slot:
        raise ValueError("control marker image slots must be distinct")

    observation = layout.get("observation")
    if not isinstance(observation, dict):
        raise ValueError("layout.observation must be a mapping")
    timeout_s = float(observation.get("emulated_timeout_s", 20.0))
    poll_s = float(observation.get("poll_interval_s", 0.02))
    wall_s = float(observation.get("wall_timeout_s", 180.0))
    if timeout_s <= 0 or poll_s <= 0 or wall_s <= 0:
        raise ValueError("layout observation budgets must be positive")

    raw_pre_boot_writes = layout.get("pre_boot_writes", [])
    if not isinstance(raw_pre_boot_writes, list):
        raise ValueError("layout.pre_boot_writes must be a list")
    pre_boot_writes: List[Dict[str, int]] = []
    nvm_end = nvm_base + nvm_size
    for index, definition in enumerate(raw_pre_boot_writes):
        if not isinstance(definition, dict):
            raise ValueError(
                "layout.pre_boot_writes[{}] must be a mapping".format(index)
            )
        address = _parse_int(
            definition.get("address"),
            "layout.pre_boot_writes[{}].address".format(index),
        )
        value = _parse_int(
            definition.get("value"),
            "layout.pre_boot_writes[{}].value".format(index),
        ) & 0xFFFFFFFF
        if address % 4 or not (nvm_base <= address <= nvm_end - 4):
            raise ValueError(
                "layout.pre_boot_writes[{}] is unaligned or outside NVM".format(index)
            )
        pre_boot_writes.append({"address": address, "value": value})

    metadata_size = metadata[0]["size"] if metadata else 0
    metadata_base_0 = metadata[0]["base"] if metadata else 0
    metadata_base_1 = metadata[1]["base"] if len(metadata) == 2 else metadata_base_0

    contract = {
        "version": 1,
        "nvm": {"base": nvm_base, "size": nvm_size},
        "bootloader": {"base": bootloader_base},
        "slots": normalized_slots,
        "metadata": metadata,
        "pre_boot_writes": pre_boot_writes,
        "write_granularity": write_granularity,
        "ota_header_size": header_size,
        "control": {
            "expected_slot": expected_slot,
            "marker": {
                "address": marker_address,
                "offset": marker_offset,
                "value": marker_value,
                "other_value": marker_other,
                "expected_image_slot": expected_image_slot,
                "alternate_image_slot": alternate_image_slot,
            },
        },
        "observation": {
            "emulated_timeout_s": timeout_s,
            "poll_interval_s": poll_s,
            "wall_timeout_s": wall_s,
        },
    }

    derived = [
        "NVM_BASE:0x{:08X}".format(nvm_base),
        "NVM_SIZE:0x{:X}".format(nvm_size),
        "BOOTLOADER_ENTRY:0x{:08X}".format(bootloader_base),
        "WRITE_GRANULARITY:{}".format(write_granularity),
        "SLOT_A_BASE:0x{:08X}".format(normalized_slots["A"]["base"]),
        "SLOT_B_BASE:0x{:08X}".format(normalized_slots["B"]["base"]),
        "SLOT_SIZE:0x{:X}".format(normalized_slots["A"]["size"]),
        "META_BASE:0x{:08X}".format(metadata_base_0),
        "META_BASE_0:0x{:08X}".format(metadata_base_0),
        "META_BASE_1:0x{:08X}".format(metadata_base_1),
        "META_SIZE:0x{:X}".format(metadata_size),
        "OTA_HEADER_SIZE:0x{:X}".format(header_size),
        "EXPECTED_CONTROL_SLOT:{}".format(expected_slot),
        "BOOT_MARKER_ADDR:0x{:08X}".format(marker_address),
        "BOOT_MARKER_VALUE:0x{:08X}".format(marker_value),
        "BOOT_MARKER_OTHER_VALUE:0x{:08X}".format(marker_other),
        "BOOT_OBSERVATION_TIMEOUT_S:{}".format(timeout_s),
        "BOOT_POLL_INTERVAL_S:{}".format(poll_s),
        "BOOT_WALL_TIMEOUT_S:{}".format(wall_s),
    ]
    if pre_boot_writes:
        derived.append(
            "PRE_BOOT_WRITES:{}".format(
                ",".join(
                    "0x{:08X}=0x{:08X}".format(item["address"], item["value"])
                    for item in pre_boot_writes
                )
            )
        )
    return contract, derived


def _resolve_robot_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else repo_root / path


def validate_rendered_load_plan(
    repo_root: Path,
    rendered: Dict[str, Any],
    robot_vars: List[str],
    contract: Dict[str, Any],
) -> Dict[str, Any]:
    """Fail before Renode if any real write can damage the bootloader."""
    robot_map = _robot_var_map(robot_vars)
    bootloader_value = robot_map.get("BOOTLOADER_ELF")
    if not bootloader_value:
        raise LayoutValidationError("BOOTLOADER_ELF is required")
    bootloader_elf = _resolve_robot_path(repo_root, bootloader_value)

    loads: List[Dict[str, Any]] = []
    image_paths: Dict[str, Path] = {}
    for slot_name, top_level_key in (
        ("A", "slot_a_image_file"),
        ("B", "slot_b_image_file"),
    ):
        raw_path = rendered.get(top_level_key)
        if not raw_path:
            raise LayoutValidationError("{} is required".format(top_level_key))
        path = _resolve_robot_path(repo_root, str(raw_path))
        image_paths[slot_name] = path
        loads.append({
            "name": "slot {} image".format(slot_name),
            "path": str(path),
            "address": contract["slots"][slot_name]["base"],
            "slot": slot_name,
        })

    plan = {
        "version": 1,
        "nvm": dict(contract["nvm"]),
        "bootloader": {"elf": str(bootloader_elf)},
        "slots": {
            "A": dict(contract["slots"]["A"], write_full=True),
            "B": dict(contract["slots"]["B"], write_full=True),
        },
        "metadata": list(contract["metadata"]),
        "loads": loads,
    }
    normalized = validate_load_plan(plan)

    for index, write in enumerate(contract.get("pre_boot_writes", [])):
        start = write["address"]
        end = start + 4
        for boot_interval in normalized["bootloader"]:
            if start < boot_interval["end"] and boot_interval["start"] < end:
                raise LayoutValidationError(
                    "pre-boot write {} [0x{:x}, 0x{:x}) overlaps {} [0x{:x}, 0x{:x})".format(
                        index,
                        start,
                        end,
                        boot_interval["name"],
                        boot_interval["start"],
                        boot_interval["end"],
                    )
                )

    marker = contract["control"]["marker"]
    marker_offset = marker["offset"]
    for slot_name, expected in (
        (marker["expected_image_slot"], marker["value"]),
        (marker["alternate_image_slot"], marker["other_value"]),
    ):
        image = image_paths[slot_name]
        data = image.read_bytes()
        if marker_offset + 4 > len(data):
            raise LayoutValidationError(
                "marker offset 0x{:X} lies outside {}".format(marker_offset, image)
            )
        actual = int.from_bytes(data[marker_offset:marker_offset + 4], "little")
        if actual != expected:
            raise LayoutValidationError(
                "{} marker at offset 0x{:X} is 0x{:08X}, expected 0x{:08X}".format(
                    image, marker_offset, actual, expected
                )
            )

    return normalized


def _validate_batch_payload(
    payload: Any,
    fault_points: List[int],
) -> Dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise BatchProtocolError("batch result must be a version 1 object")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise BatchProtocolError("batch result must contain the clean control")
    control = results[0]
    if not isinstance(control, dict):
        raise BatchProtocolError("clean control result must be an object")
    if (
        control.get("fault_at") != -1
        or control.get("is_control") is not True
        or control.get("fault_injected") is not False
    ):
        raise BatchProtocolError("first result is not a clean, unfaulted control")

    control_passed = payload.get("control_passed") is True
    if not control_passed:
        if payload.get("aborted") is not True or len(results) != 1:
            raise BatchProtocolError(
                "failed control must abort before every fault point"
            )
        return payload

    if payload.get("aborted"):
        raise BatchProtocolError(
            "campaign aborted after a passing control: {}".format(
                payload.get("abort_reason") or "unknown reason"
            )
        )
    expected = [-1] + list(fault_points)
    observed = [result.get("fault_at") for result in results if isinstance(result, dict)]
    if len(results) != len(expected) or observed != expected:
        raise BatchProtocolError(
            "batch result order/cardinality mismatch: expected {}, observed {}".format(
                expected, observed
            )
        )
    for index, result in enumerate(results[1:], start=1):
        if not isinstance(result, dict) or result.get("is_control") is not False:
            raise BatchProtocolError("fault result {} is malformed".format(index))
    return payload


def run_fault_batch(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir: Path,
    total_writes: int,
    wall_timeout_s: float,
) -> Dict[str, Any]:
    """Run control plus all fault points in one Renode process."""
    batch_dir = work_dir / "batch"
    batch_dir.mkdir(parents=True, exist_ok=True)
    result_file = batch_dir / "result.json"
    try:
        result_file.unlink()
    except FileNotFoundError:
        pass
    bundle_dir = work_dir / ".dotnet_bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    ordered_points = [-1] + list(fault_points)
    cmd = [
        renode_test,
        "--renode-config", str(work_dir / "renode.config"),
        str(repo_root / robot_suite),
        "--results-dir", str(batch_dir / "robot"),
        "--variable", "FAULT_AT:-1",
        "--variable", "FAULT_POINTS_CSV:{}".format(
            ",".join(str(point) for point in ordered_points)
        ),
        "--variable", "TOTAL_WRITES:{}".format(total_writes),
        "--variable", "RESULT_FILE:{}".format(result_file),
    ]
    for robot_var in robot_vars:
        cmd.extend(["--variable", robot_var])

    env = os.environ.copy()
    env.setdefault("DOTNET_BUNDLE_EXTRACT_BASE_DIR", str(bundle_dir))
    process_timeout = max(120.0, 120.0 + len(ordered_points) * wall_timeout_s)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=process_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BatchProtocolError(
            "Renode campaign exceeded {:.1f}s process budget".format(process_timeout)
        ) from exc

    if not result_file.exists():
        raise BatchProtocolError(
            "Renode campaign produced no result (rc={}): {}".format(
                proc.returncode, (proc.stderr or "")[-1000:]
            )
        )
    try:
        payload = json.loads(result_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BatchProtocolError("Renode campaign result is invalid JSON") from exc
    payload = _validate_batch_payload(payload, fault_points)
    if proc.returncode != 0:
        raise BatchProtocolError(
            "Renode campaign failed after writing a result (rc={}): {}".format(
                proc.returncode, (proc.stderr or "")[-1000:]
            )
        )
    return payload


def run_profile(
    repo_root: Path, renode_test: str, profile: Dict[str, Any],
    variables: Dict[str, str], workers: int, skip_setup: bool,
) -> Dict[str, Any]:
    if workers != 1:
        raise ValueError(
            "--workers must be 1: each profile now runs as one isolated Renode batch"
        )
    name = validate_profile_name(profile["name"])
    variables = dict(variables)
    source_checkout = render(profile.get("source_checkout"), variables)
    source_worktree: Path | None = None
    if source_checkout:
        source_worktree = source_worktree_path(repo_root, name)
        variables["source_worktree"] = str(source_worktree)
    rendered = render(profile, variables)
    robot_suite = str(rendered.get("robot_suite", "tests/generic_fault_point.robot"))
    robot_vars = [str(rv) for rv in rendered.get("robot_vars", [])]
    total_writes = int(rendered.get("total_writes", 28672))
    if total_writes <= 0:
        raise ValueError("total_writes must be positive")

    for key in ("slot_a_image_file", "slot_b_image_file",
                "evaluation_mode", "boot_mode"):
        val = rendered.get(key)
        if val is not None:
            robot_vars.append("{}:{}".format(key.upper(), val))
    contract, derived_layout_vars = _layout_contract(rendered, robot_vars)
    robot_vars.extend(derived_layout_vars)

    source_worktree_ready = False
    if not skip_setup:
        for raw_cmd in (rendered.get("setup_commands") or []):
            cmd = str(render(raw_cmd, variables))
            if (
                source_checkout
                and source_worktree is not None
                and not source_worktree_ready
                and str(source_worktree) in cmd
            ):
                ensure_source_worktree(repo_root, name, source_checkout, source_worktree)
                source_worktree_ready = True
            print("  setup>> {}".format(cmd), file=sys.stderr)
            proc = subprocess.run(["/bin/bash", "-lc", cmd], cwd=str(repo_root), check=False)
            if proc.returncode != 0:
                raise RuntimeError("setup failed (rc={}): {}".format(proc.returncode, cmd))
    elif source_checkout and source_worktree is not None:
        ensure_source_worktree(repo_root, name, source_checkout, source_worktree)

    # Resolve and inspect the real built artifacts immediately before Renode
    # loads them.  The guard uses PT_LOAD memory extents rather than the ELF
    # file's size and rejects any slot/metadata write that can touch one.
    validate_rendered_load_plan(repo_root, rendered, robot_vars, contract)

    # Build fault point list from profile range/step.
    fault_range = str(rendered.get("fault_range", "0:{}".format(total_writes - 1)))
    fault_step = int(rendered.get("fault_step", 4000))
    if fault_step <= 0:
        raise ValueError("fault_step must be positive")
    start_s, end_s = fault_range.split(":", 1)
    start, end = int(start_s), int(end_s)
    if start < 0 or end < start or end >= total_writes:
        raise ValueError(
            "fault_range must be an inclusive subset of 0:{}; got {}".format(
                total_writes - 1,
                fault_range,
            )
        )
    fault_points = list(range(start, end + 1, fault_step))
    if end not in fault_points:
        fault_points.append(end)

    temp_ctx = tempfile.TemporaryDirectory(prefix="oss_val_{}_".format(name))
    work_dir = Path(temp_ctx.name)
    print(
        "  one-process batch: control + {} fault point(s)".format(len(fault_points)),
        file=sys.stderr,
    )
    campaign_error: str | None = None
    payload: Dict[str, Any] = {}
    try:
        payload = run_fault_batch(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            fault_points=fault_points,
            robot_vars=robot_vars,
            work_dir=work_dir,
            total_writes=total_writes,
            wall_timeout_s=contract["observation"]["wall_timeout_s"],
        )
    except BatchProtocolError as exc:
        campaign_error = str(exc)
    finally:
        temp_ctx.cleanup()

    results = list(payload.get("results") or [])

    # Evaluate against expectations.
    expect = rendered.get("expect") or {}
    control = [r for r in results if r.get("is_control")]
    faulted = [r for r in results if not r.get("is_control")]
    bricks = sum(1 for r in faulted if is_brick(r))
    issues = sum(1 for r in faulted if _effective_outcome_str(r) != "success")
    incomplete_outcomes = {
        "",
        "unknown",
        "infra_error",
        "infrastructure_error",
        "timeout",
        "skipped",
    }
    incomplete_results = [
        r
        for r in results
        if (
            _effective_outcome_str(r) in incomplete_outcomes
            or r.get("error")
            or type(r.get("fault_injected")) is not bool
            or (
                not r.get("is_control")
                and r.get("fault_injected") is not True
            )
            or (
                r.get("is_control")
                and r.get("fault_injected") is not False
            )
        )
    ]
    errors = len(incomplete_results) + (1 if campaign_error else 0)
    brick_rate = (float(bricks) / len(faulted)) if faulted else 0.0
    issue_rate = (float(issues) / len(faulted)) if faulted else 0.0
    failures: List[str] = []

    if campaign_error:
        failures.append("campaign infrastructure failure: {}".format(campaign_error))

    if payload.get("aborted"):
        failures.append(
            "campaign aborted before fault dispatch: {}".format(
                payload.get("abort_reason") or "clean control failed"
            )
        )

    if len(control) != 1:
        failures.append("exactly one clean control is required")
    elif (
        payload.get("control_passed") is not True
        or control[0].get("control_passed") is not True
        or _effective_outcome_str(control[0]) != "success"
    ):
        failures.append(
            "control failed: {}".format(_format_outcome_span(control[0]))
        )

    if incomplete_results:
        failures.append(
            "{} run(s) produced incomplete or infrastructure results".format(
                len(incomplete_results)
            )
        )

    bricks_max = expect.get("bricks_max")
    if bricks_max is not None and bricks > int(bricks_max):
        failures.append("bricks={} exceeds max {}".format(bricks, bricks_max))
    bricks_min = expect.get("bricks_min")
    if bricks_min is not None and bricks < int(bricks_min):
        failures.append("bricks={} below min {}".format(bricks, bricks_min))

    issues_max = expect.get("issues_max")
    if issues_max is not None and issues > int(issues_max):
        failures.append("issues={} exceeds max {}".format(issues, issues_max))
    issues_min = expect.get("issues_min")
    if issues_min is not None and issues < int(issues_min):
        failures.append("issues={} below min {}".format(issues, issues_min))

    return {
        "profile": name, "passed": len(failures) == 0,
        "faulted_runs": len(faulted), "bricks": bricks,
        "brick_rate": round(brick_rate, 4), "issues": issues,
        "issue_rate": round(issue_rate, 4), "infra_errors": errors,
        "failures": failures, "results": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="OSS validation profile runner")
    p.add_argument("--manifest", default="docs/oss_validation_profiles.json")
    p.add_argument("--profile", default=None, help="Run a single profile by name")
    p.add_argument("--renode-test", default=os.environ.get("RENODE_TEST", "renode-test"))
    p.add_argument("--output", default=None, help="Output summary JSON path")
    p.add_argument("--list", action="store_true", dest="list_profiles")
    p.add_argument("--skip-setup", action="store_true")
    p.add_argument("--workers", type=int, default=1)
    args = p.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = (repo_root / manifest_path).resolve()

    profiles = json.loads(manifest_path.read_text(encoding="utf-8"))["profiles"]
    profile_names = [validate_profile_name(profile.get("name")) for profile in profiles]
    if len(set(profile_names)) != len(profile_names):
        raise ValueError("OSS validation manifest contains duplicate profile names")

    if args.list_profiles:
        for prof in profiles:
            print("{:<40s} {}".format(prof["name"], prof.get("description", "")))
        return 0

    renode_test = args.renode_test
    if not os.path.isabs(renode_test):
        resolved = shutil.which(renode_test)
        if resolved is None:
            print("ERROR: renode-test '{}' not found in PATH".format(renode_test), file=sys.stderr)
            return 2
        renode_test = resolved

    if args.profile:
        selected = [p for p in profiles if p["name"] == args.profile]
        if not selected:
            print("ERROR: profile '{}' not found".format(args.profile), file=sys.stderr)
            return 2
    else:
        selected = profiles

    all_results: List[Dict[str, Any]] = []
    for profile in selected:
        name = profile["name"]
        variables = {"repo_root": str(repo_root), "variant_name": name}
        print("--- {} ---".format(name), file=sys.stderr)
        entry = run_profile(repo_root, renode_test, profile, variables, args.workers, args.skip_setup)
        all_results.append(entry)
        status = "PASS" if entry["passed"] else "FAIL"
        print("  {} bricks={}/{} issues={}/{} {}".format(
            status, entry["bricks"], entry["faulted_runs"],
            entry["issues"], entry["faulted_runs"],
            " ".join(entry["failures"])), file=sys.stderr)

    all_passed = all(r["passed"] for r in all_results)
    summary = {
        "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "all_passed": all_passed,
        "profiles": [{k: v for k, v in r.items() if k != "results"} for r in all_results],
        "detailed_results": all_results,
    }

    out_path = Path(args.output) if args.output else (repo_root / "results" / "oss_validation" / "summary.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print("wrote {}".format(out_path), file=sys.stderr)

    compact = {k: v for k, v in summary.items() if k != "detailed_results"}
    print(json.dumps(compact, indent=2, sort_keys=True))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
