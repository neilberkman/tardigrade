"""Calibration result caching for tardigrade.

Profiles sharing the same bootloader ELF, images, and fault configuration
produce identical calibration results.  This module saves and loads
calibration artifacts (write/erase counts, trace files) so repeated
calibrations can be skipped.
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from renode_runner import CalibrationResult


def _file_sha256(path: str) -> str:
    """Return hex SHA-256 digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_binary_b64(path: Optional[str]) -> Optional[str]:
    """Read a binary file and return base64-encoded contents, or None."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def _write_binary_b64(b64_data: Optional[str], dest: str) -> Optional[str]:
    """Write base64-decoded data to *dest*, return the path or None."""
    if not b64_data:
        return None
    data = base64.b64decode(b64_data)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def _normalize_cache_value(value: Any) -> Any:
    """Convert configuration objects to deterministic JSON-compatible data."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, enum.Enum):
        return _normalize_cache_value(value.value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalize_cache_value(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {
            str(key): _normalize_cache_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_cache_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_normalize_cache_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if hasattr(value, "__dict__"):
        return _normalize_cache_value({
            key: item
            for key, item in vars(value).items()
            if not key.startswith("_") and not callable(item)
        })
    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    if slots:
        return _normalize_cache_value({
            slot: getattr(value, slot)
            for slot in slots
            if not slot.startswith("_") and hasattr(value, slot)
        })
    raise TypeError(
        "unsupported calibration cache value type: {}".format(type(value).__name__)
    )


def _content_digests(files: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Hash named referenced files without coupling the key to checkout paths."""
    return {
        str(name): _file_sha256(path)
        for name, path in sorted((files or {}).items())
    }


def compute_cache_key(
    *,
    bootloader_elf: str,
    images: Dict[str, str],
    fault_types: List[str],
    flash_backend: Optional[str],
    memory_slots: Dict[str, Any],
    pre_boot_state: List[Any],
    hash_bypass_symbols: List[str],
    write_granularity: int,
    platform_files: Optional[Dict[str, str]] = None,
    setup_files: Optional[Dict[str, str]] = None,
    hook_files: Optional[Dict[str, str]] = None,
    entry_point: Optional[int] = None,
    image_load_addresses: Optional[Dict[str, int]] = None,
    tool_versions: Optional[Dict[str, str]] = None,
    runtime_config: Optional[Dict[str, Any]] = None,
) -> str:
    """Compute a deterministic cache key from calibration inputs.

    Returns a hex SHA-256 digest.
    """
    payload = {
        "key_format": 2,
        "bootloader_elf_sha256": _file_sha256(bootloader_elf),
        "image_sha256": _content_digests(images),
        "fault_types": sorted(fault_types),
        "flash_backend": flash_backend,
        "memory_slots": _normalize_cache_value(memory_slots),
        "pre_boot_state": _normalize_cache_value(pre_boot_state),
        "hash_bypass_symbols": sorted(hash_bypass_symbols),
        "write_granularity": write_granularity,
        "platform_file_sha256": _content_digests(platform_files),
        "setup_file_sha256": _content_digests(setup_files),
        "hook_file_sha256": _content_digests(hook_files),
        "entry_point": entry_point,
        "image_load_addresses": _normalize_cache_value(image_load_addresses or {}),
        "tool_versions": _normalize_cache_value(tool_versions or {}),
        "runtime_config": _normalize_cache_value(runtime_config or {}),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def save_calibration(
    path: str,
    cal: CalibrationResult,
    cache_key: str,
) -> None:
    """Save calibration result and trace files to a JSON cache file."""
    payload: Dict[str, Any] = {
        "cache_key": cache_key,
        "version": 1,
        "total_writes": cal.total_writes,
        "total_erases": cal.total_erases,
        "calibration_exec_hash": cal.calibration_exec_hash,
        "calibration_boot_outcome": cal.calibration_boot_outcome,
        "stop_reason": cal.stop_reason,
        "emulated_s": cal.emulated_s,
        "elapsed_s": cal.elapsed_s,
        "pc": cal.pc,
        "setup_writes": cal.setup_writes,
        "total_i2c_transactions": cal.total_i2c_transactions,
        "total_otp_blows": cal.total_otp_blows,
        "trace_file_b64": _read_binary_b64(cal.trace_file),
        "erase_trace_file_b64": _read_binary_b64(cal.erase_trace_file),
        "trace_file_bin_b64": _read_binary_b64(cal.trace_file_bin),
        "erase_trace_file_bin_b64": _read_binary_b64(cal.erase_trace_file_bin),
    }
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=".{}-".format(destination.name),
            suffix=".tmp",
            dir=str(destination.parent),
            delete=False,
        ) as stream:
            temp_name = stream.name
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, destination)
        temp_name = None
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def load_calibration(
    path: str,
    cache_key: str,
    work_dir: Path,
) -> Optional[CalibrationResult]:
    """Load a cached calibration result if the cache key matches.

    Trace files are restored to *work_dir*.  Returns None on cache miss
    (file missing or key mismatch).
    """
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if payload.get("cache_key") != cache_key:
        return None

    # Restore trace files into work_dir
    trace_dir = work_dir / "cached_traces"
    trace_dir.mkdir(parents=True, exist_ok=True)

    trace_file = _write_binary_b64(
        payload.get("trace_file_b64"),
        str(trace_dir / "write_trace.csv"),
    )
    erase_trace_file = _write_binary_b64(
        payload.get("erase_trace_file_b64"),
        str(trace_dir / "erase_trace.csv"),
    )
    trace_file_bin = _write_binary_b64(
        payload.get("trace_file_bin_b64"),
        str(trace_dir / "write_trace.bin"),
    )
    erase_trace_file_bin = _write_binary_b64(
        payload.get("erase_trace_file_bin_b64"),
        str(trace_dir / "erase_trace.bin"),
    )

    return CalibrationResult(
        total_writes=payload["total_writes"],
        total_erases=payload["total_erases"],
        trace_file=trace_file,
        erase_trace_file=erase_trace_file,
        trace_file_bin=trace_file_bin,
        erase_trace_file_bin=erase_trace_file_bin,
        calibration_exec_hash=payload.get("calibration_exec_hash"),
        calibration_boot_outcome=payload.get("calibration_boot_outcome"),
        stop_reason=payload.get("stop_reason"),
        emulated_s=payload.get("emulated_s"),
        elapsed_s=payload.get("elapsed_s"),
        pc=payload.get("pc"),
        setup_writes=payload.get("setup_writes", 0),
        total_i2c_transactions=payload.get("total_i2c_transactions", 0),
        total_otp_blows=payload.get("total_otp_blows", 0),
    )
