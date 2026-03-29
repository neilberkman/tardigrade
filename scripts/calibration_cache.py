"""Calibration result caching for tardigrade.

Profiles sharing the same bootloader ELF, images, and fault configuration
produce identical calibration results.  This module saves and loads
calibration artifacts (write/erase counts, trace files) so repeated
calibrations can be skipped.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
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
) -> str:
    """Compute a deterministic cache key from calibration inputs.

    Returns a hex SHA-256 digest.
    """
    h = hashlib.sha256()

    # ELF file content
    h.update(b"elf:")
    h.update(_file_sha256(bootloader_elf).encode())

    # Image file contents (sorted by key for determinism)
    for key in sorted(images):
        h.update("image:{}:".format(key).encode())
        h.update(_file_sha256(images[key]).encode())

    # Fault types
    h.update(b"fault_types:")
    h.update(",".join(sorted(fault_types)).encode())

    # Flash backend
    h.update(b"flash_backend:")
    h.update((flash_backend or "").encode())

    # Memory slot geometry (sorted by slot name)
    h.update(b"memory_slots:")
    for name in sorted(memory_slots):
        slot = memory_slots[name]
        base = slot.get("base", 0) if isinstance(slot, dict) else getattr(slot, "base", 0)
        size = slot.get("size", 0) if isinstance(slot, dict) else getattr(slot, "size", 0)
        h.update("{}:{}:{}".format(name, base, size).encode())

    # Pre-boot state
    h.update(b"pre_boot_state:")
    for pbs in pre_boot_state:
        if hasattr(pbs, "address") and hasattr(pbs, "u32"):
            h.update("{}:{}".format(pbs.address, pbs.u32).encode())
        elif isinstance(pbs, dict):
            h.update("{}:{}".format(pbs.get("address", 0), pbs.get("u32", 0)).encode())

    # Hash bypass symbols
    h.update(b"hash_bypass:")
    h.update(",".join(sorted(hash_bypass_symbols)).encode())

    # Write granularity
    h.update(b"write_gran:")
    h.update(str(write_granularity).encode())

    return h.hexdigest()


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
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


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
