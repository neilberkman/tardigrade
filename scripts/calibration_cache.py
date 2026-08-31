"""Calibration result caching for tardigrade.

Profiles sharing the same bootloader ELF, images, and fault configuration
produce identical calibration results.  This module saves and loads
calibration artifacts (write/erase counts, trace files) so repeated
calibrations can be skipped.
"""

from __future__ import annotations

import base64
import csv
import dataclasses
import enum
import hashlib
import io
import json
import math
import os
import re
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from renode_runner import CalibrationResult


CACHE_VERSION = 2
MAX_CACHE_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_COUNTER = 100_000_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CACHE_FIELDS = {
    "cache_key",
    "version",
    "total_writes",
    "total_erases",
    "calibration_exec_hash",
    "calibration_boot_outcome",
    "stop_reason",
    "emulated_s",
    "elapsed_s",
    "pc",
    "setup_writes",
    "total_i2c_transactions",
    "total_otp_blows",
    "trace_file_b64",
    "trace_file_sha256",
    "erase_trace_file_b64",
    "erase_trace_file_sha256",
    "trace_file_bin_b64",
    "trace_file_bin_sha256",
    "erase_trace_file_bin_b64",
    "erase_trace_file_bin_sha256",
}


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
    if not isinstance(b64_data, str):
        raise ValueError("cached artifact must be a base64 string")
    try:
        data = base64.b64decode(b64_data, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("cached artifact is not valid base64") from exc
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("cached artifact exceeds size limit")
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def _artifact_payload(path: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    encoded = _read_binary_b64(path)
    if encoded is None:
        return None, None
    data = base64.b64decode(encoded, validate=True)
    return encoded, hashlib.sha256(data).hexdigest()


def _decode_artifact(payload: Dict[str, Any], field: str) -> Optional[bytes]:
    encoded = payload[field]
    expected_digest = payload[field.replace("_b64", "_sha256")]
    if encoded is None:
        if expected_digest is not None:
            raise ValueError("{} digest exists without artifact".format(field))
        return None
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("{} must be a non-empty base64 string or null".format(field))
    if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(
        expected_digest
    ):
        raise ValueError("{} digest must be lowercase SHA-256".format(field))
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("{} is not valid base64".format(field)) from exc
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("{} exceeds size limit".format(field))
    actual_digest = hashlib.sha256(data).hexdigest()
    if actual_digest != expected_digest:
        raise ValueError("{} digest mismatch".format(field))
    return data


def _counter(payload: Dict[str, Any], name: str) -> int:
    value = payload[name]
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_COUNTER
    ):
        raise ValueError("{} must be a bounded non-negative integer".format(name))
    return value


def _parse_trace_csv(
    data: bytes,
    *,
    name: str,
    header: list[str],
) -> list[tuple[int, ...]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("{} must be UTF-8 CSV".format(name)) from exc
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        actual_header = next(reader)
    except StopIteration as exc:
        raise ValueError("{} is empty".format(name)) from exc
    if actual_header != header:
        raise ValueError("{} has an unexpected header".format(name))
    rows: list[tuple[int, ...]] = []
    previous_index = 0
    for line_number, row in enumerate(reader, start=2):
        if len(row) != len(header):
            raise ValueError("{} row {} has wrong column count".format(name, line_number))
        try:
            values = tuple(int(value.strip(), 0) for value in row)
        except ValueError as exc:
            raise ValueError("{} row {} is not numeric".format(name, line_number)) from exc
        # Trace indices, offsets, and erase metadata are uint32. Write values
        # may be wider when the CSV exporter records a write width explicitly.
        if any(value < 0 or value > 0xFFFFFFFF for value in values[:1]):
            raise ValueError("{} row {} exceeds uint32 range".format(name, line_number))
        if len(values) > 1 and not (0 <= values[1] <= 0xFFFFFFFF):
            raise ValueError("{} row {} exceeds uint32 range".format(name, line_number))
        if header == ["write_index", "flash_offset", "value", "width"]:
            width = values[3]
            if width not in (1, 2, 4, 8):
                raise ValueError(
                    "{} row {} has unsupported write width {}".format(
                        name, line_number, width
                    )
                )
            if values[2] < 0 or values[2] > (1 << (width * 8)) - 1:
                raise ValueError(
                    "{} row {} value exceeds width {}".format(
                        name, line_number, width
                    )
                )
        elif any(value < 0 or value > 0xFFFFFFFF for value in values[2:]):
            raise ValueError("{} row {} exceeds uint32 range".format(name, line_number))
        if values[0] <= previous_index:
            raise ValueError("{} indices must be positive and increasing".format(name))
        previous_index = values[0]
        rows.append(values)
    return rows


def _validate_trace_pair(
    csv_data: Optional[bytes],
    bin_data: Optional[bytes],
    *,
    erase: bool,
) -> int:
    name = "erase trace" if erase else "write trace"
    # CSV is the canonical trace representation and may be present without a
    # binary companion (for example after a backend emits width-bearing CSV
    # only). A binary artifact without its CSV cannot be validated safely.
    if csv_data is None and bin_data is not None:
        raise ValueError("{} binary artifact requires a CSV artifact".format(name))
    if csv_data is None:
        return 0
    if erase:
        header = [
            "erase_index",
            "flash_offset",
            "writes_at_this_point",
            "erase_size",
        ]
    else:
        try:
            decoded = csv.reader(io.StringIO(csv_data.decode("utf-8"), newline=""))
            actual_header = next(decoded)
        except (UnicodeDecodeError, StopIteration) as exc:
            raise ValueError("write trace has an invalid header") from exc
        legacy_header = ["write_index", "flash_offset", "value"]
        width_header = legacy_header + ["width"]
        if actual_header not in (legacy_header, width_header):
            raise ValueError("write trace has an unexpected header")
        header = actual_header
    rows = _parse_trace_csv(csv_data, name=name, header=header)
    if bin_data is None:
        return len(rows)
    if not erase and header == ["write_index", "flash_offset", "value", "width"]:
        if any(row[3] != 4 for row in rows):
            raise ValueError(
                "write trace binary companion requires every width to be 4"
            )
    if len(bin_data) != len(rows) * 12:
        raise ValueError("{} binary record count does not match CSV".format(name))
    binary_rows = list(struct.iter_unpack("<III", bin_data))
    expected_rows = (
        [(row[2], row[1], row[3]) for row in rows]
        if erase
        else [(row[0], row[1], row[2]) for row in rows]
    )
    if binary_rows != expected_rows:
        raise ValueError("{} binary records do not match CSV".format(name))
    return len(rows)


def _validate_cache_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("calibration cache must contain a JSON object")
    if set(payload) != CACHE_FIELDS:
        missing = sorted(CACHE_FIELDS - set(payload))
        unknown = sorted(set(payload) - CACHE_FIELDS)
        raise ValueError(
            "calibration cache fields are invalid (missing={}, unknown={})".format(
                missing,
                unknown,
            )
        )
    if type(payload["version"]) is not int or payload["version"] != CACHE_VERSION:
        raise ValueError(
            "unsupported calibration cache version {}; regenerate the cache".format(
                payload["version"]
            )
        )
    if (
        not isinstance(payload["cache_key"], str)
        or not payload["cache_key"]
        or len(payload["cache_key"]) > 256
    ):
        raise ValueError("cache_key must be a short non-empty string")

    total_writes = _counter(payload, "total_writes")
    total_erases = _counter(payload, "total_erases")
    _counter(payload, "setup_writes")
    _counter(payload, "total_i2c_transactions")
    _counter(payload, "total_otp_blows")

    exec_hash = payload["calibration_exec_hash"]
    if exec_hash is not None and (
        not isinstance(exec_hash, str) or not SHA256_RE.fullmatch(exec_hash)
    ):
        raise ValueError("calibration_exec_hash must be lowercase SHA-256 or null")
    for name in ("calibration_boot_outcome", "stop_reason", "pc"):
        value = payload[name]
        if value is not None and (
            not isinstance(value, str) or not value or len(value) > 256
        ):
            raise ValueError("{} must be a short non-empty string or null".format(name))
    for name in ("emulated_s", "elapsed_s"):
        value = payload[name]
        if value is not None and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError("{} must be a finite non-negative number or null".format(name))

    trace_csv = _decode_artifact(payload, "trace_file_b64")
    erase_csv = _decode_artifact(payload, "erase_trace_file_b64")
    trace_bin = _decode_artifact(payload, "trace_file_bin_b64")
    erase_bin = _decode_artifact(payload, "erase_trace_file_bin_b64")
    write_rows = _validate_trace_pair(trace_csv, trace_bin, erase=False)
    erase_rows = _validate_trace_pair(erase_csv, erase_bin, erase=True)
    # The trace records actual flash mutations, while TotalWordWrites also
    # includes counter-only write attempts (for example, programming an
    # already-erased word with 0xFFFFFFFF).  The trace is therefore a subset
    # of the counter, not an exact accounting of it.
    if write_rows > total_writes:
        raise ValueError("write trace record count is inconsistent with total_writes")
    if erase_rows and erase_rows != total_erases:
        raise ValueError("erase trace record count does not match total_erases")
    return payload


def _restore_artifact(data: Optional[bytes], destination: Path) -> Optional[str]:
    if data is None:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return str(destination)


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
    trace_b64, trace_sha256 = _artifact_payload(cal.trace_file)
    erase_trace_b64, erase_trace_sha256 = _artifact_payload(cal.erase_trace_file)
    trace_bin_b64, trace_bin_sha256 = _artifact_payload(cal.trace_file_bin)
    erase_trace_bin_b64, erase_trace_bin_sha256 = _artifact_payload(
        cal.erase_trace_file_bin
    )
    payload: Dict[str, Any] = {
        "cache_key": cache_key,
        "version": CACHE_VERSION,
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
        "trace_file_b64": trace_b64,
        "trace_file_sha256": trace_sha256,
        "erase_trace_file_b64": erase_trace_b64,
        "erase_trace_file_sha256": erase_trace_sha256,
        "trace_file_bin_b64": trace_bin_b64,
        "trace_file_bin_sha256": trace_bin_sha256,
        "erase_trace_file_bin_b64": erase_trace_bin_b64,
        "erase_trace_file_bin_sha256": erase_trace_bin_sha256,
    }
    _validate_cache_payload(payload)
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
    *,
    expected_sha256: Optional[str] = None,
    allow_unsigned: bool = False,
) -> Optional[CalibrationResult]:
    """Load a cached calibration result if the cache key matches.

    Trace files are restored to *work_dir*. Returns None when the file is
    missing, or for an explicitly trusted unsigned cache with a key mismatch.
    Existing caches otherwise require a trusted whole-file digest.
    """
    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.strip().lower()
        if not SHA256_RE.fullmatch(expected_sha256):
            raise ValueError("expected calibration cache SHA-256 is invalid")
    if not os.path.exists(path):
        if expected_sha256 is not None:
            raise ValueError("pinned calibration cache does not exist")
        return None

    raw = Path(path).read_bytes()
    if len(raw) > MAX_CACHE_BYTES:
        raise ValueError("calibration cache exceeds size limit")
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is None and not allow_unsigned:
        raise ValueError(
            "refusing unsigned calibration cache; provide its trusted SHA-256 "
            "or explicitly allow unsigned cache input"
        )
    if expected_sha256 is not None and actual_sha256 != expected_sha256:
        raise ValueError(
            "calibration cache SHA-256 mismatch: expected {}, got {}".format(
                expected_sha256,
                actual_sha256,
            )
        )
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("calibration cache is not valid UTF-8 JSON") from exc
    payload = _validate_cache_payload(payload)

    if payload["cache_key"] != cache_key:
        if expected_sha256 is not None:
            raise ValueError("pinned calibration cache key does not match this run")
        return None

    trace_csv = _decode_artifact(payload, "trace_file_b64")
    erase_csv = _decode_artifact(payload, "erase_trace_file_b64")
    trace_bin = _decode_artifact(payload, "trace_file_bin_b64")
    erase_bin = _decode_artifact(payload, "erase_trace_file_bin_b64")

    # Restore already-validated trace files into work_dir.
    trace_dir = work_dir / "cached_traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_file = _restore_artifact(trace_csv, trace_dir / "write_trace.csv")
    erase_trace_file = _restore_artifact(erase_csv, trace_dir / "erase_trace.csv")
    trace_file_bin = _restore_artifact(trace_bin, trace_dir / "write_trace.bin")
    erase_trace_file_bin = _restore_artifact(
        erase_bin,
        trace_dir / "erase_trace.bin",
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
