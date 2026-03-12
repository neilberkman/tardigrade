"""Trace loading, operation interleaving, and fault-window annotation.

Extracted from audit_bootloader.py to provide a focused module for
calibration trace I/O and clean-operation timeline construction.
"""

from __future__ import annotations

import csv
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


def _parse_optional_int(value: Any) -> Optional[int]:
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except Exception:
        return None


def _fmt_u32(value: int) -> str:
    return "0x{0:08X}".format(int(value) & 0xFFFFFFFF)


def load_clean_write_trace(trace_file: Optional[str]) -> List[Dict[str, int]]:
    """Load calibration write trace CSV."""
    if not trace_file or not os.path.exists(trace_file):
        return []
    entries: List[Dict[str, int]] = []
    skip_count = 0
    with open(trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                entries.append(
                    {
                        "write_index": int(row.get("write_index", "0")),
                        "flash_offset": int(row.get("flash_offset", "0")),
                        "value": int(row.get("value", "0") or "0"),
                    }
                )
            except Exception:
                skip_count += 1
                continue
    if skip_count:
        print(
            "WARNING: skipped {} malformed rows in write trace".format(skip_count),
            file=sys.stderr,
            flush=True,
        )
    entries.sort(key=lambda e: e["write_index"])
    return entries


def load_clean_erase_trace(erase_trace_file: Optional[str]) -> List[Dict[str, Any]]:
    """Load calibration erase trace CSV (if available).

    The preferred column is `writes_at_this_point`. Some traces may omit it;
    in that case entries are still loaded and kept in source order with
    `writes_at_this_point=None` so downstream interleaving can degrade safely.
    """
    if not erase_trace_file or not os.path.exists(erase_trace_file):
        return []
    entries: List[Dict[str, Any]] = []
    with open(erase_trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames:
            fieldnames = {name.strip().lower() for name in reader.fieldnames if name}
        else:
            fieldnames = set()
        writes_at_key: Optional[str] = None
        for candidate in (
            "writes_at_this_point",
            "writes_at",
            "write_index",
            "write_count_at_erase",
        ):
            if candidate in fieldnames:
                writes_at_key = candidate
                break
        for idx, row in enumerate(reader, start=1):
            try:
                erase_index_raw = row.get("erase_index", str(idx))
                erase_index = int(str(erase_index_raw).strip() or str(idx), 0)
                flash_offset_raw = row.get("flash_offset")
                if flash_offset_raw is None:
                    flash_offset_raw = row.get("offset", "0")
                flash_offset = int(str(flash_offset_raw).strip() or "0", 0)
            except Exception:
                continue
            writes_at: Optional[int] = None
            if writes_at_key is not None:
                writes_at = _parse_optional_int(row.get(writes_at_key, ""))
            if writes_at is not None and writes_at < 0:
                writes_at = None
            entries.append(
                {
                    "erase_index": erase_index,
                    "flash_offset": flash_offset,
                    "writes_at_this_point": writes_at,
                    "source_order": idx,
                }
            )
    entries.sort(
        key=lambda e: (
            e["writes_at_this_point"] is None,
            e["writes_at_this_point"] if e["writes_at_this_point"] is not None else 0,
            e["source_order"],
            e["erase_index"],
        )
    )
    return entries


def build_clean_operation_trace(
    write_entries: List[Dict[str, int]],
    erase_entries: List[Dict[str, Any]],
    flash_base: int,
) -> List[Dict[str, Any]]:
    """Interleave clean-run write+erase operations into a single timeline."""
    ops: List[Dict[str, Any]] = []
    max_write_index = 0
    for w in write_entries:
        idx = int(w["write_index"])
        if idx > max_write_index:
            max_write_index = idx
        off = int(w["flash_offset"])
        val = int(w["value"])
        ops.append(
            {
                "_sort_key": (idx, 1, 0),
                "kind": "write",
                "write_index": idx,
                "flash_offset": off,
                "address": _fmt_u32(flash_base + off),
                "value": _fmt_u32(val),
            }
        )
    for e in erase_entries:
        erase_idx = int(e["erase_index"])
        writes_at_raw = e.get("writes_at_this_point")
        source_order = int(e.get("source_order", erase_idx))
        if writes_at_raw is None:
            # Missing writes_at means precise interleaving is unavailable.
            # Keep deterministic ordering by appending after known write-indexed
            # operations while preserving original erase row order.
            writes_at = max_write_index + source_order
            writes_at_known = False
        else:
            writes_at = int(writes_at_raw)
            writes_at_known = True
        off = int(e["flash_offset"])
        ops.append(
            {
                "_sort_key": (writes_at + 1, 0, erase_idx),
                "kind": "erase",
                "erase_index": erase_idx,
                "writes_at_this_point": writes_at_raw,
                "writes_at_known": writes_at_known,
                "flash_offset": off,
                "address": _fmt_u32(flash_base + off),
            }
        )
    ops.sort(key=lambda o: o["_sort_key"])
    for i, op in enumerate(ops, start=1):
        op["sequence"] = i
        op.pop("_sort_key", None)
    return ops


def _compact_operation(op: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(op, dict):
        return None
    base = {
        "sequence": int(op.get("sequence", 0)),
        "kind": op.get("kind"),
        "address": op.get("address"),
        "flash_offset": int(op.get("flash_offset", 0)),
    }
    if op.get("kind") == "write":
        base["write_index"] = int(op.get("write_index", 0))
        base["value"] = op.get("value")
    elif op.get("kind") == "erase":
        base["erase_index"] = int(op.get("erase_index", 0))
        writes_at = op.get("writes_at_this_point")
        if writes_at is not None:
            base["writes_at_this_point"] = int(writes_at)
        base["writes_at_known"] = bool(op.get("writes_at_known", True))
    return base


def annotate_fault_windows(
    results: List[Dict[str, Any]],
    clean_operations: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Attach clean-trace window annotations to injected results."""
    if not clean_operations:
        return {"annotated": 0, "skipped_unknown_interleaving": 0}

    annotated = 0
    skipped_unknown_interleaving = 0
    write_pos = {int(op["write_index"]): i for i, op in enumerate(clean_operations) if op.get("kind") == "write"}
    erase_pos = {int(op["erase_index"]): i for i, op in enumerate(clean_operations) if op.get("kind") == "erase"}

    for r in results:
        if r.get("is_control", False):
            continue
        if not r.get("fault_injected", False):
            continue

        fp = int(r.get("fault_at", 0))
        fault_type = str(r.get("fault_type", "w") or "w")
        target_pos: Optional[int] = None

        if fault_type in {"e", "a"}:
            target_pos = erase_pos.get(fp + 1)
        else:
            target_pos = write_pos.get(fp + 1)

        if target_pos is None:
            continue

        target_op = clean_operations[target_pos]
        if target_op.get("kind") == "erase" and not target_op.get("writes_at_known", True):
            r["fault_window_unavailable_reason"] = "erase_interleaving_unknown"
            skipped_unknown_interleaving += 1
            continue

        before_op = clean_operations[target_pos - 1] if target_pos > 0 else None
        next_op = clean_operations[target_pos + 1] if target_pos + 1 < len(clean_operations) else None

        r["fault_window"] = {
            "fault_type": fault_type,
            "fault_at": fp,
            "before": _compact_operation(before_op),
            "at": _compact_operation(target_op),
            "after": _compact_operation(next_op),
        }
        annotated += 1

    return {
        "annotated": annotated,
        "skipped_unknown_interleaving": skipped_unknown_interleaving,
    }


def annotate_clean_trace(
    sweep_results: List[Dict[str, Any]],
    trace_file: Optional[str],
    erase_trace_file: Optional[str],
    flash_base: int,
) -> Optional[Dict[str, Any]]:
    """Load clean traces, annotate sweep results with fault windows, return metadata.

    Returns None if *trace_file* is absent or does not exist on disk.
    As a side-effect, each entry in *sweep_results* is enriched with a
    ``fault_window`` key by :func:`annotate_fault_windows`.
    """
    if not trace_file or not os.path.exists(trace_file):
        return None

    clean_write_trace = load_clean_write_trace(trace_file)
    clean_erase_trace = load_clean_erase_trace(erase_trace_file)
    clean_ops = build_clean_operation_trace(
        write_entries=clean_write_trace,
        erase_entries=clean_erase_trace,
        flash_base=flash_base,
    )
    erase_missing_writes_at = sum(
        1 for e in clean_erase_trace if e.get("writes_at_this_point") is None
    )
    window_stats = annotate_fault_windows(sweep_results, clean_ops)

    print(
        "Fault-window annotation: {} points mapped to clean trace.".format(
            window_stats["annotated"]
        ),
        file=sys.stderr,
    )
    if erase_missing_writes_at > 0:
        print(
            "Clean erase trace: {} entries missing writes_at; "
            "{} fault windows skipped because precise erase ordering is unknown.".format(
                erase_missing_writes_at,
                window_stats["skipped_unknown_interleaving"],
            ),
            file=sys.stderr,
        )

    return {
        "trace_file": trace_file,
        "erase_trace_file": erase_trace_file,
        "writes": len(clean_write_trace),
        "erases": len(clean_erase_trace),
        "erases_missing_writes_at": erase_missing_writes_at,
        "operations": len(clean_ops),
        "fault_windows_annotated": window_stats["annotated"],
        "fault_windows_skipped_unknown_interleaving": window_stats[
            "skipped_unknown_interleaving"
        ],
    }
