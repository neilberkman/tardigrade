"""Trace loading, operation interleaving, and fault-window annotation.

Extracted from audit_bootloader.py to provide a focused module for
calibration trace I/O and clean-operation timeline construction.
"""

from __future__ import annotations

import csv
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import MetadataFaultRegion


EXACT_PROGRAM_TRACE_FIELDS = (
    "write_index",
    "program_address",
    "offset",
    "width",
    "intended_hex",
    "pre_program_hex",
    "post_program_hex",
    "faulted",
)
MAX_EXACT_PROGRAM_WIDTH = 1 << 20


def flash_base_for_profile(profile: Any) -> int:
    """Return the address corresponding to backend trace offset zero.

    Runtime flash traces are relative to the backing peripheral, not to the
    first application slot.  The bootloader entry is the canonical backing
    base for ordinary profiles.  Profiles with an explicit address map trace
    shared backing offsets directly, so their unmapped fallback base is zero.
    """
    memory = profile.memory
    if getattr(memory, "trace_address_map", None):
        return 0

    candidates = [int(profile.bootloader_entry)]
    candidates.extend(int(slot.base) for slot in memory.slots.values())

    bootloader_region = getattr(profile, "bootloader_region", None)
    if bootloader_region is not None:
        candidates.append(int(bootloader_region.base))
    candidates.extend(
        int(region.base)
        for region in getattr(memory, "erase_regions", ()) or ()
    )
    candidates.extend(
        int(region.base)
        for region in getattr(memory, "postmortem_partitions", ()) or ()
    )
    return min(candidates)


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


def _trace_absolute_address(
    flash_offset: int,
    flash_base: int,
    trace_address_map: Optional[List[Dict[str, int]]] = None,
) -> int:
    """Map a backend trace offset to a CPU-visible address.

    Most backends expose offsets relative to their declared flash base.  An
    aliased backend may expose one shared backing offset for multiple CPU
    ranges; an explicit map (offset range plus ``address_addend``) lets the
    profile select the canonical alias for classification without changing
    the trace file format.
    """
    offset = int(flash_offset)
    for mapping in trace_address_map or []:
        if int(mapping["offset_start"]) <= offset < int(mapping["offset_end"]):
            return int(mapping["address_addend"]) + offset
    return int(flash_base) + offset


def _classify_slot_region(
    address: int,
    slots: Dict[str, Any],
    page_size: int,
) -> str:
    """Classify an absolute flash address relative to declared slots."""
    if page_size <= 0:
        page_size = 4096
    for slot_name, slot_info in slots.items():
        slot_base = int(slot_info.base)
        slot_end = slot_base + int(slot_info.size)
        if slot_end - page_size <= address < slot_end:
            return "{}_trailer".format(slot_name)
        if slot_base <= address < slot_end:
            return "{}_data".format(slot_name)
    return "outside"


def load_clean_write_trace(
    trace_file: Optional[str], flash_size: Optional[int] = None
) -> List[Dict[str, int]]:
    """Load and validate calibration write trace CSV.

    Trace provenance is security-sensitive: malformed rows are an error, not
    rows to skip.  Indices must be non-negative, unique, and strictly
    increasing in source order.  Width is retained when an exporter supplied
    one; legacy three-column rows intentionally have no ``width`` key.
    """
    if not trace_file:
        return []
    if not os.path.isfile(trace_file):
        raise ValueError(
            "write trace path is not a regular file: {}".format(trace_file)
        )
    entries: List[Dict[str, int]] = []
    with open(trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = [str(name).strip() for name in (reader.fieldnames or ()) if name]
        if not fields:
            raise ValueError("write trace CSV has no header")
        if len(fields) != len(set(fields)):
            raise ValueError("write trace CSV has duplicate columns")
        required = {"write_index", "flash_offset", "value"}
        missing = required - set(fields)
        if missing:
            raise ValueError(
                "write trace CSV is missing columns: {}".format(",".join(sorted(missing)))
            )
        allowed = required | {"width", "write_width", "length"}
        unexpected = set(fields) - allowed
        if unexpected:
            raise ValueError(
                "write trace CSV has unexpected columns: {}".format(
                    ",".join(sorted(unexpected))
                )
            )
        width_fields = [
            name for name in ("width", "write_width", "length") if name in fields
        ]
        if len(width_fields) > 1:
            raise ValueError("write trace CSV has conflicting width columns")
        capacity = None if flash_size is None else int(flash_size)
        if capacity is not None and capacity < 0:
            raise ValueError("write trace flash size is negative")
        previous_index: Optional[int] = None
        for row in reader:
            if None in row and row[None]:
                raise ValueError("write trace CSV row has extra fields")
            try:
                write_index = int(str(row.get("write_index", "")).strip(), 0)
                flash_offset = int(str(row.get("flash_offset", "")).strip(), 0)
                value = int(str(row.get("value", "")).strip() or "0", 0)
            except (TypeError, ValueError) as exc:
                raise ValueError("malformed write trace row: {}".format(exc))
            if write_index < 0:
                raise ValueError("write trace index is negative")
            if flash_offset < 0:
                raise ValueError("write trace offset is negative")
            if capacity is not None and flash_offset >= capacity:
                raise ValueError(
                    "write trace offset {} is outside flash size {}".format(
                        flash_offset, capacity
                    )
                )
            if previous_index is not None and write_index <= previous_index:
                raise ValueError(
                    "write trace indices must be strictly increasing: {} after {}".format(
                        write_index, previous_index
                    )
                )
            previous_index = write_index
            entry = {
                "write_index": write_index,
                "flash_offset": flash_offset,
                "value": value,
            }
            if width_fields:
                raw_width = row.get(width_fields[0], "")
                if str(raw_width).strip():
                    try:
                        width = int(str(raw_width).strip(), 0)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("malformed write width: {}".format(exc))
                    if width not in (1, 2, 4, 8):
                        raise ValueError("unsupported write width {}".format(width))
                    if capacity is not None and (
                        flash_offset > capacity or width > capacity - flash_offset
                    ):
                        raise ValueError(
                            "write trace span [{}, {}) is outside flash size {}".format(
                                flash_offset, flash_offset + width, capacity
                            )
                        )
                    entry["width"] = width
            entries.append(entry)
    return entries


def load_normalized_write_spans(
    trace_file: Optional[str],
    flash_base: int,
    default_width: int,
    trace_address_map: Optional[List[Dict[str, int]]] = None,
) -> Optional[List[Tuple[int, int]]]:
    """Load one calibration trace into absolute, width-aware write spans."""
    if not trace_file:
        return None
    if (
        isinstance(default_width, bool)
        or not isinstance(default_width, int)
        or default_width <= 0
    ):
        raise ValueError("default write width must be a positive integer")
    return [
        (
            _trace_absolute_address(
                entry["flash_offset"], flash_base, trace_address_map
            ),
            int(entry.get("width", default_width)),
        )
        for entry in load_clean_write_trace(trace_file)
    ]


def parse_exact_program_trace_csv(
    text: str,
    source: str = "exact MRAM program trace",
) -> List[Dict[str, Any]]:
    """Parse and validate an exact, width-aware MRAM calibration trace."""
    reader = csv.DictReader(text.splitlines(), strict=True)
    fields = tuple(reader.fieldnames or ())
    if fields != EXACT_PROGRAM_TRACE_FIELDS:
        raise ValueError("{} has an unexpected header".format(source))

    entries: List[Dict[str, Any]] = []
    previous_index = 0
    address_base: Optional[int] = None
    for line_number, row in enumerate(reader, start=2):
        if None in row and row[None]:
            raise ValueError(
                "{} row {} has extra fields".format(source, line_number)
            )
        if any(
            row.get(field) is None or not str(row[field]).strip()
            for field in EXACT_PROGRAM_TRACE_FIELDS
        ):
            raise ValueError(
                "{} row {} has a missing field".format(source, line_number)
            )
        try:
            write_index = int(str(row["write_index"]).strip(), 0)
            program_address = int(str(row["program_address"]).strip(), 0)
            offset = int(str(row["offset"]).strip(), 0)
            width = int(str(row["width"]).strip(), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "{} row {} has a malformed numeric field".format(
                    source, line_number
                )
            ) from exc
        if write_index <= previous_index:
            raise ValueError(
                "{} indices must be positive and strictly increasing".format(source)
            )
        if not 0 <= program_address <= 0xFFFFFFFF:
            raise ValueError(
                "{} row {} program address is outside uint32".format(
                    source, line_number
                )
            )
        if not 0 <= offset <= 0xFFFFFFFF:
            raise ValueError(
                "{} row {} offset is outside uint32".format(source, line_number)
            )
        if width <= 0 or width > MAX_EXACT_PROGRAM_WIDTH:
            raise ValueError(
                "{} row {} width is not positive and bounded".format(
                    source, line_number
                )
            )
        if program_address + width > 1 << 32 or offset + width > 1 << 32:
            raise ValueError(
                "{} row {} program span is outside uint32".format(
                    source, line_number
                )
            )

        current_base = program_address - offset
        if current_base < 0:
            raise ValueError(
                "{} row {} address contradicts its offset".format(
                    source, line_number
                )
            )
        if address_base is None:
            address_base = current_base
        elif current_base != address_base:
            raise ValueError(
                "{} row {} has contradictory address provenance".format(
                    source, line_number
                )
            )

        exact_bytes: Dict[str, str] = {}
        for field in ("intended_hex", "pre_program_hex", "post_program_hex"):
            value = str(row[field]).strip()
            if len(value) != width * 2 or any(
                character not in "0123456789abcdefABCDEF" for character in value
            ):
                raise ValueError(
                    "{} row {} {} does not match width {}".format(
                        source, line_number, field, width
                    )
                )
            exact_bytes[field] = value.lower()

        faulted_text = str(row["faulted"]).strip().lower()
        if faulted_text not in {"false", "true"}:
            raise ValueError(
                "{} row {} has an invalid fault marker".format(
                    source, line_number
                )
            )
        if faulted_text == "true":
            raise ValueError(
                "{} row {} contains a faulted calibration event".format(
                    source, line_number
                )
            )

        entries.append(
            {
                "write_index": write_index,
                "program_address": program_address,
                "offset": offset,
                "program_width": width,
                "intended_bytes": exact_bytes["intended_hex"],
                "pre_program_bytes": exact_bytes["pre_program_hex"],
                "post_program_bytes": exact_bytes["post_program_hex"],
                "faulted": False,
            }
        )
        previous_index = write_index
    return entries


def load_exact_program_trace(
    program_trace_file: Optional[str],
) -> List[Dict[str, Any]]:
    """Load an exact MRAM calibration trace, rejecting missing provenance."""
    if not program_trace_file:
        return []
    if not os.path.isfile(program_trace_file):
        raise ValueError(
            "exact MRAM program trace does not identify a regular file: {}".format(
                program_trace_file
            )
        )
    try:
        with open(program_trace_file, "r", encoding="utf-8", newline="") as stream:
            return parse_exact_program_trace_csv(
                stream.read(), source="exact MRAM program trace"
            )
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError("exact MRAM program trace could not be read: {}".format(exc))


def _validate_coexisting_write_traces(
    write_entries: List[Dict[str, int]],
    program_entries: List[Dict[str, Any]],
) -> None:
    """Require legacy and exact write representations to describe one stream."""
    if len(write_entries) != len(program_entries):
        raise ValueError(
            "legacy write trace contradicts exact MRAM program trace count"
        )
    for legacy, exact in zip(write_entries, program_entries):
        if (
            int(legacy["write_index"]) != int(exact["write_index"])
            or int(legacy["flash_offset"]) != int(exact["offset"])
        ):
            raise ValueError(
                "legacy write trace contradicts exact MRAM program provenance"
            )
        if "width" in legacy and int(legacy["width"]) != int(
            exact["program_width"]
        ):
            raise ValueError(
                "legacy write trace contradicts exact MRAM program width"
            )


def _classify_exact_program_regions(
    address: int,
    width: int,
    slots: Dict[str, Any],
    page_size: int,
    metadata_regions: Optional[List[MetadataFaultRegion]],
) -> Tuple[set[str], set[str]]:
    """Return every classified region touched by one exact program span."""
    start = int(address)
    end = start + int(width)
    effective_page_size = int(page_size)
    if effective_page_size <= 0:
        effective_page_size = 4096
    boundaries = {start, end}
    for slot_info in slots.values():
        slot_start = int(slot_info.base)
        slot_end = slot_start + int(slot_info.size)
        trailer_start = max(slot_start, slot_end - effective_page_size)
        for boundary in (slot_start, trailer_start, slot_end):
            if start < boundary < end:
                boundaries.add(boundary)
    for region in metadata_regions or []:
        for boundary in (int(region.start), int(region.end)):
            if start < boundary < end:
                boundaries.add(boundary)

    categories: set[str] = set()
    metadata_names: set[str] = set()
    ordered = sorted(boundaries)
    for segment_start, segment_end in zip(ordered, ordered[1:]):
        if segment_start >= segment_end:
            continue
        slot_region = _classify_slot_region(
            segment_start, slots, effective_page_size
        )
        if slot_region.endswith("_data"):
            categories.add("data")
            continue
        if slot_region.endswith("_trailer"):
            categories.add("trailer")
            continue
        matched = next(
            (
                region
                for region in metadata_regions or []
                if region.contains(segment_start)
            ),
            None,
        )
        if matched is not None:
            categories.add("metadata")
            metadata_names.add(matched.name)
        else:
            categories.add("outside")
    return categories, metadata_names


def _classify_trace_span_regions(
    flash_offset: int,
    width: int,
    flash_base: int,
    slots: Dict[str, Any],
    page_size: int,
    metadata_regions: Optional[List[MetadataFaultRegion]],
    trace_address_map: Optional[List[Dict[str, int]]],
) -> Tuple[set[str], set[str]]:
    """Classify every region touched by a relative trace operation span."""
    start = int(flash_offset)
    span_width = int(width)
    if start < 0 or span_width <= 0:
        raise ValueError(
            "trace operation span must have a non-negative offset and positive width"
        )
    end = start + span_width
    offset_boundaries = {start, end}
    for mapping in trace_address_map or []:
        for boundary in (
            int(mapping["offset_start"]),
            int(mapping["offset_end"]),
        ):
            if start < boundary < end:
                offset_boundaries.add(boundary)

    categories: set[str] = set()
    metadata_names: set[str] = set()
    ordered = sorted(offset_boundaries)
    for segment_start, segment_end in zip(ordered, ordered[1:]):
        if segment_start >= segment_end:
            continue
        segment_categories, segment_metadata = _classify_exact_program_regions(
            _trace_absolute_address(
                segment_start,
                flash_base,
                trace_address_map,
            ),
            segment_end - segment_start,
            slots,
            page_size,
            metadata_regions,
        )
        categories.update(segment_categories)
        metadata_names.update(segment_metadata)
    return categories, metadata_names


def load_clean_erase_trace(
    erase_trace_file: Optional[str], flash_size: Optional[int] = None,
    page_size: int = 4096,
) -> List[Dict[str, Any]]:
    """Load calibration erase trace CSV (if available).

    The preferred column is `writes_at_this_point`. Some traces may omit it;
    in that case entries are still loaded and kept in source order with
    `writes_at_this_point=None` so downstream interleaving can degrade safely.
    """
    if not erase_trace_file:
        return []
    if not os.path.isfile(erase_trace_file):
        raise ValueError(
            "erase trace path is not a regular file: {}".format(erase_trace_file)
        )
    entries: List[Dict[str, Any]] = []
    with open(erase_trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("erase trace CSV has no header")
        fields = [str(name).strip() for name in reader.fieldnames if name]
        if len(fields) != len(reader.fieldnames) or len(fields) != len(set(fields)):
            raise ValueError("erase trace CSV has empty or duplicate columns")
        allowed = {
            "erase_index",
            "flash_offset",
            "offset",
            "writes_at_this_point",
            "writes_at",
            "write_index",
            "write_count_at_erase",
            "erase_size",
        }
        unexpected = set(fields) - allowed
        if unexpected:
            raise ValueError(
                "erase trace CSV has unexpected columns: {}".format(
                    ",".join(sorted(unexpected))
                )
            )
        offset_fields = [name for name in ("flash_offset", "offset") if name in fields]
        if not offset_fields:
            raise ValueError("erase trace CSV is missing flash_offset")
        if len(offset_fields) > 1:
            raise ValueError("erase trace CSV has conflicting offset columns")
        writes_at_fields = [
            candidate
            for candidate in (
                "writes_at_this_point",
                "writes_at",
                "write_index",
                "write_count_at_erase",
            )
            if candidate in fields
        ]
        if len(writes_at_fields) > 1:
            raise ValueError("erase trace CSV has conflicting write-count columns")
        writes_at_key = writes_at_fields[0] if writes_at_fields else None
        capacity = None if flash_size is None else int(flash_size)
        page_size = int(page_size)
        if page_size <= 0:
            page_size = 4096
        if capacity is not None and capacity < 0:
            raise ValueError("erase trace flash size is negative")
        previous_erase_index: Optional[int] = None
        previous_writes_at: Optional[int] = None
        for idx, row in enumerate(reader, start=1):
            if None in row and row[None]:
                raise ValueError("erase trace CSV row has extra fields")
            try:
                erase_index_raw = row.get("erase_index", str(idx))
                erase_index = int(str(erase_index_raw).strip() or str(idx), 0)
                flash_offset_raw = row.get(offset_fields[0])
                if flash_offset_raw is None or not str(flash_offset_raw).strip():
                    raise ValueError("erase trace offset is empty")
                flash_offset = int(str(flash_offset_raw).strip(), 0)
            except Exception as exc:
                raise ValueError("malformed erase trace row: {}".format(exc))
            if flash_offset < 0:
                raise ValueError("erase trace offset is negative")
            writes_at: Optional[int] = None
            if writes_at_key is not None:
                writes_at = _parse_optional_int(row.get(writes_at_key, ""))
                if writes_at is None:
                    raise ValueError("erase trace writes_at_this_point is malformed")
                if writes_at < 0:
                    raise ValueError("erase trace writes_at_this_point is negative")
                if previous_writes_at is not None and writes_at < previous_writes_at:
                    raise ValueError("erase trace writes_at_this_point is out of order")
                previous_writes_at = writes_at
            if erase_index < 0:
                raise ValueError("erase trace index is negative")
            if previous_erase_index is not None and erase_index <= previous_erase_index:
                raise ValueError(
                    "erase trace indices must be strictly increasing: {} after {}".format(
                        erase_index, previous_erase_index
                    )
                )
            previous_erase_index = erase_index
            # Missing/blank erase_size is the legacy page-size sentinel.  A
            # nonblank value that cannot be parsed is malformed provenance,
            # not another spelling of that sentinel.
            erase_size_raw = row.get("erase_size", "")
            erase_size_text = str(erase_size_raw).strip()
            erase_size = (
                0 if not erase_size_text
                else _parse_optional_int(erase_size_text)
            )
            if erase_size is None:
                raise ValueError("erase trace size is malformed")
            if erase_size < 0:
                raise ValueError("erase trace size is negative")
            effective_size = erase_size if erase_size > 0 else page_size
            if capacity is not None and (
                flash_offset > capacity
                or effective_size > capacity - flash_offset
            ):
                raise ValueError(
                    "erase trace region [{}, {}) is outside flash size {}".format(
                        flash_offset, flash_offset + effective_size, capacity
                    )
                )
            entries.append(
                {
                    "erase_index": erase_index,
                    "flash_offset": flash_offset,
                    "writes_at_this_point": writes_at,
                    "erase_size": erase_size,
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


def summarize_calibration_coverage(
    trace_file: Optional[str],
    erase_trace_file: Optional[str],
    flash_base: int,
    slots: Dict[str, Any],
    page_size: int = 4096,
    metadata_regions: Optional[List[MetadataFaultRegion]] = None,
    trace_address_map: Optional[List[Dict[str, int]]] = None,
    program_trace_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Summarize whether calibration exercised slot data movement."""
    has_write_trace = bool(trace_file)
    has_erase_trace = bool(erase_trace_file)
    has_program_trace = bool(program_trace_file)
    if not has_write_trace and not has_erase_trace and not has_program_trace:
        return {
            "status": "unavailable",
            "reason": "No calibration write, exact program, or erase trace available.",
        }
    if not slots:
        return {
            "status": "unavailable",
            "reason": "No memory slots declared; slot coverage cannot be classified.",
        }

    write_entries = load_clean_write_trace(trace_file) if has_write_trace else []
    program_entries = (
        load_exact_program_trace(program_trace_file) if has_program_trace else []
    )
    if has_write_trace and has_program_trace:
        _validate_coexisting_write_traces(write_entries, program_entries)
    erase_entries = load_clean_erase_trace(erase_trace_file) if has_erase_trace else []
    counts = {
        "slot_data_writes": 0,
        "slot_data_erases": 0,
        "slot_trailer_writes": 0,
        "slot_trailer_erases": 0,
        "metadata_region_writes": 0,
        "metadata_region_erases": 0,
        "outside_slot_writes": 0,
        "outside_slot_erases": 0,
    }
    named_region_ops: Dict[str, int] = {}
    cross_region_programs = 0
    cross_region_writes = 0
    cross_region_erases = 0

    def count_regions(
        categories: set[str], metadata_names: set[str], operation: str
    ) -> None:
        suffix = "writes" if operation == "write" else "erases"
        if "data" in categories:
            counts["slot_data_{}".format(suffix)] += 1
        if "trailer" in categories:
            counts["slot_trailer_{}".format(suffix)] += 1
        if "metadata" in categories:
            counts["metadata_region_{}".format(suffix)] += 1
            for name in metadata_names:
                named_region_ops[name] = named_region_ops.get(name, 0) + 1
        if "outside" in categories:
            counts["outside_slot_{}".format(suffix)] += 1

    if has_write_trace:
        authoritative_write_entries: List[Dict[str, Any]] = write_entries
        write_trace_source = "legacy_write_trace"
        for entry in authoritative_write_entries:
            categories, metadata_names = _classify_trace_span_regions(
                entry["flash_offset"],
                entry.get("width", 1),
                flash_base,
                slots,
                page_size,
                metadata_regions,
                trace_address_map,
            )
            if len(categories) > 1:
                cross_region_writes += 1
            count_regions(categories, metadata_names, "write")
    elif has_program_trace:
        authoritative_write_entries = program_entries
        write_trace_source = "exact_mram_program_trace"
        for entry in authoritative_write_entries:
            categories, metadata_names = _classify_exact_program_regions(
                entry["program_address"],
                entry["program_width"],
                slots,
                page_size,
                metadata_regions,
            )
            if len(categories) > 1:
                cross_region_programs += 1
                cross_region_writes += 1
            count_regions(categories, metadata_names, "write")
    else:
        authoritative_write_entries = []
        write_trace_source = "erase_trace_only"

    for entry in erase_entries:
        erase_size = int(entry.get("erase_size", 0))
        effective_erase_size = erase_size if erase_size > 0 else max(1, int(page_size))
        categories, metadata_names = _classify_trace_span_regions(
            entry["flash_offset"],
            effective_erase_size,
            flash_base,
            slots,
            page_size,
            metadata_regions,
            trace_address_map,
        )
        if len(categories) > 1:
            cross_region_erases += 1
        count_regions(categories, metadata_names, "erase")

    slot_data_ops = counts["slot_data_writes"] + counts["slot_data_erases"]
    trailer_ops = counts["slot_trailer_writes"] + counts["slot_trailer_erases"]
    metadata_region_ops = counts["metadata_region_writes"] + counts["metadata_region_erases"]
    outside_ops = counts["outside_slot_writes"] + counts["outside_slot_erases"]

    if slot_data_ops > 0:
        status = "slot_activity"
        reason = "Calibration observed slot data movement."
    elif trailer_ops > 0:
        status = "metadata_only"
        reason = "Calibration touched slot trailers/metadata but never moved slot data."
    elif metadata_region_ops > 0:
        status = "named_metadata_only"
        if named_region_ops:
            reason = "Calibration touched declared metadata regions ({}) but never moved slot data.".format(
                ", ".join(sorted(named_region_ops))
            )
        else:
            reason = "Calibration touched declared metadata regions but never moved slot data."
    elif outside_ops > 0:
        status = "outside_slots_only"
        reason = "Calibration touched flash but never touched declared slots."
    else:
        status = "no_nvm_activity"
        reason = "Calibration produced no NVM writes or erases."

    return {
        "status": status,
        "reason": reason,
        "writes": len(authoritative_write_entries),
        "erases": len(erase_entries),
        "write_trace_source": write_trace_source,
        "exact_programs": len(program_entries),
        "coexisting_write_traces": bool(has_write_trace and has_program_trace),
        "cross_region_programs": cross_region_programs,
        "cross_region_writes": cross_region_writes,
        "cross_region_erases": cross_region_erases,
        "slot_data_ops": slot_data_ops,
        "slot_trailer_ops": trailer_ops,
        "metadata_region_ops": metadata_region_ops,
        "outside_slot_ops": outside_ops,
        "slot_data_writes": counts["slot_data_writes"],
        "slot_data_erases": counts["slot_data_erases"],
        "slot_trailer_writes": counts["slot_trailer_writes"],
        "slot_trailer_erases": counts["slot_trailer_erases"],
        "metadata_region_writes": counts["metadata_region_writes"],
        "metadata_region_erases": counts["metadata_region_erases"],
        "outside_slot_writes": counts["outside_slot_writes"],
        "outside_slot_erases": counts["outside_slot_erases"],
        "metadata_region_breakdown": {
            name: named_region_ops[name] for name in sorted(named_region_ops)
        },
    }


def build_clean_operation_trace(
    write_entries: List[Dict[str, int]],
    erase_entries: List[Dict[str, Any]],
    flash_base: int,
    trace_address_map: Optional[List[Dict[str, int]]] = None,
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
        op = {
                "_sort_key": (idx, 1, 0),
                "kind": "write",
                "write_index": idx,
                "flash_offset": off,
                "address": _fmt_u32(
                    _trace_absolute_address(off, flash_base, trace_address_map)
                ),
                "value": _fmt_u32(val),
            }
        if "width" in w and w.get("width") is not None:
            op["width"] = int(w["width"])
        ops.append(op)
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
                "address": _fmt_u32(
                    _trace_absolute_address(off, flash_base, trace_address_map)
                ),
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
        if op.get("width") is not None:
            base["width"] = int(op.get("width"))
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
    trace_address_map: Optional[List[Dict[str, int]]] = None,
) -> Optional[Dict[str, Any]]:
    """Load clean traces, annotate sweep results with fault windows, return metadata.

    Returns None if *trace_file* is absent. A supplied path that is missing or
    not a regular file is malformed provenance and raises ``ValueError``.
    As a side-effect, each entry in *sweep_results* is enriched with a
    ``fault_window`` key by :func:`annotate_fault_windows`.
    """
    if not trace_file:
        return None
    if not os.path.isfile(trace_file):
        raise ValueError(
            "write trace path is not a regular file: {}".format(trace_file)
        )

    clean_write_trace = load_clean_write_trace(trace_file)
    clean_erase_trace = load_clean_erase_trace(erase_trace_file)
    clean_ops = build_clean_operation_trace(
        write_entries=clean_write_trace,
        erase_entries=clean_erase_trace,
        flash_base=flash_base,
        trace_address_map=trace_address_map,
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
