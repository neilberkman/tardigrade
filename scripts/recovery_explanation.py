# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Explain recovery observations after classification, using recorded evidence."""

import base64
import os
import zlib

from fault_classification import (
    _effective_boot_result, _effective_boot_signals, result_has_issues, result_is_timeout,
    result_recovered_after_failure,
)
from recovery_search import (
    attribute_ranges_to_operations, compare_persistent_states, passing_siblings,
)
from recovery_state import PersistentState, merge_operation_traces
from report_points import point_cuts, point_status
from source_locations import SourceLocations
from trace_utils import (
    build_clean_operation_trace, load_clean_erase_trace, load_clean_write_trace,
    load_exact_program_trace,
)


def _cut_paths(row):
    """Canonical and equivalent power-cut paths within this runtime campaign."""
    cuts = point_cuts(row)
    if not cuts:
        kind = {"w": "power_loss", "e": "interrupted_erase"}.get(row.get("fault_type"))
        if not kind:
            return
        cuts = [(row.get("fault_requested", row.get("fault_at")), kind)]
    paths = [cuts]
    search = row.get("recovery_state_search") or {}
    for alias in search.get("equivalent_chains", []):
        paths.append([(c["operation_index"], c["fault_type"]) for c in alias["cuts"]])
    for path in paths:
        if all(isinstance(i, int) and i >= 0 and t in ("power_loss", "interrupted_erase")
               for i, t in path):
            yield tuple((i, t) for i, t in path)


def _decode_pre_recovery_state(encoded):
    if not isinstance(encoded, dict) or not encoded.get("zlib_b64"):
        return None
    try:
        raw = zlib.decompress(base64.b64decode(encoded["zlib_b64"]))
        base = int(str(encoded.get("base_address", "0")), 0)
        marks = []
        for item in encoded.get("uncorrectable_words") or ():
            addr = int(str(item), 0)
            if addr >= base:
                marks.append(("nvm", addr - base))
        return PersistentState.from_bytes(
            bytearray(raw),
            name="nvm",
            base_address=base,
            uncorrectable_words=tuple(marks),
        )
    except Exception:
        return None


def _snapshot_bytes(snapshot):
    """Expand a complete sparse comparison within its recorded identity slot."""
    image = snapshot.get("closest_declared_image") or {}
    if not image.get("sha256") or image.get("ranges_truncated") is not False:
        return None
    try:
        base = int(str(snapshot["identity_slot_base"]), 0)
        extent = snapshot["identity_slot_extent"]
        values = {}
        for span in image["differing_ranges"]:
            if span["bytes_truncated"]:
                return None
            address = int(str(span["address"]), 0)
            actual = bytes.fromhex(span["actual_hex"])
            expected = bytes.fromhex(span["expected_hex"])
            if (len(actual) != len(expected) or len(actual) != span["size"]
                    or address < base or address + len(actual) > base + extent):
                return None
            values.update((address + i, pair) for i, pair in enumerate(zip(actual, expected)))
        if len(values) != image["differing_bytes"] or len(image["differing_ranges"]) != image["differing_range_count"]:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return (image["sha256"], base, extent), values


def compare_snapshots(failing, passing):
    """Compare at the cut, before recovery mutates either state."""
    if not failing or not passing:
        return {"status": "snapshots_unavailable"}
    bad_marks = set(failing.get("uncorrectable_words", []))
    good_marks = set(passing.get("uncorrectable_words", []))
    result = {
        "uncorrectable_only_in_failing": sorted(bad_marks - good_marks),
        "uncorrectable_only_in_passing": sorted(good_marks - bad_marks),
    }
    if failing.get("sha256") and failing["sha256"] == passing.get("sha256"):
        return dict(result, status="identical_snapshot_bytes", ranges=[])
    bad = _snapshot_bytes(failing)
    good = _snapshot_bytes(passing)
    if bad is None or good is None or bad[0] != good[0]:
        return dict(result, status="no_complete_common_extent")
    (_, base, extent), left = bad
    _, right = good
    ranges = []
    last = None
    for address in sorted(left.keys() | right.keys()):
        # Both records use the same reference image. An omitted byte equals
        # the reference value recorded by the side that differs there.
        reference = (left.get(address) or right[address])[1]
        f, f_ref = left.get(address, (reference, reference))
        p, p_ref = right.get(address, (reference, reference))
        if f_ref != p_ref:
            return dict(result, status="inconsistent_reference")
        if f == p:
            continue
        if address != last:
            ranges.append({"address": f"0x{address:08X}", "failing_hex": "", "passing_hex": ""})
        ranges[-1]["failing_hex"] += f"{f:02x}"
        ranges[-1]["passing_hex"] += f"{p:02x}"
        last = address + 1
    return dict(result, status="compared_identity_slot", base=f"0x{base:08X}", size=extent, ranges=ranges)


_FAULT_HANDLER_NAMES = frozenset((
    "HardFault_Handler", "BusFault_Handler", "MemManage_Handler",
    "UsageFault_Handler", "Default_Handler",
))


def _resolve_last_function(row, signals, endpoint, source):
    last_obs = endpoint.get("last_observed")
    exc_entry = endpoint.get("exception_entry")
    if (
        exc_entry
        and exc_entry.get("function")
        and (not last_obs or not last_obs.get("function") or last_obs.get("function") in _FAULT_HANDLER_NAMES)
    ):
        return exc_entry
    if last_obs and last_obs.get("function"):
        return last_obs
    if exc_entry and exc_entry.get("function"):
        return exc_entry
    handoff = signals.get("phase2_pc_handoff_observation") or signals.get("pc_handoff_observation") or {}
    for branch in reversed(handoff.get("indirect_branches") or ()):
        resolved = source.resolve_pc(branch.get("pc"))
        if resolved and resolved.get("function"):
            return resolved
    for sample_pc in reversed(signals.get("phase2_pc_samples") or signals.get("pc_samples") or ()):
        resolved = source.resolve_pc(sample_pc)
        if resolved and resolved.get("function"):
            return resolved
    p2 = row.get("phase2_fault") or {}
    for entry in reversed(p2.get("p2_write_trace") or ()):
        resolved = source.resolve_pc(entry.get("pc"))
        if resolved and resolved.get("function"):
            return resolved
    return last_obs


def _endpoint(row, expected, source):
    outcome, slot = _effective_boot_result(row)
    signals = _effective_boot_signals(row)
    if result_recovered_after_failure(row, expected):
        outcome = row.get("initial_boot_outcome") or row.get("boot_outcome")
        slot = row.get("initial_boot_slot") or row.get("boot_slot")
        signals = row.get("signals") or {}
    execution = signals.get("recovery_execution") or {}
    endpoint = {"outcome": outcome, "boot_slot": slot, "execution_evidence": "observed"}
    if not (execution or signals.get("phase2_executed_instructions")):
        endpoint["execution_evidence"] = "unavailable"
        if "copy_completed" in signals:
            endpoint["execution_evidence"] = "simulated_copy"
            endpoint["copy_completed"] = signals["copy_completed"]
            endpoint["vector_valid"] = signals.get("vector_valid")
            endpoint["completed_writes"] = row.get("actual_writes")
        return endpoint
    endpoint["last_observed"] = source.resolve_pc(signals.get("pc"))
    endpoint["stop_reason"] = execution.get("stop_reason") or signals.get("phase2_stop_reason")
    if slot and signals.get("execution_observed"):
        endpoint["matched_image"] = signals.get("matched_image")
    active = execution.get("ipsr")
    exceptions = {3: "HardFault", 4: "MemManage", 5: "BusFault", 6: "UsageFault"}
    if active in exceptions:
        endpoint["exception"] = exceptions[active]
        fault = (execution.get("fault_timing") or {}).get("fault_first_active") or {}
        if fault.get("exception") == active and fault.get("source") == "interrupt_begin":
            endpoint["exception_entry"] = source.resolve_pc(fault.get("pc"))
    loop = signals.get("phase2_terminal_self_branch_observation") or {}
    location = source.resolve_pc(loop.get("pc"))
    if location and endpoint["last_observed"] and location["pc"] == endpoint["last_observed"]["pc"]:
        endpoint["hang_loop"] = location
    last_fn = _resolve_last_function(row, signals, endpoint, source)
    if last_fn is not None:
        endpoint["last_function"] = last_fn
    return endpoint


def _p2_merged_operations(p2_info):
    if not isinstance(p2_info, dict):
        return []
    writes = []
    for item in p2_info.get("p2_write_trace") or ():
        entry = {
            "write_index": int(item["write_index"]),
            "offset": int(item.get("flash_offset", 0)),
            "value": int(str(item.get("value", "0")), 0),
            "width": int(item.get("width", 4) or 4),
        }
        if item.get("address"):
            entry["address"] = item["address"]
        if item.get("pc"):
            entry["pc"] = item["pc"]
        writes.append(entry)
    erases = []
    for item in p2_info.get("p2_erase_trace") or ():
        entry = {
            "erase_index": int(item["erase_index"]),
            "offset": int(item.get("flash_offset", 0)),
            "writes_at_this_point": int(item.get("writes_at_this_point", 0)),
            "erase_size": int(item.get("erase_size", 4096) or 4096),
        }
        if item.get("address"):
            entry["address"] = item["address"]
        if item.get("pc"):
            entry["pc"] = item["pc"]
        erases.append(entry)
    if writes and erases:
        try:
            return merge_operation_traces(writes, erases)
        except Exception:
            pass
    ops = []
    for item in erases:
        op = dict(item, kind="erase", operation="erase", operation_index=item["erase_index"] - 1)
        ops.append(op)
    for item in writes:
        op = dict(item, kind="write", operation="write", operation_index=item["write_index"] - 1)
        ops.append(op)
    return ops


def _lookup_op_in_list(operations, kind, op_index):
    for op in operations or ():
        op_kind = str(op.get("kind") or op.get("operation") or "").lower()
        if not op_kind:
            if "write_index" in op:
                op_kind = "write"
            elif "erase_index" in op:
                op_kind = "erase"
        if op_kind != kind:
            continue
        if "operation_index" in op:
            idx = int(op["operation_index"])
        elif kind == "write" and "write_index" in op:
            idx = int(op["write_index"]) - 1
        elif kind == "erase" and "erase_index" in op:
            idx = int(op["erase_index"]) - 1
        else:
            continue
        if idx == int(op_index):
            return op
    return None


def _resolve_cuts(row, source, calibration_ops=(), flash_base=0):
    cuts_out = []
    search = row.get("recovery_state_search") or {}
    chain = (search.get("chain") or {}).get("cuts")
    if chain:
        for idx, raw_cut in enumerate(chain):
            op_kind = str(raw_cut.get("operation") or ("erase" if raw_cut.get("fault_type") == "interrupted_erase" else "write"))
            op_index = int(raw_cut["operation_index"])
            entry = {
                "operation": op_kind,
                "operation_index": op_index,
                "fault_type": str(raw_cut.get("fault_type") or ("interrupted_erase" if op_kind == "erase" else "power_loss")),
            }
            if raw_cut.get("address"):
                entry["address"] = str(raw_cut["address"])
            pc = raw_cut.get("pc")
            if not pc and idx == 0:
                cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
                if cal_op and cal_op.get("pc"):
                    pc = cal_op["pc"]
            if not pc and idx == len(chain) - 1 and row.get("fault_pc"):
                pc = row["fault_pc"]
            if pc:
                entry["pc"] = str(pc)
                entry["source"] = source.resolve_pc(pc)
            cuts_out.append(entry)
        return cuts_out

    p2 = row.get("phase2_fault")
    if isinstance(p2, dict):
        p1_kind = "erase" if str(p2.get("p1_fault_type")) in ("e", "a", "interrupted_erase") else "write"
        p1_idx = int(p2.get("p1_fault_at", row.get("fault_at", 0)))
        p1_entry = {
            "operation": p1_kind,
            "operation_index": p1_idx,
            "fault_type": "interrupted_erase" if p1_kind == "erase" else "power_loss",
        }
        if p2.get("p1_fault_address"):
            p1_entry["address"] = str(p2["p1_fault_address"])
        p1_pc = p2.get("p1_fault_pc")
        if not p1_pc:
            cal_op = _lookup_op_in_list(calibration_ops, p1_kind, p1_idx)
            if cal_op:
                if cal_op.get("pc"):
                    p1_pc = cal_op["pc"]
                if not p1_entry.get("address") and cal_op.get("address"):
                    p1_entry["address"] = cal_op["address"]
        if p1_pc:
            p1_entry["pc"] = str(p1_pc)
            p1_entry["source"] = source.resolve_pc(p1_pc)
        cuts_out.append(p1_entry)

        p2_kind = "erase" if str(p2.get("p2_fault_type")) in ("e", "a", "interrupted_erase") else "write"
        p2_idx = int(p2.get("p2_fault_at", 0))
        p2_entry = {
            "operation": p2_kind,
            "operation_index": p2_idx,
            "fault_type": "interrupted_erase" if p2_kind == "erase" else "power_loss",
        }
        if p2.get("p2_fault_address"):
            p2_entry["address"] = str(p2["p2_fault_address"])
        p2_ops = _p2_merged_operations(p2)
        p2_trace_op = _lookup_op_in_list(p2_ops, p2_kind, p2_idx)
        p2_pc = p2.get("p2_fault_pc") or (p2_trace_op.get("pc") if p2_trace_op else None) or row.get("fault_pc")
        if p2_pc:
            p2_entry["pc"] = str(p2_pc)
            p2_entry["source"] = source.resolve_pc(p2_pc)
        cuts_out.append(p2_entry)
        return cuts_out

    pchain = row.get("phase2_fault_chain")
    if isinstance(pchain, dict) and pchain.get("cuts"):
        for idx, cut_rec in enumerate(pchain["cuts"]):
            op_kind = str(cut_rec.get("operation") or ("erase" if cut_rec.get("fault_type") == "e" else "write"))
            op_index = int(cut_rec.get("fault_at", 0))
            entry = {
                "operation": op_kind,
                "operation_index": op_index,
                "fault_type": "interrupted_erase" if op_kind == "erase" else "power_loss",
            }
            if cut_rec.get("fault_address"):
                entry["address"] = str(cut_rec["fault_address"])
            pc = cut_rec.get("fault_pc")
            if not pc and idx == 0:
                cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
                if cal_op and cal_op.get("pc"):
                    pc = cal_op["pc"]
            if pc:
                entry["pc"] = str(pc)
                entry["source"] = source.resolve_pc(pc)
            cuts_out.append(entry)
        return cuts_out

    paths = list(_cut_paths(row))
    if not paths:
        return cuts_out
    for idx, (op_index, fault_type) in enumerate(paths[0]):
        op_kind = "erase" if fault_type == "interrupted_erase" else "write"
        entry = {
            "operation": op_kind,
            "operation_index": int(op_index),
            "fault_type": fault_type,
        }
        if idx == len(paths[0]) - 1 and row.get("fault_address"):
            entry["address"] = str(row["fault_address"])
        pc = row.get("fault_pc") if idx == len(paths[0]) - 1 else None
        if not pc:
            mram_ev = row.get("mram_fault_evidence") or {}
            if mram_ev.get("fault_pc"):
                pc = mram_ev["fault_pc"]
            else:
                mram_op = _lookup_op_in_list(mram_ev.get("write_trace") or (), op_kind, op_index)
                if mram_op and mram_op.get("pc"):
                    pc = mram_op["pc"]
        if not pc:
            fw = row.get("fault_window") or {}
            fw_ops = list(fw.get("operations") or ())
            for key in ("before", "at", "after"):
                if isinstance(fw.get(key), dict):
                    fw_ops.append(fw[key])
            fw_op = _lookup_op_in_list(fw_ops, op_kind, op_index)
            if fw_op:
                if fw_op.get("pc"):
                    pc = fw_op["pc"]
                if not entry.get("address") and fw_op.get("address"):
                    entry["address"] = fw_op["address"]
        if not pc and idx == 0:
            cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
            if cal_op:
                if cal_op.get("pc"):
                    pc = cal_op["pc"]
                if not entry.get("address") and cal_op.get("address"):
                    entry["address"] = cal_op["address"]
                elif not entry.get("address") and "offset" in cal_op:
                    entry["address"] = f"0x{(int(flash_base) + int(cal_op['offset'])) & 0xFFFFFFFF:08X}"
        if pc:
            entry["pc"] = str(pc)
            entry["source"] = source.resolve_pc(pc)
        cuts_out.append(entry)
    return cuts_out


def _attribute_comparison_ranges(row, other, comparison, source, calibration_ops=(), flash_base=0):
    ranges = comparison.get("ranges") or []
    if not ranges:
        return
    row_paths = list(_cut_paths(row))
    other_paths = list(_cut_paths(other)) if other is not None else []
    fail_last = row_paths[0][-1] if row_paths else None
    pass_last = other_paths[0][-1] if other_paths else None
    fail_cut = (
        ("erase" if fail_last[1] == "interrupted_erase" else "write", int(fail_last[0]))
        if fail_last else None
    )
    pass_cut = (
        ("erase" if pass_last[1] == "interrupted_erase" else "write", int(pass_last[0]))
        if pass_last else None
    )

    p2 = row.get("phase2_fault")
    if isinstance(p2, dict):
        p2_ops = _p2_merged_operations(p2)
        if p2_ops:
            attribute_ranges_to_operations(
                ranges, p2_ops, flash_base=flash_base, fail_cut=fail_cut, pass_cut=pass_cut,
            )
        if other is not None and isinstance(other.get("phase2_fault"), dict):
            other_p2_ops = _p2_merged_operations(other["phase2_fault"])
            if other_p2_ops:
                attribute_ranges_to_operations(
                    ranges, other_p2_ops, flash_base=flash_base, fail_cut=fail_cut, pass_cut=pass_cut,
                )
        if calibration_ops and any("operation" not in span for span in ranges):
            p1_fail = (
                "erase" if str(p2.get("p1_fault_type")) in ("e", "a", "interrupted_erase") else "write",
                int(p2.get("p1_fault_at", 0)),
            )
            other_p2 = (other.get("phase2_fault") or {}) if other is not None else {}
            p1_pass = (
                (
                    "erase" if str(other_p2.get("p1_fault_type")) in ("e", "a", "interrupted_erase") else "write",
                    int(other_p2["p1_fault_at"]),
                )
                if "p1_fault_at" in other_p2 else None
            )
            attribute_ranges_to_operations(
                ranges, calibration_ops, flash_base=flash_base, fail_cut=p1_fail, pass_cut=p1_pass,
            )
    else:
        candidate_ops = []
        for candidate_row in (row, other):
            if not isinstance(candidate_row, dict):
                continue
            mram_ev = candidate_row.get("mram_fault_evidence") or {}
            if mram_ev.get("write_trace"):
                candidate_ops.extend(mram_ev["write_trace"])
            fw = candidate_row.get("fault_window") or {}
            if fw.get("operations"):
                candidate_ops.extend(fw["operations"])
            for key in ("before", "at", "after"):
                if isinstance(fw.get(key), dict):
                    candidate_ops.append(fw[key])
        if candidate_ops:
            attribute_ranges_to_operations(
                ranges, candidate_ops, flash_base=flash_base, fail_cut=fail_cut, pass_cut=pass_cut,
            )
        if calibration_ops and any("operation" not in span for span in ranges):
            attribute_ranges_to_operations(
                ranges, calibration_ops, flash_base=flash_base, fail_cut=fail_cut, pass_cut=pass_cut,
            )

    for span in ranges:
        op = span.get("operation")
        if isinstance(op, dict) and op.get("pc") and "source" not in op:
            op["source"] = source.resolve_pc(op["pc"])


def _format_cut_source(location, fallback_cut=None):
    if location:
        fn = location.get("function") or location.get("pc")
        if location.get("resolution") == "dwarf":
            return f"cut during {fn} at {location['file']}:{location['line']}"
        if location.get("resolution") == "symbol_table":
            return f"cut during {fn} at {location['pc']} (symbol table only)"
        if location.get("pc"):
            return f"cut during {location['pc']}"
    if fallback_cut:
        op = fallback_cut.get("operation", "operation")
        idx = fallback_cut.get("operation_index", "?")
        addr = f" ({fallback_cut['address']})" if fallback_cut.get("address") else ""
        return f"cut at {op} {idx}{addr}"
    return "cut"


def _format_recovery_source(location):
    if not location:
        return "unknown PC"
    fn = location.get("function")
    if location.get("resolution") == "dwarf":
        if fn:
            return f"{fn} {location['file']}:{location['line']}"
        return f"{location['file']}:{location['line']} ({location['pc']})"
    if location.get("resolution") == "symbol_table":
        return f"{fn} ({location['pc']}, symbol table only)"
    return str(location.get("pc") or "unknown PC")


def _format_range_label(span):
    addr_str = str(span["address"])
    size = max(1, len(span.get("failing_hex") or "") // 2)
    try:
        start = int(addr_str, 0)
        if size > 1:
            return f"0x{start:08X}..0x{(start + size - 1) & 0xFFFFFFFF:08X} ({size} bytes)"
        return f"0x{start:08X} (1 byte)"
    except Exception:
        return f"{addr_str} ({size} bytes)"


def _message(endpoint, comparison, cuts=()):
    spans = comparison.get("ranges") or []
    last_cut = cuts[-1] if cuts else None
    first_op = (spans[0].get("operation") if spans and isinstance(spans[0].get("operation"), dict) else None)
    cut_source = (
        (last_cut.get("source") if last_cut else None)
        or (first_op.get("source") if first_op else None)
    )
    cut_clause = _format_cut_source(cut_source, fallback_cut=last_cut or first_op)

    ecc_Notes = []
    if comparison.get("uncorrectable_only_in_failing"):
        ecc_Notes.append(f"uncorrectable ECC at {comparison['uncorrectable_only_in_failing'][0]} only in failing state")
    if comparison.get("uncorrectable_only_in_passing"):
        ecc_Notes.append(f"uncorrectable ECC at {comparison['uncorrectable_only_in_passing'][0]} only in passing state")
    ecc_suffix = f" ({'; '.join(ecc_Notes)})" if ecc_Notes else ""

    if spans:
        span = spans[0]
        size = len(span["failing_hex"]) // 2
        suffix = "…" if size > 16 else ""
        old_hex = span["failing_hex"][:32] + suffix
        new_hex = span["passing_hex"][:32] + suffix
        state_clause = f"leaves {_format_range_label(span)} holding {old_hex} instead of {new_hex}{ecc_suffix}"
    elif comparison.get("uncorrectable_only_in_failing"):
        addr = comparison["uncorrectable_only_in_failing"][0]
        state_clause = f"leaves {addr} holding uncorrectable ECC instead of clean data"
    elif comparison.get("persistent_values"):
        first = comparison["persistent_values"][0]
        state_clause = (
            f"leaves persistent value {first['name']} holding "
            f"{first['failing_hex']} instead of {first['passing_hex']}{ecc_suffix}"
        )
    elif comparison["status"] == "no_passing_sibling":
        state_clause = f"leaves persistent state with no passing sibling observed{ecc_suffix}"
    elif comparison["status"] in ("compared_persistent_state", "compared_identity_slot", "identical_snapshot_bytes"):
        state_clause = f"leaves persistent bytes matching the passing sibling{ecc_suffix}"
    else:
        state_clause = f"leaves persistent state with comparable snapshot bytes unavailable{ecc_suffix}"

    if endpoint["execution_evidence"] == "observed":
        outcome_label = endpoint["outcome"].replace("_", " ")
        image_note = f" with image {endpoint['matched_image']}" if endpoint.get("matched_image") else ""
        if endpoint.get("exception"):
            exc = endpoint["exception"]
            if endpoint.get("exception_entry"):
                entry_loc = _format_recovery_source(endpoint["exception_entry"])
                last_obs = endpoint.get("last_observed")
                if last_obs and last_obs.get("pc") != endpoint["exception_entry"].get("pc"):
                    end_loc = _format_recovery_source(last_obs)
                    recovery_clause = f"recovery triggered {exc}{image_note} at {entry_loc} (ended at {end_loc})"
                else:
                    recovery_clause = f"recovery triggered {exc}{image_note} at {entry_loc}"
            else:
                loc = _format_recovery_source(endpoint.get("last_observed") or endpoint.get("last_function"))
                recovery_clause = f"recovery triggered {exc}{image_note} at {loc}"
        elif endpoint.get("hang_loop"):
            loc = _format_recovery_source(endpoint["hang_loop"])
            recovery_clause = f"recovery hung in self-branch ({outcome_label}{image_note}) at {loc}"
        else:
            loc = _format_recovery_source(endpoint.get("last_observed") or endpoint.get("last_function"))
            recovery_clause = f"recovery ended with {outcome_label}{image_note} at {loc}"
    elif endpoint.get("copy_completed") is False:
        count = endpoint.get("completed_writes")
        progress = f" after {count} completed writes" if count is not None else ""
        recovery_clause = (
            f"recovery simulated copy was interrupted{progress} and its state verdict was {endpoint['outcome']}"
        )
    else:
        recovery_clause = f"recovery observed {endpoint['outcome']} with no recovery execution evidence"

    return f"{cut_clause} {state_clause}; {recovery_clause}"


def explain_recovery_failures(
    rows,
    expected,
    elf,
    root,
    trace_file=None,
    erase_trace_file=None,
    program_trace_file=None,
    flash_base=0,
    page_size=4096,
    write_granularity=4,
    trace_address_map=None,
):
    source = SourceLocations(elf, root)
    records = []
    comparisons = {}
    pre_states = {}
    for row in rows:
        candidate = row.pop("_sibling_snapshot_comparison", None)
        if candidate:
            comparisons[id(row)] = candidate
        raw_pre = row.pop("_pre_recovery_state", None)
        if raw_pre:
            decoded_pre = _decode_pre_recovery_state(raw_pre)
            if decoded_pre is not None:
                pre_states[id(row)] = decoded_pre
        if row.get("is_control") or point_status(row)[0]:
            continue
        paths = list(_cut_paths(row))
        if not paths:
            continue
        status = "other"
        if result_has_issues(row, expected):
            if "failure_explanation" not in row and (
                _effective_boot_result(row)[0] in (
                    "no_boot", "hard_fault", "bus_fault", "wrong_pc",
                    "misaligned_vtor", "wrong_image", "memory_checks_unmet",
                )
                or result_recovered_after_failure(row, expected)
            ):
                status = "failure"
        elif not result_is_timeout(row) and not row.get("semantic_observation_failures"):
            status = "pass"
        records.append((row, paths, status))

    calibration_ops = None

    def get_calibration_ops():
        nonlocal calibration_ops
        if calibration_ops is None:
            if trace_file or erase_trace_file or program_trace_file:
                try:
                    write_entries = (
                        load_clean_write_trace(trace_file)
                        if trace_file and os.path.isfile(trace_file)
                        else []
                    )
                    if not write_entries and program_trace_file and os.path.isfile(program_trace_file):
                        for prog in load_exact_program_trace(program_trace_file):
                            entry = {
                                "write_index": int(prog["write_index"]),
                                "flash_offset": max(0, int(prog["program_address"]) - int(flash_base)),
                                "value": int(prog["value"]),
                                "width": int(prog.get("program_width", write_granularity) or write_granularity),
                            }
                            if prog.get("pc"):
                                entry["pc"] = prog["pc"]
                            write_entries.append(entry)
                    erase_entries = (
                        load_clean_erase_trace(erase_trace_file, page_size=page_size)
                        if erase_trace_file and os.path.isfile(erase_trace_file)
                        else []
                    )
                    calibration_ops = build_clean_operation_trace(
                        write_entries=write_entries,
                        erase_entries=erase_entries,
                        flash_base=flash_base,
                        trace_address_map=trace_address_map,
                    )
                except Exception:
                    calibration_ops = []
            else:
                calibration_ops = []
        return calibration_ops

    for row, other, index in passing_siblings(records):
        sibling = None
        comparison = {"status": "no_passing_sibling"}
        cal_ops = get_calibration_ops()
        if other is not None:
            row_path = next(_cut_paths(row))
            kind = row_path[-1][1]
            sibling = {"operation_index": index, "fault_type": kind}
            if row.get("recovery_state_search"):
                sibling["state_identity"] = other["recovery_state_search"].get("state_identity")
            if len(row_path) >= 2 and not row.get("recovery_state_search"):
                other_paths = list(_cut_paths(other))
                if not any(p[:-1] == row_path[:-1] for p in other_paths):
                    for p in other_paths:
                        if len(p) == len(row_path) and p[-1][0] == index:
                            sibling["parent_operation_index"] = p[-2][0]
                            break
            candidate = comparisons.get(id(row))
            if candidate and candidate["sibling"] == sibling.get("state_identity"):
                comparison = candidate["comparison"]
            elif id(row) in pre_states and id(other) in pre_states:
                comparison = compare_persistent_states(pre_states[id(row)], pre_states[id(other)])
            else:
                comparison = compare_snapshots(row.get("fault_snapshot"), other.get("fault_snapshot"))
            _attribute_comparison_ranges(
                row, other, comparison, source, calibration_ops=cal_ops, flash_base=flash_base,
            )
        cuts = _resolve_cuts(row, source, calibration_ops=cal_ops, flash_base=flash_base)
        endpoint = _endpoint(row, expected, source)
        row["failure_explanation"] = {
            "message": _message(endpoint, comparison, cuts),
            "cuts": cuts,
            "passing_sibling": sibling,
            "state_comparison": comparison,
            "recovery": endpoint,
        }
