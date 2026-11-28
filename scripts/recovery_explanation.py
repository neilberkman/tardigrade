# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Explain recovery observations after classification, using recorded evidence."""

import base64
import importlib.util
import os
from pathlib import Path
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
from recovery_trace_comparison import comparison_message
from source_locations import SourceLocations
from trace_utils import (
    build_clean_operation_trace, load_clean_erase_trace, load_clean_write_trace,
    load_exact_program_trace,
)


def _cut_paths(row):
    """Canonical and equivalent power-cut paths within this runtime campaign."""
    cuts = point_cuts(row)
    if not cuts:
        raw_ft = row.get("fault_type")
        op_kind = str(row.get("operation_kind") or "").strip().lower()
        kind = {
            "w": "power_loss",
            "power_loss": "power_loss",
            "e": "interrupted_erase",
            "a": "interrupted_erase",
            "interrupted_erase": "interrupted_erase",
        }.get(raw_ft)
        if not kind and op_kind in ("erase", "program", "write"):
            kind = "interrupted_erase" if op_kind == "erase" else "power_loss"
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
        persistent_values = {}
        for name, val_b64 in (encoded.get("persistent_values") or {}).items():
            if isinstance(val_b64, str) and val_b64:
                persistent_values[str(name)] = bytearray(base64.b64decode(val_b64))
        return PersistentState.from_bytes(
            bytearray(raw),
            name="nvm",
            base_address=base,
            uncorrectable_words=tuple(marks),
            persistent_values=persistent_values,
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
    if endpoint["last_observed"] is not None:
        endpoint["last_function"] = endpoint["last_observed"]
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
        if item.get("call_context"):
            entry["call_context"] = item["call_context"]
        elif item.get("call_chain"):
            entry["call_context"] = item["call_chain"]
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
        if item.get("call_context"):
            entry["call_context"] = item["call_context"]
        elif item.get("call_chain"):
            entry["call_context"] = item["call_chain"]
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


def _attach_call_chain(target, pc, call_context, source, driver_functions=()):
    if not pc and not call_context:
        return
    chain, caller = source.resolve_call_chain(
        pc,
        call_context=call_context,
        driver_functions=driver_functions,
    )
    if not pc and chain:
        pc = chain[0].get("pc")
    if pc:
        target["pc"] = str(pc)
    if chain:
        target["call_chain"] = chain
    target["source"] = caller


def _resolve_cuts(row, source, calibration_ops=(), flash_base=0, driver_functions=()):
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
            call_ctx = raw_cut.get("call_context") or raw_cut.get("call_chain")
            if (not pc or not call_ctx) and idx == 0:
                cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
                if cal_op:
                    if not pc and cal_op.get("pc"):
                        pc = cal_op["pc"]
                    if not call_ctx and (cal_op.get("call_context") or cal_op.get("call_chain")):
                        call_ctx = cal_op.get("call_context") or cal_op.get("call_chain")
            if idx == len(chain) - 1:
                if not pc and row.get("fault_pc"):
                    pc = row["fault_pc"]
                if not call_ctx and row.get("fault_call_context"):
                    call_ctx = row["fault_call_context"]
            _attach_call_chain(entry, pc, call_ctx, source, driver_functions=driver_functions)
            if isinstance(raw_cut, dict):
                raw_cut.pop("call_context", None)
                if "call_chain" in entry:
                    raw_cut["call_chain"] = entry["call_chain"]
                if "source" in entry:
                    raw_cut["source"] = entry["source"]
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
        p1_ctx = p2.get("p1_fault_call_context")
        cal_op = _lookup_op_in_list(calibration_ops, p1_kind, p1_idx)
        if cal_op:
            if not p1_pc and cal_op.get("pc"):
                p1_pc = cal_op["pc"]
            if not p1_ctx and (cal_op.get("call_context") or cal_op.get("call_chain")):
                p1_ctx = cal_op.get("call_context") or cal_op.get("call_chain")
            if not p1_entry.get("address") and cal_op.get("address"):
                p1_entry["address"] = cal_op["address"]
        _attach_call_chain(p1_entry, p1_pc, p1_ctx, source, driver_functions=driver_functions)
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
        p2_ctx = (
            p2.get("p2_fault_call_context")
            or (p2_trace_op.get("call_context") if p2_trace_op else None)
            or row.get("fault_call_context")
        )
        _attach_call_chain(p2_entry, p2_pc, p2_ctx, source, driver_functions=driver_functions)
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
            call_ctx = cut_rec.get("fault_call_context") or cut_rec.get("call_chain")
            if (not pc or not call_ctx) and idx == 0:
                cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
                if cal_op:
                    if not pc and cal_op.get("pc"):
                        pc = cal_op["pc"]
                    if not call_ctx and (cal_op.get("call_context") or cal_op.get("call_chain")):
                        call_ctx = cal_op.get("call_context") or cal_op.get("call_chain")
            _attach_call_chain(entry, pc, call_ctx, source, driver_functions=driver_functions)
            if isinstance(cut_rec, dict):
                cut_rec.pop("fault_call_context", None)
                if "call_chain" in entry:
                    cut_rec["call_chain"] = entry["call_chain"]
                if "source" in entry:
                    cut_rec["source"] = entry["source"]
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
        call_ctx = row.get("fault_call_context") if idx == len(paths[0]) - 1 else None
        if not pc or not call_ctx:
            mram_ev = row.get("mram_fault_evidence") or {}
            if not pc and mram_ev.get("fault_pc"):
                pc = mram_ev["fault_pc"]
            if not call_ctx and mram_ev.get("fault_call_context"):
                call_ctx = mram_ev["fault_call_context"]
            if not pc or not call_ctx:
                mram_trace_ops = list(mram_ev.get("write_trace") or ()) + list(
                    mram_ev.get("erase_trace") or ()
                )
                mram_op = _lookup_op_in_list(mram_trace_ops, op_kind, op_index)
                if mram_op:
                    if not pc and mram_op.get("pc"):
                        pc = mram_op["pc"]
                    if not call_ctx and (mram_op.get("call_context") or mram_op.get("call_chain")):
                        call_ctx = mram_op.get("call_context") or mram_op.get("call_chain")
        if not pc or not call_ctx:
            fw = row.get("fault_window") or {}
            fw_ops = list(fw.get("operations") or ())
            for key in ("before", "at", "after"):
                if isinstance(fw.get(key), dict):
                    fw_ops.append(fw[key])
            fw_op = _lookup_op_in_list(fw_ops, op_kind, op_index)
            if fw_op:
                if not pc and fw_op.get("pc"):
                    pc = fw_op["pc"]
                if not call_ctx and (fw_op.get("call_context") or fw_op.get("call_chain")):
                    call_ctx = fw_op.get("call_context") or fw_op.get("call_chain")
                if not entry.get("address") and fw_op.get("address"):
                    entry["address"] = fw_op["address"]
        if (not pc or not call_ctx) and idx == 0:
            cal_op = _lookup_op_in_list(calibration_ops, op_kind, op_index)
            if cal_op:
                if not pc and cal_op.get("pc"):
                    pc = cal_op["pc"]
                if not call_ctx and (cal_op.get("call_context") or cal_op.get("call_chain")):
                    call_ctx = cal_op.get("call_context") or cal_op.get("call_chain")
                if not entry.get("address") and cal_op.get("address"):
                    entry["address"] = cal_op["address"]
                elif not entry.get("address") and "offset" in cal_op:
                    entry["address"] = f"0x{(int(flash_base) + int(cal_op['offset'])) & 0xFFFFFFFF:08X}"
        _attach_call_chain(entry, pc, call_ctx, source, driver_functions=driver_functions)
        cuts_out.append(entry)
    return cuts_out


def _attribute_comparison_ranges(row, other, comparison, source, calibration_ops=(), flash_base=0, driver_functions=()):
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
            if mram_ev.get("erase_trace"):
                candidate_ops.extend(mram_ev["erase_trace"])
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
        if isinstance(op, dict):
            call_ctx = op.pop("call_context", None) or op.get("call_chain")
            if op.get("pc") or call_ctx:
                _attach_call_chain(op, op.get("pc"), call_ctx, source, driver_functions=driver_functions)


def _annotate_row_operation_traces(row, source, driver_functions=()):
    if not isinstance(row, dict):
        return
    row.pop("fault_call_context", None)
    p2 = row.get("phase2_fault")
    if isinstance(p2, dict):
        p2.pop("p1_fault_call_context", None)
        p2.pop("p2_fault_call_context", None)
        for key in ("p2_write_trace", "p2_erase_trace"):
            for item in p2.get(key) or ():
                if isinstance(item, dict):
                    call_ctx = item.pop("call_context", None) or item.get("call_chain")
                    if item.get("pc") or call_ctx:
                        _attach_call_chain(item, item.get("pc"), call_ctx, source, driver_functions=driver_functions)
    mram_ev = row.get("mram_fault_evidence")
    if isinstance(mram_ev, dict):
        mram_ev.pop("fault_call_context", None)
        for key in ("write_trace", "erase_trace"):
            for item in mram_ev.get(key) or ():
                if isinstance(item, dict):
                    call_ctx = item.pop("call_context", None) or item.get("call_chain")
                    if item.get("pc") or call_ctx:
                        _attach_call_chain(item, item.get("pc"), call_ctx, source, driver_functions=driver_functions)
    fw = row.get("fault_window")
    if isinstance(fw, dict):
        for item in fw.get("operations") or ():
            if isinstance(item, dict):
                call_ctx = item.pop("call_context", None) or item.get("call_chain")
                if item.get("pc") or call_ctx:
                    _attach_call_chain(item, item.get("pc"), call_ctx, source, driver_functions=driver_functions)
        for key in ("before", "at", "after"):
            item = fw.get(key)
            if isinstance(item, dict):
                call_ctx = item.pop("call_context", None) or item.get("call_chain")
                if item.get("pc") or call_ctx:
                    _attach_call_chain(item, item.get("pc"), call_ctx, source, driver_functions=driver_functions)


_PROBE_MODULE_CACHE = {}

_TARGET_PROBE_SCRIPTS = {
    "mcuboot": "targets/mcuboot/probe.py",
    "tf_m_bl2": "targets/tf_m_bl2/probe.py",
    "tfm": "targets/tf_m_bl2/probe.py",
    "nxboot": "targets/nxboot/probe.py",
    "nuttx_nxboot": "targets/nuttx_nxboot/probe.py",
    "rustboot": "targets/rustboot/probe.py",
    "esp_idf": "targets/esp_idf/probe.py",
}


def _load_probe_module(script_path):
    if not script_path:
        return None
    resolved = str(Path(script_path).resolve())
    if resolved in _PROBE_MODULE_CACHE:
        return _PROBE_MODULE_CACHE[resolved]
    if not os.path.isfile(resolved):
        _PROBE_MODULE_CACHE[resolved] = None
        return None
    try:
        spec = importlib.util.spec_from_file_location("_tardigrade_state_probe", resolved)
        if spec is None or spec.loader is None:
            _PROBE_MODULE_CACHE[resolved] = None
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _PROBE_MODULE_CACHE[resolved] = module
        return module
    except Exception:
        _PROBE_MODULE_CACHE[resolved] = None
        return None


def _infer_target_probe_script(row, other, source, elf, root):
    repo_root = Path(root) if root else Path(__file__).resolve().parents[1]
    for candidate_row in (row, other):
        if not isinstance(candidate_row, dict):
            continue
        for key in ("fault_semantic_state", "semantic_state"):
            sem = candidate_row.get(key)
            if isinstance(sem, dict) and sem.get("target"):
                target_name = str(sem["target"]).strip().lower().replace("-", "_")
                rel = _TARGET_PROBE_SCRIPTS.get(target_name)
                if rel:
                    candidate = repo_root / rel
                    if candidate.is_file():
                        return str(candidate)
    elf_str = str(elf or "").lower()
    if "mcuboot" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["mcuboot"])
    if "tf_m" in elf_str or "tfm" in elf_str or "bl2" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["tf_m_bl2"])
    if "nuttx_nxboot" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["nuttx_nxboot"])
    if "nxboot" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["nxboot"])
    if "rustboot" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["rustboot"])
    if "esp_idf" in elf_str or "espidf" in elf_str:
        return str(repo_root / _TARGET_PROBE_SCRIPTS["esp_idf"])
    if source is not None and getattr(source, "index", None) is not None:
        sym_names = {name for _, _, name in getattr(source.index, "symbols", ())}
        if any(
            name.startswith(("boot_write_magic", "boot_write_trailer", "boot_swap_", "bootutil_"))
            for name in sym_names
        ):
            return str(repo_root / _TARGET_PROBE_SCRIPTS["mcuboot"])
        if any(name.startswith("nxboot_") for name in sym_names):
            return str(repo_root / _TARGET_PROBE_SCRIPTS["nxboot"])
    return None


def _collect_effective_slots(row, other, comparison, slots):
    out = {}
    if isinstance(slots, dict):
        for name, cfg in slots.items():
            if isinstance(cfg, dict) and "base" in cfg and "size" in cfg:
                try:
                    out[str(name)] = {
                        "base": int(str(cfg["base"]), 0),
                        "size": int(str(cfg["size"]), 0),
                    }
                except Exception:
                    pass
            elif hasattr(cfg, "base") and hasattr(cfg, "size"):
                out[str(name)] = {"base": int(cfg.base), "size": int(cfg.size)}
    for candidate_row in (row, other):
        if not isinstance(candidate_row, dict):
            continue
        for key in ("fault_semantic_state", "semantic_state"):
            sem = candidate_row.get(key)
            sem_slots = sem.get("slots") if isinstance(sem, dict) else None
            if isinstance(sem_slots, dict):
                for name, cfg in sem_slots.items():
                    if name not in out and isinstance(cfg, dict) and "base" in cfg and "size" in cfg:
                        try:
                            out[str(name)] = {
                                "base": int(str(cfg["base"]), 0),
                                "size": int(str(cfg["size"]), 0),
                            }
                        except Exception:
                            pass
    if not out and isinstance(comparison, dict) and comparison.get("base") and comparison.get("size"):
        try:
            out["exec"] = {
                "base": int(str(comparison["base"]), 0),
                "size": int(str(comparison["size"]), 0),
            }
        except Exception:
            pass
    return out


def _build_probe_boot_role(row, cuts=None):
    existing = row.get("boot_role") if isinstance(row, dict) else None
    if isinstance(existing, dict) and existing.get("phase"):
        role = dict(existing)
        if cuts and not role.get("preceding_cuts"):
            role["preceding_cuts"] = [dict(c) for c in cuts]
            role["preceding_cut"] = dict(cuts[-1])
            role["cut"] = dict(cuts[-1])
        return role
    row_dict = row if isinstance(row, dict) else {}
    signals = row_dict.get("signals") if isinstance(row_dict.get("signals"), dict) else {}
    is_ctrl = bool(row_dict.get("is_control") or row_dict.get("fault_type") == "control")
    phase = "first_operation" if is_ctrl else "recovery"
    resolved_cuts = [dict(c) for c in (cuts or ())]
    gen = (
        0
        if is_ctrl
        else int(
            signals.get("recovery_state_generation")
            or (len(resolved_cuts) if resolved_cuts else 1)
        )
    )
    replay_mode = str(signals.get("trace_replay_mode") or "").strip().lower()
    is_computed = bool(
        replay_mode in ("computed_recovery_state", "python", "native")
        or row_dict.get("recovery_state_search")
        or row_dict.get("fault_type") == "rs"
    )
    source_kind = "computed_source" if is_computed else "live_injection"
    last_cut = dict(resolved_cuts[-1]) if resolved_cuts else None
    reset_kind = "power_on" if is_ctrl else "power_loss"
    return {
        "phase": phase,
        "generation": gen,
        "source": source_kind,
        "is_computed_source": is_computed,
        "is_live_injection": not is_computed,
        "preceding_cut": last_cut,
        "preceding_cuts": resolved_cuts,
        "cut": dict(last_cut) if last_cut is not None else None,
        "reset_kind": reset_kind,
        "cycle": 0,
    }


def _resolve_probe_ranges(row, other, comparison, source, elf, root, state_probe=None, slots=None, page_size=4096, trailer_align=8, cuts=None):
    effective_slots = _collect_effective_slots(row, other, comparison, slots)
    align = trailer_align
    for candidate_row in (row, other):
        if isinstance(candidate_row, dict):
            for key in ("fault_semantic_state", "semantic_state"):
                sem = candidate_row.get(key)
                if isinstance(sem, dict) and sem.get("trailer_align"):
                    try:
                        align = int(str(sem["trailer_align"]), 0)
                    except Exception:
                        pass
    boot_role = _build_probe_boot_role(row, cuts=cuts)
    context = {
        "slots": effective_slots,
        "slot_geometry": effective_slots,
        "page_size": page_size,
        "trailer_align": align,
        "boot_role": boot_role,
        "boot_phase": boot_role["phase"],
        "boot_generation": boot_role["generation"],
        "boot_source": boot_role["source"],
        "is_computed_source": boot_role["is_computed_source"],
        "is_live_injection": boot_role["is_live_injection"],
        "preceding_cut": boot_role["preceding_cut"],
        "preceding_cuts": boot_role["preceding_cuts"],
        "cut": boot_role["cut"],
        "reset_kind": boot_role["reset_kind"],
    }
    raw_ranges = None
    if isinstance(state_probe, (list, tuple)):
        raw_ranges = state_probe
    elif callable(state_probe):
        try:
            raw_ranges = state_probe(context)
        except TypeError:
            raw_ranges = state_probe()
    elif hasattr(state_probe, "describe_ranges") and callable(state_probe.describe_ranges):
        raw_ranges = state_probe.describe_ranges(context)
    else:
        script_path = None
        if isinstance(state_probe, dict):
            if isinstance(state_probe.get("ranges"), (list, tuple)):
                raw_ranges = state_probe["ranges"]
            elif state_probe.get("script"):
                script_path = state_probe["script"]
        elif hasattr(state_probe, "script") and getattr(state_probe, "script"):
            script_path = state_probe.script
        elif isinstance(state_probe, (str, Path)) and str(state_probe).strip():
            script_path = str(state_probe).strip()
        if script_path and root and not os.path.isabs(str(script_path)):
            candidate = Path(root) / str(script_path)
            if candidate.is_file():
                script_path = str(candidate)
        if not script_path and raw_ranges is None:
            script_path = _infer_target_probe_script(row, other, source, elf, root)
        if script_path and raw_ranges is None:
            module = _load_probe_module(script_path)
            if module is not None and hasattr(module, "describe_ranges"):
                try:
                    raw_ranges = module.describe_ranges(context)
                except Exception:
                    raw_ranges = None
    normalized = []
    for item in raw_ranges or ():
        if not isinstance(item, dict) or not item.get("name"):
            continue
        try:
            start = int(str(item["start"]), 0)
            if "end" in item and item["end"] is not None:
                end = int(str(item["end"]), 0)
            else:
                end = start + int(str(item.get("size", 0)), 0)
        except Exception:
            continue
        if end > start:
            entry = {"start": start, "end": end, "name": str(item["name"])}
            if item.get("slot"):
                entry["slot"] = str(item["slot"])
            normalized.append(entry)
    return normalized


def _match_probe_range(start, end, probe_ranges):
    span_size = max(1, end - start)
    containing = [
        item for item in probe_ranges
        if item["start"] <= start and end <= item["end"]
    ]
    if containing:
        return min(containing, key=lambda item: (item["end"] - item["start"], item["start"]))
    best = None
    best_key = None
    for item in probe_ranges:
        ov_start = max(start, item["start"])
        ov_end = min(end, item["end"])
        overlap = ov_end - ov_start
        if overlap <= 0 or overlap * 2 < span_size:
            continue
        key = (overlap, 1 if item["start"] <= start < item["end"] else 0, -(item["end"] - item["start"]))
        if best_key is None or key > best_key:
            best_key = key
            best = item
    return best


def _annotate_comparison_probe_fields(comparison, probe_ranges):
    if not isinstance(comparison, dict) or not probe_ranges:
        return
    for span in comparison.get("ranges") or ():
        if not isinstance(span, dict) or not span.get("address"):
            continue
        try:
            start = int(str(span["address"]), 0)
        except Exception:
            continue
        size = max(1, len(span.get("failing_hex") or "") // 2)
        matched = _match_probe_range(start, start + size, probe_ranges)
        if matched is not None:
            span["field"] = matched["name"]
            if matched.get("slot") and "slot" not in span:
                span["slot"] = matched["slot"]


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
            addr_label = f"0x{start:08X}..0x{(start + size - 1) & 0xFFFFFFFF:08X} ({size} bytes)"
        else:
            addr_label = f"0x{start:08X} (1 byte)"
    except Exception:
        addr_label = f"{addr_str} ({size} bytes)"
    field = span.get("field")
    if field:
        return f"{field} {addr_label}"
    return addr_label


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
                loc = _format_recovery_source(endpoint.get("last_observed"))
                recovery_clause = f"recovery triggered {exc}{image_note} at {loc}"
        elif endpoint.get("hang_loop"):
            loc = _format_recovery_source(endpoint["hang_loop"])
            recovery_clause = f"recovery hung in self-branch ({outcome_label}{image_note}) at {loc}"
        else:
            loc = _format_recovery_source(endpoint.get("last_observed"))
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


def _resolve_trace_comparison(comparison, source, drivers):
    for pair in (comparison.get("first_differing_operation"),
                 comparison.get("last_completed_writer"),
                 comparison.get("interrupted_operation_covering_byte")):
        for side in comparison["trace_lengths"]:
            op = (pair or {}).get(side)
            if op:
                _attach_call_chain(op, op.get("pc"), op.get("call_context"), source, drivers)


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
    driver_functions=(),
    state_probe=None,
    slots=None,
    trailer_align=8,
):
    source = SourceLocations(elf, root)
    records = []
    comparisons = {}
    pre_states = {}
    for row in rows:
        comparison = row.get("recovery_trace_comparison")
        if comparison:
            _resolve_trace_comparison(comparison, source, driver_functions)
            row["error"] = row["error_reason"] + ": " + comparison_message(comparison)
        for sample in row.get("determinism_preflight", ()):
            for name in ("computed_vs_live", "computed_vs_repeat"):
                _resolve_trace_comparison(sample[name], source, driver_functions)
        # Saved reports can have an earlier symbol in last_function even
        # when the terminal PC was outside the supplied ELF.
        explanation = row.get("failure_explanation")
        recovery = explanation.get("recovery") if isinstance(explanation, dict) else None
        if isinstance(recovery, dict):
            if recovery.get("last_observed"):
                recovery["last_function"] = recovery["last_observed"]
            else:
                recovery.pop("last_function", None)
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
                            if prog.get("call_context"):
                                entry["call_context"] = prog["call_context"]
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
                row,
                other,
                comparison,
                source,
                calibration_ops=cal_ops,
                flash_base=flash_base,
                driver_functions=driver_functions,
            )
        cuts = _resolve_cuts(
            row,
            source,
            calibration_ops=cal_ops,
            flash_base=flash_base,
            driver_functions=driver_functions,
        )
        if other is not None:
            probe_ranges = _resolve_probe_ranges(
                row,
                other,
                comparison,
                source,
                elf,
                root,
                state_probe=state_probe,
                slots=slots,
                page_size=page_size,
                trailer_align=trailer_align,
                cuts=cuts,
            )
            _annotate_comparison_probe_fields(comparison, probe_ranges)
        _annotate_row_operation_traces(row, source, driver_functions=driver_functions)
        endpoint = _endpoint(row, expected, source)
        row["failure_explanation"] = {
            "message": _message(endpoint, comparison, cuts),
            "cuts": cuts,
            "passing_sibling": sibling,
            "state_comparison": comparison,
            "recovery": endpoint,
        }
