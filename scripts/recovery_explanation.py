# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Explain recovery observations after classification, using recorded evidence."""

from fault_classification import (
    _effective_boot_result, _effective_boot_signals, result_has_issues, result_is_timeout,
    result_recovered_after_failure,
)
from recovery_search import passing_siblings
from report_points import point_cuts, point_status
from source_locations import SourceLocations


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
    return endpoint


def _describe_location(location):
    if not location:
        return ""
    function = location.get("function", location["pc"])
    if location["resolution"] == "dwarf":
        return f" at {function} ({location['file']}:{location['line']})"
    if location["resolution"] == "symbol_table":
        return f" at {function} ({location['pc']}, symbol table only)"
    return f" at {location['pc']}"


def _message(endpoint, comparison):
    spans = comparison.get("ranges") or []
    details = []
    if spans:
        span = spans[0]
        size = len(span["failing_hex"]) // 2
        suffix = "…" if size > 16 else ""
        details.append(f"{size}-byte range at {span['address']} holds {span['failing_hex'][:32]}{suffix} "
                       f"(passing sibling holds {span['passing_hex'][:32]}{suffix})")
    elif comparison["status"] == "no_passing_sibling":
        details.append("no passing sibling was observed")
    elif comparison["status"] == "compared_persistent_state":
        details.append("the persistent memory bytes match")
    elif comparison["status"] == "compared_identity_slot":
        details.append("the compared slot bytes match")
    elif comparison["status"] == "identical_snapshot_bytes":
        details.append("the snapshot bytes match")
    else:
        details.append("comparable snapshot bytes are unavailable")
    for marked, label in (("uncorrectable_only_in_failing", "failing"), ("uncorrectable_only_in_passing", "passing")):
        if comparison.get(marked):
            details.append(f"{comparison[marked][0]} is uncorrectable only in the {label} state")
    values = comparison.get("persistent_values") or []
    if values:
        first = values[0]
        details.append(f"persistent value {first['name']} differs between the two states")
    if endpoint["execution_evidence"] == "observed":
        observed = endpoint.get("exception") or endpoint["outcome"].replace("_", " ")
        if endpoint.get("hang_loop"):
            observed += " in a self-branch"
        if endpoint.get("matched_image"):
            observed += f" with image {endpoint['matched_image']}"
        if endpoint.get("exception_entry"):
            details.append(observed + " on exception entry" + _describe_location(endpoint["exception_entry"]))
            details.append("last recovery PC" + _describe_location(endpoint["last_observed"]))
        else:
            details.append("recovery reported " + observed + _describe_location(endpoint["last_observed"]))
    elif endpoint.get("copy_completed") is False:
        count = endpoint.get("completed_writes")
        progress = f" after {count} completed writes" if count is not None else ""
        details.append(f"the simulated copy was interrupted{progress} and its state verdict was {endpoint['outcome']}")
    else:
        details.append(f"observed {endpoint['outcome']} with no recovery execution evidence")
    return ". ".join(s[:1].upper() + s[1:] for s in details) + "."


def explain_recovery_failures(rows, expected, elf, root):
    source = SourceLocations(elf, root)
    records = []
    comparisons = {}
    for row in rows:
        candidate = row.pop("_sibling_snapshot_comparison", None)
        if candidate:
            comparisons[id(row)] = candidate
        if row.get("is_control") or point_status(row)[0]:
            continue
        paths = list(_cut_paths(row))
        if not paths:
            continue
        status = "other"
        if result_has_issues(row, expected):
            if "failure_explanation" not in row and (
                _effective_boot_result(row)[0] in ("no_boot", "hard_fault", "bus_fault", "wrong_pc", "misaligned_vtor")
                or result_recovered_after_failure(row, expected)
            ):
                status = "failure"
        elif not result_is_timeout(row) and not row.get("semantic_observation_failures"):
            status = "pass"
        records.append((row, paths, status))

    for row, other, index in passing_siblings(records):
        sibling = None
        comparison = {"status": "no_passing_sibling"}
        if other is not None:
            kind = next(_cut_paths(row))[-1][1]
            sibling = {"operation_index": index, "fault_type": kind}
            if row.get("recovery_state_search"):
                sibling["state_identity"] = other["recovery_state_search"].get("state_identity")
            candidate = comparisons.get(id(row))
            if candidate and candidate["sibling"] == sibling.get("state_identity"):
                comparison = candidate["comparison"]
            else:
                comparison = compare_snapshots(row.get("fault_snapshot"), other.get("fault_snapshot"))
        endpoint = _endpoint(row, expected, source)
        row["failure_explanation"] = {
            "message": _message(endpoint, comparison), "passing_sibling": sibling,
            "state_comparison": comparison, "recovery": endpoint,
        }
