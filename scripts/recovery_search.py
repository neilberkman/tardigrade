# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Pure helpers for deterministic recovery-state exploration."""

from __future__ import division

import binascii
import copy
import hashlib
from bisect import bisect_left
from collections import defaultdict, deque

from recovery_trace_comparison import RecoveryTraceMismatch
from recovery_checkpoint import SnapshotWriter, restore_snapshots, validate_checkpoint
from recovery_state import (
    normalize_trace,
    apply_completed_operation,
    apply_interrupted_operation,
)


class RecoverySearchError(ValueError):
    pass


SUPPORTED_SEARCH_ORDERS = ("breadth_first", "coverage_guided")

try:
    _string_types = (basestring,)
except NameError:
    _string_types = (str,)

try:
    _integer_types = (int, long)
except NameError:
    _integer_types = (int,)


def _is_int(value):
    return isinstance(value, _integer_types) and not isinstance(value, bool)


def _normalize_coverage_unit(unit):
    if _is_int(unit):
        return int(unit) & ~1
    text = str(unit).strip()
    if not text:
        raise RecoverySearchError("coverage unit must not be empty")
    try:
        return int(text, 0) & ~1
    except ValueError:
        return text


def _coverage_signature(units):
    digest = hashlib.sha256()
    digest.update(b"tardigrade-recovery-search-cov-v1\0")
    for item in sorted((str(u) for u in (units or ()))):
        digest.update(item.encode("utf-8"))
        digest.update(b"\0")
    return binascii.hexlify(digest.digest()).decode("ascii")


def _extract_result_coverage_units(result):
    if not isinstance(result, dict):
        return None
    cov = result.get("recovery_coverage")
    if isinstance(cov, dict) and "executed_pcs" in cov:
        return cov.get("executed_pcs")
    signals = result.get("signals")
    if isinstance(signals, dict) and "recovery_coverage_pcs" in signals:
        return signals.get("recovery_coverage_pcs")
    return None


def _byte_value(value):
    if isinstance(value, _string_types):
        if len(value) != 1:
            raise RecoverySearchError("persistent byte value is not one character")
        return ord(value)
    return int(value) & 0xFF


def _hex_value(value):
    return "".join("{:02x}".format(_byte_value(item)) for item in value)


def search_cut_paths(row):
    search = row["recovery_state_search"]
    chains = [search["chain"]] + search.get("equivalent_chains", [])
    return [tuple((cut["operation_index"], cut["fault_type"]) for cut in chain["cuts"])
            for chain in chains]


def _final_cut_address(row):
    try:
        return int(str(row.get("fault_address") or "0"), 0)
    except Exception:
        return 0


def passing_siblings(records):
    """Match canonical failures to passing paths in the same parent and index domain."""
    if not any(status == "failure" for _, _, status in records):
        return
    parents = {}
    for row, paths, _ in records:
        state = (row.get("recovery_state_search") or {}).get("state_identity")
        if state:
            for path in paths:
                parents[path] = state

    def group(row, path):
        search = bool(row.get("recovery_state_search"))
        prefix = path[:-1]
        parent = parents.get(prefix, prefix) if search else prefix
        return search, parent, path[-1][1]

    passed = defaultdict(dict)
    multi_cut_passed = []
    for row, paths, status in records:
        if status == "pass":
            for path in paths:
                passed[group(row, path)][path[-1][0]] = row
                if len(path) >= 2:
                    multi_cut_passed.append((bool(row.get("recovery_state_search")), path, row))
    indices = dict((key, sorted(rows)) for key, rows in passed.items())
    for row, paths, status in records:
        if status != "failure":
            continue
        path = paths[0]
        key = group(row, path)
        index = path[-1][0]
        ordered = indices.get(key, [])
        pos = bisect_left(ordered, index)
        nearby = [i for i in ordered[max(0, pos - 1):pos + 2] if i != index]
        chosen = min(nearby, key=lambda i: (abs(i - index), i)) if nearby else None
        if chosen is not None:
            yield row, passed[key].get(chosen), chosen
            continue
        if len(path) >= 2:
            search = bool(row.get("recovery_state_search"))
            row_addr = _final_cut_address(row)
            candidates = [
                (cand_path, cand_row)
                for cand_search, cand_path, cand_row in multi_cut_passed
                if cand_search == search
                and len(cand_path) == len(path)
                and cand_path[:-2] == path[:-2]
                and cand_path[-2][1] == path[-2][1]
                and cand_path[-1][1] == path[-1][1]
                and cand_path != path
            ]
            if candidates:
                best_path, best_row = min(
                    candidates,
                    key=lambda item: (
                        abs(item[0][-2][0] - path[-2][0]),
                        item[0][-2][0],
                        0 if (row_addr and _final_cut_address(item[1]) == row_addr) else 1,
                        abs(item[0][-1][0] - index),
                        item[0][-1][0],
                    ),
                )
                yield row, best_row, best_path[-1][0]
                continue
        yield row, None, None


def compare_persistent_states(failing, passing):
    """Compare the actual pre-recovery states retained by the explorer."""
    ranges = []
    for left in failing.regions:
        right = passing.region(left.name)
        if (left.base_address, left.length) != (right.base_address, right.length):
            raise RecoverySearchError("sibling states have incompatible region geometry")
        start = None
        for index, (bad, good) in enumerate(zip(left.chunks, right.chunks)):
            offset = index * left.chunk_size
            if bad == good:
                if start is not None:
                    ranges.append((left, right, start, offset))
                    start = None
                continue
            for i in range(len(bad)):
                if bad[i] != good[i]:
                    if start is None:
                        start = offset + i
                elif start is not None:
                    end = offset + i
                    ranges.append((left, right, start, end))
                    start = None
        if start is not None:
            ranges.append((left, right, start, left.length))

    def addresses(state, marks):
        return ["0x{:08X}".format(state.region(name).base_address + offset)
                for name, offset in sorted(marks)]

    bad_values, good_values = dict(failing.persistent_values), dict(passing.persistent_values)
    return {
        "status": "compared_persistent_state",
        "ranges": [
            {"region": left.name, "address": "0x{:08X}".format(left.base_address + start),
             "failing_hex": binascii.hexlify(left.read(start, end - start)).decode("ascii"),
             "passing_hex": binascii.hexlify(right.read(start, end - start)).decode("ascii")}
            for left, right, start, end in ranges
        ],
        "uncorrectable_only_in_failing": addresses(failing, failing.uncorrectable_words - passing.uncorrectable_words),
        "uncorrectable_only_in_passing": addresses(passing, passing.uncorrectable_words - failing.uncorrectable_words),
        "persistent_values": [
            {"name": name,
             "failing_hex": _hex_value(bad_values[name]) if name in bad_values else None,
             "passing_hex": _hex_value(good_values[name]) if name in good_values else None}
            for name in sorted(set(bad_values) | set(good_values))
            if bad_values.get(name) != good_values.get(name)
        ],
    }


def select_first_cuts(total_writes, first_cuts):
    total_writes = max(0, int(total_writes))
    config = first_cuts or {}
    mode = str(config.get("mode", "quick")).strip().lower()
    excluded = 0
    if mode == "quick":
        if total_writes <= 3:
            selected = list(range(total_writes))
        else:
            selected = sorted(set((0, total_writes // 2, total_writes - 1)))
    elif mode in ("all", "distinct_states"):
        selected = list(range(total_writes))
    elif mode == "ranges":
        selected_set = set()
        for item in config.get("ranges", []):
            start = int(item["start"])
            end = int(item["end"])
            for index in range(start, end + 1):
                if index < total_writes:
                    selected_set.add(index)
                else:
                    excluded += 1
        selected = sorted(selected_set)
    else:
        raise RecoverySearchError("unknown first-cut mode {!r}".format(mode))
    return selected, excluded


def select_first_cut_operations(operations, first_cuts):
    """Select typed first cuts from the write and erase trace domains."""
    config = first_cuts or {}
    fault_types = config.get("fault_types") or ("power_loss",)
    kinds = []
    for fault_type in fault_types:
        normalized = str(fault_type).strip().lower()
        if normalized == "power_loss":
            kind = "write"
        elif normalized == "interrupted_erase":
            kind = "erase"
        else:
            raise RecoverySearchError(
                "unsupported first-cut fault type {!r}".format(fault_type)
            )
        if kind not in kinds:
            kinds.append(kind)

    counts = dict((kind, 0) for kind in ("write", "erase"))
    for operation in operations:
        kind = str(operation.get("kind") or "")
        if kind in counts:
            counts[kind] += 1

    selected = []
    excluded = {"write": 0, "erase": 0}
    for kind in kinds:
        indices, excluded_count = select_first_cuts(counts[kind], config)
        selected.extend((kind, index) for index in indices)
        excluded[kind] = excluded_count
    return tuple(selected), excluded


def operation_in_address_ranges(operation, flash_base, address_ranges):
    if not address_ranges:
        return True
    start = int(flash_base) + int(operation["offset"])
    length = (
        int(operation["width"])
        if operation["kind"] == "write"
        else int(operation["erase_size"])
    )
    end = start + length
    return any(
        end > int(item["start"]) and start <= int(item["end"])
        for item in address_ranges
    )


def recovery_operation_kinds(recovery_fault_types):
    normalized_recovery_fault_types = tuple(
        str(fault_type).strip().lower()
        for fault_type in recovery_fault_types
    )
    unsupported_recovery_fault_types = sorted(
        set(normalized_recovery_fault_types)
        - set(("power_loss", "interrupted_erase"))
    )
    if unsupported_recovery_fault_types:
        raise RecoverySearchError(
            "unsupported recovery cut type(s) {!r}".format(
                unsupported_recovery_fault_types
            )
        )
    return frozenset(
        kind
        for fault_type, kind in (
            ("power_loss", "write"),
            ("interrupted_erase", "erase"),
        )
        if fault_type in normalized_recovery_fault_types
    )


def _recovery_exclusion(operation, kinds, flash_base, ranges):
    if operation["kind"] not in kinds:
        return "recovery_operations_excluded_by_fault_type"
    if not operation_in_address_ranges(operation, flash_base, ranges):
        return "recovery_operations_excluded_by_address"
    return None


def _count_recovery_candidates(operations, kinds, flash_base, ranges):
    return sum(
        1 for operation in operations
        if _recovery_exclusion(operation, kinds, flash_base, ranges) is None
    )


def recovery_trace_size(operations, tracking_start, flash_base, config):
    kinds = recovery_operation_kinds(config.get("fault_types") or ("power_loss",))
    ranges = config.get("address_ranges") or ()
    return {
        "address": "0x{:08X}".format(tracking_start),
        "traced_operations": len(operations),
        "candidate_operations": _count_recovery_candidates(
            operations, kinds, flash_base, ranges
        ),
    }


def format_cut(operation, flash_base, fault_type="power_loss"):
    operation_kind = str(operation["kind"])
    operation_index = int(operation["operation_index"])
    address = int(flash_base) + int(operation["offset"])
    cut = {
        "operation": operation_kind,
        "operation_index": operation_index,
        "trace_sequence": int(operation.get("sequence", operation_index)),
        "address": "0x{:08X}".format(address & 0xFFFFFFFF),
        "fault_type": (
            "interrupted_erase" if operation_kind == "erase" else str(fault_type)
        ),
    }
    if operation.get("pc"):
        cut["pc"] = str(operation["pc"])
    if operation.get("call_context"):
        cut["call_context"] = str(operation["call_context"])
    return cut


def attribute_ranges_to_operations(
    ranges,
    operations,
    flash_base=0,
    fail_cut=None,
    pass_cut=None,
):
    """Map each differing byte range to the trace operation that produced it."""
    if not ranges or not operations:
        return
    normalized_ops = []
    for seq_idx, op in enumerate(operations):
        kind = str(op.get("kind") or op.get("operation") or "").lower()
        if not kind:
            if "write_index" in op:
                kind = "write"
            elif "erase_index" in op:
                kind = "erase"
        if kind not in ("write", "erase"):
            continue
        if "operation_index" in op:
            op_index = int(op["operation_index"])
        elif kind == "write" and "write_index" in op:
            op_index = int(op["write_index"]) - 1
        elif kind == "erase" and "erase_index" in op:
            op_index = int(op["erase_index"]) - 1
        else:
            continue
        if "address" in op and op["address"] is not None:
            addr = int(str(op["address"]), 0)
        elif "program_address" in op and op["program_address"] is not None:
            addr = int(str(op["program_address"]), 0)
        else:
            off = int(op.get("offset", op.get("flash_offset", 0)))
            addr = int(flash_base) + off
        if kind == "write":
            size = int(op.get("width", op.get("program_width", 4)) or 4)
        else:
            size = int(op.get("erase_size", op.get("size", 4096)) or 4096)
        if size <= 0:
            size = 4
        entry = {
            "operation": kind,
            "operation_index": op_index,
            "address": "0x{:08X}".format(addr & 0xFFFFFFFF),
            "size": size,
            "_start": addr,
            "_end": addr + size,
            "_seq": int(op.get("sequence", seq_idx)),
        }
        if op.get("pc"):
            entry["pc"] = str(op["pc"])
        if op.get("call_context"):
            entry["call_context"] = str(op["call_context"])
        normalized_ops.append(entry)
    if not normalized_ops:
        return

    fail_seq = None
    pass_seq = None
    if fail_cut is not None:
        for item in normalized_ops:
            if (
                item["operation"] == fail_cut[0]
                and item["operation_index"] == fail_cut[1]
            ):
                fail_seq = item["_seq"]
                break
    if pass_cut is not None:
        for item in normalized_ops:
            if (
                item["operation"] == pass_cut[0]
                and item["operation_index"] == pass_cut[1]
            ):
                pass_seq = item["_seq"]
                break
    lo_seq = (
        min(fail_seq, pass_seq)
        if fail_seq is not None and pass_seq is not None
        else None
    )
    hi_seq = (
        max(fail_seq, pass_seq)
        if fail_seq is not None and pass_seq is not None
        else (fail_seq if fail_seq is not None else pass_seq)
    )

    for span in ranges:
        if "operation" in span:
            continue
        try:
            start = int(str(span["address"]), 0)
        except Exception:
            continue
        span_len = max(1, len(str(span.get("failing_hex") or "")) // 2)
        end = start + span_len
        overlapping = [
            item
            for item in normalized_ops
            if item["_start"] < end and start < item["_end"]
        ]
        if not overlapping:
            continue
        covering_start = [
            item
            for item in overlapping
            if item["_start"] <= start < item["_end"]
        ]
        if covering_start:
            overlapping = covering_start
        chosen = None
        if lo_seq is not None and hi_seq is not None:
            window = [
                item
                for item in overlapping
                if lo_seq <= item["_seq"] <= hi_seq
            ]
            if window:
                if fail_seq is not None:
                    exact_fail = [
                        item for item in window if item["_seq"] == fail_seq
                    ]
                    if exact_fail:
                        chosen = exact_fail[-1]
                if chosen is None:
                    chosen = window[-1]
        if chosen is None and hi_seq is not None:
            before_hi = [
                item for item in overlapping if item["_seq"] <= hi_seq
            ]
            if before_hi:
                chosen = before_hi[-1]
        if chosen is None:
            chosen = overlapping[-1]
        public_op = {
            "operation": chosen["operation"],
            "operation_index": chosen["operation_index"],
            "address": chosen["address"],
            "size": chosen["size"],
        }
        if chosen.get("pc"):
            public_op["pc"] = chosen["pc"]
        if chosen.get("call_context"):
            public_op["call_context"] = chosen["call_context"]
        span["operation"] = public_op


def format_chain(chain):
    cuts = [dict(cut) for cut in chain]
    result = {
        "cuts": cuts,
        "cut_count": len(cuts),
        "text": " -> ".join(
            "{}[{}]@{}".format(
                cut["operation"], cut["operation_index"], cut["address"]
            )
            for cut in cuts
        ),
    }
    if len(cuts) == 2:
        pair = [cuts[0]["operation_index"], cuts[1]["operation_index"]]
        result["phase2_fault_pair"] = pair
        result["phase2_fault_pair_yaml"] = "- [{}, {}]".format(pair[0], pair[1])
        result["phase2_fault_pair_first_fault_type"] = cuts[0]["fault_type"]
        result["phase2_fault_pair_fault_type"] = cuts[1]["fault_type"]
        result["phase2_fault_yaml"] = (
            "first_fault_types: [{}]\n"
            "fault_types: [{}]\n"
            "pairs:\n"
            "  - [{}, {}]"
        ).format(
            cuts[0]["fault_type"], cuts[1]["fault_type"], pair[0], pair[1]
        )
    elif len(cuts) > 2:
        explicit = [
            [int(cut["operation_index"]), str(cut["fault_type"])]
            for cut in cuts
        ]
        inline = ", ".join(
            "[{}, {}]".format(operation_index, fault_type)
            for operation_index, fault_type in explicit
        )
        result["phase2_fault_chain"] = explicit
        result["phase2_fault_chain_yaml"] = "- [{}]".format(inline)
        result["phase2_fault_yaml"] = "chains:\n  - [{}]".format(inline)
    return result


class StateVerdictCache(object):
    def __init__(self):
        self._entries = {}

    def get(self, state):
        return self._entries.get(state.identity())

    def remember(self, state, entry):
        key = state.identity()
        if key in self._entries:
            raise RecoverySearchError("persistent state was already evaluated")
        self._entries[key] = entry
        return key

    def __len__(self):
        return len(self._entries)


class SearchBudget(object):
    def __init__(self, max_new_states, max_wall_time_s, clock):
        self.max_new_states = int(max_new_states)
        self.max_wall_time_s = float(max_wall_time_s)
        self.clock = clock
        self.started_at = float(clock())
        self.booted = 0

    def wall_time_s(self):
        return max(0.0, float(self.clock()) - self.started_at)

    def wall_expired(self):
        return self.wall_time_s() >= self.max_wall_time_s

    def boot_limit_reached(self):
        return self.booted >= self.max_new_states

    def can_boot(self):
        return not self.wall_expired() and not self.boot_limit_reached()

    def record_boot(self):
        if not self.can_boot():
            raise RecoverySearchError("cannot boot a state after a search bound")
        self.booted += 1


def first_persistent_difference(
    expected,
    observed_regions,
    observed_uncorrectable,
    observed_persistent_values=None,
):
    expected_regions = expected.materialize()
    for region in expected.regions:
        observed = observed_regions.get(region.name)
        if observed is None:
            return {
                "kind": "missing_region",
                "region": region.name,
                "address": "0x{:08X}".format(region.base_address & 0xFFFFFFFF),
            }
        observed = bytes(bytearray(observed))
        wanted = expected_regions[region.name]
        common = min(len(wanted), len(observed))
        for offset in range(common):
            wanted_value = _byte_value(wanted[offset])
            observed_value = _byte_value(observed[offset])
            if wanted_value != observed_value:
                return {
                    "kind": "bytes",
                    "region": region.name,
                    "offset": offset,
                    "address": "0x{:08X}".format(
                        (region.base_address + offset) & 0xFFFFFFFF
                    ),
                    "expected": "0x{:02X}".format(wanted_value),
                    "observed": "0x{:02X}".format(observed_value),
                }
        if len(wanted) != len(observed):
            return {
                "kind": "region_length",
                "region": region.name,
                "address": "0x{:08X}".format(
                    (region.base_address + common) & 0xFFFFFFFF
                ),
                "expected": len(wanted),
                "observed": len(observed),
            }
    expected_marks = set(expected.uncorrectable_words)
    observed_marks = set(
        (str(region), int(offset)) for region, offset in observed_uncorrectable
    )
    if expected_marks != observed_marks:
        missing = sorted(expected_marks - observed_marks)
        extra = sorted(observed_marks - expected_marks)
        region_name, offset = (missing or extra)[0]
        region = expected.region(region_name)
        return {
            "kind": "uncorrectable_words",
            "region": region_name,
            "offset": offset,
            "address": "0x{:08X}".format(
                (region.base_address + offset) & 0xFFFFFFFF
            ),
            "expected_marked": bool(missing),
            "observed_marked": bool(extra),
        }
    expected_values = dict(expected.persistent_values)
    observed_values = dict(
        (str(name), bytes(bytearray(value)))
        for name, value in (observed_persistent_values or {}).items()
    )
    if expected_values != observed_values:
        differing_names = sorted(
            name
            for name in set(expected_values) | set(observed_values)
            if expected_values.get(name) != observed_values.get(name)
        )
        name = differing_names[0]
        expected_value = expected_values.get(name)
        observed_value = observed_values.get(name)
        return {
            "kind": "persistent_value",
            "name": name,
            "expected": (
                None if expected_value is None else _hex_value(expected_value)
            ),
            "observed": (
                None if observed_value is None else _hex_value(observed_value)
            ),
        }
    return None


def attach_search_metadata(result, chain, state, generation, reused=False):
    target = copy.deepcopy(result) if reused else result
    metadata = {
        "generation": int(generation),
        "state_identity": state.identity_hex(),
        "reused": bool(reused),
        "chain": format_chain(chain),
    }
    target["recovery_state_search"] = metadata
    target["fault_requested"] = 0
    target["fault_type"] = "rs"
    if chain:
        target["fault_at"] = int(chain[0]["operation_index"])
        target["fault_address"] = chain[-1]["address"]
        first_op = str(chain[0].get("operation") or "").strip().lower()
        first_ft = str(chain[0].get("fault_type") or "").strip().lower()
        target["operation_kind"] = (
            "erase"
            if (
                first_op == "erase"
                or first_ft in ("e", "a", "interrupted_erase", "multi_sector_atomicity")
            )
            else "program"
        )
    return target


def add_equivalent_chain(result, chain, cross_check=None):
    metadata = result.setdefault("recovery_state_search", {})
    equivalent = metadata.setdefault("equivalent_chains", [])
    formatted = format_chain(chain)
    for existing in equivalent:
        if existing.get("cuts") == formatted.get("cuts"):
            if cross_check is not None:
                existing["cross_check"] = copy.deepcopy(cross_check)
            return
    if cross_check is not None:
        formatted["cross_check"] = copy.deepcopy(cross_check)
    equivalent.append(formatted)


class RecoveryStateExplorer(object):
    """Breadth-first exploration with one boot per persistent state.

    ``boot_state`` receives ``(state, chain, generation)`` and returns the
    ordinary runtime result, the recovery operation trace, and optionally the
    complete persistent state captured when that trace began. The optional
    state equals ``state`` for boot-start tracing. The trace is used only after
    the result has been retained in the verdict cache, so equivalent paths
    never cause another recovery boot.
    """

    _normalize_trace = staticmethod(normalize_trace)

    def __init__(
        self,
        initial_state,
        calibration_operations,
        first_cuts,
        max_cuts,
        max_new_states,
        max_wall_time_s,
        clock,
        boot_state,
        flash_base=0,
        address_ranges=(),
        backend_kind="flash",
        torn_word_mode="half",
        torn_word_for_cut=None,
        erase_fill=0xFF,
        corruption_seed=0,
        page_size=4096,
        program_unit=4,
        recovery_fault_types=("power_loss",),
        cross_check_every=0,
        cross_check=None,
        plan_only=False,
        order="breadth_first",
        max_boots_without_new_coverage=None,
        coverage_for_result=None,
        initial_coverage=(),
    ):
        self.initial_state = initial_state
        self.calibration_operations = self._normalize_trace(calibration_operations)
        self.first_cuts = tuple(
            (str(item[0]), int(item[1]))
            if isinstance(item, (tuple, list)) and len(item) == 2
            else ("write", int(item))
            for item in first_cuts
        )
        self.max_cuts = int(max_cuts)
        self.boot_state = boot_state
        self.flash_base = int(flash_base)
        self.address_ranges = tuple(address_ranges or ())
        self.backend_kind = str(backend_kind)
        self.torn_word_mode = str(torn_word_mode)
        self.torn_word_for_cut = torn_word_for_cut
        self.erase_fill = int(erase_fill) & 0xFF
        self.corruption_seed = int(corruption_seed) & 0xFFFFFFFF
        self.page_size = int(page_size)
        self.program_unit = int(program_unit)
        normalized_order = str(order or "breadth_first").strip().lower()
        if normalized_order not in SUPPORTED_SEARCH_ORDERS:
            raise RecoverySearchError(
                "unsupported state_search order {!r}; expected one of {}".format(
                    order, list(SUPPORTED_SEARCH_ORDERS)
                )
            )
        self.order = normalized_order
        if max_boots_without_new_coverage is not None:
            if not _is_int(max_boots_without_new_coverage) or int(
                max_boots_without_new_coverage
            ) < 1:
                raise RecoverySearchError(
                    "max_boots_without_new_coverage must be a positive integer"
                )
            self.max_boots_without_new_coverage = int(
                max_boots_without_new_coverage
            )
        else:
            self.max_boots_without_new_coverage = None
        self.coverage_for_result = coverage_for_result
        self.initial_coverage = frozenset(
            _normalize_coverage_unit(u) for u in (initial_coverage or ())
        )
        self.recovery_operation_kinds = recovery_operation_kinds(recovery_fault_types)
        self.cross_check_every = int(cross_check_every)
        self.cross_check = cross_check
        self._boot_times = []
        self.plan_only = plan_only
        self.budget = SearchBudget(max_new_states, max_wall_time_s, clock)
        self._seen = {}
        self._booted_states = {}
        self._traces = []
        # A frame retains the completed prefix immediately before its next cut.
        # Parent None denotes the calibration trace; other parents index results.
        self._frames = deque([(None, 0, initial_state, 0)] if self.calibration_operations else [])
        self._pending = deque()
        self._computed_frontier = {}
        self._prior_elapsed = 0.0
        self._resumed = False
        self._deeper_cross_check_candidates = 0
        self._seen_coverage = set(self.initial_coverage)
        self._recovery_coverage_seen = set()
        self._unit_first_boot = {}
        self._unit_boot_count = {}
        self._seen_signatures = (
            set([_coverage_signature(self.initial_coverage)])
            if self.initial_coverage
            else set()
        )
        self._signature_boot_count = {}
        self._expanded_signatures = set()
        self._productive_signatures = set()
        self._parent_cov = {}
        self._consecutive_boots_without_new_coverage = 0
        self._discovery_counter = 0
        self._current_cov_parent = None
        self._coverage_tracking_active = bool(
            self.order == "coverage_guided"
            or self.max_boots_without_new_coverage is not None
            or self.coverage_for_result is not None
            or self.initial_coverage
        )
        self.results = []
        self.summary = {
            "order": self.order,
            "max_boots_without_new_coverage": self.max_boots_without_new_coverage,
            "first_cuts_selected": len(self.first_cuts),
            "first_cut_programs_selected": sum(
                1 for kind, _index in self.first_cuts if kind == "write"
            ),
            "first_cut_erases_selected": sum(
                1 for kind, _index in self.first_cuts if kind == "erase"
            ),
            "first_cut_states_computed": 0,
            "first_cut_program_states_computed": 0,
            "first_cut_erase_states_computed": 0,
            "states_computed": 0,
            "states_booted": 0,
            "single_cut_states_booted": 0,
            "single_cut_program_states_booted": 0,
            "single_cut_erase_states_booted": 0,
            "deeper_cut_states_booted": 0,
            "states_reused": 0,
            "program_first_states_reused": 0,
            "erase_first_states_reused": 0,
            "recovery_operations_seen": 0,
            "recovery_operations_considered": 0,
            "recovery_operations_excluded_by_fault_type": 0,
            "recovery_operations_excluded_by_address": 0,
            "recovery_operations_excluded_by_max_cuts": 0,
            "states_excluded_by_max_new_states": 0,
            "states_excluded_by_wall_time": 0,
            "states_excluded_by_coverage_plateau": 0,
            "unexpanded_states_at_wall_time": 0,
            "unexpanded_states_at_coverage_plateau": 0,
            "cross_checks_run": 0,
            "cross_checks_passed": 0,
            "coverage_units_reached": 0,
            "boots_reaching_new_coverage": 0,
            "consecutive_boots_without_new_coverage": 0,
            "max_consecutive_boots_without_new_coverage": 0,
            "coverage_by_boot": [],
            "stopped_reason": None,
        }

    def _mode_for_cut(self, operation, generation, chain):
        if self.torn_word_for_cut is None:
            return self.torn_word_mode
        return str(self.torn_word_for_cut(operation, generation, chain))

    def _eligible_count(self, operations):
        return _count_recovery_candidates(
            operations, self.recovery_operation_kinds, self.flash_base, self.address_ranges
        )

    def _maybe_cross_check(
        self, state, chain, generation, operation, selection_ordinal=None
    ):
        selected = (
            int(selection_ordinal)
            if selection_ordinal is not None
            else self.summary["states_booted"] + 1
        )
        if (
            generation < 2
            or self.cross_check is None
            or self.cross_check_every <= 0
            or selected % self.cross_check_every != 0
        ):
            return None
        self.summary["cross_checks_run"] += 1
        try:
            outcome = self.cross_check(state, chain, generation, operation)
        except RecoveryTraceMismatch:
            raise
        except Exception as exc:
            raise RecoverySearchError(
                "live cross-check failed for {}: {}".format(
                    format_chain(chain)["text"], exc
                )
            )
        self.summary["cross_checks_passed"] += 1
        return outcome

    def _coverage_plateau_reached(self):
        return (
            self.max_boots_without_new_coverage is not None
            and self._consecutive_boots_without_new_coverage
            >= self.max_boots_without_new_coverage
        )

    def _record_boot_coverage(self, parent_id, result, state, chain, generation):
        if self.coverage_for_result is not None:
            raw_units = self.coverage_for_result(result, state, chain, generation)
            units = (
                None
                if raw_units is None
                else tuple(_normalize_coverage_unit(u) for u in raw_units)
            )
        else:
            units = _extract_result_coverage_units(result)

        boot_ordinal = int(self.summary["states_booted"])
        entry = {}
        if units is None:
            if self.order == "coverage_guided":
                raise RecoverySearchError(
                    "state_search order 'coverage_guided' requires recovery coverage data on each booted state"
                )
            if self.max_boots_without_new_coverage is not None:
                raise RecoverySearchError(
                    "max_boots_without_new_coverage requires recovery coverage data on each booted state"
                )
            entry["coverage_units"] = frozenset()
            entry["coverage_signature"] = ()
            entry["reached_new_signature"] = False
            entry["new_coverage_units"] = ()
            entry["new_coverage_count"] = 0
            entry["diverged_from_prior_recovery"] = False
            entry["boot_ordinal"] = boot_ordinal
            entry["discovery_ordinal"] = int(self._discovery_counter)
            self._discovery_counter += 1
            self._parent_cov[parent_id] = {
                "entry": entry,
                "generation": int(generation),
                "children_booted": 0,
                "productive_children": 0,
                "child_stall": 0,
            }
            return entry

        self._coverage_tracking_active = True
        had_prior_recovery_coverage = bool(self._recovery_coverage_seen)
        unit_set = frozenset(units)
        signature = _coverage_signature(unit_set)
        reached_new_signature = bool(
            signature and signature not in self._seen_signatures
        )
        if signature:
            self._seen_signatures.add(signature)
            self._signature_boot_count[signature] = (
                int(self._signature_boot_count.get(signature, 0)) + 1
            )
        new_units = tuple(
            sorted(
                (u for u in unit_set if u not in self._seen_coverage),
                key=lambda item: (str(type(item)), item),
            )
        )
        new_recovery_units = tuple(
            sorted(
                (u for u in unit_set if u not in self._recovery_coverage_seen),
                key=lambda item: (str(type(item)), item),
            )
        )
        for u in unit_set:
            self._seen_coverage.add(u)
            self._recovery_coverage_seen.add(u)
            self._unit_boot_count[u] = int(self._unit_boot_count.get(u, 0)) + 1
            if u not in self._unit_first_boot:
                self._unit_first_boot[u] = boot_ordinal

        if new_units:
            self._consecutive_boots_without_new_coverage = 0
            self.summary["boots_reaching_new_coverage"] += 1
        else:
            self._consecutive_boots_without_new_coverage += 1
        if (
            self._consecutive_boots_without_new_coverage
            > self.summary["max_consecutive_boots_without_new_coverage"]
        ):
            self.summary["max_consecutive_boots_without_new_coverage"] = (
                self._consecutive_boots_without_new_coverage
            )
        self.summary["consecutive_boots_without_new_coverage"] = (
            self._consecutive_boots_without_new_coverage
        )
        self.summary["coverage_units_reached"] = len(self._seen_coverage)

        formatted_chain = format_chain(chain)
        self.summary["coverage_by_boot"].append(
            {
                "boot_index": boot_ordinal,
                "generation": int(generation),
                "chain": formatted_chain["text"],
                "state_identity": state.identity_hex(),
                "boot_coverage_units": len(unit_set),
                "new_coverage_units": len(new_units),
                "cumulative_coverage_units": len(self._seen_coverage),
                "cumulative_recovery_coverage_units": len(
                    self._recovery_coverage_seen
                ),
                "consecutive_boots_without_new_coverage": (
                    self._consecutive_boots_without_new_coverage
                ),
            }
        )
        if isinstance(result.get("recovery_state_search"), dict):
            result["recovery_state_search"]["coverage"] = {
                "boot_index": boot_ordinal,
                "boot_coverage_units": len(unit_set),
                "new_coverage_units": len(new_units),
                "cumulative_coverage_units": len(self._seen_coverage),
                "cumulative_recovery_coverage_units": len(
                    self._recovery_coverage_seen
                ),
                "reached_new_coverage": bool(new_units),
            }

        entry["coverage_units"] = unit_set
        entry["coverage_signature"] = signature
        entry["reached_new_signature"] = reached_new_signature
        entry["new_coverage_units"] = new_units
        entry["new_coverage_count"] = len(new_units)
        entry["diverged_from_prior_recovery"] = bool(
            had_prior_recovery_coverage and new_recovery_units
        )
        entry["boot_ordinal"] = boot_ordinal
        entry["discovery_ordinal"] = int(self._discovery_counter)
        self._discovery_counter += 1
        self._parent_cov[parent_id] = {
            "entry": entry,
            "generation": int(generation),
            "children_booted": 0,
            "productive_children": 0,
            "child_stall": 0,
        }
        return entry

    def _boot(
        self,
        state,
        chain,
        generation,
        operation=None,
        cross_check_ordinal=None,
    ):
        # Admission covers the check and its recovery boot as one visit.
        # A live check may itself carry the clock past the deadline.
        self.budget.booted += 1
        checked = self._maybe_cross_check(
            state, chain, generation, operation, selection_ordinal=cross_check_ordinal,
        )
        started = self.budget.clock() if self.plan_only else None
        booted = self.boot_state(state, chain, generation)
        if self.plan_only:
            self._boot_times.append(max(0.0, self.budget.clock() - started))
        if len(booted) == 2:
            result, operations = booted
            trace_base_state = state
        elif len(booted) == 3:
            result, operations, trace_base_state = booted
        else:
            raise RecoverySearchError(
                "boot_state must return result, operations, and optional trace base"
            )
        attach_search_metadata(result, chain, state, generation)
        if self._resumed:
            result["recovery_state_search"]["resume_origin"] = "after_resume"
        if checked is not None and checked is not False:
            result["recovery_state_search"]["cross_check"] = checked
        parent = len(self.results)
        self._seen[state.identity_hex()] = result
        self.results.append(result)
        self._traces.append(self._normalize_trace(operations))
        if self._traces[-1]:
            self._frames.append((parent, 0, trace_base_state, 0))
        self.summary["states_booted"] += 1
        if generation == 1:
            self.summary["single_cut_states_booted"] += 1
            if chain and chain[0].get("operation") == "erase":
                self.summary["single_cut_erase_states_booted"] += 1
            else:
                self.summary["single_cut_program_states_booted"] += 1
        else:
            self.summary["deeper_cut_states_booted"] += 1
        return self._record_boot_coverage(parent, result, state, chain, generation)

    def _source(self, parent):
        if parent is None:
            return self.calibration_operations, ()
        chain = self.results[parent]["recovery_state_search"]["chain"]["cuts"]
        return self._traces[parent], tuple(chain)

    def cross_check_source(self, cuts):
        """Look up the original parent boot only when a live check disagrees."""
        path = [c["trace_sequence"] for c in cuts[:-1]]
        for index, result in enumerate(self.results):
            meta = result["recovery_state_search"]
            if path == [c["trace_sequence"] for c in meta["chain"]["cuts"]]:
                ops = self._traces[index]
                return (ops[:cuts[-1]["trace_sequence"] + 1], len(ops),
                        result.get("recovery_boot_start_identity"),
                        result.get("recovery_trace_base_identity"))
        raise RecoverySearchError("missing computed-source recovery trace")

    def preflight_states(self, count):
        """Walk calibration once and sample the first distinct selected states."""
        if count <= 0:
            return
        selected = set(self.first_cuts)
        seen = set()
        prefix = self.initial_state
        erases = 0
        for op in self.calibration_operations:
            if (op["kind"], op["operation_index"]) in selected:
                state = self._interrupted_state(prefix, op, (), erases)
                identity = state.identity_hex()
                if identity not in seen:
                    yield state, (format_cut(op, self.flash_base),)
                    seen.add(identity)
                    if len(seen) == count:
                        return
            prefix = apply_completed_operation(prefix, op, self.erase_fill)
            erases += op["kind"] == "erase"

    def _interrupted_state(self, prefix, op, chain, erases):
        return apply_interrupted_operation(
            prefix, op, backend_kind=self.backend_kind,
            torn_word_mode=self._mode_for_cut(op, len(chain) + 1, chain),
            erase_fill=self.erase_fill, corruption_seed=self.corruption_seed,
            total_erases=erases, page_size=self.page_size, program_unit=self.program_unit,
        )

    def _visit(self, parent, index, state):
        operations, prefix = self._source(parent)
        operation = operations[index]
        chain = prefix + (format_cut(operation, self.flash_base),)
        generation = len(chain)
        ordinal = None
        if generation > 2:
            self._deeper_cross_check_candidates += 1
            ordinal = self._deeper_cross_check_candidates
        prior = self._seen.get(state.identity_hex())
        if prior is None:
            self._booted_states[state.identity_hex()] = {
                "state": state,
                "parent": parent,
                "chain": chain,
            }
            child_entry = self._boot(state, chain, generation, operation, ordinal)
            if parent is not None and parent in self._parent_cov:
                pnode = self._parent_cov[parent]
                pnode["children_booted"] += 1
                psig = pnode["entry"].get("coverage_signature", ())
                if psig:
                    self._expanded_signatures.add(psig)
                if child_entry is not None and int(child_entry.get("new_coverage_count", 0)) > 0:
                    pnode["productive_children"] += 1
                    pnode["child_stall"] = 0
                    if psig:
                        self._productive_signatures.add(psig)
                else:
                    pnode["child_stall"] += 1
            return
        self._count_reuse(self.summary, chain)
        checked = None
        if ordinal is not None:
            checked = self._maybe_cross_check(state, chain, generation, operation, ordinal)
        add_equivalent_chain(prior, chain, checked)

    @staticmethod
    def _count_reuse(summary, chain):
        summary["states_reused"] += 1
        field = ("erase_first_states_reused" if chain[0]["operation"] == "erase"
                 else "program_first_states_reused")
        summary[field] += 1

    def _selected(self, operation, first, selected, counts):
        if first:
            if (operation["kind"], operation["operation_index"]) not in selected:
                return False
            counts["first_cut_states_computed"] += 1
            field = ("first_cut_erase_states_computed" if operation["kind"] == "erase"
                     else "first_cut_program_states_computed")
            counts[field] += 1
        else:
            counts["recovery_operations_seen"] += 1
            exclusion = _recovery_exclusion(
                operation, self.recovery_operation_kinds, self.flash_base, self.address_ranges
            )
            if exclusion:
                counts[exclusion] += 1
                return False
            counts["recovery_operations_considered"] += 1
        counts["states_computed"] += 1
        return True

    def _expand(self, frames, selected, counts, preview=False):
        parent, index, prefix, erases = frames.popleft()
        operations, chain = self._source(parent)
        if len(chain) >= self.max_cuts:
            counts["recovery_operations_excluded_by_max_cuts"] += self._eligible_count(operations)
            return
        op = operations[index]
        if index + 1 < len(operations):
            completed = apply_completed_operation(prefix, op, self.erase_fill)
            frames.appendleft((parent, index + 1, completed, erases + (op["kind"] == "erase")))
        elif not preview and parent is not None and parent in self._parent_cov:
            psig = self._parent_cov[parent]["entry"].get("coverage_signature", ())
            if psig:
                self._expanded_signatures.add(psig)
        if not self._selected(op, parent is None, selected, counts):
            return None
        key = (parent, index)
        candidate = self._computed_frontier.get(key)
        if candidate is None:
            candidate = self._interrupted_state(prefix, op, chain, erases)
        if preview:
            self._computed_frontier[key] = candidate
        else:
            self._computed_frontier.pop(key, None)
        return parent, index, candidate

    def _parent_priority_key(self, node):
        entry = node["entry"]
        new_count = int(entry.get("new_coverage_count", 0))
        reached_new = 1 if new_count > 0 else 0
        reached_new_sig = 1 if entry.get("reached_new_signature") else 0
        diverged = 1 if entry.get("diverged_from_prior_recovery") else 0
        productive_children = int(node.get("productive_children", 0))
        child_stall = int(node.get("child_stall", 0))
        children_booted = int(node.get("children_booted", 0))
        signature = entry.get("coverage_signature", ())
        signature_productive = (
            1 if signature and signature in self._productive_signatures else 0
        )
        sig_unexpanded = (
            1
            if (signature and signature not in self._expanded_signatures)
            else 0
        )
        sig_frequency = (
            int(self._signature_boot_count.get(signature, 10**9))
            if signature
            else 10**9
        )
        units = entry.get("coverage_units") or ()
        if units:
            min_unit_frequency = min(
                int(self._unit_boot_count.get(u, 1)) for u in units
            )
        else:
            min_unit_frequency = 10**9

        has_new_path = 1 if (reached_new or reached_new_sig) else 0
        if has_new_path and child_stall == 0:
            tier = 0
        elif signature_productive and child_stall == 0:
            tier = 1
        elif signature_productive or productive_children > 0:
            tier = 2
        elif has_new_path:
            tier = 3
        elif child_stall == 0:
            tier = 4
        else:
            tier = 5

        return (
            tier,
            -diverged,
            -reached_new,
            -reached_new_sig,
            -sig_unexpanded,
            -productive_children,
            child_stall,
            sig_frequency,
            min_unit_frequency,
            -new_count,
            children_booted,
            int(node["generation"]),
            int(entry.get("discovery_ordinal", 0)),
        )

    def _select_best_coverage_frame(self, frames):
        if not frames or frames[0][0] is None:
            return
        best_idx = 0
        best_key = None
        for idx, frame in enumerate(frames):
            parent = frame[0]
            if parent is None:
                return
            _ops, chain = self._source(parent)
            if len(chain) >= self.max_cuts:
                key = (-1,)
            else:
                pnode = self._parent_cov.get(parent)
                if pnode is None:
                    key = (99, int(parent))
                else:
                    key = self._parent_priority_key(pnode)
            if best_key is None or key < best_key:
                best_key = key
                best_idx = idx
        if best_idx > 0:
            chosen = frames[best_idx]
            del frames[best_idx]
            frames.appendleft(chosen)

    def _needs_boot(self, parent, state):
        return state.identity_hex() not in self._seen

    def _serialize_coverage_state(self):
        parent_cov = {}
        for parent_id, node in sorted(
            self._parent_cov.items(),
            key=lambda kv: (-1 if kv[0] is None else int(kv[0])),
        ):
            entry = node["entry"]
            key = "null" if parent_id is None else str(int(parent_id))
            parent_cov[key] = {
                "generation": int(node["generation"]),
                "children_booted": int(node["children_booted"]),
                "productive_children": int(node["productive_children"]),
                "child_stall": int(node["child_stall"]),
                "entry": {
                    "coverage_units": sorted(
                        entry.get("coverage_units") or (),
                        key=lambda item: (str(type(item)), item),
                    ),
                    "coverage_signature": list(
                        entry.get("coverage_signature") or ()
                    ),
                    "reached_new_signature": bool(
                        entry.get("reached_new_signature")
                    ),
                    "new_coverage_units": list(
                        entry.get("new_coverage_units") or ()
                    ),
                    "new_coverage_count": int(
                        entry.get("new_coverage_count", 0)
                    ),
                    "diverged_from_prior_recovery": bool(
                        entry.get("diverged_from_prior_recovery")
                    ),
                    "boot_ordinal": int(entry.get("boot_ordinal", 0)),
                    "discovery_ordinal": int(
                        entry.get("discovery_ordinal", 0)
                    ),
                },
            }
        return {
            "seen_coverage": sorted(
                self._seen_coverage, key=lambda item: (str(type(item)), item)
            ),
            "recovery_coverage_seen": sorted(
                self._recovery_coverage_seen,
                key=lambda item: (str(type(item)), item),
            ),
            "unit_first_boot": [
                [u, int(b)]
                for u, b in sorted(
                    self._unit_first_boot.items(),
                    key=lambda kv: (str(type(kv[0])), kv[0]),
                )
            ],
            "unit_boot_count": [
                [u, int(c)]
                for u, c in sorted(
                    self._unit_boot_count.items(),
                    key=lambda kv: (str(type(kv[0])), kv[0]),
                )
            ],
            "seen_signatures": [
                list(sig)
                for sig in sorted(
                    self._seen_signatures,
                    key=lambda s: [
                        (str(type(item)), item) for item in s
                    ],
                )
            ],
            "signature_boot_count": [
                [list(sig), int(count)]
                for sig, count in sorted(
                    self._signature_boot_count.items(),
                    key=lambda kv: [
                        (str(type(item)), item) for item in kv[0]
                    ],
                )
            ],
            "expanded_signatures": [
                list(sig)
                for sig in sorted(
                    self._expanded_signatures,
                    key=lambda s: [
                        (str(type(item)), item) for item in s
                    ],
                )
            ],
            "productive_signatures": [
                list(sig)
                for sig in sorted(
                    self._productive_signatures,
                    key=lambda s: [
                        (str(type(item)), item) for item in s
                    ],
                )
            ],
            "parent_cov": parent_cov,
            "consecutive_boots_without_new_coverage": int(
                self._consecutive_boots_without_new_coverage
            ),
            "discovery_counter": int(self._discovery_counter),
            "current_cov_parent": self._current_cov_parent,
        }

    def _deserialize_coverage_state(self, cov_state):
        if not isinstance(cov_state, dict):
            return
        self._coverage_tracking_active = True
        self._seen_coverage = set(
            _normalize_coverage_unit(u)
            for u in (cov_state.get("seen_coverage") or ())
        )
        self._recovery_coverage_seen = set(
            _normalize_coverage_unit(u)
            for u in (cov_state.get("recovery_coverage_seen") or ())
        )
        self._unit_first_boot = {}
        for item in cov_state.get("unit_first_boot") or ():
            if isinstance(item, dict):
                u, b = item["unit"], item["first_boot"]
            else:
                u, b = item
            self._unit_first_boot[_normalize_coverage_unit(u)] = int(b)
        self._unit_boot_count = {}
        for item in cov_state.get("unit_boot_count") or ():
            if isinstance(item, dict):
                u, c = item["unit"], item["boot_count"]
            else:
                u, c = item
            self._unit_boot_count[_normalize_coverage_unit(u)] = int(c)
        if "seen_signatures" in cov_state:
            self._seen_signatures = set(
                tuple(_normalize_coverage_unit(u) for u in sig)
                for sig in (cov_state.get("seen_signatures") or ())
            )
        if "signature_boot_count" in cov_state:
            self._signature_boot_count = dict(
                (tuple(_normalize_coverage_unit(u) for u in sig), int(count))
                for sig, count in (cov_state.get("signature_boot_count") or ())
            )
        if "expanded_signatures" in cov_state:
            self._expanded_signatures = set(
                tuple(_normalize_coverage_unit(u) for u in sig)
                for sig in (cov_state.get("expanded_signatures") or ())
            )
        if "productive_signatures" in cov_state:
            self._productive_signatures = set(
                tuple(_normalize_coverage_unit(u) for u in sig)
                for sig in (cov_state.get("productive_signatures") or ())
            )
        if "parent_cov" in cov_state and isinstance(
            cov_state["parent_cov"], dict
        ):
            self._parent_cov = {}
            for key, node in cov_state["parent_cov"].items():
                parent_id = None if key == "null" else int(key)
                raw_entry = node.get("entry") or {}
                self._parent_cov[parent_id] = {
                    "generation": int(node.get("generation", 1)),
                    "children_booted": int(node.get("children_booted", 0)),
                    "productive_children": int(
                        node.get("productive_children", 0)
                    ),
                    "child_stall": int(node.get("child_stall", 0)),
                    "entry": {
                        "coverage_units": frozenset(
                            _normalize_coverage_unit(u)
                            for u in (raw_entry.get("coverage_units") or ())
                        ),
                        "coverage_signature": tuple(
                            _normalize_coverage_unit(u)
                            for u in (
                                raw_entry.get("coverage_signature") or ()
                            )
                        ),
                        "reached_new_signature": bool(
                            raw_entry.get("reached_new_signature")
                        ),
                        "new_coverage_units": tuple(
                            _normalize_coverage_unit(u)
                            for u in (
                                raw_entry.get("new_coverage_units") or ()
                            )
                        ),
                        "new_coverage_count": int(
                            raw_entry.get("new_coverage_count", 0)
                        ),
                        "diverged_from_prior_recovery": bool(
                            raw_entry.get("diverged_from_prior_recovery")
                        ),
                        "boot_ordinal": int(raw_entry.get("boot_ordinal", 0)),
                        "discovery_ordinal": int(
                            raw_entry.get("discovery_ordinal", 0)
                        ),
                    },
                }
        self._consecutive_boots_without_new_coverage = int(
            cov_state.get("consecutive_boots_without_new_coverage", 0)
        )
        if "discovery_counter" in cov_state:
            self._discovery_counter = int(cov_state["discovery_counter"])
        self._current_cov_parent = cov_state.get("current_cov_parent")
        self.summary["consecutive_boots_without_new_coverage"] = (
            self._consecutive_boots_without_new_coverage
        )
        self.summary["coverage_units_reached"] = len(self._seen_coverage)

    def export_coverage_checkpoint(self):
        """Export deterministic coverage and search state for checkpoint/merge."""
        serialized = self._serialize_coverage_state()
        return {
            "schema_version": 1,
            "order": self.order,
            "max_boots_without_new_coverage": self.max_boots_without_new_coverage,
            "initial_coverage": sorted(
                self.initial_coverage, key=lambda item: (str(type(item)), item)
            ),
            "seen_coverage": serialized["seen_coverage"],
            "recovery_coverage_seen": serialized["recovery_coverage_seen"],
            "unit_first_boot": [
                {"unit": u, "first_boot": int(b)}
                for u, b in serialized["unit_first_boot"]
            ],
            "unit_boot_count": [
                {"unit": u, "boot_count": int(c)}
                for u, c in serialized["unit_boot_count"]
            ],
            "seen_signatures": serialized["seen_signatures"],
            "signature_boot_count": serialized["signature_boot_count"],
            "expanded_signatures": serialized["expanded_signatures"],
            "productive_signatures": serialized["productive_signatures"],
            "parent_cov": serialized["parent_cov"],
            "consecutive_boots_without_new_coverage": serialized[
                "consecutive_boots_without_new_coverage"
            ],
            "discovery_counter": serialized["discovery_counter"],
            "current_cov_parent": serialized["current_cov_parent"],
            "visited_state_identities": sorted(
                self._seen.keys()
            ),
            "coverage_by_boot": copy.deepcopy(self.summary["coverage_by_boot"]),
            "summary": copy.deepcopy(self.summary),
        }

    def restore_coverage_checkpoint(self, checkpoint):
        """Restore prior coverage state into this explorer before running."""
        if not isinstance(checkpoint, dict):
            raise RecoverySearchError("checkpoint must be a dict")
        self._deserialize_coverage_state(checkpoint)

    def checkpoint(self, inputs):
        if self.plan_only or (not self._pending and not self._frames):
            return None
        snapshots = SnapshotWriter()
        visits = [[parent, index, snapshots.reference(state)]
                  for parent, index, state in self._pending]
        frames = [[parent, index, snapshots.reference(prefix), erases]
                  for parent, index, prefix, erases in self._frames]
        data = {
            "version": 1, "inputs": inputs, "results": self.results,
            "recovery_traces": self._traces, "pending_visits": visits,
            "computed_frontier": [[parent, index, snapshots.reference(state)]
                                  for (parent, index), state in self._computed_frontier.items()],
            "trace_queue": frames, "snapshots": snapshots.states, "chunks": snapshots.chunks,
            "cross_check_position": self._deeper_cross_check_candidates,
            "counters": self.summary, "elapsed_s": self._elapsed,
            "limits": {"max_new_states": self.budget.max_new_states,
                       "max_wall_time_s": self.budget.max_wall_time_s},
        }
        if self._coverage_tracking_active:
            data["coverage_state"] = self._serialize_coverage_state()
        return data

    def restore(self, checkpoint, inputs):
        if self.plan_only:
            raise RecoverySearchError("plan_only cannot resume a state search checkpoint")
        partition = checkpoint.get("shard", {})
        for field, default in (("shard_index", 0), ("shard_count", 1)):
            if partition.get(field, default) != getattr(self, field, default):
                raise RecoverySearchError("state search checkpoint mismatch: " + field)
        validate_checkpoint(checkpoint, inputs)
        snapshots = restore_snapshots(checkpoint)
        self.results = checkpoint["results"]
        self._traces = checkpoint["recovery_traces"]
        self.summary = checkpoint["counters"]
        for result in self.results:
            metadata = result["recovery_state_search"]
            metadata["resume_origin"] = "before_resume"
            self._seen[metadata["state_identity"]] = result
        self._pending = deque((parent, index, snapshots[key])
                              for parent, index, key in checkpoint["pending_visits"])
        self._frames = deque((parent, index, snapshots[key], erases)
                             for parent, index, key, erases in checkpoint["trace_queue"])
        self._computed_frontier = dict(((parent, index), snapshots[key])
                                       for parent, index, key in checkpoint["computed_frontier"])
        self._deeper_cross_check_candidates = checkpoint["cross_check_position"]
        self.budget.max_new_states += checkpoint["limits"]["max_new_states"]
        self.budget.max_wall_time_s += checkpoint["limits"]["max_wall_time_s"]
        self.budget.booted = len(self.results)
        self._prior_elapsed = checkpoint["elapsed_s"]
        self._resumed = True
        if "coverage_state" in checkpoint:
            self._deserialize_coverage_state(checkpoint["coverage_state"])

    def _trace_counts(self, index):
        operations = self._traces[index]
        return len(operations), self._eligible_count(operations)

    def _first_cut_traces(self, results):
        rows = []
        for index, result in enumerate(results):
            meta = result["recovery_state_search"]
            if meta["generation"] != 1:
                break
            total, candidates = self._trace_counts(index)
            rows.append({
                "first_cut": meta["chain"]["cuts"][0],
                "equivalent_first_cuts": [c["cuts"][0] for c in meta.get("equivalent_chains", [])
                                          if c["cut_count"] == 1],
                "trace_operations": total,
                "generation_two_candidates": candidates,
            })
        return rows

    def _check_plan_time(self):
        if self.budget.wall_expired():
            raise RecoverySearchError("incomplete state_search plan: max_wall_time_s reached")

    def _plan_generation_two(self, rows, selected):
        identities = set()
        new_states = 0
        for parent, row in enumerate(rows):
            children = set()
            candidates_before = self.summary["recovery_operations_considered"]
            while self._frames and self._frames[0][0] == parent:
                self._check_plan_time()
                visit = self._expand(self._frames, selected, self.summary)
                if visit:
                    children.add(visit[2].identity_hex())
            new = sum(1 for key in children if key not in self._seen and key not in identities)
            identities.update(children)
            candidates = self.summary["recovery_operations_considered"] - candidates_before
            reused = candidates - new
            new_states += new
            row.update({
                "distinct_candidate_states": len(children),
                "new_states": new,
                "reused_candidates": reused,
                "recovery_boots_through_generation_two": 1 + new,
                "measured_boot_s": self._boot_times[parent],
            })
            self.summary["states_reused"] += reused
            kind = "erase" if row["first_cut"]["operation"] == "erase" else "program"
            self.summary[kind + "_first_states_reused"] += reused
        self._check_plan_time()
        boots = len(rows) + new_states
        candidates = self.summary["recovery_operations_considered"]
        measured = sum(self._boot_times)
        plan = {
            "trace_operations": self.summary["recovery_operations_seen"],
            "generation_two_candidates": candidates,
            "distinct_candidate_states": len(identities),
            "new_states": new_states,
            "reused_candidates": candidates - new_states,
            "recovery_boots_through_generation_two": boots,
            "measured_first_cut_boot_s": measured,
            "estimated_recovery_boot_time_s": round(measured / len(rows) * boots, 3) if rows else None,
        }
        if self.max_cuts > 2:
            plan["deeper_counts"] = "not_estimated"
        return plan

    def compare_boot_snapshots(self):
        # Final host-side invariant checks may disqualify a successful boot.
        # Bind each comparison to its sibling identity for the host to verify.
        records = []
        states = {}
        chains = {}
        parent_ops = {}
        for identity, row in self._seen.items():
            if row is None:
                continue
            booted_entry = self._booted_states.get(identity)
            if booted_entry is None:
                continue
            outcome = row.get("boot_outcome")
            status = "other"
            if outcome == "success":
                status = "pass"
            elif outcome in (
                "no_boot", "hard_fault", "bus_fault", "wrong_pc",
                "misaligned_vtor", "wrong_image", "memory_checks_unmet",
            ):
                status = "failure"
            records.append((row, search_cut_paths(row), status))
            states[id(row)] = booted_entry["state"]
            chains[id(row)] = booted_entry.get("chain") or ()
            parent = booted_entry.get("parent")
            parent_ops[id(row)] = (
                self.calibration_operations if parent is None else self._traces[parent]
            )
        for row, sibling, chosen_index in passing_siblings(records):
            if sibling is not None:
                comparison = compare_persistent_states(states[id(row)], states[id(sibling)])
                row_chain = chains.get(id(row)) or ()
                fail_cut = (
                    (row_chain[-1]["operation"], int(row_chain[-1]["operation_index"]))
                    if row_chain else None
                )
                pass_cut = (
                    (row_chain[-1]["operation"], int(chosen_index))
                    if row_chain and chosen_index is not None else None
                )
                attribute_ranges_to_operations(
                    comparison.get("ranges"),
                    parent_ops.get(id(row)) or self.calibration_operations,
                    flash_base=self.flash_base,
                    fail_cut=fail_cut,
                    pass_cut=pass_cut,
                )
                if any("operation" not in r for r in comparison.get("ranges") or ()):
                    attribute_ranges_to_operations(
                        comparison.get("ranges"),
                        parent_ops.get(id(sibling)) or self.calibration_operations,
                        flash_base=self.flash_base,
                    )
                    attribute_ranges_to_operations(
                        comparison.get("ranges"),
                        self.calibration_operations,
                        flash_base=self.flash_base,
                    )
                row["_sibling_snapshot_comparison"] = {
                    "sibling": sibling["recovery_state_search"]["state_identity"],
                    "comparison": comparison,
                }

    def run(self):
        self.budget.started_at = self.budget.clock() - self._prior_elapsed
        selected = set(self.first_cuts)
        reason = "complete"
        while self._pending or self._frames:
            if self.budget.wall_expired():
                reason = "max_wall_time_s"
                break
            if self.plan_only and not self._pending and self._frames[0][0] is not None:
                break
            if self._pending:
                parent, index, state = self._pending[0]
                if self.budget.boot_limit_reached() and self._needs_boot(parent, state):
                    reason = "max_new_states"
                    break
                if self._coverage_plateau_reached() and self._needs_boot(parent, state):
                    reason = "coverage_plateau"
                    break
                self._pending.popleft()
                will_boot = self._needs_boot(parent, state)
                self._visit(parent, index, state)
                if will_boot:
                    self._current_cov_parent = None
            else:
                if (
                    self.order == "coverage_guided"
                    and self._frames
                    and self._frames[0][0] is not None
                    and (
                        self._current_cov_parent is None
                        or self._frames[0][0] != self._current_cov_parent
                    )
                ):
                    self._select_best_coverage_frame(self._frames)
                    self._current_cov_parent = self._frames[0][0]
                visit = self._expand(self._frames, selected, self.summary)
                if visit:
                    self._pending.append(visit)

        if self.plan_only:
            if reason != "complete":
                raise RecoverySearchError("incomplete state_search plan: " + reason + " reached")
            rows = self._first_cut_traces(self.results)
            plan = self._plan_generation_two(rows, selected)
            reason = "plan_complete"
        self._elapsed = self.budget.wall_time_s()
        summary = dict(self.summary)
        omitted = list(self._pending)
        if reason in ("max_new_states", "coverage_plateau"):
            # Count the known frontier for this report without advancing the
            # durable visit cursor. A later wall stop must see exactly the same
            # counters and unexpanded parents as an uninterrupted search.
            frames = deque(self._frames)
            while frames and not self.budget.wall_expired():
                visit = self._expand(frames, selected, summary, preview=True)
                if visit:
                    omitted.append(visit)
        known = set(self._seen)
        results = self.results
        if omitted:
            # Project the omitted frontier onto this report only. A subsequent
            # run accounts for each deferred visit when it reaches that visit.
            results = [
                dict(r, recovery_state_search=copy.deepcopy(r["recovery_state_search"]))
                for r in results
            ]
            by_id = dict((r["recovery_state_search"]["state_identity"], r) for r in results)
            for parent, index, state in omitted:
                identity = state.identity_hex()
                if identity in known:
                    operations, prefix = self._source(parent)
                    chain = prefix + (format_cut(operations[index], self.flash_base),)
                    self._count_reuse(summary, chain)
                    if identity in by_id:
                        add_equivalent_chain(by_id[identity], chain)
                known.add(identity)
        summary["first_cut_traces"] = rows if self.plan_only else self._first_cut_traces(results)
        summary["complete"] = reason in ("complete", "plan_complete")
        if reason == "max_wall_time_s":
            summary["states_excluded_by_wall_time"] = len(known) - len(self._seen)
            summary["unexpanded_states_at_wall_time"] = len(self._frames)
        elif reason == "max_new_states":
            summary["states_excluded_by_max_new_states"] = len(known) - len(self._seen)
        elif reason == "coverage_plateau":
            summary["states_excluded_by_coverage_plateau"] = len(known) - len(self._seen)
            summary["unexpanded_states_at_coverage_plateau"] = len(self._frames)
        summary["stopped_reason"] = reason
        summary["unique_states_seen"] = len(known)
        if self.plan_only:
            summary["generation_two_plan"] = plan
            summary["unique_states_seen"] = plan["recovery_boots_through_generation_two"]
        summary["elapsed_s"] = round(self._elapsed, 3)
        if results:
            results = list(results)
            results[0] = dict(results[0], recovery_state_search_summary=dict(summary))
        return results, summary
