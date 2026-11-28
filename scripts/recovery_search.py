# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Pure helpers for deterministic recovery-state exploration."""

from __future__ import division

import copy
from collections import deque

from recovery_checkpoint import SnapshotWriter, restore_snapshots, validate_checkpoint
from recovery_state import (
    normalize_trace,
    apply_completed_operation,
    apply_interrupted_operation,
)


class RecoverySearchError(ValueError):
    pass


try:
    _string_types = (basestring,)
except NameError:
    _string_types = (str,)


def _byte_value(value):
    if isinstance(value, _string_types):
        if len(value) != 1:
            raise RecoverySearchError("persistent byte value is not one character")
        return ord(value)
    return int(value) & 0xFF


def _hex_value(value):
    return "".join("{:02x}".format(_byte_value(item)) for item in value)


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
    elif mode == "all":
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
    return {
        "operation": operation_kind,
        "operation_index": operation_index,
        "trace_sequence": int(operation.get("sequence", operation_index)),
        "address": "0x{:08X}".format(address & 0xFFFFFFFF),
        "fault_type": (
            "interrupted_erase" if operation_kind == "erase" else str(fault_type)
        ),
    }


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
    ):
        self.initial_state = initial_state
        self.calibration_operations = normalize_trace(calibration_operations)
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
        self.recovery_operation_kinds = recovery_operation_kinds(recovery_fault_types)
        self.cross_check_every = int(cross_check_every)
        self.cross_check = cross_check
        self._boot_times = []
        self.plan_only = plan_only
        self.budget = SearchBudget(max_new_states, max_wall_time_s, clock)
        self._seen = {}
        self._traces = []
        # A frame retains the completed prefix immediately before its next cut.
        # Parent None denotes the calibration trace; other parents index results.
        self._frames = deque([(None, 0, initial_state, 0)] if self.calibration_operations else [])
        self._pending = deque()
        self._computed_frontier = {}
        self._prior_elapsed = 0.0
        self._resumed = False
        self._deeper_cross_check_candidates = 0
        self.results = []
        self.summary = {
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
            "unexpanded_states_at_wall_time": 0,
            "cross_checks_run": 0,
            "cross_checks_passed": 0,
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
        except Exception as exc:
            raise RecoverySearchError(
                "live cross-check failed for {}: {}".format(
                    format_chain(chain)["text"], exc
                )
            )
        self.summary["cross_checks_passed"] += 1
        return outcome

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
        self._traces.append(normalize_trace(operations))
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

    def _source(self, parent):
        if parent is None:
            return self.calibration_operations, ()
        chain = self.results[parent]["recovery_state_search"]["chain"]["cuts"]
        return self._traces[parent], tuple(chain)

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
            self._boot(state, chain, generation, operation, ordinal)
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
        if not self._selected(op, parent is None, selected, counts):
            return None
        key = (parent, index)
        candidate = self._computed_frontier.get(key)
        if candidate is None:
            candidate = apply_interrupted_operation(
                prefix, op, backend_kind=self.backend_kind,
                torn_word_mode=self._mode_for_cut(op, len(chain) + 1, chain),
                erase_fill=self.erase_fill, corruption_seed=self.corruption_seed,
                total_erases=erases, page_size=self.page_size, program_unit=self.program_unit,
            )
        if preview:
            self._computed_frontier[key] = candidate
        else:
            self._computed_frontier.pop(key, None)
        return parent, index, candidate

    def _needs_boot(self, parent, state):
        return state.identity_hex() not in self._seen

    def checkpoint(self, inputs):
        if self.plan_only or (not self._pending and not self._frames):
            return None
        snapshots = SnapshotWriter()
        visits = [[parent, index, snapshots.reference(state)]
                  for parent, index, state in self._pending]
        frames = [[parent, index, snapshots.reference(prefix), erases]
                  for parent, index, prefix, erases in self._frames]
        return {
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

    def _first_cut_traces(self, results):
        rows = []
        for index, result in enumerate(results):
            meta = result["recovery_state_search"]
            if meta["generation"] != 1:
                break
            operations = self._traces[index]
            rows.append({
                "first_cut": meta["chain"]["cuts"][0],
                "equivalent_first_cuts": [c["cuts"][0] for c in meta.get("equivalent_chains", [])
                                          if c["cut_count"] == 1],
                "trace_operations": len(operations),
                "generation_two_candidates": self._eligible_count(operations),
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
                self._pending.popleft()
                self._visit(parent, index, state)
            else:
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
        if reason == "max_new_states":
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
