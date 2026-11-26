# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Pure helpers for deterministic recovery-state exploration."""

from __future__ import division

import copy

from recovery_state import (
    RecoveryStateComputer,
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
    if len(cuts) == 2 and cuts[0]["operation"] == "write":
        pair = [cuts[0]["operation_index"], cuts[1]["operation_index"]]
        result["phase2_fault_pair"] = pair
        result["phase2_fault_pair_yaml"] = "- [{}, {}]".format(pair[0], pair[1])
        result["phase2_fault_pair_fault_type"] = cuts[1]["fault_type"]
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


def add_equivalent_chain(result, chain):
    metadata = result.setdefault("recovery_state_search", {})
    equivalent = metadata.setdefault("equivalent_chains", [])
    formatted = format_chain(chain)
    if formatted not in equivalent:
        equivalent.append(formatted)


class RecoveryStateExplorer(object):
    """Breadth-first exploration with one boot per persistent state.

    ``boot_state`` receives ``(state, chain, generation)`` and returns a pair
    containing the ordinary runtime result and the recovery operation trace.
    The trace is used only after the result has been retained in the verdict
    cache, so equivalent paths never cause another recovery boot.
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
        cross_check_every=0,
        cross_check=None,
    ):
        self.initial_state = initial_state
        self.calibration_operations = tuple(calibration_operations)
        self.first_cuts = tuple(int(item) for item in first_cuts)
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
        self.cross_check_every = int(cross_check_every)
        self.cross_check = cross_check
        self.budget = SearchBudget(max_new_states, max_wall_time_s, clock)
        self._seen = {}
        self._cross_checks = {}
        self.results = []
        self.summary = {
            "first_cuts_selected": len(self.first_cuts),
            "first_cut_states_computed": 0,
            "states_computed": 0,
            "states_booted": 0,
            "single_cut_states_booted": 0,
            "deeper_cut_states_booted": 0,
            "states_reused": 0,
            "recovery_operations_seen": 0,
            "recovery_operations_considered": 0,
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

    def _computer(self, state, operations, generation, chain):
        # RecoveryStateComputer accepts one mode per walk.  Point-dependent
        # modes are handled by walking one operation at a time in _candidates.
        return RecoveryStateComputer(
            state,
            operations,
            backend_kind=self.backend_kind,
            torn_word_mode=self.torn_word_mode,
            erase_fill=self.erase_fill,
            corruption_seed=self.corruption_seed,
            page_size=self.page_size,
            program_unit=self.program_unit,
        )

    def _candidates(self, state, operations, generation, chain):
        if self.torn_word_for_cut is None:
            for operation, candidate in self._computer(
                state, operations, generation, chain
            ).iter_cut_states():
                yield operation, candidate
            return

        # Preserve the completed prefix while allowing the configured MRAM
        # torn-word choice to vary deterministically with each operation.
        prefix = state
        for operation in operations:
            one = RecoveryStateComputer(
                prefix,
                (operation,),
                backend_kind=self.backend_kind,
                torn_word_mode=self._mode_for_cut(operation, generation, chain),
                erase_fill=self.erase_fill,
                corruption_seed=self.corruption_seed,
                page_size=self.page_size,
                program_unit=self.program_unit,
            )
            candidate = next(iter(one.iter_cut_states()))[1]
            yield operation, candidate
            prefix = one.final_state()

    def _remember_or_reuse(self, state, chain):
        identity = state.identity()
        prior = self._seen.get(identity)
        if prior is not None:
            self.summary["states_reused"] += 1
            if prior.get("result") is not None:
                add_equivalent_chain(prior["result"], chain)
            return prior
        entry = {"state": state, "result": None}
        self._seen[identity] = entry
        return None

    def _maybe_cross_check(self, state, chain, generation, operation):
        if (
            generation != 2
            or self.cross_check is None
            or self.cross_check_every <= 0
            or (self.summary["states_booted"] + 1) % self.cross_check_every != 0
        ):
            return
        self.summary["cross_checks_run"] += 1
        try:
            outcome = self.cross_check(state, chain, generation, operation)
        except Exception as exc:
            raise RecoverySearchError(
                "live cross-check failed for {}: {}".format(
                    format_chain(chain)["text"], exc
                )
            )
        if outcome is not False:
            self._cross_checks[state.identity()] = outcome
        self.summary["cross_checks_passed"] += 1

    def _boot(self, state, chain, generation, operation=None):
        if self.budget.wall_expired():
            self.summary["states_excluded_by_wall_time"] += 1
            self.summary["stopped_reason"] = "max_wall_time_s"
            return None
        if self.budget.boot_limit_reached():
            self.summary["states_excluded_by_max_new_states"] += 1
            if self.summary["stopped_reason"] is None:
                self.summary["stopped_reason"] = "max_new_states"
            return None
        self._maybe_cross_check(state, chain, generation, operation)
        self.budget.record_boot()
        result, operations = self.boot_state(state, chain, generation)
        attach_search_metadata(result, chain, state, generation)
        if state.identity() in self._cross_checks:
            result["recovery_state_search"]["cross_check"] = self._cross_checks[
                state.identity()
            ]
        entry = self._seen[state.identity()]
        entry["result"] = result
        entry["operations"] = tuple(operations)
        self.results.append(result)
        self.summary["states_booted"] += 1
        if generation == 1:
            self.summary["single_cut_states_booted"] += 1
        else:
            self.summary["deeper_cut_states_booted"] += 1
        return entry

    def run(self):
        queue = []
        selected = set(self.first_cuts)
        for operation, candidate in self._candidates(
            self.initial_state, self.calibration_operations, 1, ()
        ):
            if operation["kind"] != "write":
                continue
            if operation["operation_index"] not in selected:
                continue
            self.summary["first_cut_states_computed"] += 1
            self.summary["states_computed"] += 1
            chain = (format_cut(operation, self.flash_base),)
            if self._remember_or_reuse(candidate, chain) is not None:
                continue
            entry = self._boot(candidate, chain, 1)
            if entry is not None:
                queue.append((candidate, chain, 1, entry["operations"]))
            if self.budget.wall_expired():
                self.summary["stopped_reason"] = "max_wall_time_s"
                break

        cursor = 0
        while cursor < len(queue):
            if self.budget.wall_expired():
                self.summary["stopped_reason"] = "max_wall_time_s"
                self.summary["unexpanded_states_at_wall_time"] += len(queue) - cursor
                break
            state, chain, generation, operations = queue[cursor]
            cursor += 1
            eligible = sum(
                1
                for operation in operations
                if operation_in_address_ranges(
                    operation, self.flash_base, self.address_ranges
                )
            )
            if generation >= self.max_cuts:
                self.summary["recovery_operations_excluded_by_max_cuts"] += eligible
                continue

            for operation, candidate in self._candidates(
                state, operations, generation + 1, chain
            ):
                self.summary["recovery_operations_seen"] += 1
                if not operation_in_address_ranges(
                    operation, self.flash_base, self.address_ranges
                ):
                    self.summary["recovery_operations_excluded_by_address"] += 1
                    continue
                self.summary["recovery_operations_considered"] += 1
                self.summary["states_computed"] += 1
                next_chain = chain + (format_cut(operation, self.flash_base),)
                if self._remember_or_reuse(candidate, next_chain) is not None:
                    continue
                entry = self._boot(
                    candidate, next_chain, generation + 1, operation=operation
                )
                if entry is not None:
                    queue.append(
                        (candidate, next_chain, generation + 1, entry["operations"])
                    )
                if self.budget.wall_expired():
                    self.summary["stopped_reason"] = "max_wall_time_s"
                    self.summary["unexpanded_states_at_wall_time"] += len(queue) - cursor
                    break
            if self.summary["stopped_reason"] == "max_wall_time_s":
                break

        self.summary["unique_states_seen"] = len(self._seen)
        self.summary["elapsed_s"] = round(self.budget.wall_time_s(), 3)
        if self.summary["stopped_reason"] is None:
            self.summary["stopped_reason"] = "complete"
        if self.results:
            self.results[0]["recovery_state_search_summary"] = copy.deepcopy(
                self.summary
            )
        return self.results, self.summary
