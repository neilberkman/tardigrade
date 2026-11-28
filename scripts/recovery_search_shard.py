# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Generation-two partitioning and the trace evidence needed for an offline merge.

This module also runs inside Renode's IronPython.
"""

import copy

from recovery_search import RecoveryStateExplorer, format_cut, _recovery_exclusion


def state_owner(identity_hex, count):
    return int(identity_hex[:8], 16) % count


def chain_key(cuts):
    return tuple(cut["trace_sequence"] for cut in cuts)


class ShardedRecoveryStateExplorer(RecoveryStateExplorer):
    def __init__(self, *args, **kwargs):
        self.shard_count = kwargs.pop("shard_count")
        self.shard_index = kwargs.pop("shard_index")
        super(ShardedRecoveryStateExplorer, self).__init__(*args, **kwargs)
        self._evidence = {"roots": [], "expansions": {}, "cross_checks": []}
        self._preview_evidence = None
        self._second_seen = set()
        self._foreign = set()

    def _expand(self, frames, selected, counts, preview=False):
        parent, index = frames[0][:2]
        visit = super(ShardedRecoveryStateExplorer, self)._expand(frames, selected, counts, preview)
        if getattr(self, "_last_expanded_index", None) is not None:
            parent = self._last_expanded_parent
            index = self._last_expanded_index
        elif self.order == "best_first" and not self.plan_only:
            return None
        # The budget preview belongs to this report. Resume starts at the
        # durable cursor and records these edges once as it actually reaches them.
        if preview and self._preview_evidence is None:
            self._preview_evidence = copy.deepcopy(self._evidence)
        evidence = self._preview_evidence if preview else self._evidence
        if parent is None:
            if visit:
                cut = format_cut(self.calibration_operations[index], self.flash_base)
                if self.order == "best_first":
                    cut["tier_key"] = list(self._cut_tier_key(None, index))
                    cut["region_tier"] = self._cut_region_tier(None, index)
                evidence["roots"].append([cut, visit[2].identity_hex()])
            return visit

        generation = self.results[parent]["recovery_state_search"]["generation"]
        if generation == self.max_cuts:
            return None
        op = self._traces[parent][index]
        expansion = evidence["expansions"].setdefault(str(parent), {
            "edges": [], "excluded_by_fault_type": 0, "excluded_by_address": 0,
        })
        if not visit:
            exclusion = _recovery_exclusion(op, self.recovery_operation_kinds,
                                            self.flash_base, self.address_ranges)
            expansion[exclusion[len("recovery_operations_"):]] += 1
            return None
        identity = visit[2].identity_hex()
        cut = format_cut(op, self.flash_base)
        if self.order == "best_first":
            cut["tier_key"] = list(self._cut_tier_key(parent, index))
            cut["region_tier"] = self._cut_region_tier(parent, index)
        edge = [cut, identity]
        if generation == 1:
            if not preview:
                self._second_seen.add(identity)
            if state_owner(identity, self.shard_count) != self.shard_index:
                if not preview:
                    self._foreign.add(identity)
                expansion.setdefault("peer_edges", []).append(edge)
                counts["recovery_operations_considered"] -= 1
                counts["states_computed"] -= 1
                return None
        expansion["edges"].append(edge)
        return visit

    def _boot(self, state, chain, generation, operation=None, cross_check_ordinal=None):
        if generation == 1:
            self._second_seen.add(state.identity_hex())
        elif generation == 2:
            cross_check_ordinal = len(self._second_seen)
        return super(ShardedRecoveryStateExplorer, self)._boot(
            state, chain, generation, operation, cross_check_ordinal
        )

    def _needs_boot(self, parent, state):
        if parent is None:
            return super(ShardedRecoveryStateExplorer, self)._needs_boot(parent, state)
        return (state.identity_hex() not in self._foreign and
                super(ShardedRecoveryStateExplorer, self)._needs_boot(parent, state))

    def _visit(self, parent, index, state):
        if (
            parent is not None
            and state.identity_hex() in self._foreign
            and state.identity_hex() not in self._seen
        ):
            operations, prefix = self._source(parent)
            operation = operations[index]
            chain = prefix + (format_cut(operation, self.flash_base),)
            self._count_reuse(self.summary, chain)
            check = self._maybe_cross_check(state, chain, len(chain), operation)
            if check is not None:
                self._evidence["cross_checks"].append([chain_key(chain), check])
            return
        if (
            self.order == "best_first"
            and parent is not None
            and state.identity_hex() in self._seen
        ):
            operations, prefix = self._source(parent)
            operation = operations[index]
            chain = prefix + (format_cut(operation, self.flash_base),)
            if len(chain) == 2 and self.cross_check_every > 0:
                check = self._maybe_cross_check(state, chain, 2, operation)
                if check is not None:
                    self._evidence["cross_checks"].append([chain_key(chain), check])
        return super(ShardedRecoveryStateExplorer, self)._visit(parent, index, state)

    def _maybe_cross_check(self, state, chain, generation, operation, selection_ordinal=None):
        # Deeper subtrees may converge across runners. Preserve the proof for
        # every such chain so the merger can select by the global visit ordinal.
        if (
            generation > 2
            or (self.order == "best_first" and generation >= 2)
        ) and self.cross_check_every > 0:
            selection_ordinal = self.cross_check_every
        return super(ShardedRecoveryStateExplorer, self)._maybe_cross_check(
            state, chain, generation, operation, selection_ordinal
        )

    def checkpoint(self, inputs):
        data = super(ShardedRecoveryStateExplorer, self).checkpoint(inputs)
        if data is not None:
            data["shard"] = {
                "shard_index": self.shard_index, "shard_count": self.shard_count,
                "evidence": self._evidence,
                "second_seen": sorted(self._second_seen), "foreign": sorted(self._foreign),
            }
        return data

    def restore(self, checkpoint, inputs):
        super(ShardedRecoveryStateExplorer, self).restore(checkpoint, inputs)
        shard = checkpoint["shard"]
        self._evidence = shard["evidence"]
        self._second_seen = set(shard["second_seen"])
        self._foreign = set(shard["foreign"])

    def run(self):
        results, summary = super(ShardedRecoveryStateExplorer, self).run()
        evidence = self._preview_evidence or self._evidence
        results = [dict(row) for row in results]
        for index, row in enumerate(results):
            if row["recovery_state_search"]["generation"] == self.max_cuts:
                row["shard_depth_excluded"] = self._eligible_count(self._traces[index])
            else:
                row["shard_expansion"] = evidence["expansions"].get(str(index), {
                    "edges": [], "excluded_by_address": 0, "excluded_by_fault_type": 0,
                })
        gen1_rows = [
            row
            for row in results
            if row["recovery_state_search"]["generation"] == 1
        ]
        for row, trace in zip(gen1_rows, summary["first_cut_traces"]):
            expansion = row["shard_expansion"]
            owned = len(expansion["edges"])
            if owned + len(expansion.get("peer_edges", ())) == trace["generation_two_candidates"]:
                trace["owned_generation_two_candidates"] = owned
        self.partition = {
            "shard_index": self.shard_index, "shard_count": self.shard_count,
            "max_cuts": self.max_cuts, "max_new_states": self.budget.max_new_states,
            "cross_check_every": 0 if self.cross_check is None else self.cross_check_every,
            "roots": evidence["roots"], "cross_checks": evidence["cross_checks"],
        }
        return results, summary
