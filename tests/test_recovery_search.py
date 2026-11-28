# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from recovery_search import (  # noqa: E402
    RecoverySearchError,
    RecoveryStateExplorer,
    SearchBudget,
    StateVerdictCache,
    _byte_value,
    add_equivalent_chain,
    attach_search_metadata,
    first_persistent_difference,
    format_chain,
    operation_in_address_ranges,
    select_first_cut_operations,
    select_first_cuts,
)
from recovery_state import PersistentState, merge_operation_traces  # noqa: E402


def test_byte_value_accepts_ironpython_character_bytes():
    assert _byte_value("\xff") == 255
    assert _byte_value(255) == 255


def test_first_cut_selection_is_ordered_and_reports_out_of_range_indices():
    assert select_first_cuts(9, {"mode": "quick"}) == ([0, 4, 8], 0)
    assert select_first_cuts(4, {"mode": "all"}) == ([0, 1, 2, 3], 0)
    assert select_first_cuts(
        5,
        {
            "mode": "ranges",
            "ranges": [
                {"start": 3, "end": 7},
                {"start": 1, "end": 3},
            ],
        },
    ) == ([1, 2, 3, 4], 3)


def test_typed_first_cut_selection_uses_independent_program_and_erase_domains():
    operations = merge_operation_traces(
        [_write(1, 0, 1), _write(2, 1, 2), _write(3, 2, 3)],
        [
            {
                "erase_index": 1,
                "offset": 0,
                "erase_size": 1,
                "writes_at_this_point": 0,
            },
            {
                "erase_index": 2,
                "offset": 1,
                "erase_size": 1,
                "writes_at_this_point": 2,
            },
        ],
    )

    selected, excluded = select_first_cut_operations(
        operations,
        {
            "mode": "all",
            "fault_types": ["power_loss", "interrupted_erase"],
        },
    )

    assert selected == (
        ("write", 0),
        ("write", 1),
        ("write", 2),
        ("erase", 0),
        ("erase", 1),
    )
    assert excluded == {"write": 0, "erase": 0}


def test_address_ranges_use_operation_overlap_and_absolute_addresses():
    write = {"kind": "write", "offset": 8, "width": 4}
    assert operation_in_address_ranges(
        write, 0x1000, [{"start": 0x100A, "end": 0x100F}]
    )
    assert not operation_in_address_ranges(
        write, 0x1000, [{"start": 0x100C, "end": 0x1010}]
    )


def test_verdict_cache_reuses_bytes_and_ecc_marks_only_when_both_match():
    cache = StateVerdictCache()
    baseline = PersistentState.from_bytes(b"abcd")
    cache.remember(baseline, {"verdict": "ok"})

    assert cache.get(PersistentState.from_bytes(b"abcd")) == {"verdict": "ok"}
    assert cache.get(
        PersistentState.from_bytes(b"abcd", uncorrectable_words=(0,))
    ) is None


def test_boot_and_wall_bounds_are_independent_and_deterministic():
    now = [10.0]
    budget = SearchBudget(2, 5.0, lambda: now[0])
    assert budget.can_boot()
    budget.record_boot()
    budget.record_boot()
    assert budget.boot_limit_reached()
    assert not budget.can_boot()

    time_budget = SearchBudget(10, 5.0, lambda: now[0])
    now[0] = 15.0
    assert time_budget.wall_expired()
    assert not time_budget.can_boot()


def test_cross_check_difference_names_first_byte_address_then_ecc():
    expected = PersistentState.from_bytes(
        b"abcd", base_address=0x2000, uncorrectable_words=(0,)
    )
    mismatch = first_persistent_difference(
        expected, {"nvm": b"abXd"}, (("nvm", 0),)
    )
    assert mismatch == {
        "kind": "bytes",
        "region": "nvm",
        "offset": 2,
        "address": "0x00002002",
        "expected": "0x63",
        "observed": "0x58",
    }

    ecc_mismatch = first_persistent_difference(expected, {"nvm": b"abcd"}, ())
    assert ecc_mismatch["kind"] == "uncorrectable_words"
    assert ecc_mismatch["address"] == "0x00002000"


def test_cross_check_difference_includes_other_persistent_values():
    expected = PersistentState.from_bytes(
        b"abcd", persistent_values={"wear_epoch": b"\x02"}
    )
    mismatch = first_persistent_difference(
        expected,
        {"nvm": b"abcd"},
        (),
        {"wear_epoch": b"\x03"},
    )
    assert mismatch == {
        "kind": "persistent_value",
        "name": "wear_epoch",
        "expected": "02",
        "observed": "03",
    }


def test_two_cut_result_format_is_pasteable_and_preserves_equivalent_chain():
    state = PersistentState.from_bytes(b"abcd")
    chain = [
        {
            "operation": "write",
            "operation_index": 2,
            "trace_sequence": 2,
            "address": "0x00001000",
            "fault_type": "power_loss",
        },
        {
            "operation": "erase",
            "operation_index": 6,
            "trace_sequence": 8,
            "address": "0x00002000",
            "fault_type": "interrupted_erase",
        },
    ]
    result = attach_search_metadata(
        {
            "fault_at": 99,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
        },
        chain,
        state,
        2,
    )
    formatted = result["recovery_state_search"]["chain"]
    assert formatted["phase2_fault_pair"] == [2, 6]
    assert formatted["phase2_fault_pair_yaml"] == "- [2, 6]"
    assert formatted["phase2_fault_pair_fault_type"] == "interrupted_erase"

    add_equivalent_chain(result, chain)
    add_equivalent_chain(result, chain)
    assert len(result["recovery_state_search"]["equivalent_chains"]) == 1


def test_deeper_result_format_is_a_pasteable_explicit_chain():
    formatted = format_chain(
        [
            {
                "operation": "write",
                "operation_index": 2,
                "address": "0x00001000",
                "fault_type": "power_loss",
            },
            {
                "operation": "erase",
                "operation_index": 6,
                "address": "0x00002000",
                "fault_type": "interrupted_erase",
            },
            {
                "operation": "write",
                "operation_index": 1,
                "address": "0x00003000",
                "fault_type": "power_loss",
            },
        ]
    )

    assert formatted["phase2_fault_chain"] == [
        [2, "power_loss"],
        [6, "interrupted_erase"],
        [1, "power_loss"],
    ]
    assert formatted["phase2_fault_yaml"] == (
        "chains:\n"
        "  - [[2, power_loss], [6, interrupted_erase], [1, power_loss]]"
    )


def _write(index, offset, value):
    return {
        "write_index": index,
        "offset": offset,
        "value": value,
        "width": 1,
    }


def _erase(index, offset, size, writes_at=0):
    return {
        "erase_index": index,
        "offset": offset,
        "erase_size": size,
        "writes_at_this_point": writes_at,
    }


def test_program_only_recovery_skips_erase_candidates_but_applies_their_prefix():
    baseline = PersistentState.from_bytes(b"\x00\x00")
    calibration = merge_operation_traces([_write(1, 1, 0x11)], [])
    checked = []

    def boot_state(state, _chain, generation):
        operations = (
            merge_operation_traces(
                [_write(1, 1, 0x22)],
                [_erase(1, 0, 1)],
            )
            if generation == 1
            else ()
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        backend_kind="mram",
        torn_word_mode="untouched",
        recovery_fault_types=("power_loss",),
        cross_check_every=1,
        cross_check=lambda state, chain, _generation, _operation: checked.append(
            (state.materialize()["nvm"], [cut["operation"] for cut in chain])
        )
        or {"matched": True},
    )

    results, summary = explorer.run()

    assert len(results) == 2
    assert results[1]["recovery_state_search"]["chain"]["cuts"][-1][
        "operation"
    ] == "write"
    assert results[1]["recovery_state_search"]["state_identity"] == (
        PersistentState.from_bytes(b"\xff\x00").identity_hex()
    )
    assert checked == [(b"\xff\x00", ["write", "write"])]
    assert summary["recovery_operations_seen"] == 2
    assert summary["recovery_operations_excluded_by_fault_type"] == 1
    assert summary["recovery_operations_considered"] == 1


def test_program_only_recovery_deduplicates_across_a_completed_erase_prefix():
    baseline = PersistentState.from_bytes(b"\xff\x00")
    calibration = merge_operation_traces(
        [_write(1, 0, 0x00), _write(2, 1, 0x11)], []
    )

    def boot_state(state, _chain, generation):
        if generation > 1:
            operations = ()
        elif state.materialize()["nvm"] == b"\xff\x00":
            operations = merge_operation_traces([_write(1, 1, 0x22)], [])
        else:
            operations = merge_operation_traces(
                [_write(1, 1, 0x33)],
                [_erase(1, 0, 1)],
            )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        backend_kind="mram",
        torn_word_mode="untouched",
        recovery_fault_types=("power_loss",),
    )

    results, summary = explorer.run()

    assert len(results) == 2
    assert summary["states_reused"] == 2
    equivalent = results[0]["recovery_state_search"]["equivalent_chains"]
    assert len(equivalent) == 2
    assert all(
        cut["operation"] == "write"
        for chain in equivalent
        for cut in chain["cuts"]
    )


def test_erase_only_recovery_skips_program_candidates_but_applies_their_prefix():
    baseline = PersistentState.from_bytes(b"\x00\x00")
    calibration = merge_operation_traces([_write(1, 1, 0x11)], [])
    checked = []

    def boot_state(_state, _chain, generation):
        operations = (
            merge_operation_traces(
                [_write(1, 0, 0x22)],
                [_erase(1, 1, 1, writes_at=1)],
            )
            if generation == 1
            else ()
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        backend_kind="mram",
        torn_word_mode="untouched",
        recovery_fault_types=("interrupted_erase",),
        cross_check_every=1,
        cross_check=lambda state, chain, _generation, _operation: checked.append(
            (state.materialize()["nvm"], [cut["operation"] for cut in chain])
        )
        or {"matched": True},
    )

    results, summary = explorer.run()

    assert len(results) == 2
    assert checked == [(b"\x22\x00", ["write", "erase"])]
    assert summary["recovery_operations_seen"] == 2
    assert summary["recovery_operations_excluded_by_fault_type"] == 1
    assert summary["recovery_operations_considered"] == 1


def test_explorer_is_breadth_first_deduplicates_and_keeps_generation_counts():
    baseline = PersistentState.from_bytes(b"\xff\xff", base_address=0x1000)
    calibration = merge_operation_traces(
        [_write(1, 0, 0x11), _write(2, 1, 0x22)], []
    )
    booted = []

    def boot_state(state, chain, generation):
        booted.append((state.materialize()["nvm"], generation))
        # Every recovery writes the same byte twice.  Cutting before either
        # write yields one existing state and one new state, exercising reuse.
        operations = merge_operation_traces(
            [_write(1, 0, 0x33), _write(2, 0, 0x33)], []
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1),
        max_cuts=2,
        max_new_states=20,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        flash_base=0x1000,
    )
    results, summary = explorer.run()

    assert [generation for _data, generation in booted[:2]] == [1, 1]
    assert summary["single_cut_states_booted"] == 2
    assert summary["deeper_cut_states_booted"] == 1
    assert summary["states_reused"] == 3
    assert summary["states_booted"] == len(results) == 3
    assert results[0]["recovery_state_search_summary"]["states_booted"] == 3


@pytest.mark.parametrize("plan_only", [False, True])
@pytest.mark.parametrize(
    ("fault_types", "ranges", "expected"),
    [
        (("power_loss",), (), 2),
        (("power_loss", "interrupted_erase"), (), 3),
        (("interrupted_erase",), (), 1),
        (("power_loss",), ((0x1001, 0x1001),), 1),
        (("power_loss", "interrupted_erase"), ((0x1001, 0x1001),), 2),
        (("power_loss", "interrupted_erase"), ((0x2000, 0x2002),), 0),
    ],
)
def test_first_cut_trace_counts_use_full_filtered_trace(plan_only, fault_types, ranges, expected):
    trace = merge_operation_traces([_write(1, 0, 1), _write(2, 1, 2)], [_erase(1, 0, 2)])
    mode = {"plan_only": True} if plan_only else {}
    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"\xff\xff"),
        merge_operation_traces([_write(1, 0, 1)], []),
        first_cuts=(0,), max_cuts=2, max_new_states=1, max_wall_time_s=30,
        clock=lambda: 1.0, boot_state=lambda *_: ({}, trace),
        flash_base=0x1000,
        address_ranges=[{"start": start, "end": end} for start, end in ranges],
        recovery_fault_types=fault_types, **mode,
    )
    results, summary = explorer.run()
    (row,) = summary["first_cut_traces"]
    assert row["first_cut"]["operation_index"] == 0
    assert row["trace_operations"] == 3
    assert row["generation_two_candidates"] == expected
    assert len(results) == 1
    if plan_only:
        assert summary["generation_two_plan"]["generation_two_candidates"] == expected


def test_plan_counts_identities_and_boots_in_full_search_order():
    # The first two calibration cuts alias. Each recovery's first cut
    # revisits its parent, then both traces converge on the same new state.
    calibration = merge_operation_traces(
        [_write(1, 0, 0xff), _write(2, 0, 0x11), _write(3, 1, 0x22)], []
    )
    trace = merge_operation_traces([_write(1, 0, 0x33), _write(2, 0, 0x33)], [])

    def search(plan_only, max_cuts):
        clock = [0.0]
        boots = []

        def boot(state, chain, generation):
            boots.append((chain[0]["operation_index"], generation, state.identity()))
            clock[0] += 2.0
            return {}, trace if generation == 1 else ()

        explorer = RecoveryStateExplorer(
            PersistentState.from_bytes(b"\xff\xff"), calibration,
            first_cuts=(0, 1, 2), max_cuts=max_cuts, max_new_states=10,
            max_wall_time_s=60, clock=lambda: clock[0], boot_state=boot,
            cross_check_every=1, cross_check=lambda *_: True,
            plan_only=plan_only,
        )
        return explorer.run()[1], boots

    full, full_boots = search(False, 2)
    planned, plan_boots = search(True, 3)
    assert plan_boots == full_boots[:2]
    assert len(plan_boots) == 2
    assert all(generation == 1 for _, generation, _ in plan_boots)
    assert full["states_booted"] == len(full_boots) == 3
    assert planned["states_reused"] == full["states_reused"] == 4
    assert planned["cross_checks_run"] == 0
    plan = planned["generation_two_plan"]
    assert plan["generation_two_candidates"] == full["recovery_operations_considered"] == 4
    assert plan["distinct_candidate_states"] == 3
    assert plan["reused_candidates"] == 3
    assert plan["new_states"] == full["deeper_cut_states_booted"] == 1
    assert plan["recovery_boots_through_generation_two"] == full["states_booted"]
    assert plan["measured_first_cut_boot_s"] == 4.0
    assert plan["estimated_recovery_boot_time_s"] == 6.0
    assert plan["deeper_counts"] == "not_estimated"
    rows = planned["first_cut_traces"]
    assert [r["first_cut"]["operation_index"] for r in rows] == [0, 2]
    assert [c["operation_index"] for c in rows[0]["equivalent_first_cuts"]] == [1]
    assert [r["generation_two_candidates"] for r in rows] == [2, 2]
    assert [r["distinct_candidate_states"] for r in rows] == [2, 2]
    assert [r["reused_candidates"] for r in rows] == [1, 2]
    assert [r["recovery_boots_through_generation_two"] for r in rows] == [2, 1]


@pytest.mark.parametrize("bound", ["max_new_states", "max_wall_time_s"])
def test_plan_refuses_incomplete_first_cut_pass(bound):
    clock = [0.0]

    def boot(*_):
        clock[0] += 1.0
        return {}, ()

    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"\xff\xff"),
        merge_operation_traces([_write(1, 0, 1), _write(2, 1, 2)], []),
        first_cuts=(0, 1), max_cuts=2,
        max_new_states=1 if bound == "max_new_states" else 10,
        max_wall_time_s=1 if bound == "max_wall_time_s" else 30,
        clock=lambda: clock[0], boot_state=boot, plan_only=True,
    )
    with pytest.raises(RecoverySearchError, match="incomplete state_search plan: " + bound):
        explorer.run()


@pytest.mark.parametrize("bound", ["max_new_states", "max_wall_time_s"])
def test_plan_stops_calibration_walk_as_soon_as_a_bound_prevents_sizing(bound, monkeypatch):
    clock = [0.0]
    visited = []

    import recovery_search
    complete = recovery_search.apply_completed_operation

    def walk(prefix, operation, fill):
        visited.append(operation["operation_index"])
        clock[0] += 1.0
        return complete(prefix, operation, fill)

    monkeypatch.setattr(recovery_search, "apply_completed_operation", walk)

    writes = [_write(i + 1, 0, i) for i in range(6)]
    # For the time limit the second operation is outside the selected range.
    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"\xff"), merge_operation_traces(writes, []),
        first_cuts=(0, 1, 5) if bound == "max_new_states" else (0, 5),
        max_cuts=2, max_new_states=1,
        max_wall_time_s=2 if bound == "max_wall_time_s" else 60,
        clock=lambda: clock[0], boot_state=lambda *_: ({}, ()),
        torn_word_mode="untouched", plan_only=True,
    )
    with pytest.raises(RecoverySearchError, match="incomplete state_search plan: " + bound):
        explorer.run()
    assert visited == [0, 1]


def test_plan_counts_deferred_trace_base_with_distinct_ecc_marks():
    trace = merge_operation_traces([_write(1, 1, 0x11)], [])
    baseline = PersistentState.from_bytes(b"\xff\xff")
    marked = PersistentState.from_bytes(b"\xff\xff", uncorrectable_words=(0,))
    explorer = RecoveryStateExplorer(
        baseline, trace, first_cuts=(0,), max_cuts=2,
        max_new_states=1, max_wall_time_s=30, clock=lambda: 0.0,
        boot_state=lambda *_: ({}, trace, marked),
        backend_kind="mram", torn_word_mode="untouched", plan_only=True,
    )
    _, summary = explorer.run()
    assert summary["states_booted"] == 1
    assert summary["generation_two_plan"]["recovery_boots_through_generation_two"] == 2


def test_normal_summary_counts_trace_tail_after_wall_time_stop():
    trace = merge_operation_traces([_write(i, 0, i) for i in range(1, 9)], [])
    clock = [0.0]

    def boot(_state, _chain, generation):
        clock[0] += 1
        return {}, trace if generation == 1 else ()

    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"\xff"), trace, first_cuts=(0,), max_cuts=2,
        max_new_states=20, max_wall_time_s=2, clock=lambda: clock[0], boot_state=boot,
    )
    _, summary = explorer.run()
    assert summary["stopped_reason"] == "max_wall_time_s"
    assert summary["recovery_operations_considered"] == 2
    assert summary["first_cut_traces"][0]["generation_two_candidates"] == 8


def test_explorer_uses_deferred_recovery_trace_base_for_deeper_states():
    initial = PersistentState.from_bytes(b"\xff\xff", base_address=0x1000)
    calibration = merge_operation_traces([_write(1, 1, 0x10)], [])

    def boot_state(state, _chain, generation):
        operations = (
            merge_operation_traces([_write(1, 1, 0x20)], [])
            if generation == 1
            else ()
        )
        trace_base = (
            PersistentState.from_bytes(b"\xaa\x10", base_address=0x1000)
            if generation == 1
            else state
        )
        return (
            {"fault_injected": True, "signals": {}},
            operations,
            trace_base,
        )

    explorer = RecoveryStateExplorer(
        initial,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        flash_base=0x1000,
        backend_kind="mram",
        torn_word_mode="programmed",
    )

    results, _summary = explorer.run()

    expected = PersistentState.from_bytes(b"\xaa\x20", base_address=0x1000)
    assert results[1]["recovery_state_search"]["state_identity"] == (
        expected.identity_hex()
    )


def test_explorer_reuses_erase_first_states_and_reports_them_separately():
    baseline = PersistentState.from_bytes(b"\xff\xff")
    erases = [
        {
            "erase_index": index,
            "offset": index - 1,
            "erase_size": 1,
            "writes_at_this_point": 0,
        }
        for index in (1, 2)
    ]
    calibration = merge_operation_traces([], erases)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(("erase", 0), ("erase", 1)),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=lambda _state, _chain, _generation: (
            {"fault_injected": True, "signals": {}},
            (),
        ),
        backend_kind="flash",
        torn_word_mode="fixed",
    )

    results, summary = explorer.run()

    assert len(results) == 1
    assert results[0]["recovery_state_search"]["chain"]["cuts"][0][
        "operation"
    ] == "erase"
    assert summary["first_cut_erases_selected"] == 2
    assert summary["first_cut_erase_states_computed"] == 2
    assert summary["single_cut_erase_states_booted"] == 1
    assert summary["erase_first_states_reused"] == 1
    assert summary["first_cut_program_states_computed"] == 0


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("fixed", b"\xee" * 4 + bytes(range(4, 8))),
        ("untouched", bytes(range(8))),
        ("programmed", b"\xee" * 8),
        ("partial_bits", None),
    ],
)
def test_explorer_computes_each_erase_first_outcome(mode, expected):
    baseline_bytes = bytes(range(8))
    baseline = PersistentState.from_bytes(baseline_bytes)
    calibration = merge_operation_traces(
        [],
        [
            {
                "erase_index": 1,
                "offset": 0,
                "erase_size": 8,
                "writes_at_this_point": 0,
            }
        ],
    )
    booted = []

    def boot_state(state, _chain, _generation):
        booted.append(state.materialize()["nvm"])
        return ({"fault_injected": True, "signals": {}}, ())

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(("erase", 0),),
        max_cuts=1,
        max_new_states=1,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        backend_kind="flash",
        torn_word_mode=mode,
        erase_fill=0xEE,
        corruption_seed=17,
        program_unit=4,
    )

    _results, summary = explorer.run()

    assert len(booted) == 1
    if expected is None:
        assert booted[0] not in (baseline_bytes, b"\xee" * 8)
    else:
        assert booted[0] == expected
    assert summary["first_cut_erase_states_computed"] == 1
    assert summary["single_cut_erase_states_booted"] == 1


def test_explorer_applies_address_filter_without_skipping_prefix_mutations():
    baseline = PersistentState.from_bytes(b"\xff\xff", base_address=0x2000)
    calibration = merge_operation_traces([_write(1, 0, 0x10)], [])

    def boot_state(_state, _chain, generation):
        if generation == 1:
            return (
                {"fault_injected": True, "signals": {}},
                merge_operation_traces(
                    [_write(1, 0, 0x20), _write(2, 1, 0x30)], []
                ),
            )
        return ({"fault_injected": True, "signals": {}}, ())

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        flash_base=0x2000,
        address_ranges=({"start": 0x2001, "end": 0x2001},),
    )
    results, summary = explorer.run()

    assert summary["recovery_operations_seen"] == 2
    assert summary["recovery_operations_excluded_by_address"] == 1
    assert summary["recovery_operations_considered"] == 1
    deeper_state = results[1]["recovery_state_search"]["state_identity"]
    expected = PersistentState.from_bytes(b"\x20\xff", base_address=0x2000)
    assert deeper_state == expected.identity_hex()


def test_explorer_calls_periodic_cross_check_and_honors_boot_limit():
    baseline = PersistentState.from_bytes(b"\xff", base_address=0x3000)
    calibration = merge_operation_traces([_write(1, 0, 1)], [])
    checked = []

    def boot_state(_state, _chain, generation):
        operations = (
            merge_operation_traces([_write(1, 0, 2), _write(2, 0, 3)], [])
            if generation == 1
            else ()
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=1,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        cross_check_every=1,
        cross_check=lambda state, chain, generation, operation: checked.append(
            (state.identity_hex(), len(chain), generation, operation["operation_index"])
        ),
    )
    _results, summary = explorer.run()

    assert checked == []
    assert summary["cross_checks_run"] == summary["cross_checks_passed"] == 0
    assert summary["states_excluded_by_max_new_states"] == 1
    assert summary["stopped_reason"] == "max_new_states"


def test_explorer_cross_checks_only_unique_states_that_will_be_booted():
    baseline = PersistentState.from_bytes(b"\xff")
    calibration = merge_operation_traces([_write(1, 0, 1)], [])
    checked = []

    def boot_state(_state, _chain, generation):
        return (
            {"fault_injected": True, "signals": {}},
            merge_operation_traces(
                [_write(1, 0, 2), _write(2, 0, 3)], []
            )
            if generation == 1
            else (),
        )

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        cross_check_every=2,
        cross_check=lambda state, chain, generation, operation: checked.append(
            (state.identity_hex(), len(chain), generation, operation["operation_index"])
        ),
    )
    results, summary = explorer.run()

    # The first recovery cut reuses the generation-one state. The only new
    # deeper state is boot number two and therefore receives one live check.
    assert len(results) == 2
    assert len(checked) == 1
    assert summary["cross_checks_run"] == summary["cross_checks_passed"] == 1


def test_explorer_cross_checks_third_cut_chains_including_reused_state():
    baseline = PersistentState.from_bytes(b"\xff\xff\xff")
    calibration = merge_operation_traces([_write(1, 0, 1)], [])
    checked = []

    def boot_state(_state, _chain, generation):
        return (
            {"fault_injected": True, "signals": {}},
            merge_operation_traces(
                [
                    _write(1, generation, generation + 1),
                    _write(2, generation, generation + 1),
                ],
                [],
            )
            if generation < 3
            else (),
        )

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=3,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        cross_check_every=1,
        cross_check=lambda _state, chain, generation, _operation: checked.append(
            (len(chain), generation)
        )
        or {"matched": True},
    )

    results, summary = explorer.run()

    assert checked == [(2, 2), (3, 3), (3, 3)]
    assert summary["cross_checks_run"] == summary["cross_checks_passed"] == 3
    reused_third_cut = results[1]["recovery_state_search"]["equivalent_chains"]
    assert reused_third_cut[0]["cut_count"] == 3
    assert reused_third_cut[0]["cross_check"] == {"matched": True}


def test_explorer_cross_checks_erase_first_two_cut_state_with_typed_chain():
    baseline = PersistentState.from_bytes(b"\x00")
    calibration = merge_operation_traces(
        [],
        [
            {
                "erase_index": 1,
                "offset": 0,
                "erase_size": 1,
                "writes_at_this_point": 0,
            }
        ],
    )
    checked = []

    def boot_state(_state, _chain, generation):
        operations = (
            merge_operation_traces([_write(1, 0, 0x22)], [])
            if generation == 1
            else ()
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(("erase", 0),),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        torn_word_mode="programmed",
        erase_fill=0xFF,
        cross_check_every=2,
        cross_check=lambda _state, chain, generation, operation: checked.append(
            (chain[0]["operation"], generation, operation["kind"])
        ),
    )

    _results, summary = explorer.run()

    assert checked == [("erase", 2, "write")]
    assert summary["cross_checks_run"] == 1
    assert summary["cross_checks_passed"] == 1


def test_explorer_cross_check_error_names_the_cut_chain():
    baseline = PersistentState.from_bytes(b"\xff")
    calibration = merge_operation_traces([_write(1, 0, 1)], [])

    def boot_state(_state, _chain, generation):
        operations = (
            merge_operation_traces([_write(1, 0, 2), _write(2, 0, 3)], [])
            if generation == 1
            else ()
        )
        return ({"fault_injected": True, "signals": {}}, operations)

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=2,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        cross_check_every=2,
        cross_check=lambda *_args: (_ for _ in ()).throw(RuntimeError("mismatch")),
    )

    with pytest.raises(
        ValueError,
        match=r"live cross-check failed for write\[0\]@0x00000000 -> write\[1\]@0x00000000: mismatch",
    ):
        explorer.run()


def test_explorer_repeats_the_same_trace_step_for_a_third_cut():
    baseline = PersistentState.from_bytes(b"\xff")
    calibration = merge_operation_traces([_write(1, 0, 1)], [])

    def boot_state(_state, _chain, generation):
        first_value = generation
        return (
            {"fault_injected": True, "signals": {}},
            merge_operation_traces(
                [
                    _write(1, 0, first_value),
                    _write(2, 0, first_value + 1),
                ],
                [],
            ),
        )

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=3,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
    )
    results, summary = explorer.run()

    assert [result["recovery_state_search"]["generation"] for result in results] == [
        1,
        2,
        3,
    ]
    assert summary["single_cut_states_booted"] == 1
    assert summary["deeper_cut_states_booted"] == 2
    assert summary["recovery_operations_excluded_by_max_cuts"] == 2


def _make_coverage_guided_fixture():
    """Synthetic two-cut tree modeling a divergent recovery branch at first-cut 2.

    First cuts 0 and 1 follow the baseline recovery path {0x1000, 0x1004} and
    their second-cut children all recover cleanly with no new coverage.
    First cut 2 takes a rare recovery branch {0x1000, 0x1008}; its second-cut
    children fail recovery and execute {0x1000, 0x1008, 0x2000}.
    First cut 3 shares first cut 2's coverage signature {0x1000, 0x1008} and its
    second-cut children also fail recovery.
    """
    baseline = PersistentState.from_bytes(b"\xff\xff\xff\xff", base_address=0x1000)
    calibration = merge_operation_traces(
        [
            _write(1, 0, 0x10),
            _write(2, 1, 0x20),
            _write(3, 2, 0x30),
            _write(4, 3, 0x40),
        ],
        [],
    )

    def boot_state(state, chain, generation):
        nvm = state.materialize()["nvm"]
        first_idx = int(chain[0]["operation_index"])
        if generation == 1:
            ops = merge_operation_traces(
                [
                    _write(1, 0, (nvm[0] ^ 0x01) & 0xFF),
                    _write(2, 1, (nvm[1] ^ 0x02) & 0xFF),
                    _write(3, 2, (nvm[2] ^ 0x04) & 0xFF),
                ],
                [],
            )
            if first_idx in (2, 3):
                pcs = [0x1000, 0x1008]
            else:
                pcs = [0x1000, 0x1004]
            outcome = "recovered"
        else:
            ops = ()
            if first_idx in (2, 3):
                pcs = [0x1000, 0x1008, 0x2000]
                outcome = "boot_failure"
            else:
                pcs = [0x1000, 0x1004]
                outcome = "recovered"
        return (
            {
                "fault_injected": True,
                "boot_outcome": outcome,
                "signals": {},
                "recovery_coverage": {"executed_pcs": pcs},
            },
            ops,
        )

    return baseline, calibration, boot_state


def test_coverage_guided_visits_identical_set_when_unlimited_and_is_deterministic():
    baseline, calibration, boot_state = _make_coverage_guided_fixture()

    bfs_explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="breadth_first",
    )
    bfs_results, bfs_summary = bfs_explorer.run()

    cg_explorer_1 = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    cg_results_1, cg_summary_1 = cg_explorer_1.run()

    cg_explorer_2 = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    cg_results_2, _cg_summary_2 = cg_explorer_2.run()

    bfs_identities = {
        r["recovery_state_search"]["state_identity"] for r in bfs_results
    }
    cg_seq_1 = [
        r["recovery_state_search"]["state_identity"] for r in cg_results_1
    ]
    cg_seq_2 = [
        r["recovery_state_search"]["state_identity"] for r in cg_results_2
    ]

    # Deterministic for identical inputs.
    assert cg_seq_1 == cg_seq_2
    # Identical visited sets when unlimited.
    assert set(cg_seq_1) == bfs_identities
    assert cg_summary_1["states_booted"] == bfs_summary["states_booted"]
    assert cg_summary_1["unique_states_seen"] == bfs_summary["unique_states_seen"]

    # Coverage-guided expands first cut 2 first in Generation 2 (boot index 5,
    # 0-based index 4) and finds the first failing chain before breadth-first.
    bfs_first_failure_boot = next(
        idx + 1
        for idx, r in enumerate(bfs_results)
        if r["boot_outcome"] == "boot_failure"
    )
    cg_first_failure_boot = next(
        idx + 1
        for idx, r in enumerate(cg_results_1)
        if r["boot_outcome"] == "boot_failure"
    )
    assert cg_first_failure_boot == 5
    assert cg_first_failure_boot < bfs_first_failure_boot


def test_coverage_guided_reaches_more_code_under_boot_and_wall_time_limits():
    baseline, calibration, boot_state = _make_coverage_guided_fixture()

    bfs_limited = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=6,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="breadth_first",
    )
    bfs_results, bfs_summary = bfs_limited.run()

    cg_limited = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=6,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    cg_results, cg_summary = cg_limited.run()

    assert bfs_summary["stopped_reason"] == "max_new_states"
    assert cg_summary["stopped_reason"] == "max_new_states"
    assert (
        cg_summary["coverage_units_reached"]
        > bfs_summary["coverage_units_reached"]
    )
    assert any(r["boot_outcome"] == "boot_failure" for r in cg_results)
    assert not any(r["boot_outcome"] == "boot_failure" for r in bfs_results)

    # Also verify under max_wall_time_s where each boot advances the clock by 1s.
    bfs_clock = [0.0]

    def bfs_timed_boot(state, chain, generation):
        bfs_clock[0] += 1.0
        return boot_state(state, chain, generation)

    cg_clock = [0.0]

    def cg_timed_boot(state, chain, generation):
        cg_clock[0] += 1.0
        return boot_state(state, chain, generation)

    _, bfs_time_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=5.5,
        clock=lambda: bfs_clock[0],
        boot_state=bfs_timed_boot,
        order="breadth_first",
    ).run()

    _, cg_time_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=5.5,
        clock=lambda: cg_clock[0],
        boot_state=cg_timed_boot,
        order="coverage_guided",
    ).run()

    assert bfs_time_summary["stopped_reason"] == "max_wall_time_s"
    assert cg_time_summary["stopped_reason"] == "max_wall_time_s"
    assert (
        cg_time_summary["coverage_units_reached"]
        > bfs_time_summary["coverage_units_reached"]
    )


def test_explorer_stops_on_coverage_plateau_and_checkpoints_state():
    baseline, calibration, boot_state = _make_coverage_guided_fixture()

    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
        max_boots_without_new_coverage=3,
    )
    results, summary = explorer.run()

    assert summary["stopped_reason"] == "coverage_plateau"
    assert summary["consecutive_boots_without_new_coverage"] == 3
    assert summary["states_excluded_by_coverage_plateau"] > 0
    assert summary["coverage_units_reached"] == 4
    assert len(summary["coverage_by_boot"]) == len(results)

    checkpoint = explorer.export_coverage_checkpoint()
    assert checkpoint["schema_version"] == 1
    assert checkpoint["seen_coverage"] == [0x1000, 0x1004, 0x1008, 0x2000]

    restored = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0,),
        max_cuts=1,
        max_new_states=10,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    restored.restore_coverage_checkpoint(checkpoint)
    assert restored.summary["coverage_units_reached"] == 4


def test_explorer_rejects_invalid_order_or_missing_coverage_when_required():
    baseline = PersistentState.from_bytes(b"\xff")
    calibration = merge_operation_traces([_write(1, 0, 1)], [])

    with pytest.raises(
        ValueError,
        match=r"unsupported state_search order",
    ):
        RecoveryStateExplorer(
            baseline,
            calibration,
            first_cuts=(0,),
            max_cuts=1,
            max_new_states=5,
            max_wall_time_s=30,
            clock=lambda: 1.0,
            boot_state=lambda *_a: ({"fault_injected": True}, ()),
            order="random_walk",
        )

    with pytest.raises(
        ValueError,
        match=r"requires recovery coverage data on each booted state",
    ):
        RecoveryStateExplorer(
            baseline,
            calibration,
            first_cuts=(0,),
            max_cuts=1,
            max_new_states=5,
            max_wall_time_s=30,
            clock=lambda: 1.0,
            boot_state=lambda *_a: ({"fault_injected": True}, ()),
            order="coverage_guided",
        ).run()


def test_coverage_guided_checkpoint_resume_matches_single_run():
    import json

    baseline, calibration, boot_state = _make_coverage_guided_fixture()
    inputs = {
        "firmware_sha256": "f" * 64,
        "profile_sha256": "a" * 64,
        "tardigrade_revision": "b" * 40,
        "renode_version": "1.17.0",
    }

    first = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=5,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    prior, first_summary = first.run()
    assert first_summary["stopped_reason"] == "max_new_states"
    saved = json.loads(json.dumps(first.checkpoint(inputs)))
    assert "coverage_state" in saved

    second = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    )
    second.restore(saved, inputs)
    actual, summary = second.run()

    expected, expected_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=105,
        max_wall_time_s=60,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
    ).run()

    for idx, row in enumerate(actual):
        assert row["recovery_state_search"].pop("resume_origin") == (
            "before_resume" if idx < len(prior) else "after_resume"
        )
    assert actual == expected
    assert summary == expected_summary


def test_coverage_guided_sharded_merge_matches_single_run_and_attributes_coverage():
    from audit_report import summarize_runtime_sweep
    from merge_state_search import merge_reports
    from recovery_search_shard import ShardedRecoveryStateExplorer

    baseline, calibration, boot_state = _make_coverage_guided_fixture()
    scope = {
        "enabled": True,
        "mechanism": "oneshot_address_hooks",
        "granularity": "function_only",
        "line_info_available": False,
        "line_info_notice": "No DWARF line info in synthetic fixture.",
        "functions": [
            {
                "id": "common_recovery@0x00001000",
                "name": "common_recovery",
                "start_address": "0x00001000",
                "end_address": "0x0000100C",
                "size_bytes": 12,
                "probe_pcs": [0x1000, 0x1004, 0x1008],
            },
            {
                "id": "rare_recovery_branch@0x00002000",
                "name": "rare_recovery_branch",
                "start_address": "0x00002000",
                "end_address": "0x00002008",
                "size_bytes": 8,
                "probe_pcs": [0x2000, 0x2004],
            },
            {
                "id": "deep_bug_handler@0x00003000",
                "name": "deep_bug_handler",
                "start_address": "0x00003000",
                "end_address": "0x00003008",
                "size_bytes": 8,
                "probe_pcs": [0x3000, 0x3004],
            },
        ],
        "source_lines": [],
        "basic_blocks": [
            {"start": 0x1000, "end": 0x1004},
            {"start": 0x1004, "end": 0x1008},
            {"start": 0x1008, "end": 0x100C},
            {"start": 0x2000, "end": 0x2004},
            {"start": 0x2004, "end": 0x2008},
            {"start": 0x3000, "end": 0x3004},
            {"start": 0x3004, "end": 0x3008},
        ],
        "probe_pcs": [0x1000, 0x1004, 0x1008, 0x2000, 0x2004, 0x3000, 0x3004],
        "active_intervals": [[0x1000, 0x100C], [0x2000, 0x2008], [0x3000, 0x3008]],
    }
    expect = {
        "control_outcome": "success",
        "should_find_issues": True,
        "mode": "regression",
    }
    shard_reports = []
    for shard_idx in range(2):
        explorer = ShardedRecoveryStateExplorer(
            baseline,
            calibration,
            first_cuts=(0, 1, 2, 3),
            max_cuts=2,
            max_new_states=100,
            max_wall_time_s=30,
            clock=lambda: 0.0,
            boot_state=boot_state,
            order="coverage_guided",
            shard_count=2,
            shard_index=shard_idx,
        )
        rows, _summary = explorer.run()
        runtime = summarize_runtime_sweep(
            rows, expected_fault_points=1, expected_control_points=0
        )
        shard_reports.append(
            {
                "state_search_shard": {
                    **explorer.partition,
                    "firmware_sha256": "1" * 64,
                    "profile_sha256": "2" * 64,
                    "tardigrade_revision": "3" * 40,
                    "renode_version": "1.17.0",
                    "report_context": {
                        "expect": expect,
                        "page_size": 4096,
                        "slots": {},
                        "planned_fault_types": ["rs"],
                        "total_writes": 4,
                        "calibration_point_coverage": {},
                        "recovery_coverage_scope": scope,
                    },
                },
                "summary": {"runtime_sweep": runtime},
                "runtime_sweep_results": rows,
                "expect": expect,
                "profile": "cg_sharded",
                "calibrated_writes": 4,
                "fault_points_tested": 1,
            }
        )

    merged = merge_reports(shard_reports)
    single_rows, single_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="coverage_guided",
    ).run()
    summarize_runtime_sweep(
        single_rows, expected_fault_points=1, expected_control_points=0
    )
    assert merged["runtime_sweep_results"] == single_rows
    assert (
        merged["summary"]["runtime_sweep"]["recovery_state_search"]
        == single_summary
    )
    assert "recovery_coverage" in merged
    cov_report = merged["recovery_coverage"]
    assert cov_report["function_summary"]["executed_only_under_cut_count"] == 2
    assert cov_report["function_summary"]["never_executed_by_cut_count"] == 1


def test_coverage_guided_plan_only_sizing():
    baseline, calibration, boot_state = _make_coverage_guided_fixture()
    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=(0, 1, 2, 3),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 1.0,
        boot_state=boot_state,
        order="coverage_guided",
        plan_only=True,
    )
    rows, summary = explorer.run()
    assert summary["stopped_reason"] == "plan_complete"
    assert len(rows) == 4
    assert "generation_two_plan" in summary
    assert explorer.checkpoint({}) is None


def test_guided_boot_preserves_trace_context_and_sibling_comparison():
    writes = [_write(1, 0, 0x10), _write(2, 1, 0x20)]
    contexts = ["0x1010@0x1021", "0x1030@0x1041"]
    for write, context in zip(writes, contexts):
        write["call_context"] = context

    def boot(state, chain, generation):
        index = chain[-1]["operation_index"]
        return {
            "boot_outcome": ("success", "no_boot")[index],
            "recovery_coverage": {"executed_pcs": [0x1000 + 2 * index]},
        }, []

    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"abcd"), merge_operation_traces(writes, []),
        first_cuts=(0, 1), max_cuts=1, max_new_states=2, max_wall_time_s=10,
        clock=lambda: 1, boot_state=boot, order="coverage_guided",
    )
    rows, _ = explorer.run()
    explorer.compare_boot_snapshots()
    good, bad = rows
    assert [row["recovery_state_search"]["chain"]["cuts"][0]["call_context"]
            for row in rows] == contexts
    assert bad["recovery_coverage"]["executed_pcs"] == [0x1002]
    comparison = bad["_sibling_snapshot_comparison"]
    assert comparison["sibling"] == good["recovery_state_search"]["state_identity"]
    assert comparison["comparison"]["ranges"]


def _make_best_first_tiered_fixture(with_coverage=False):
    # Slot layout: exec slot [0x0000, 0x4000) with page_size=0x1000 (4096).
    # - Boundary region: [0x0000, 0x2000)
    # - Bulk region:     [0x2000, 0x3000)
    # - Trailer region:  [0x3000, 0x4000), trailer tail [0x3FC0, 0x4000)
    # - Declared metadata_regions: [0x3800, 0x3900)
    baseline = PersistentState.from_bytes(
        b"\xff" * 0x4000,
        name="nvm",
        base_address=0,
    )
    calibration_writes = [
        # 8 bulk writes in [0x2000, 0x2020)
        _write(1, 0x2000, 0x11111111),
        _write(2, 0x2004, 0x22222222),
        _write(3, 0x2008, 0x33333333),
        _write(4, 0x200C, 0x44444444),
        _write(5, 0x2010, 0x55555555),
        _write(6, 0x2014, 0x66666666),
        # 1 boundary write in [0x0100, 0x0104)
        _write(7, 0x0100, 0x77777777),
        # 2 declared metadata writes in [0x3800, 0x3808)
        _write(8, 0x3800, 0x88888888),
        _write(9, 0x3804, 0x99999999),
        # 1 trailer tail write at 0x3FF0
        _write(10, 0x3FF0, 0xAAAAAAAA),
    ]
    calibration = merge_operation_traces(calibration_writes, [])

    def boot_state(state, chain, generation):
        first_op = int(chain[0]["operation_index"])
        last_op = int(chain[-1]["operation_index"])
        outcome = "success"
        if generation == 2 and first_op == 9 and last_op == 2:
            outcome = "no_boot"
        result = {
            "boot_outcome": outcome,
            "boot_slot": "exec",
            "fault_injected": True,
            "signals": {},
        }
        if with_coverage:
            if generation == 1:
                if first_op in (7, 8):
                    pcs = [0x1000, 0x1004]
                elif first_op == 9:
                    pcs = [0x1000, 0x2000, 0x2004]
                else:
                    pcs = [0x1000]
            else:
                pcs = [0x1000, 0x3000 + 4 * first_op + last_op]
            result["recovery_coverage"] = {"executed_pcs": pcs}

        if generation >= 2:
            return result, ()

        # Each Generation-1 state produces a recovery trace with 2 bulk writes
        # and 1 trailer-tail write (index 2).
        rec_writes = [
            _write(1, 0x2100 + first_op * 0x10, 0xA0000001 + first_op),
            _write(2, 0x2104 + first_op * 0x10, 0xB0000002 + first_op),
            _write(3, 0x3FC0 + first_op * 4, 0xC0000003 + first_op),
        ]
        return result, merge_operation_traces(rec_writes, [])

    return baseline, calibration, boot_state


def test_best_first_without_coverage_orders_metadata_and_recovery_cuts_before_bulk():
    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=False
    )
    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_new_states=7,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="best_first",
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
        starvation_guard_interval=0,
    )
    rows, summary = explorer.run()
    assert summary["order"] == "best_first"
    assert summary["stopped_reason"] == "max_new_states"
    # Metadata first cuts (indices 7, 8, 9) and their metadata recovery cuts
    # (generation 2 at index 2) are evaluated ahead of bulk first cuts (0..5).
    chains = [
        tuple(
            cut["operation_index"]
            for cut in r["recovery_state_search"]["chain"]["cuts"]
        )
        for r in rows
    ]
    assert (7,) in chains
    assert (8,) in chains
    assert (9,) in chains
    assert (9, 2) in chains
    assert any(r["boot_outcome"] == "no_boot" for r in rows)
    # Generation-2 metadata cuts were interleaved before all Generation-1 cuts finished.
    generations = [r["recovery_state_search"]["generation"] for r in rows]
    assert 2 in generations
    assert summary["evaluated_states_by_generation"]["2"] >= 1
    assert summary["evaluated_states_by_tier"]["metadata"] >= 4


def test_best_first_with_coverage_prioritizes_novel_signature_parents_across_generations():
    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=True
    )
    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_new_states=6,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="best_first",
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
        starvation_guard_interval=0,
    )
    rows, summary = explorer.run()
    chains = [
        tuple(
            cut["operation_index"]
            for cut in r["recovery_state_search"]["chain"]["cuts"]
        )
        for r in rows
    ]
    # Cut 8 shares cut 7's coverage signature [0x1000, 0x1004], so after cut 7 is
    # probed, cut 8 is not expanded ahead of cut 9; cut 9 reaches novel signature
    # [0x1000, 0x2000, 0x2004] and its recovery cut (9, 2) is immediately expanded
    # ahead of (8, 2).
    assert (9, 2) in chains
    assert (8, 2) not in chains
    assert any(r["boot_outcome"] == "no_boot" for r in rows)
    assert summary["evaluated_states_by_generation"]["2"] >= 2


def test_best_first_starvation_guard_evaluates_generation_one_in_trace_order():
    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=True
    )
    explorer = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_new_states=8,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="best_first",
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
        starvation_guard_interval=3,
    )
    rows, _summary = explorer.run()
    chains = [
        tuple(
            cut["operation_index"]
            for cut in r["recovery_state_search"]["chain"]["cuts"]
        )
        for r in rows
    ]
    # Despite bulk first cuts (0, 1, ...) having tier_rank=2, the starvation
    # guard periodically schedules Generation-1 cuts in trace order (0, then 1).
    assert (0,) in chains
    assert (1,) in chains
    assert chains.index((0,)) < chains.index((1,))


def test_best_first_determinism_across_repeated_runs():
    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=True
    )
    runs = []
    for _ in range(3):
        explorer = RecoveryStateExplorer(
            baseline,
            calibration,
            first_cuts=tuple(range(10)),
            max_cuts=2,
            max_new_states=15,
            max_wall_time_s=30,
            clock=lambda: 0.0,
            boot_state=boot_state,
            order="best_first",
            page_size=0x1000,
            slot_ranges=[{"start": 0x0000, "end": 0x4000}],
            metadata_regions=[{"start": 0x3800, "end": 0x3900}],
        )
        runs.append(explorer.run())
    first_rows, first_summary = runs[0]
    for rows, summary in runs[1:]:
        assert rows == first_rows
        assert summary == first_summary


def test_best_first_unlimited_equals_breadth_first_and_limited_reports_tier_generation_counts():
    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=True
    )
    common_kwargs = dict(
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
    )
    bfs_rows, bfs_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=200,
        order="breadth_first",
        **common_kwargs,
    ).run()
    bf_rows, bf_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=200,
        order="best_first",
        **common_kwargs,
    ).run()
    assert bfs_summary["complete"] is True
    assert bf_summary["complete"] is True
    assert bf_summary["states_booted"] == bfs_summary["states_booted"]
    bfs_outcomes = {
        r["recovery_state_search"]["state_identity"]: r["boot_outcome"]
        for r in bfs_rows
    }
    bf_outcomes = {
        r["recovery_state_search"]["state_identity"]: r["boot_outcome"]
        for r in bf_rows
    }
    assert bf_outcomes == bfs_outcomes
    assert bf_summary["unexpanded_states_by_generation"] == {}
    assert bf_summary["unexpanded_states_by_tier"] == {
        "metadata": 0,
        "boundary": 0,
        "bulk": 0,
    }

    # Under a limit, per-generation and per-tier counts of evaluated and
    # unexpanded states are reported in summary.
    lim_rows, lim_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=8,
        order="best_first",
        **common_kwargs,
    ).run()
    assert lim_summary["complete"] is False
    assert lim_summary["stopped_reason"] == "max_new_states"
    assert sum(lim_summary["evaluated_states_by_generation"].values()) == len(
        lim_rows
    )
    assert sum(lim_summary["evaluated_states_by_tier"].values()) == len(
        lim_rows
    )
    assert sum(lim_summary["unexpanded_states_by_generation"].values()) > 0
    assert (
        sum(lim_summary["unexpanded_states_by_tier"].values())
        == sum(lim_summary["unexpanded_states_by_generation"].values())
    )


@pytest.mark.parametrize("with_coverage", [False, True])
@pytest.mark.parametrize("split_at", [3, 7, 12])
def test_best_first_checkpoint_resume_and_plan_only_sizing(
    with_coverage, split_at
):
    import json

    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=with_coverage
    )
    common_kwargs = dict(
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="best_first",
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
    )
    full_rows, full_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=100,
        **common_kwargs,
    ).run()

    part1 = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=split_at,
        **common_kwargs,
    )
    part1.run()
    ckpt = json.loads(json.dumps(part1.checkpoint({})))
    assert ckpt is not None

    part2 = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=100 - split_at,
        **common_kwargs,
    )
    part2.restore(ckpt, {})
    resumed_rows, resumed_summary = part2.run()
    for row in resumed_rows:
        row["recovery_state_search"].pop("resume_origin", None)
    assert resumed_rows == full_rows
    assert resumed_summary == full_summary

    # Plan-only sizing under order="best_first" matches breadth_first sizing.
    plan_bf = RecoveryStateExplorer(
        baseline,
        calibration,
        max_new_states=100,
        plan_only=True,
        **common_kwargs,
    )
    _, plan_bf_summary = plan_bf.run()
    plan_bfs = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="breadth_first",
        plan_only=True,
        page_size=0x1000,
        slot_ranges=[{"start": 0x0000, "end": 0x4000}],
        metadata_regions=[{"start": 0x3800, "end": 0x3900}],
    )
    _, plan_bfs_summary = plan_bfs.run()
    assert (
        plan_bf_summary["generation_two_plan"]
        == plan_bfs_summary["generation_two_plan"]
    )


def test_best_first_sharded_merge_matches_unsharded():
    from audit_report import summarize_runtime_sweep
    from merge_state_search import merge_reports
    from recovery_search_shard import ShardedRecoveryStateExplorer

    baseline, calibration, boot_state = _make_best_first_tiered_fixture(
        with_coverage=True
    )
    slots = {"exec": {"base": 0x0000, "size": 0x4000}}
    metadata_regions = [{"start": 0x3800, "end": 0x3900}]
    expect = {
        "control_outcome": "success",
        "should_find_issues": True,
        "mode": "regression",
    }
    shard_reports = []
    for shard_idx in range(3):
        explorer = ShardedRecoveryStateExplorer(
            baseline,
            calibration,
            first_cuts=tuple(range(10)),
            max_cuts=2,
            max_new_states=100,
            max_wall_time_s=30,
            clock=lambda: 0.0,
            boot_state=boot_state,
            order="best_first",
            page_size=0x1000,
            slots=slots,
            metadata_regions=metadata_regions,
            shard_count=3,
            shard_index=shard_idx,
        )
        rows, _summary = explorer.run()
        runtime = summarize_runtime_sweep(
            rows, expected_fault_points=1, expected_control_points=0
        )
        shard_reports.append(
            {
                "state_search_shard": {
                    **explorer.partition,
                    "firmware_sha256": "1" * 64,
                    "profile_sha256": "2" * 64,
                    "tardigrade_revision": "3" * 40,
                    "renode_version": "1.17.0",
                    "report_context": {
                        "expect": expect,
                        "page_size": 0x1000,
                        "slots": slots,
                        "metadata_regions": metadata_regions,
                        "planned_fault_types": ["rs"],
                        "total_writes": 10,
                        "calibration_point_coverage": {},
                    },
                },
                "summary": {"runtime_sweep": runtime},
                "runtime_sweep_results": rows,
                "expect": expect,
                "profile": "bf_sharded",
                "calibrated_writes": 10,
                "fault_points_tested": 1,
            }
        )

    merged = merge_reports(shard_reports)
    single_rows, single_summary = RecoveryStateExplorer(
        baseline,
        calibration,
        first_cuts=tuple(range(10)),
        max_cuts=2,
        max_new_states=100,
        max_wall_time_s=30,
        clock=lambda: 0.0,
        boot_state=boot_state,
        order="best_first",
        page_size=0x1000,
        slots=slots,
        metadata_regions=metadata_regions,
    ).run()
    summarize_runtime_sweep(
        single_rows, expected_fault_points=1, expected_control_points=0
    )
    assert merged["runtime_sweep_results"] == single_rows
    assert (
        merged["summary"]["runtime_sweep"]["recovery_state_search"]
        == single_summary
    )
