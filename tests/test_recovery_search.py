# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from recovery_search import (  # noqa: E402
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
