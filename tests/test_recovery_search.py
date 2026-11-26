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
