# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from recovery_state import (
    PersistentState,
    RecoveryStateComputer,
    RecoveryStateError,
    apply_completed_operation,
    apply_interrupted_operation,
    merge_operation_traces,
)


def write(index=1, offset=0, value=0x44332211, width=4):
    return {
        "kind": "write",
        "write_index": index,
        "offset": offset,
        "value": value,
        "width": width,
    }


def erase(index=1, offset=0, size=8, writes_at=0):
    return {
        "kind": "erase",
        "erase_index": index,
        "offset": offset,
        "erase_size": size,
        "writes_at_this_point": writes_at,
    }


def raw(state):
    return state.materialize()["nvm"]


def test_merge_operation_traces_puts_erases_at_their_write_boundary():
    operations = merge_operation_traces(
        [write(1, 0), write(2, 4)],
        [erase(1, 8, 4, writes_at=0), erase(2, 12, 4, writes_at=1)],
    )

    assert [(op["kind"], op["operation_index"]) for op in operations] == [
        ("erase", 0),
        ("write", 0),
        ("erase", 1),
        ("write", 1),
    ]
    assert [op["sequence"] for op in operations] == list(range(4))


def test_merge_operation_traces_accepts_full_width_hex_values():
    operations = merge_operation_traces(
        [write(value="0xFFFFFF01")],
        [],
    )
    assert operations[0]["value"] == 0xFFFFFF01


def test_merge_operation_traces_rejects_ambiguous_order():
    with pytest.raises(RecoveryStateError, match="strictly increasing"):
        merge_operation_traces([write(1), write(1, 4)], [])


def test_completed_operations_replay_write_and_erase_and_clear_ecc_marks():
    state = PersistentState.from_bytes(
        bytes(range(16)), uncorrectable_words=(0, 8)
    )
    state = apply_completed_operation(state, write(offset=0), erase_fill=0xEE)
    state = apply_completed_operation(state, erase(offset=8, size=4), erase_fill=0xEE)

    assert raw(state) == b"\x11\x22\x33\x44\x04\x05\x06\x07" + b"\xEE" * 4 + bytes(range(12, 16))
    assert state.uncorrectable_words == frozenset()


@pytest.mark.parametrize(
    ("mode", "expected", "marked"),
    [
        ("half", b"\x11\x22\xEE\xEE", False),
        ("half_retain", b"\x11\x22\x30\x40", False),
        ("untouched", b"\x10\x20\x30\x40", False),
        ("erased", b"\xEE\xEE\xEE\xEE", False),
        ("programmed", b"\x11\x22\x33\x44", False),
        ("uncorrectable", b"\x10\x20\x30\x40", True),
    ],
)
def test_mram_power_loss_modes(mode, expected, marked):
    state = PersistentState.from_bytes(b"\x10\x20\x30\x40")
    result = apply_interrupted_operation(
        state,
        write(),
        backend_kind="mram",
        torn_word_mode=mode,
        erase_fill=0xEE,
    )

    assert raw(result) == expected
    assert (("nvm", 0) in result.uncorrectable_words) is marked


def test_mram_corrupted_mode_matches_deterministically_and_changes_data():
    state = PersistentState.from_bytes(b"\x10\x20\x30\x40")
    one = apply_interrupted_operation(
        state,
        write(),
        backend_kind="mram",
        torn_word_mode="corrupted",
        corruption_seed=0x1234,
    )
    two = apply_interrupted_operation(
        state,
        write(),
        backend_kind="mram",
        torn_word_mode="corrupted",
        corruption_seed=0x1234,
    )

    assert raw(one) == raw(two)
    assert raw(one) != b"\x11\x22\x33\x44"


def test_flash_power_loss_leaves_target_write_untouched():
    state = PersistentState.from_bytes(b"\x10\x20\x30\x40")
    result = apply_interrupted_operation(state, write(), backend_kind="flash")
    assert raw(result) == raw(state)


@pytest.mark.parametrize(
    ("fault_type", "predicate"),
    [
        ("bit_corruption", lambda before, after: after[:4] not in (before[:4], b"\x00" * 4)),
        ("silent_write_failure", lambda before, after: after[:4] == b"\x00" * 4 and after[4:] == before[4:]),
        ("write_rejection", lambda before, after: after == before),
        ("driver_error", lambda before, after: after == before),
        ("write_disturb", lambda before, after: after[:4] == b"\x00" * 4 and after[4:8] != before[4:8]),
        ("wear_leveling_corruption", lambda before, after: after[:4] != before[:4] and after != before),
    ],
)
def test_computed_write_fault_types(fault_type, predicate):
    before = b"\xFF" * 16
    state = PersistentState.from_bytes(before)
    result = apply_interrupted_operation(
        state,
        write(offset=0, value=0),
        fault_type=fault_type,
        corruption_seed=7,
        page_size=16,
    )
    assert predicate(before, raw(result))


@pytest.mark.parametrize(
    ("mode", "expected", "marks"),
    [
        ("half", b"\xEE" * 4 + b"\x04\x05\x06\x07", frozenset()),
        ("half_retain", b"\xEE" * 4 + b"\x04\x05\x06\x07", frozenset()),
        ("untouched", bytes(range(8)), frozenset()),
        ("erased", b"\xEE" * 8, frozenset()),
        ("programmed", b"\xEE" * 8, frozenset()),
        ("uncorrectable", bytes(range(8)), frozenset((("nvm", 0), ("nvm", 4)))),
    ],
)
def test_interrupted_erase_modes(mode, expected, marks):
    state = PersistentState.from_bytes(bytes(range(8)))
    result = apply_interrupted_operation(
        state,
        erase(size=8),
        fault_type="interrupted_erase",
        backend_kind="mram",
        torn_word_mode=mode,
        erase_fill=0xEE,
        program_unit=4,
    )

    assert raw(result) == expected
    assert result.uncorrectable_words == marks


def test_corrupted_erase_is_deterministic_and_not_plain_erased_fill():
    state = PersistentState.from_bytes(bytes(range(8)))
    one = apply_interrupted_operation(
        state,
        erase(size=8),
        fault_type="interrupted_erase",
        torn_word_mode="corrupted",
        erase_fill=0xEE,
        corruption_seed=9,
        program_unit=4,
    )
    two = apply_interrupted_operation(
        state,
        erase(size=8),
        fault_type="interrupted_erase",
        torn_word_mode="corrupted",
        erase_fill=0xEE,
        corruption_seed=9,
        program_unit=4,
    )
    assert raw(one) == raw(two)
    assert raw(one) != b"\xEE" * 8


def test_multi_sector_atomicity_erases_half_target_and_quarter_neighbor():
    state = PersistentState.from_bytes(bytes(range(16)))
    result = apply_interrupted_operation(
        state,
        erase(offset=0, size=8),
        fault_type="multi_sector_atomicity",
        erase_fill=0xEE,
    )
    assert raw(result) == b"\xEE" * 4 + bytes(range(4, 8)) + b"\xEE" * 2 + bytes(range(10, 16))


def test_identity_includes_all_regions_uncorrectable_words_and_persistent_values():
    baseline = PersistentState.from_bytes(b"abcd")
    same = PersistentState.from_bytes(b"abcd")
    marked = PersistentState.from_bytes(b"abcd", uncorrectable_words=(0,))
    valued = PersistentState.from_bytes(
        b"abcd", persistent_values={"latch": b"1"}
    )

    assert baseline.identity() == same.identity()
    assert baseline.identity() != marked.identity()
    assert baseline.identity() != valued.identity()


def test_identity_changes_only_the_merkle_path_for_a_write():
    state = PersistentState.from_bytes(b"a" * 4096 + b"b" * 4096)
    changed = state.write("nvm", 4096, b"Z")

    assert state.region().levels[0][0] == changed.region().levels[0][0]
    assert state.region().levels[0][1] != changed.region().levels[0][1]
    assert state.identity() != changed.identity()


def test_recovery_state_computer_cuts_before_each_operation_and_advances_prefix():
    state = PersistentState.from_bytes(b"\xFF" * 8)
    operations = merge_operation_traces(
        [write(1, 0, 0xAAAAAAAA), write(2, 4, 0xBBBBBBBB)], []
    )
    candidates = list(RecoveryStateComputer(state, operations).iter_cut_states())

    assert raw(candidates[0][1]) == b"\xFF" * 8
    assert raw(candidates[1][1]) == b"\xAA" * 4 + b"\xFF" * 4
    assert raw(RecoveryStateComputer(state, operations).final_state()) == b"\xAA" * 4 + b"\xBB" * 4
