# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def write(offset, value, time=7):
    return dict(kind="write", region="nvm", offset=offset, width=2, value=value,
                pc="0x00000040", virtual_us_since_reset=time)


def compare(a, b, start="a", mismatch=None):
    from recovery_trace_comparison import compare_recovery_traces
    return compare_recovery_traces(a, b, "a", start, 0x1000, 0xff, mismatch)


def test_write_data_disagreement_locates_last_writer_in_each_boot():
    a = [write(2, 1), write(3, 0x1234), write(8, 8)]
    b = [write(2, 1), write(3, 0x1278, 9), write(8, 8)]
    result = compare(a, b, mismatch=dict(kind="bytes", region="nvm", offset=3))
    assert result["classification"] == "same operations, different data"
    assert result["starting_state_identical"]
    diff = result["first_differing_operation"]
    assert diff["index"] == 1 and diff["live"]["address"] == "0x00001003"
    assert (diff["computed"]["data"], diff["live"]["data"]) == ("3412", "7812")
    assert diff["live"]["virtual_us_since_reset"] == 9
    assert result["last_completed_writer"]["computed"] == diff["computed"]


def test_sequence_disagreement_after_earlier_data_disagreement():
    erase = dict(kind="erase", region="nvm", offset=0, erase_size=4)
    result = compare([write(0, 2), erase], [write(0, 3), write(0, 4)])
    assert result["classification"] == "different operation sequence"
    assert result["first_differing_operation"]["index"] == 0


@pytest.mark.parametrize("short_side", ["computed", "live"])
def test_unmatched_tail_has_only_one_event(short_side):
    traces = [[write(0, 2)], [write(0, 2), write(4, 3)]]
    if short_side == "live":
        traces.reverse()
    result = compare(*traces)
    assert result["classification"] == "one boot ended early"
    assert result["trace_lengths"][short_side] == 1
    assert result["first_differing_operation"][short_side] is None


def test_replay_defect_requires_equal_initial_state_and_operations():
    a, b = [write(0, 2)], [write(0, 2, 12)]
    diff = dict(kind="bytes", region="nvm", offset=6)
    result = compare(a, b, mismatch=diff)
    assert result["classification"] == "identical traces, different resulting state (replay defect)"
    assert result["last_completed_writer"] == {"computed": None, "live": None}
    assert compare(a, b, start="b", mismatch=diff)["starting_state_identical"] is False
    assert compare(a, b)["classification"] == "identical traces"


def test_byte_history_distinguishes_completed_writer_and_overlapping_cut():
    from recovery_trace_comparison import compare_recovery_traces
    erased = dict(kind="erase", region="nvm", offset=0, erase_size=16)
    trace = [erased, write(2, 8)]
    diff = dict(kind="bytes", region="nvm", offset=2)
    result = compare_recovery_traces(trace, trace, "a", "a", 0x1000, 255, diff, cut_reached=True)
    assert result["last_completed_writer"]["computed"]["kind"] == "erase"
    assert result["interrupted_operation_covering_byte"]["live"]["index"] == 1


def test_different_tracking_bases_preclude_replay_defect():
    from recovery_trace_comparison import compare_recovery_traces
    result = compare_recovery_traces([], [], "start", "start", 0, 0,
                                     {"kind": "region_length"}, trace_bases=("a", "b"))
    assert result["classification"] == "identical operations, different states at tracking start"


def test_interrupted_program_compares_issued_data():
    a = [dict(write(2, 0xabcd), intended_value=0xabcd)]
    b = [dict(write(2, 0x00cd), intended_value=0xabcd)]
    assert compare(a, b)["classification"] == "identical traces"

