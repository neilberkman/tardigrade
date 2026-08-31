from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from writeback_reconstruction import (
    AmbiguousWriteEvent,
    normalise_write_event,
    parse_write_trace_record,
    reconstruct_committed_snapshot,
    validate_erase_trace_data,
    validate_write_trace_width,
    is_unsupported_writeback_fault_type,
    is_known_writeback_fault_type,
)


def test_committed_write_then_erase_then_pending_write_is_erased():
    baseline = bytes([0xFF] * 32)
    trace = [
        (1, 0, 0x11223344, 4),
        (2, 8, 0xAABBCCDD, 4),  # commits event 1 with capacity=1
        (3, 0, 0x55667788, 4),  # pending when the fault occurs
    ]
    erases = [(0, 2, 4)]

    committed, discarded = reconstruct_committed_snapshot(
        baseline, trace, erases, 3, 0x08000000, 16, 1
    )

    assert discarded == 1
    assert committed[0:4] == b"\xff\xff\xff\xff"
    assert committed[8:12] == b"\xdd\xcc\xbb\xaa"


def test_large_pending_window_preserves_only_committed_trailer_write():
    baseline = bytes([0xFF] * 64)
    trace = []
    for write_index in range(1, 100001):
        offset = 16
        value = write_index
        if write_index == 67232:
            offset, value = 0, 0x11111111
        elif write_index == 67233:
            offset, value = 4, 0x22222222
        elif write_index == 100000:
            offset, value = 8, 0x33333333
        trace.append((write_index, offset, value, 4))

    committed, discarded = reconstruct_committed_snapshot(
        baseline, trace, [], 100000, 0x08000000, 0x20000, 32768
    )

    assert discarded == 32768
    assert committed[0:4] == b"\x11\x11\x11\x11"
    assert committed[4:12] == b"\xff" * 8


def test_byte_and_halfword_pending_events_do_not_touch_neighbours():
    baseline = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
    trace = [
        (1, 1, 0xAB, 1),
        (2, 4, 0xCDEF, 2),
    ]

    committed, discarded = reconstruct_committed_snapshot(
        baseline, trace, [], 2, 0x08000000, 16, 1
    )

    assert discarded == 1
    assert committed == bytes([0x10, 0xAB, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])


def test_eight_byte_program_event_is_supported_for_nvm_backends():
    event = normalise_write_event((1, 0, 0x8877665544332211, 8))
    assert event == (1, 0, 0x8877665544332211, 8)


def test_eight_byte_reconstruction_preserves_only_committed_event():
    baseline = bytes([0xFF] * 24)
    trace = [
        (1, 0, 0x8877665544332211, 8),
        (2, 8, 0x0102030405060708, 8),
    ]
    committed, discarded = reconstruct_committed_snapshot(
        baseline, trace, [], 2, 0x10000000, 4096, 1
    )
    assert discarded == 1
    assert committed[:8] == b"\x11\x22\x33\x44\x55\x66\x77\x88"
    assert committed[8:] == b"\xFF" * 16


def test_trailing_erase_at_fault_boundary_is_applied():
    baseline = bytes([0x00] * 16)
    trace = [(1, 0, 0x11223344, 4)]
    committed, discarded = reconstruct_committed_snapshot(
        baseline, trace, [(0, 0, 4)], 1, 0x10000000, 4096, 8
    )
    assert discarded == 1
    assert committed == b"\xFF" * 4 + b"\x00" * 12


def test_legacy_trace_requires_explicit_backend_width():
    assert validate_write_trace_width([(1, 0, 1)], legacy_width=4) == [(1, 0, 1, 4)]
    with pytest.raises(AmbiguousWriteEvent):
        validate_write_trace_width([(1, 0, 1)])


def test_write_trace_parser_accepts_colon_comma_and_width_records():
    assert parse_write_trace_record('1:16:287454020') == (1, 16, 287454020)
    assert parse_write_trace_record('1,16,287454020') == (1, 16, 287454020)
    assert parse_write_trace_record('1,16,287454020,2') == (1, 16, 287454020, 2)
    assert parse_write_trace_record('1:16') == (1, 16, 0)


def test_erase_trace_validation_rejects_negative_and_out_of_bounds_records():
    with pytest.raises(ValueError):
        validate_erase_trace_data([(-1, 0, 4)], flash_size=16, page_size=4)
    with pytest.raises(ValueError):
        validate_erase_trace_data([(14, 0, 4)], flash_size=16, page_size=4)


def test_erase_trace_validation_can_reject_non_monotonic_native_records():
    entries = [(0, 2, 4), (4, 1, 4)]
    assert validate_erase_trace_data(entries, flash_size=16, page_size=4)
    with pytest.raises(ValueError):
        validate_erase_trace_data(
            entries, flash_size=16, page_size=4, require_monotonic=True
        )


def test_unsupported_writeback_lifecycle_prefixes_are_explicitly_rejected():
    for fault_type in (
        "m:w",
        "m:b",
        "h:3:b",
        "cc:2:w",
        "p2:4:5:w:e",
        "p2:4:5:b:b",
        "mf:1:2",
        "c:4:7",
    ):
        assert is_unsupported_writeback_fault_type(fault_type)
    assert not is_unsupported_writeback_fault_type("w")
    assert not is_unsupported_writeback_fault_type("nv:0")


def test_unknown_or_malformed_writeback_fault_types_fail_closed():
    for fault_type in ("", "bogus", "h", "p2", "unknown:1"):
        assert not is_known_writeback_fault_type(fault_type)
        assert is_unsupported_writeback_fault_type(fault_type)
    for fault_type in ("w", "w:ss:4", "b:17", "nv:0", "h:3:w"):
        assert is_known_writeback_fault_type(fault_type)


def test_writeback_erase_and_atomicity_faults_are_explicitly_unsupported():
    for fault_type in ("e", "a", "interrupted_erase", "multi_sector_atomicity"):
        assert is_unsupported_writeback_fault_type(fault_type)
