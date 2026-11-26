# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Pure helpers for sampled live validation of trace-replayed cuts."""

from __future__ import division


class ReplayCrossCheckError(ValueError):
    pass


def replay_cross_check_selected(fault_at, every):
    """Select cuts independently of batch boundaries and worker ordering."""

    fault_at = int(fault_at)
    every = int(every)
    if every < 0:
        raise ReplayCrossCheckError("cross-check interval must be non-negative")
    return every > 0 and fault_at >= 0 and fault_at % every == 0


def _normalize_write(raw):
    if isinstance(raw, dict):
        return (
            int(raw.get("write_index", raw.get("index", 0))),
            int(raw.get("offset", raw.get("flash_offset", -1))),
            int(raw.get("value", 0)),
            int(raw.get("width", raw.get("write_width", 0))),
        )
    if len(raw) == 3:
        return (int(raw[0]), int(raw[1]), int(raw[2]), 4)
    return (int(raw[0]), int(raw[1]), int(raw[2]), int(raw[3]))


def _normalize_erase(raw, sequence):
    if isinstance(raw, dict):
        return (
            int(raw.get("erase_index", raw.get("index", sequence))),
            int(raw.get("offset", raw.get("flash_offset", -1))),
            int(raw.get("writes_at_this_point", raw.get("writes_at", 0))),
            int(raw.get("erase_size", raw.get("size", 0))),
        )
    return (int(sequence), int(raw[0]), int(raw[1]), int(raw[2]))


def _event_payload(event, operation):
    if event is None:
        return None
    if operation == "write":
        index, offset, value, width = event
        return {
            "write_index": index,
            "offset": "0x{:X}".format(offset),
            "value": "0x{:0{}X}".format(value, max(2, width * 2)),
            "width": width,
        }
    index, offset, writes_at, size = event
    return {
        "erase_index": index,
        "offset": "0x{:X}".format(offset),
        "writes_at_this_point": writes_at,
        "erase_size": size,
    }


def _first_sequence_difference(expected, observed, operation):
    common = min(len(expected), len(observed))
    for position in range(common):
        if expected[position] != observed[position]:
            return {
                "kind": "pre_cut_execution_diverged",
                "operation": operation,
                "sequence_position": position,
                "expected": _event_payload(expected[position], operation),
                "observed": _event_payload(observed[position], operation),
            }
    if len(expected) != len(observed):
        position = common
        return {
            "kind": "pre_cut_execution_diverged",
            "operation": operation,
            "sequence_position": position,
            "expected": _event_payload(
                expected[position] if position < len(expected) else None,
                operation,
            ),
            "observed": _event_payload(
                observed[position] if position < len(observed) else None,
                operation,
            ),
        }
    return None


def first_pre_cut_trace_difference(
    cut_kind,
    cut_index,
    expected_writes,
    observed_writes,
    expected_erases=(),
    observed_erases=(),
):
    """Return the first operation-prefix difference before a zero-based cut."""

    cut_kind = str(cut_kind).strip().lower()
    cut_index = int(cut_index)
    if cut_kind not in ("write", "erase"):
        raise ReplayCrossCheckError("cut kind must be write or erase")
    if cut_index < 0:
        raise ReplayCrossCheckError("cut index must be non-negative")

    wanted_writes = [_normalize_write(item) for item in expected_writes]
    actual_writes = [_normalize_write(item) for item in observed_writes]
    wanted_erases = [
        _normalize_erase(item, position)
        for position, item in enumerate(expected_erases, start=1)
    ]
    actual_erases = [
        _normalize_erase(item, position)
        for position, item in enumerate(observed_erases, start=1)
    ]

    if cut_kind == "write":
        completed_writes = cut_index
    else:
        target_erase = cut_index + 1
        target = next(
            (item for item in wanted_erases if item[0] == target_erase),
            None,
        )
        if target is None:
            raise ReplayCrossCheckError(
                "calibration has no erase at zero-based index {}".format(cut_index)
            )
        completed_writes = target[2]

    wanted_write_prefix = [item for item in wanted_writes if item[0] <= completed_writes]
    actual_write_prefix = [item for item in actual_writes if item[0] <= completed_writes]
    difference = _first_sequence_difference(
        wanted_write_prefix, actual_write_prefix, "write"
    )
    if difference is not None:
        return difference

    if cut_kind == "write":
        wanted_erase_prefix = [item for item in wanted_erases if item[2] <= cut_index]
        actual_erase_prefix = [item for item in actual_erases if item[2] <= cut_index]
    else:
        wanted_erase_prefix = [item for item in wanted_erases if item[0] <= cut_index]
        actual_erase_prefix = [item for item in actual_erases if item[0] <= cut_index]
    return _first_sequence_difference(
        wanted_erase_prefix, actual_erase_prefix, "erase"
    )
