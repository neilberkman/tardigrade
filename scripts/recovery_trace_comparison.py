# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Compare the storage operations observed by two recovery boots (IronPython compatible)."""


def _extent(op):
    return op["kind"], op["region"], op["offset"], op.get("width", op.get("erase_size"))


def _event(ops, index, base, erase_fill):
    if index >= len(ops):
        return None
    op = ops[index]
    kind, region, offset, width = _extent(op)
    if kind == "erase":
        data = "{:02x} repeated".format(erase_fill)
    else:
        value = op.get("intended_value", op["value"])
        data = "".join("{:02x}".format((value >> (8 * i)) & 255) for i in range(width))
    return {
        "index": index, "kind": kind, "region": region,
        "address": "0x{:08X}".format(base + offset), "width": width, "data": data,
        "pc": op.get("pc"), "virtual_us_since_reset": op.get("virtual_us_since_reset"),
        "call_context": op.get("call_context"),
    }


def compare_recovery_traces(computed, live, computed_start, live_start, base, erase_fill,
                            state_difference=None, cut_reached=False, trace_bases=None):
    """Compare issued operations. Timing, stack and interrupted completion are evidence."""
    shorter = min(len(computed), len(live))
    first = None
    sequence_differs = False
    for i in range(shorter):
        sequence_change = _extent(computed[i]) != _extent(live[i])
        sequence_differs |= sequence_change
        expected = computed[i].get("intended_value", computed[i].get("value"))
        observed = live[i].get("intended_value", live[i].get("value"))
        if first is None and (sequence_change or expected != observed):
            first = i
    if first is None and len(computed) != len(live):
        first = shorter
    if sequence_differs:
        classification = "different operation sequence"
    elif len(computed) != len(live):
        classification = "one boot ended early"
    elif first is not None:
        classification = "same operations, different data"
    elif computed_start is None or live_start is None:
        classification = "identical operations, starting state unavailable"
    elif computed_start != live_start:
        classification = "identical operations, different starting states"
    elif trace_bases and trace_bases[0] != trace_bases[1]:
        classification = "identical operations, different states at tracking start"
    elif state_difference:
        classification = "identical traces, different resulting state (replay defect)"
    else:
        classification = "identical traces"

    sides = (("computed", computed), ("live", live))
    result = {
        "classification": classification,
        "traces_identical": first is None,
        "trace_lengths": dict((side, len(ops)) for side, ops in sides),
        "starting_state_identical": (computed_start == live_start
                                     if computed_start is not None and live_start is not None else None),
        "starting_state": {"computed": computed_start, "live": live_start},
        "first_differing_operation": None,
    }
    if trace_bases:
        result["tracking_base"] = dict(zip(("computed", "live"), trace_bases))
    if first is not None:
        difference = dict((side, _event(ops, first, base, erase_fill)) for side, ops in sides)
        difference["index"] = first
        result["first_differing_operation"] = difference
    if state_difference:
        result["first_state_difference"] = state_difference
        if state_difference.get("kind") == "bytes":
            offset = state_difference["offset"]
            writers = {}
            interrupted = {}
            for side, ops in sides:
                writers[side] = None
                for index in range(len(ops) - 1, -1, -1):
                    _, region, start, width = _extent(ops[index])
                    if region == state_difference["region"] and start <= offset < start + width:
                        event = _event(ops, index, base, erase_fill)
                        if cut_reached and index == len(ops) - 1:
                            interrupted[side] = event
                            continue
                        writers[side] = event
                        break
            result["last_completed_writer"] = writers
            if interrupted:
                result["interrupted_operation_covering_byte"] = interrupted
    return result


def comparison_message(comparison):
    lengths = comparison["trace_lengths"]
    message = "{} (computed {} ops, live {} ops, starting state {})".format(
        comparison["classification"], lengths["computed"], lengths["live"],
        {True: "identical", False: "different", None: "unavailable"}[comparison["starting_state_identical"]])
    if "computed_full_trace_length" in comparison:
        message += ", full computed-source boot {} ops".format(comparison["computed_full_trace_length"])
    difference = comparison["first_differing_operation"]
    if difference:
        message += ", first difference at operation {}".format(difference["index"])
        for side in ("computed", "live"):
            op = difference[side]
            message += ", {} ".format(side)
            if op is None:
                message += "end of trace"
                continue
            message += "{kind} {address} ({width} bytes, data={data}, PC={pc}, time={virtual_us_since_reset} us)".format(**op)
            source = op.get("source") or {}
            if source.get("function"):
                message += " " + source["function"]
            if source.get("line"):
                message += " {}:{}".format(source["file"], source["line"])
    for side, op in sorted(comparison.get("interrupted_operation_covering_byte", {}).items()):
        message += ", {} interrupted operation {} covers byte".format(side, op["index"])
    for side, op in sorted(comparison.get("last_completed_writer", {}).items()):
        message += ", {} last completed writer {}".format(side, op["index"] if op else "none")
    return message


class RecoveryTraceMismatch(RuntimeError):
    """Carry a structured infrastructure failure across the batch boundary."""

    def __init__(self, reason, comparison, kind="recovery_state_cross_check_mismatch"):
        self.reason = reason
        self.comparison = comparison
        self.kind = kind
        RuntimeError.__init__(self, reason + ": " + comparison_message(comparison))

    def result(self):
        return {"fault_at": 0, "fault_requested": 0, "fault_type": "rs",
                "fault_injected": False, "boot_outcome": "infra_error",
                "fault_class": "infrastructure_error", "infrastructure_error": True,
                "error_kind": self.kind, "error": str(self), "signals": {},
                "error_reason": self.reason, "recovery_trace_comparison": self.comparison}
