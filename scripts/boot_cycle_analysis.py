#!/usr/bin/env python3
"""Pure boot-cycle analysis helpers.

This module is intentionally free of Renode globals so the convergence /
rollback logic can be tested in isolation and reused by the runtime sweep.

It must remain compatible with Renode's embedded Python, so avoid modern
syntax features here.
"""


def _pair_sequence(cycle_records):
    return [
        (record.get("boot_slot"), record.get("boot_outcome"))
        for record in cycle_records
    ]


def analyze_boot_cycles(
    cycle_records,
    requested_cycles,
    target_slot=None,
    expected_rollback_at_cycle=None,
):
    if not cycle_records:
        return {
            "status": "not_run",
            "requested_cycles": int(requested_cycles),
            "completed_cycles": 0,
        }

    pairs = _pair_sequence(cycle_records)
    analysis = {
        "requested_cycles": int(requested_cycles),
        "completed_cycles": len(cycle_records),
        "initial_slot": cycle_records[0].get("boot_slot"),
        "initial_outcome": cycle_records[0].get("boot_outcome"),
        "final_slot": cycle_records[-1].get("boot_slot"),
        "final_outcome": cycle_records[-1].get("boot_outcome"),
        "slots_observed": [record.get("boot_slot") for record in cycle_records],
        "outcomes_observed": [record.get("boot_outcome") for record in cycle_records],
    }

    if expected_rollback_at_cycle is not None:
        analysis["expected_rollback_at_cycle"] = int(expected_rollback_at_cycle)
        if target_slot is not None:
            analysis["rollback_target_slot"] = target_slot

    if len(cycle_records) == 1:
        analysis["status"] = "single_boot"
        return analysis

    generic_status = "oscillating"
    converged_at_cycle = None
    if all(pair == pairs[0] for pair in pairs):
        generic_status = "converged"
        converged_at_cycle = 0
    elif len(pairs) >= 2 and pairs[-1] == pairs[-2]:
        generic_status = "converged"
        converged_at = len(pairs) - 2
        final_pair = pairs[-1]
        for index in range(len(pairs) - 2, -1, -1):
            if pairs[index] == final_pair:
                converged_at = index
            else:
                break
        converged_at_cycle = converged_at

    if converged_at_cycle is not None:
        analysis["converged_at_cycle"] = converged_at_cycle

    if expected_rollback_at_cycle is None:
        analysis["status"] = generic_status
        return analysis

    rollback_cycle = None
    initial_slot = analysis.get("initial_slot")
    if target_slot is None:
        target_slot = initial_slot
    if target_slot == initial_slot:
        analysis["status"] = generic_status
        analysis["rollback_not_applicable"] = True
        return analysis

    for record in cycle_records[1:]:
        if record.get("boot_outcome") != "success":
            continue
        if record.get("boot_slot") == target_slot:
            rollback_cycle = int(record.get("cycle", 0))
            break

    if rollback_cycle is None:
        analysis["status"] = "rollback_missing"
        return analysis

    analysis["rollback_cycle"] = rollback_cycle
    if rollback_cycle > int(expected_rollback_at_cycle):
        analysis["status"] = "rollback_late"
        return analysis

    if (
        generic_status == "converged"
        and analysis.get("final_outcome") == "success"
        and analysis.get("final_slot") == target_slot
    ):
        analysis["status"] = "rollback_converged"
        return analysis

    analysis["status"] = "rollback_observed_oscillating"
    return analysis
