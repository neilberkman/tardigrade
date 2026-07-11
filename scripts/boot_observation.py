"""Polling boot-completion oracle shared by generic Renode campaigns.

Only Python 2-compatible syntax is used so Renode can import this module from
IronPython.  Callers supply the emulator and register callbacks, which also
makes the timeout/oracle logic testable without launching Renode.
"""

import time


def _fmt_u32(value):
    return "0x%08X" % (int(value) & 0xFFFFFFFF)


def poll_boot(
    run_slice,
    read_pc,
    read_vtor,
    read_marker,
    classify_pc,
    classify_vtor,
    is_control,
    expected_slot,
    marker_value,
    emulated_timeout_s,
    poll_interval_s,
    wall_timeout_s,
    clock=None,
):
    """Poll until PC handoff (and, for control, marker corroboration)."""

    if emulated_timeout_s <= 0 or poll_interval_s <= 0 or wall_timeout_s <= 0:
        raise ValueError("boot observation budgets must be positive")
    clock = clock or time.time
    start_wall = clock()
    emulated_s = 0.0
    sticky_pc = None
    sticky_pc_slot = None
    sticky_vtor = None
    sticky_vtor_slot = None
    final_pc = int(read_pc())
    final_vtor = int(read_vtor())
    marker_actual = int(read_marker()) if read_marker is not None else None
    reason = "emulated_timeout"
    infrastructure_error = None

    while emulated_s < emulated_timeout_s:
        elapsed_wall = clock() - start_wall
        if elapsed_wall >= wall_timeout_s:
            reason = "wall_timeout"
            infrastructure_error = (
                "boot observation exceeded %.1fs wall-clock budget" % wall_timeout_s
            )
            break

        time_slice = min(poll_interval_s, emulated_timeout_s - emulated_s)
        try:
            run_slice(time_slice)
        except Exception as exc:
            reason = "runner_error"
            infrastructure_error = "RunFor failed: %s" % exc
            break
        emulated_s += time_slice

        final_pc = int(read_pc())
        final_vtor = int(read_vtor())
        pc_slot = classify_pc(final_pc)
        vtor_slot = classify_vtor(final_vtor)
        if pc_slot is not None and sticky_pc_slot is None:
            sticky_pc = final_pc
            sticky_pc_slot = pc_slot
        if vtor_slot is not None and sticky_vtor_slot is None:
            sticky_vtor = final_vtor
            sticky_vtor_slot = vtor_slot
        if read_marker is not None:
            marker_actual = int(read_marker())

        if is_control:
            if sticky_pc_slot == expected_slot and marker_actual == marker_value:
                reason = "control_complete"
                break
        elif sticky_pc_slot is not None:
            reason = "pc_handoff"
            break

    wall_s = clock() - start_wall
    return {
        "reason": reason,
        "emulated_s": round(emulated_s, 6),
        "wall_s": round(wall_s, 6),
        "infrastructure_error": infrastructure_error,
        "pc_final": _fmt_u32(final_pc),
        "pc_sticky": None if sticky_pc is None else _fmt_u32(sticky_pc),
        "pc_sticky_slot": sticky_pc_slot,
        "vtor_final": _fmt_u32(final_vtor),
        "vtor_sticky": None if sticky_vtor is None else _fmt_u32(sticky_vtor),
        "vtor_sticky_slot": sticky_vtor_slot,
        "marker_actual": (
            None if marker_actual is None else _fmt_u32(marker_actual)
        ),
        "marker_ok": (
            marker_actual == marker_value if read_marker is not None else False
        ),
    }
