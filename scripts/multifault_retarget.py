"""Pure helpers for adapting stage-relative multi-fault requests."""


def last_reachable_fault_index(requested_index, observed_writes):
    """Return the last reachable zero-based index for an overlong request.

    ``observed_writes`` is the number of writes completed by an unfaulted
    stage.  A return value of ``None`` means that retargeting would either be
    impossible or would hide an injection failure at an otherwise reachable
    index.
    """
    requested = int(requested_index)
    writes = int(observed_writes)
    if writes <= 0 or requested < writes:
        return None
    return writes - 1


def retarget_unreachable_sequence(
    sequence, result, validated_prior_stage=False,
):
    """Propose one reachable replacement for a failed later-stage request.

    The returned mapping contains the adjusted sequence and compact evidence
    for the decision.  ``None`` means the result is not a proven
    stage-relative out-of-range request and must remain incomplete.
    """
    if (
        validated_prior_stage is not True
        or not isinstance(result, dict)
        or result.get("fault_injected") is not False
        or result.get("boot_outcome") != "skipped"
    ):
        return None

    reason = str(result.get("skip_reason") or "")
    suffix = "_fault_index_beyond_writes"
    if not reason.startswith("stage") or not reason.endswith(suffix):
        return None

    stage_text = reason[len("stage") : -len(suffix)]
    try:
        failed_stage = int(stage_text)
    except (TypeError, ValueError):
        return None

    signals = result.get("signals")
    if not isinstance(signals, dict):
        signals = {}
    signaled_stage = signals.get("failed_stage")
    if signaled_stage is not None:
        try:
            if int(signaled_stage) != failed_stage:
                return None
        except (TypeError, ValueError):
            return None

    original = [int(point) for point in sequence]
    stage_index = failed_stage - 1
    # A clean single-fault result can validate only the state before stage 2.
    # Deeper stages require their own fully evaluated evidence and therefore
    # remain incomplete rather than being adjusted automatically.
    if stage_index != 1 or stage_index >= len(original):
        return None

    per_fault_states = result.get("per_fault_states")
    if not isinstance(per_fault_states, list) or len(per_fault_states) <= stage_index:
        return None
    failed_state = per_fault_states[stage_index]
    if not isinstance(failed_state, dict):
        return None
    try:
        if int(failed_state.get("stage")) != failed_stage:
            return None
        if int(failed_state.get("fault_at")) != original[stage_index]:
            return None
    except (TypeError, ValueError):
        return None
    if failed_state.get("fault_injected") is not False:
        return None
    stage_signals = failed_state.get("signals")
    if not isinstance(stage_signals, dict):
        return None
    stop_reason = str(stage_signals.get("stop_reason") or "")
    if stop_reason not in {"vtor_captured", "pc_captured"}:
        return None

    try:
        observed_writes = int(
            signals.get("stage_max_writes", result.get("actual_writes"))
        )
    except (TypeError, ValueError):
        return None
    try:
        if int(failed_state.get("actual_writes")) != observed_writes:
            return None
    except (TypeError, ValueError):
        return None
    replacement = last_reachable_fault_index(
        original[stage_index], observed_writes,
    )
    if replacement is None or replacement == original[stage_index]:
        return None

    adjusted = list(original)
    adjusted[stage_index] = replacement
    return {
        "sequence": adjusted,
        "stage": failed_stage,
        "requested_fault_at": original[stage_index],
        "observed_writes": observed_writes,
        "retargeted_fault_at": replacement,
        "reason": reason,
        "stage_stop_reason": stop_reason,
    }
