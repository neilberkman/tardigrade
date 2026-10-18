#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Tardigrade contributors
"""TF-M BL2 specific invariants for tardigrade fault-injection testing.

These invariants target attack surfaces unique to TF-M's use of MCUboot,
beyond what the generic MCUboot invariants cover:

1. Secure/non-secure partition isolation: A fault during BL2's SAU/MPC
   setup could leave secure memory accessible to the non-secure world.

2. Multi-image consistency: In multi-image mode, S and NS images must
   either both update or both roll back. A fault that updates one but
   not the other creates a version mismatch that may break the S/NS
   interface contract (veneer table incompatibility, etc.).

3. FIH bypass detection: TF-M's Fault Injection Hardening adds redundant
   checks. A single fault should not bypass both the primary check and
   its redundant counterpart.
"""

from invariants import InvariantViolation
from targets.tf_m_bl2.probe import (
    _magic_state,
    boot_magic_decode,
    mcuboot_trailer_magic,
)


def _joint_version_policy(config):
    """Return the declared S/NS version policy, or ``None`` if unconfigured.

    Existing profiles did not expose image-version evidence, so version
    checking remains opt-in.  Once enabled, the policy is mandatory: missing
    or malformed evidence raises an evaluation error rather than passing.
    The canonical form is the string ``"equal"`` or ``"compatible"``; a
    mapping with a ``mode`` field is accepted for forward-compatible profile
    extensions.  ``compatible`` permits minor/revision/build differences but
    requires matching major versions.
    """
    raw = config.get("tfm_joint_version_policy")
    if raw is None:
        # Accept the longer spelling while profiles migrate to the canonical
        # key.  Both spellings have identical fail-closed semantics.
        raw = config.get("tfm_multi_image_version_policy")
    if raw is None:
        return None
    if isinstance(raw, str):
        mode = raw.strip().lower()
        require_major = True
    elif isinstance(raw, dict):
        mode = str(raw.get("mode", raw.get("policy", ""))).strip().lower()
        require_major = raw.get("require_major", True)
        if type(require_major) is not bool:
            raise ValueError("tfm joint version policy require_major must be boolean")
    else:
        raise ValueError("tfm joint version policy must be a string or mapping")
    if mode in {"same", "exact"}:
        mode = "equal"
    if mode not in {"equal", "compatible"}:
        raise ValueError(
            "tfm joint version policy mode must be 'equal' or 'compatible'"
        )
    return mode, require_major


def _image_version(slot, label):
    version = slot.get("version")
    if not isinstance(version, dict) or version.get("state") != "valid":
        raise ValueError("{} image version evidence is missing or invalid".format(label))
    values = tuple(version.get(field) for field in ("major", "minor", "revision", "build"))
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("{} image version evidence is incomplete".format(label))
    return values


def _check_joint_versions(result, s_exec, ns_exec, config):
    policy = _joint_version_policy(config)
    if policy is None:
        return
    mode, require_major = policy
    secure_version = _image_version(s_exec, "secure")
    non_secure_version = _image_version(ns_exec, "non-secure")
    if mode == "equal":
        compatible = secure_version == non_secure_version
    else:
        compatible = (
            not require_major or secure_version[0] == non_secure_version[0]
        )
    if compatible:
        return
    raise InvariantViolation(
        invariant_name="tfm_multi_image_consistency",
        description=(
            "Multi-image joint version policy {!r} rejected secure/non-secure "
            "versions {} and {}.".format(
                mode, ".".join(str(item) for item in secure_version),
                ".".join(str(item) for item in non_secure_version),
            )
        ),
        result=result,
        details={
            "policy": mode,
            "secure_exec_version": s_exec.get("version"),
            "ns_exec_version": ns_exec.get("version"),
        },
    )


def _resolve_post_recovery_state(result, context=None):
    """Return post-recovery semantic state when result.nvm_state is a fault snapshot."""
    state = result.nvm_state or {}
    if not isinstance(state, dict):
        return state
    if state.get("stage") != "fault_snapshot" or not isinstance(context, dict):
        return state
    result_dict = context.get("result_dict")
    if isinstance(result_dict, dict):
        for key in ("recovery_semantic_state", "semantic_state"):
            candidate = result_dict.get(key)
            if (
                isinstance(candidate, dict)
                and candidate.get("stage") != "fault_snapshot"
                and isinstance(candidate.get("slots"), dict)
            ):
                return candidate
    return state


def _semantic_slot(result, slot_name, state=None):
    """Extract a named slot dict from result.nvm_state.slots."""
    if state is None:
        state = result.nvm_state or {}
    if not isinstance(state, dict):
        return {}
    slots = state.get("slots", {})
    if not isinstance(slots, dict):
        return {}
    slot = slots.get(slot_name, {})
    return slot if isinstance(slot, dict) else {}


def _is_multi_image(result, state=None):
    """Check if this result came from a multi-image TF-M configuration."""
    if state is None:
        state = result.nvm_state or {}
    if not isinstance(state, dict):
        return False
    flags = state.get("flags", {})
    if not isinstance(flags, dict):
        return False
    return bool(flags.get("multi_image", False))


def _slot_bounds(slot):
    try:
        base = int(str(slot.get("base")), 0)
        size = int(str(slot.get("size")), 0)
    except (TypeError, ValueError):
        return None
    if size <= 0:
        return None
    return base, base + size


def _trace_wrote_both_primary_trailers(result, s_exec, ns_exec, context):
    """Return True unless trace evidence shows the fault preceded one primary trailer."""
    if not isinstance(context, dict):
        return True
    write_spans = context.get("write_spans")
    write_log = context.get("write_log")
    if write_spans is None and write_log is None:
        return True
    s_bounds = _slot_bounds(s_exec)
    ns_bounds = _slot_bounds(ns_exec)
    if s_bounds is None or ns_bounds is None:
        return True
    fault_at = getattr(result, "fault_at", -1)
    if isinstance(fault_at, int) and fault_at >= 0:
        limit = fault_at + 1
    else:
        limit = None
    addresses = []
    if isinstance(write_spans, list):
        items = write_spans[:limit] if limit is not None else write_spans
        for span in items:
            if isinstance(span, (list, tuple)) and span:
                addresses.append(int(span[0]))
    elif isinstance(write_log, list):
        items = write_log[:limit] if limit is not None else write_log
        for addr in items:
            addresses.append(int(addr))
    trailer_window = 0x1000
    s_trailer_start = max(s_bounds[0], s_bounds[1] - trailer_window)
    ns_trailer_start = max(ns_bounds[0], ns_bounds[1] - trailer_window)
    s_touched = any(s_trailer_start <= addr < s_bounds[1] for addr in addresses)
    ns_touched = any(ns_trailer_start <= addr < ns_bounds[1] for addr in addresses)
    return s_touched and ns_touched


def check_tfm_multi_image_consistency(result, **context):
    """In multi-image mode, S and NS slots must have consistent swap state.

    If the secure image's exec slot shows swap completed (copy_done=set,
    magic=good) but the non-secure image's exec slot does not (or vice
    versa), the two images are in inconsistent update states. This means
    a power loss interrupted the swap between the two image pairs,
    leaving S and NS at different firmware versions.

    This is a TF-M-specific risk because vanilla MCUboot with a single
    image cannot have this cross-image inconsistency.
    """
    state = _resolve_post_recovery_state(result, context)
    if not _is_multi_image(result, state=state):
        return

    s_exec = _semantic_slot(result, "secure_exec", state=state)
    ns_exec = _semantic_slot(result, "ns_exec", state=state)

    config = context.get("invariant_config") or {}
    if not s_exec or not ns_exec:
        raise ValueError(
            "multi-image consistency requires secure and non-secure slot evidence"
        )

    if (
        isinstance(state, dict)
        and state.get("stage") == "fault_snapshot"
        and not _trace_wrote_both_primary_trailers(result, s_exec, ns_exec, context)
    ):
        return

    s_copy_done = (s_exec.get("copy_done") or {}).get("state")
    ns_copy_done = (ns_exec.get("copy_done") or {}).get("state")
    s_image_ok = (s_exec.get("image_ok") or {}).get("state")
    ns_image_ok = (ns_exec.get("image_ok") or {}).get("state")

    # If both have matching copy_done state, check whether one slot completed
    # a forward test swap (copy_done=set, image_ok=unset) while the other
    # reverted to a confirmed image (copy_done=set, image_ok=set), then check
    # any declared joint version policy.
    if s_copy_done == ns_copy_done:
        if (
            s_copy_done == "set"
            and {s_image_ok, ns_image_ok} == {"set", "unset"}
        ):
            if s_image_ok == "unset":
                inconsistent = (
                    "secure slot completed forward test swap (image_ok=unset) "
                    "while non-secure slot reverted (image_ok=set)"
                )
            else:
                inconsistent = (
                    "non-secure slot completed forward test swap (image_ok=unset) "
                    "while secure slot reverted (image_ok=set)"
                )
            raise InvariantViolation(
                invariant_name="tfm_multi_image_consistency",
                description=(
                    "Multi-image swap state inconsistency: {}. "
                    "S and NS images are at different update stages, which may "
                    "break the secure/non-secure interface contract.".format(
                        inconsistent
                    )
                ),
                result=result,
                details={
                    "secure_exec_copy_done": s_copy_done,
                    "ns_exec_copy_done": ns_copy_done,
                    "secure_exec_image_ok": s_image_ok,
                    "ns_exec_image_ok": ns_image_ok,
                    "secure_exec_magic": s_exec.get("magic_state"),
                    "ns_exec_magic": ns_exec.get("magic_state"),
                    "secure_exec_version": s_exec.get("version"),
                    "ns_exec_version": ns_exec.get("version"),
                },
            )
        _check_joint_versions(
            result,
            s_exec,
            ns_exec,
            config,
        )
        return

    # One completed swap, the other did not.
    if s_copy_done == "set" and ns_copy_done != "set":
        inconsistent = "secure swap completed but non-secure did not"
    elif ns_copy_done == "set" and s_copy_done != "set":
        inconsistent = "non-secure swap completed but secure did not"
    else:
        # Both in non-matching but neither is clearly "completed" --
        # could be mid-swap for both. Not clearly an inconsistency.
        return

    raise InvariantViolation(
        invariant_name="tfm_multi_image_consistency",
        description=(
            "Multi-image swap state inconsistency: {}. "
            "S and NS images are at different update stages, which may "
            "break the secure/non-secure interface contract.".format(inconsistent)
        ),
        result=result,
        details={
            "secure_exec_copy_done": s_copy_done,
            "ns_exec_copy_done": ns_copy_done,
            "secure_exec_magic": s_exec.get("magic_state"),
            "ns_exec_magic": ns_exec.get("magic_state"),
        },
    )


def check_tfm_multi_image_acceptance_consistency(result, **context):
    """Secure and non-secure primary images must be accepted together.

    ``psa_fwu_accept`` updates the acceptance marker for each image.  This
    invariant detects a post-fault observation where one primary image has
    ``image_ok=set`` while the other remains ``image_ok=unset``.  The detector
    treats that state as a violation of the declared joint-acceptance policy.
    """
    config = context.get("invariant_config") or {}
    if not config.get("tfm_joint_acceptance", False):
        return

    if not _is_multi_image(result):
        return

    s_exec = _semantic_slot(result, "secure_exec")
    ns_exec = _semantic_slot(result, "ns_exec")
    if not s_exec or not ns_exec:
        raise ValueError(
            "multi-image acceptance consistency requires secure and non-secure slot evidence"
        )

    s_image_ok = (s_exec.get("image_ok") or {}).get("state")
    ns_image_ok = (ns_exec.get("image_ok") or {}).get("state")

    # After recovery, image_ok is a one-byte MCUboot flag and only SET/UNSET
    # are valid. Treat malformed values as a violation instead of allowing
    # both images to pass with the same corrupted value.
    if s_image_ok not in {"set", "unset"} or ns_image_ok not in {"set", "unset"}:
        raise InvariantViolation(
            invariant_name="tfm_multi_image_acceptance_consistency",
            description=(
                "Malformed TF-M image_ok state after recovery: secure={!r}, "
                "non-secure={!r}.".format(s_image_ok, ns_image_ok)
            ),
            result=result,
            details={
                "secure_exec_image_ok": s_image_ok,
                "ns_exec_image_ok": ns_image_ok,
                "secure_exec_version": s_exec.get("version"),
                "ns_exec_version": ns_exec.get("version"),
            },
        )

    # Only a SET/UNSET split violates this joint-acceptance contract.
    if {s_image_ok, ns_image_ok} != {"set", "unset"}:
        return

    if s_image_ok == "set":
        inconsistent = "secure image accepted but non-secure image is not"
    else:
        inconsistent = "non-secure image accepted but secure image is not"

    raise InvariantViolation(
        invariant_name="tfm_multi_image_acceptance_consistency",
        description=(
            "Multi-image acceptance state inconsistency: {}. "
            "Secure and non-secure images must be accepted together.".format(
                inconsistent
            )
        ),
        result=result,
        details={
            "secure_exec_image_ok": s_image_ok,
            "ns_exec_image_ok": ns_image_ok,
            "secure_exec_magic": s_exec.get("magic_state"),
            "ns_exec_magic": ns_exec.get("magic_state"),
            "secure_exec_version": s_exec.get("version"),
            "ns_exec_version": ns_exec.get("version"),
        },
    )


def _parse_magic_bytes(raw_value):
    if isinstance(raw_value, (bytes, bytearray)):
        return bytes(raw_value)
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        if text and len(text) % 2 == 0:
            try:
                return bytes.fromhex(text)
            except ValueError:
                return None
        return None
    if isinstance(raw_value, (list, tuple)):
        try:
            return bytes(int(b) & 0xFF for b in raw_value)
        except (TypeError, ValueError):
            return None
    return None


def _slot_raw_magic(slot_data):
    for key in ("magic_raw", "trailer_magic", "magic"):
        if key in slot_data and slot_data[key] is not None:
            parsed = _parse_magic_bytes(slot_data[key])
            if parsed is not None:
                return parsed
    return None


def _slot_mcuboot_magic(slot_data, align=8):
    explicit = slot_data.get("mcuboot_magic")
    if isinstance(explicit, str):
        normalized = explicit.strip().lower()
        if normalized in {"good", "bad", "unset"}:
            return normalized
    raw_bytes = _slot_raw_magic(slot_data)
    if raw_bytes is not None:
        return mcuboot_trailer_magic(raw_bytes, align=align)
    magic_state = slot_data.get("magic_state")
    if magic_state == "good":
        return "good"
    if magic_state == "unset":
        return "unset"
    return "bad"


def _slot_has_partial_magic(slot_data, align=8):
    if bool(slot_data.get("partial_magic", False)):
        return True
    raw_bytes = _slot_raw_magic(slot_data)
    pad_bytes = _parse_magic_bytes(slot_data.get("magic_pad")) or b""
    if raw_bytes is not None:
        if _magic_state(raw_bytes, align=align, magic_pad=pad_bytes) not in {
            "good",
            "unset",
        }:
            return True
    if "magic_state" in slot_data and slot_data.get("magic_state") is not None:
        return slot_data.get("magic_state") not in {"good", "unset"}
    if raw_bytes is not None:
        return False
    return _slot_mcuboot_magic(slot_data, align=align) not in {"good", "unset"}


def _recovery_booted_valid_image_pair(result, state, context=None):
    if getattr(result, "boot_outcome", None) != "success":
        return False
    result_dict = (
        context.get("result_dict") if isinstance(context, dict) else None
    )
    if isinstance(result_dict, dict):
        final_outcome = result_dict.get("final_boot_outcome")
        if final_outcome is not None and final_outcome != "success":
            return False
    boot_cycles = (
        context.get("boot_cycles") if isinstance(context, dict) else None
    )
    if boot_cycles is None and isinstance(result_dict, dict):
        boot_cycles = result_dict.get("boot_cycles")
    if isinstance(boot_cycles, list):
        for cycle in boot_cycles:
            if (
                isinstance(cycle, dict)
                and cycle.get("outcome") is not None
                and cycle.get("outcome") != "success"
            ):
                return False
    multi_boot = (
        context.get("multi_boot_analysis")
        if isinstance(context, dict)
        else None
    )
    if multi_boot is None and isinstance(result_dict, dict):
        multi_boot = result_dict.get("multi_boot_analysis")
    if isinstance(multi_boot, dict) and multi_boot.get("all_succeeded") is False:
        return False

    slots = state.get("slots") if isinstance(state, dict) else None
    if not isinstance(slots, dict):
        return False
    align = state.get("trailer_align", 8) if isinstance(state, dict) else 8
    primary_names = (
        ("secure_exec", "ns_exec")
        if _is_multi_image(result, state=state)
        else ("exec",)
    )
    for slot_name in primary_names:
        slot = slots.get(slot_name)
        if not isinstance(slot, dict):
            return False
        if (
            _slot_has_partial_magic(slot, align=align)
            or _slot_mcuboot_magic(slot, align=align) != "good"
        ):
            return False
        version = slot.get("version")
        if not isinstance(version, dict) or version.get("state") != "valid":
            return False
    if _is_multi_image(result, state=state) and isinstance(context, dict):
        config = context.get("invariant_config") or {}
        try:
            _check_joint_versions(
                result,
                slots["secure_exec"],
                slots["ns_exec"],
                config,
            )
        except (InvariantViolation, ValueError):
            return False
    return True


def check_tfm_no_partial_magic(result, **context):
    """Flag partially-written trailer magic when decoded as good or blocking recovery.

    MCUboot's boot_read_swap_state() reads the 16-byte magic at boot_magic_off()
    (slot_end - 16) and classifies it as BOOT_MAGIC_UNSET if all 0xFF, or via
    boot_magic_decode() (memcmp against BOOT_IMG_MAGIC) as BOOT_MAGIC_GOOD on an
    exact 16-byte match and BOOT_MAGIC_BAD otherwise. In boot_find_status() and
    boot_swap_tables(), BOOT_MAGIC_BAD is never accepted as a valid trailer magic
    and does not trigger a swap. A half-written or half-erased magic that MCUboot
    decodes as BOOT_MAGIC_BAD is therefore benign when recovery boots a valid
    image pair.
    """
    state = _resolve_post_recovery_state(result, context)
    if not isinstance(state, dict):
        raise ValueError("TF-M trailer invariant requires nvm_state mapping")

    if "slots" not in state:
        raise ValueError("TF-M trailer invariant requires a slots mapping")
    slots = state.get("slots")
    if not isinstance(slots, dict):
        raise ValueError("TF-M trailer invariant requires a slots mapping")

    align = state.get("trailer_align", 8)
    recovery_ok = _recovery_booted_valid_image_pair(result, state, context)

    invalid_slots = []
    slot_magic_details = {}
    for slot_name, slot_data in slots.items():
        if not isinstance(slot_data, dict):
            raise ValueError(
                "TF-M trailer invariant requires slot {!r} to be a mapping".format(
                    slot_name
                )
            )
        if not _slot_has_partial_magic(slot_data, align=align):
            continue
        mcuboot_magic = _slot_mcuboot_magic(slot_data, align=align)
        if mcuboot_magic == "good" or not recovery_ok:
            invalid_slots.append(slot_name)
            slot_magic_details[slot_name] = {
                "magic_state": slot_data.get("magic_state"),
                "mcuboot_magic": mcuboot_magic,
            }

    if not invalid_slots:
        return

    raise InvariantViolation(
        invariant_name="tfm_no_partial_magic",
        description=(
            "TF-M BL2 trailer magic was invalid after recovery in slot(s): {}. "
            "The bootloader either decoded a partial trailer magic as good or "
            "failed to boot a valid image pair.".format(
                ", ".join(sorted(invalid_slots))
            )
        ),
        result=result,
        details={
            "invalid_slots": invalid_slots,
            "slot_magic": slot_magic_details,
            "recovery_booted_valid_pair": recovery_ok,
            "multi_image": _is_multi_image(result, state=state),
        },
    )


def check_tfm_secure_slot_not_empty(result, **_):
    """After recovery boot, the secure exec slot must not be erased/empty.

    In TF-M, if the secure image slot is erased (magic=unset, no valid
    image), the device has no SPE firmware and cannot function at all --
    even the non-secure world depends on secure services (crypto, storage,
    attestation). This is a stricter version of "at least one bootable
    slot" because in TF-M the secure slot is always required.

    Applies to both single-image and multi-image modes: in single-image
    mode the combined S+NS blob is in the exec slot; in multi-image mode
    the secure_exec slot specifically must be valid.
    """
    if result.boot_outcome == "success":
        # Boot succeeded, so the secure image was clearly present.
        return

    if _is_multi_image(result):
        s_exec = _semantic_slot(result, "secure_exec")
        slot_name = "secure_exec"
    else:
        s_exec = _semantic_slot(result, "exec")
        slot_name = "exec"

    if not s_exec:
        raise ValueError(
            "TF-M secure-slot invariant requires {} slot evidence".format(slot_name)
        )

    magic = s_exec.get("magic_state")
    copy_done = (s_exec.get("copy_done") or {}).get("state")
    image_ok = (s_exec.get("image_ok") or {}).get("state")

    # If magic is unset and copy_done is unset, the slot is erased.
    if magic == "unset" and copy_done == "unset":
        raise InvariantViolation(
            invariant_name="tfm_secure_slot_not_empty",
            description=(
                "The {} slot appears erased after fault recovery "
                "(magic=unset, copy_done=unset). Without a secure image, "
                "the device cannot provide any TF-M services and is "
                "effectively bricked.".format(slot_name)
            ),
            result=result,
            details={
                "slot_name": slot_name,
                "magic_state": magic,
                "copy_done": copy_done,
                "image_ok": image_ok,
                "boot_outcome": result.boot_outcome,
                "multi_image": _is_multi_image(result),
            },
        )


INVARIANTS = {
    "tfm_multi_image_consistency": check_tfm_multi_image_consistency,
    "tfm_multi_image_acceptance_consistency": (
        check_tfm_multi_image_acceptance_consistency
    ),
    "tfm_no_partial_magic": check_tfm_no_partial_magic,
    "tfm_secure_slot_not_empty": check_tfm_secure_slot_not_empty,
}
