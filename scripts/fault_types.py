"""Fault-type metadata: wire codes, human-readable labels, execute-only sets.

Extracted from audit_bootloader.py to avoid circular imports and provide a
single source of truth for fault-type constants used across the audit tool.
"""

from __future__ import annotations

from typing import Any


# Fault types that require full execute-mode handling in the runtime runner
# and cannot be evaluated with the fast state-simulation path.
EXECUTE_ONLY_FAULT_TYPES = {
    "bit_corruption",
    "interrupted_erase",
    "multi_sector_atomicity",
    "silent_write_failure",
    "driver_error",
    "rc_injection",
    "write_rejection",
    "write_disturb",
    "wear_leveling_corruption",
    "reset_at_time",
    "read_bit_flip",
    "command_drop",
    "instruction_skip",
    "otp_partial_program",
    "otp_stuck_bit",
    "otp_read_disturb",
    "otp_overblow",
    "otp_blow_nop",
    "timed_bit_corruption",
    "nvs_corruption",
    "i2c_nack",
    "i2c_timeout",
    "i2c_bit_flip",
    "i2c_truncated",
    "i2c_wrong_address",
}

# Fault types that can use trace replay in execute mode by default.
#
# Only power-loss remains enabled here. Mutated non-halting write faults
# (bit_corruption, silent_write_failure, write_rejection, write_disturb,
# wear_leveling_corruption) can change Phase-1 control flow after the faulted
# write, so persisted-flash replay is not faithful enough for CI-default use.
# The runtime keeps the specialized replay code paths for future explicit
# opt-in experiments, but the default planner now stays on full execute mode
# for those fault types.
TRACE_REPLAY_FAULT_TYPES = {
    "power_loss",
    "swap_progress",
}

# Canonical mapping from human-readable fault type names to single-char
# wire codes used in batch dispatch and result encoding.  Used by metadata
# fault, hook fault, and phase2 fault point generation.
FAULT_TYPE_NAME_TO_CODE = {
    "power_loss": "w",
    "swap_progress": "w:sp",
    "bit_corruption": "b",
    "silent_write_failure": "s",
    "driver_error": "g",
    "rc_injection": "x",
    "write_disturb": "d",
    "wear_leveling_corruption": "l",
    "write_rejection": "r",
    "interrupted_erase": "e",
    "multi_sector_atomicity": "a",
    "read_bit_flip": "f",
    "reset_at_time": "t",
    "command_drop": "k",
    "instruction_skip": "i",
    "otp_partial_program": "op",
    "otp_stuck_bit": "os",
    "otp_read_disturb": "od",
    "otp_overblow": "oo",
    "otp_blow_nop": "on",
    "timed_bit_corruption": "tb",
    "nvs_corruption": "nv",
    "i2c_nack": "in",
    "i2c_timeout": "it",
    "i2c_bit_flip": "ib",
    "i2c_truncated": "ic",
    "i2c_wrong_address": "iw",
}

# Labels used only when classifying or grouping results.  These are deliberately
# absent from ``FAULT_TYPE_NAME_TO_CODE`` because they are not injectable
# mechanisms and must never be accepted as sweep inputs.
CLASSIFICATION_ONLY_FAULT_TYPES = frozenset(
    {
        "bootloader_region_write",
        "phase2_fault",
        "hook_fault",
        "metadata_fault",
        "confirm_cycle",
    }
)

# Keep the public registry derived from the wire-code table.  A fault type
# cannot be advertised as implemented unless the planner can encode it.
IMPLEMENTED_FAULT_TYPES = frozenset(FAULT_TYPE_NAME_TO_CODE)
KNOWN_FAULT_TYPES = IMPLEMENTED_FAULT_TYPES | CLASSIFICATION_ONLY_FAULT_TYPES

# Fault types supported by the recovery-phase fault runner.  Keeping this
# narrower than the main registry prevents a known-but-unsupported type from
# falling through to the power-loss write mode.
PHASE2_FAULT_TYPES = frozenset(
    {
        "power_loss",
        "bit_corruption",
        "silent_write_failure",
        "driver_error",
        "rc_injection",
        "write_disturb",
        "wear_leveling_corruption",
        "write_rejection",
        "interrupted_erase",
        "multi_sector_atomicity",
        "reset_at_time",
    }
)

# Public peripheral mode registries.  These values mirror the open-source
# peripheral implementations and are re-exported by profile_loader for
# compatibility with existing callers.
OTP_FAULT_TYPE_CODES = {
    "otp_partial_program": 0,
    "otp_stuck_bit": 1,
    "otp_read_disturb": 2,
    "otp_overblow": 3,
    "otp_blow_nop": 4,
}

I2C_FAULT_TYPE_CODES = {
    "i2c_nack": 1,
    "i2c_timeout": 2,
    "i2c_bit_flip": 3,
    "i2c_truncated": 4,
    "i2c_wrong_address": 5,
}

TRACE_REPLAY_WIRE_CODES = frozenset(
    FAULT_TYPE_NAME_TO_CODE[name] for name in TRACE_REPLAY_FAULT_TYPES
)

# OTP wire-code to BlowFaultMode mapping (used by sweep planner).
_OTP_WIRE_CODE_TO_BLOW_MODE = {
    "op": 0,  # otp_partial_program
    "os": 1,  # otp_stuck_bit
    "od": 2,  # otp_read_disturb
    "oo": 3,  # otp_overblow
    "on": 4,  # otp_blow_nop
}

_OTP_WIRE_CODES = frozenset(_OTP_WIRE_CODE_TO_BLOW_MODE.keys())


def _fault_type_label(code: Any) -> str:
    """Convert a wire code (possibly compound) to a human-readable label."""
    code = str(code or "w")
    mapping = {
        "w": "power_loss",
        "b": "bit_corruption",
        "s": "silent_write_failure",
        "g": "driver_error",
        "x": "rc_injection",
        "d": "write_disturb",
        "l": "wear_leveling_corruption",
        "r": "write_rejection",
        "t": "reset_at_time",
        "e": "interrupted_erase",
        "a": "multi_sector_atomicity",
        "f": "read_bit_flip",
        "k": "command_drop",
        "i": "instruction_skip",
        "op": "otp_partial_program",
        "os": "otp_stuck_bit",
        "od": "otp_read_disturb",
        "oo": "otp_overblow",
        "on": "otp_blow_nop",
        "tb": "timed_bit_corruption",
        "nv": "nvs_corruption",
        "in": "i2c_nack",
        "it": "i2c_timeout",
        "ib": "i2c_bit_flip",
        "ic": "i2c_truncated",
        "iw": "i2c_wrong_address",
        "h": "hook_fault",
        "p2": "phase2",
        "cc": "confirm_cycle",
    }
    if code.startswith("b:"):
        return "bit_corruption_clustered"
    if code == "w:sp":
        return "swap_progress"
    if code.startswith("m:"):
        return "metadata_{}".format(_fault_type_label(code.split(":", 1)[1]))
    if code.startswith("h:"):
        sub_type = code.rsplit(":", 1)[-1]
        sub_label = _fault_type_label(sub_type)
        return "hook_{}".format(sub_label)
    if code.startswith("p2:"):
        return "phase2_{}".format(_fault_type_label(code.rsplit(":", 1)[-1]))
    if code.startswith("c:"):
        return "cascading_{}".format(_fault_type_label(code.rsplit(":", 1)[-1]))
    if code.startswith("cc:"):
        sub_type = code.rsplit(":", 1)[-1]
        sub_label = _fault_type_label(sub_type)
        return "confirm_{}".format(sub_label)
    if code.startswith("nv:"):
        return "nvs_corruption_variant"
    if code.startswith("mf:"):
        return "multi_fault_sequence"
    return mapping.get(code, code)
