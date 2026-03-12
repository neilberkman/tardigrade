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
    "i2c_nack",
    "i2c_timeout",
    "i2c_bit_flip",
    "i2c_truncated",
    "i2c_wrong_address",
}

# Canonical mapping from human-readable fault type names to single-char
# wire codes used in batch dispatch and result encoding.  Used by metadata
# fault, hook fault, and phase2 fault point generation.
FAULT_TYPE_NAME_TO_CODE = {
    "power_loss": "w",
    "bit_corruption": "b",
    "silent_write_failure": "s",
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
    "i2c_nack": "in",
    "i2c_timeout": "it",
    "i2c_bit_flip": "ib",
    "i2c_truncated": "ic",
    "i2c_wrong_address": "iw",
}


def _fault_type_label(code: Any) -> str:
    """Convert a wire code (possibly compound) to a human-readable label."""
    code = str(code or "w")
    mapping = {
        "w": "power_loss",
        "b": "bit_corruption",
        "s": "silent_write_failure",
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
        "in": "i2c_nack",
        "it": "i2c_timeout",
        "ib": "i2c_bit_flip",
        "ic": "i2c_truncated",
        "iw": "i2c_wrong_address",
        "h": "hook_fault",
        "p2": "phase2",
    }
    if code.startswith("b:"):
        return "bit_corruption_clustered"
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
    if code.startswith("mf:"):
        return "multi_fault_sequence"
    return mapping.get(code, code)
