#!/usr/bin/env python3
"""NuttX nxboot state probe for tardigrade semantic-state collection.

Thin wrapper around the shared nxboot probe that tags output as
``nuttx_nxboot``.  All slot-probing, role-determination, and CRC logic
lives in ``targets.nxboot.probe``.
"""

# Re-export symbols that tests and other callers import from this module.
from targets.nxboot.probe import (  # noqa: F401
    NXBOOT_HEADER_MAGIC,
    NXBOOT_HEADER_MAGIC_INT,
    _compute_roles_and_flags,
    _crc32_update,
    _determine_roles,
    _get_monitor_int,
    _hex_u64,
    _slot_probe,
)
from targets.nxboot.probe import collect_state as _base_collect_state


def collect_state(bus=None, monitor=None, context=None):
    return _base_collect_state(
        bus=bus, monitor=monitor, context=context, target_name="nuttx_nxboot"
    )
