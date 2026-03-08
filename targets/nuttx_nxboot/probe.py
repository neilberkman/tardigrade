#!/usr/bin/env python3
"""NuttX nxboot state probe for tardigrade semantic-state collection.

Thin wrapper around the shared nxboot probe that tags output as
``nuttx_nxboot``.  All slot-probing, role-determination, and CRC logic
lives in ``targets/nxboot/probe.py``.

Supports two execution modes:
- Normal Python import (tests, audit_bootloader.py)
- Renode embedded ``exec()`` where package imports are unavailable
"""

import os as _os

try:
    # Normal Python: package import works.
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
except ImportError:
    # Renode embedded exec() mode: load shared probe by file path.
    _shared = _os.path.normpath(
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                      "..", "nxboot", "probe.py")
    )
    _ns = {"__builtins__": __builtins__}
    with open(_shared, "r") as _f:
        exec(compile(_f.read(), _shared, "exec"), _ns)
    NXBOOT_HEADER_MAGIC = _ns["NXBOOT_HEADER_MAGIC"]
    NXBOOT_HEADER_MAGIC_INT = _ns["NXBOOT_HEADER_MAGIC_INT"]
    _compute_roles_and_flags = _ns.get("_compute_roles_and_flags")
    _crc32_update = _ns["_crc32_update"]
    _determine_roles = _ns.get("_determine_roles")
    _get_monitor_int = _ns["_get_monitor_int"]
    _hex_u64 = _ns["_hex_u64"]
    _slot_probe = _ns["_slot_probe"]
    _base_collect_state = _ns["collect_state"]


def collect_state(bus=None, monitor=None, context=None):
    return _base_collect_state(
        bus=bus, monitor=monitor, context=context, target_name="nuttx_nxboot"
    )
