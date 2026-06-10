# -*- coding: utf-8 -*-
"""Pure-Python helpers for read-fault address translation and accounting.

Backend bus base must be supplied by the caller (from the emulator's
peripheral mapping). These helpers do not derive bases from firmware
concepts such as boot address, image slots, partitions, executable
regions, or configured target ranges.

Imported from the IronPython sweep harness; kept side-effect-free and
free of Renode-specific symbols so it can be unit-tested directly.
"""

from __future__ import absolute_import


READ_FAULT_SKIP_REASONS = (
    "backend_unsupported",
    "no_regions_configured",
    "address_outside_backend_mapping",
    "probability_gate",
    "address_alignment",
    "cpu_path_not_interceptable",
)


CPU_PATH_OUTCOMES = (
    "not_armed",
    "fired",
    "armed_but_not_triggered",
    "cpu_path_not_interceptable",
)


def translate_bus_address_to_backend_offset(
    bus_address,
    backend_bus_base,
    backend_size,
):
    """Translate an absolute bus address into a backend-relative offset.

    Returns ``(offset, None)`` on success, or ``(None, reason)`` if
    ``bus_address`` does not lie within ``[backend_bus_base,
    backend_bus_base + backend_size)``.

    ``reason`` is one of ``READ_FAULT_SKIP_REASONS`` so callers can emit
    a precise skip diagnostic.
    """
    if backend_size is None or backend_size <= 0:
        return None, "backend_unsupported"
    if backend_bus_base is None:
        return None, "backend_unsupported"
    if bus_address < backend_bus_base:
        return None, "address_outside_backend_mapping"
    offset = bus_address - backend_bus_base
    if offset >= backend_size:
        return None, "address_outside_backend_mapping"
    return offset, None


def pick_target_address_in_regions(regions, fault_index, granularity):
    """Pick the target bus address for ``fault_index`` from ``regions``.

    ``regions`` is a list of ``(start, end)`` tuples in absolute bus
    addresses, both inclusive on the lower bound and exclusive on the
    upper. ``fault_index`` is an integer that selects a position in the
    flattened region span. ``granularity`` aligns the result downward.

    Returns ``(target_address, None)`` or ``(None, reason)``.
    """
    if not regions:
        return None, "no_regions_configured"
    if granularity is None or granularity < 1:
        granularity = 1
    total = 0
    for start, end in regions:
        if end <= start:
            return None, "no_regions_configured"
        total += end - start
    if total <= 0:
        return None, "no_regions_configured"
    word_offset = (int(fault_index) * int(granularity)) % total
    accum = 0
    for start, end in regions:
        size = end - start
        if accum + size > word_offset:
            target = start + (word_offset - accum)
            target = target & ~(granularity - 1)
            if target < start:
                target = start
            return target, None
        accum += size
    return regions[0][0], None


class ReadFaultStats(object):
    """Accumulator for read-fault planning/arming/firing counts.

    Counts are exposed as plain ints under stable keys so the audit
    summary can include them without coupling to harness internals.

    ``cpu_path_validated`` tracks armed faults whose CPU-side read was
    confirmed to pass through the backend's read hook (either by firing
    the fault, or by incrementing the peripheral's read counter without
    firing because the probability gate did not select that read).
    Without this counter the harness cannot tell the difference between
    "armed and CPU read it but probability gate skipped" (interceptable
    coverage) and "armed and CPU bypassed the hook entirely" (no
    coverage).

    ``cpu_path_unsupported`` counts armed faults that observed zero
    peripheral reads, which means the CPU mapping bypassed the hook —
    arming worked but coverage is invalid.
    """

    __slots__ = (
        "planned", "armed", "fired", "skipped", "skip_reasons",
        "cpu_path_validated", "cpu_path_unsupported",
    )

    def __init__(self):
        self.planned = 0
        self.armed = 0
        self.fired = 0
        self.skipped = 0
        self.skip_reasons = {}
        self.cpu_path_validated = 0
        self.cpu_path_unsupported = 0

    def record_planned(self):
        self.planned += 1

    def record_armed(self):
        self.armed += 1

    def record_fired(self):
        self.fired += 1

    def record_cpu_path_validated(self):
        self.cpu_path_validated += 1

    def record_cpu_path_unsupported(self):
        self.cpu_path_unsupported += 1

    def record_skipped(self, reason):
        if not reason:
            reason = "unknown"
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def merge(self, other):
        self.planned += other.planned
        self.armed += other.armed
        self.fired += other.fired
        self.skipped += other.skipped
        self.cpu_path_validated += other.cpu_path_validated
        self.cpu_path_unsupported += other.cpu_path_unsupported
        for reason, count in other.skip_reasons.items():
            self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + count

    def as_dict(self):
        return {
            "planned": int(self.planned),
            "armed": int(self.armed),
            "fired": int(self.fired),
            "skipped": int(self.skipped),
            "cpu_path_validated": int(self.cpu_path_validated),
            "cpu_path_unsupported": int(self.cpu_path_unsupported),
            "skip_reasons": {str(k): int(v) for k, v in self.skip_reasons.items()},
        }

    def coverage_validated(self):
        """True iff read-fault coverage was actually exercised.

        Requires at least one armed fault, at least one CPU-path-validated
        read, and zero faults whose CPU read bypassed the hook. A single
        non-interceptable observation invalidates coverage.
        """
        return (
            self.armed > 0
            and self.cpu_path_validated > 0
            and self.cpu_path_unsupported == 0
        )

    @classmethod
    def from_dict(cls, data):
        instance = cls()
        if not data:
            return instance
        instance.planned = int(data.get("planned", 0))
        instance.armed = int(data.get("armed", 0))
        instance.fired = int(data.get("fired", 0))
        instance.skipped = int(data.get("skipped", 0))
        instance.cpu_path_validated = int(data.get("cpu_path_validated", 0))
        instance.cpu_path_unsupported = int(data.get("cpu_path_unsupported", 0))
        reasons = data.get("skip_reasons") or {}
        instance.skip_reasons = {str(k): int(v) for k, v in reasons.items()}
        return instance


def classify_cpu_path_outcome(armed, fired, total_reads):
    """Classify a single armed read-fault's CPU-path outcome.

    Inputs are the post-run state of the backend's read-fault counters:
    - ``armed``: whether the harness completed arming for this point.
    - ``fired``: whether the targeted address was hit and the fault
      triggered (one-shot semantics).
    - ``total_reads``: how many reads the peripheral hook observed
      between arm and disarm.

    Returns one of ``CPU_PATH_OUTCOMES``:

    * ``not_armed`` - arming was skipped or failed; CPU path status is
      unknown and should not contribute to coverage.
    * ``fired`` - hook fired; CPU path is interceptable and the targeted
      read happened. Counts as validated coverage.
    * ``armed_but_not_triggered`` - hook saw at least one CPU read but
      did not fire on the targeted address (probability gate, address
      mismatch, or simply no execution path read it). CPU path is
      interceptable; coverage is validated even though the specific
      address was not hit.
    * ``cpu_path_not_interceptable`` - hook saw zero CPU reads while
      armed. Strong signal that the CPU mapping bypassed the read hook
      (e.g. a directly mapped fast path), so arming worked but no read
      coverage was actually exercised.
    """
    if not armed:
        return "not_armed"
    if fired:
        return "fired"
    if int(total_reads or 0) > 0:
        return "armed_but_not_triggered"
    return "cpu_path_not_interceptable"


def cpu_path_capability_warning(stats):
    """Return a warning if any armed read fault bypassed the CPU read hook.

    Fires whenever armed > 0 AND cpu_path_unsupported > 0, regardless of how
    many other faults validated. A run where some points validate and others
    bypass the hook (a mixed batch) still has invalid coverage for the
    bypassed points, so the warning must not be suppressed just because some
    coverage was exercised.
    """
    if stats.armed <= 0:
        return None
    if stats.cpu_path_unsupported <= 0:
        return None
    coverage_note = (
        "coverage is not validated"
        if stats.cpu_path_validated <= 0
        else "coverage is incomplete"
    )
    return (
        "read_bit_flip armed {} fault(s) but the CPU mapping appears to "
        "bypass the read hook ({} non-interceptable observations); "
        "read-fault {}.".format(
            stats.armed, stats.cpu_path_unsupported, coverage_note,
        )
    )


def read_fault_warning(stats, requested):
    """Return a warning string when read faults were requested but never
    armed or fired, otherwise ``None``.

    ``requested`` is a boolean: True iff the profile asked for at least
    one read fault.
    """
    if not requested:
        return None
    if stats.planned <= 0:
        return (
            "read_bit_flip requested but no fault was planned; "
            "check read_fault_config and target_regions."
        )
    if stats.armed <= 0:
        return (
            "read_bit_flip planned {} fault(s) but none armed; "
            "skip reasons: {}".format(stats.planned, sorted(stats.skip_reasons.items()))
        )
    if stats.fired <= 0:
        return (
            "read_bit_flip armed {} fault(s) but none fired; "
            "the firmware may not have read the targeted address.".format(stats.armed)
        )
    return None
