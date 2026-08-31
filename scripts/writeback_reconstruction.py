"""Pure write-back durability reconstruction helpers.

The runtime sweep uses these helpers for execute-mode snapshots.  Keeping the
reconstruction independent of Renode makes the ordering and erase semantics
unit-testable.
"""

class AmbiguousWriteEvent(ValueError):
    """Raised when an event does not carry a supported program width."""


SUPPORTED_WRITE_WIDTHS = (1, 2, 4, 8)
UNSUPPORTED_LIFECYCLE_PREFIXES = ("m:", "h:", "cc:", "p2:", "mf:", "c:")
UNSUPPORTED_ERASE_FAULT_CODES = (
    "e",
    "a",
    "interrupted_erase",
    "multi_sector_atomicity",
)
KNOWN_SIMPLE_FAULT_CODES = (
    "w", "b", "s", "g", "x", "d", "l", "r", "e", "a", "f", "t", "k",
    "i", "op", "os", "od", "oo", "on", "tb", "nv", "in", "it", "ib",
    "ic", "iw",
)


def is_known_writeback_fault_type(fault_type):
    """Return whether a runtime wire encoding belongs to a known family."""
    token = str(fault_type or "").strip().lower()
    if not token:
        return False
    base = token.split(":", 1)[0]
    if base in KNOWN_SIMPLE_FAULT_CODES:
        return True
    return any(token.startswith(prefix) for prefix in UNSUPPORTED_LIFECYCLE_PREFIXES)


def is_unsupported_writeback_fault_type(fault_type):
    """Return whether a fault encoding cannot be reconstructed safely.

    Lifecycle/compound paths do not provide a single persisted snapshot, and
    erase/atomicity faults capture partial or neighbour-corrupted flash that
    cannot be recreated from the clean baseline.  Both therefore fail closed
    instead of being presented as reconstructed writeback observations.
    """
    token = str(fault_type or "").strip().lower()
    base = token.split(":", 1)[0] if token else ""
    return (
        not is_known_writeback_fault_type(token)
        or any(token.startswith(prefix) for prefix in UNSUPPORTED_LIFECYCLE_PREFIXES)
        or base in UNSUPPORTED_ERASE_FAULT_CODES
    )


def _parse_trace_int(text):
    try:
        return int(text, 0)
    except ValueError:
        # Decimal records with a leading zero are valid exporter output too.
        return int(text, 10)


def parse_write_trace_record(line):
    """Parse one legacy or width-aware trace line.

    FaultTracker uses colon-separated records, while CFIFlash historically
    emitted comma-separated records.  Calibration normalises either form to
    the CSV format consumed by replay.
    """
    text = str(line).strip()
    if not text:
        return None
    delimiter = ':' if ':' in text else ','
    parts = [part.strip() for part in text.split(delimiter)]
    if len(parts) < 2:
        raise AmbiguousWriteEvent(
            "write trace record has fewer than two fields: {!r}".format(text)
        )
    if len(parts) > 4:
        raise AmbiguousWriteEvent(
            "write trace record has more than four fields: {!r}".format(text)
        )
    values = [_parse_trace_int(parts[index]) for index in range(min(3, len(parts)))]
    if len(values) == 2:
        # Preserve the old two-column exporter convention, which represented
        # an unvalued operation as a zero-valued word.
        values.append(0)
    if len(parts) >= 4 and parts[3] != '':
        values.append(_parse_trace_int(parts[3]))
    return tuple(values)


def normalise_write_event(event):
    """Return ``(index, offset, value, width)`` for a trace event.

    Legacy traces have three columns and are treated as explicit four-byte
    events only by callers that have established the backend's event width.
    New traces may carry a fourth width column.
    """
    if len(event) < 3:
        raise AmbiguousWriteEvent("write event has fewer than three fields")
    if len(event) > 4:
        raise AmbiguousWriteEvent("write event has more than four fields")
    try:
        write_index = int(event[0])
        flash_offset = int(event[1])
    except (TypeError, ValueError, IndexError):
        raise AmbiguousWriteEvent("write event index/offset is not an integer")
    if write_index < 0:
        raise AmbiguousWriteEvent("write event index is negative")
    if flash_offset < 0:
        raise AmbiguousWriteEvent("write event offset is negative")
    width = 4 if len(event) < 4 else int(event[3])
    if width not in SUPPORTED_WRITE_WIDTHS:
        raise AmbiguousWriteEvent("unsupported or ambiguous write width {!r}".format(width))
    value_mask = (1 << (8 * width)) - 1
    return write_index, flash_offset, int(event[2]) & value_mask, width


def validate_write_trace_width(trace_data, legacy_width=None, flash_size=None,
                               baseline_size=None, snapshot_size=None):
    """Normalize a trace only when every event width is unambiguous.

    Three-column traces predate width-aware traces.  They may be accepted only
    when the active backend explicitly declares the operation width.  A
    fourth-column event always carries its own width and is validated directly.
    """
    if legacy_width is not None and int(legacy_width) not in SUPPORTED_WRITE_WIDTHS:
        raise AmbiguousWriteEvent("unsupported legacy write width {!r}".format(legacy_width))
    normalized = []
    previous_index = None
    capacities = []
    for name, value in (
        ("flash", flash_size),
        ("baseline", baseline_size),
        ("snapshot", snapshot_size),
    ):
        if value is None:
            continue
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError("{} size is not an integer".format(name))
        if value < 0:
            raise ValueError("{} size is negative".format(name))
        capacities.append((name, value))
    for event in trace_data or ():
        if len(event) < 4:
            if legacy_width is None:
                raise AmbiguousWriteEvent("legacy write event has no declared width")
            event = tuple(event[:3]) + (int(legacy_width),)
        normalized_event = normalise_write_event(event)
        write_index, flash_offset, _value, width = normalized_event
        if previous_index is not None and write_index <= previous_index:
            raise ValueError(
                "write trace indices must be strictly increasing: {} after {}".format(
                    write_index, previous_index
                )
            )
        previous_index = write_index
        for name, capacity in capacities:
            if flash_offset > capacity or width > capacity - flash_offset:
                raise ValueError(
                    "write event span [{}, {}) is outside {} size {}".format(
                        flash_offset, flash_offset + width, name, capacity
                    )
                )
        normalized.append(normalized_event)
    return normalized


def validate_erase_trace_data(trace_data, flash_size=None, page_size=4096,
                              require_monotonic=False,
                              require_replay_metadata=False):
    """Validate and normalize erase records before replay.

    ``erase_size == 0`` retains the legacy meaning of the backend page size.
    Negative offsets/sizes and records outside the replay image are rejected;
    native replay additionally requires chronological ``writes_at`` values.
    """
    page_size = int(page_size)
    if page_size <= 0:
        page_size = 4096
    capacity = None if flash_size is None else int(flash_size)
    if capacity is not None and capacity < 0:
        raise ValueError("erase trace flash size is negative")
    normalized = []
    previous_writes_at = None
    previous_erase_index = None
    for entry in trace_data or ():
        if len(entry) < 3:
            raise ValueError("erase trace record has fewer than three fields")
        if len(entry) > 4:
            raise ValueError("erase trace record has more than four fields")
        offset = int(entry[0])
        writes_at = int(entry[1])
        erase_size = int(entry[2])
        if offset < 0 or writes_at < 0 or erase_size < 0:
            raise ValueError("erase trace contains a negative field")
        if require_replay_metadata and erase_size <= 0:
            raise ValueError(
                "erase trace replay metadata requires a positive erase_size"
            )
        effective_size = erase_size if erase_size > 0 else page_size
        if capacity is not None and (
            offset > capacity or effective_size > capacity - offset
        ):
            raise ValueError(
                "erase trace region [{}, {}) is outside flash size {}".format(
                    offset, offset + effective_size, capacity
                )
            )
        if (require_monotonic and previous_writes_at is not None and
                writes_at < previous_writes_at):
            raise ValueError(
                "erase trace writes_at_this_point is not monotonic: {} after {}".format(
                    writes_at, previous_writes_at
                )
                )
        # Erase tuples historically omit erase_index.  If a caller supplies a
        # fourth field, treat it as the source index and enforce the same
        # strict ordering as writes; equal writes_at values remain valid for
        # multiple erases emitted at one operation boundary.
        if len(entry) >= 4:
            erase_index = int(entry[3])
            if erase_index < 0:
                raise ValueError("erase trace index is negative")
            if previous_erase_index is not None and erase_index <= previous_erase_index:
                raise ValueError(
                    "erase trace indices must be strictly increasing: {} after {}".format(
                        erase_index, previous_erase_index
                    )
                )
            previous_erase_index = erase_index
        previous_writes_at = writes_at
        normalized.append((offset, writes_at, erase_size))
    return normalized


def _apply_write(image, offset, value, width):
    if offset < 0 or offset + width > len(image):
        raise ValueError("write event is outside the baseline image")
    for index in range(width):
        image[offset + index] = (value >> (8 * index)) & 0xFF


def _overlaps(offset, width, erase_offset, erase_size):
    return offset < erase_offset + erase_size and erase_offset < offset + width


def reconstruct_committed_snapshot(
    initial_snapshot,
    trace_data,
    erase_trace,
    fault_at,
    flash_base_addr,
    page_size,
    capacity,
    barriers=(),
    erase_fill=0xFF,
    erase_flushes_domain=False,
):
    """Replay only durable writes into a copy of the initial image.

    Erases are applied at their recorded write count and therefore participate
    in the pre-write state of later events.  Pending events are discarded at
    the fault boundary.  The return value is ``(image, discarded_count)``.
    """
    if int(fault_at) < 0:
        raise ValueError("fault boundary is negative")
    # Validate the complete provenance before making even the first mutation
    # of the replay image.  In particular, do not let _apply_write discover a
    # width/span problem only after earlier writes or erases were applied.
    trace_data = list(trace_data or ())
    normalized_trace = validate_write_trace_width(
        trace_data,
        legacy_width=None,
        baseline_size=len(initial_snapshot),
        snapshot_size=len(initial_snapshot),
    )
    normalized_erases = validate_erase_trace_data(
        list(erase_trace or ()),
        flash_size=len(initial_snapshot),
        page_size=page_size,
        require_monotonic=True,
    )
    image = bytearray(initial_snapshot)
    capacity = max(0, int(capacity))
    page_size = max(1, int(page_size))
    barrier_addresses = {int(value) for value in barriers}
    pending_erases = []
    for entry in normalized_erases:
        offset = int(entry[0])
        writes_at = int(entry[1])
        size = int(entry[2]) if int(entry[2]) > 0 else page_size
        pending_erases.append((writes_at, offset, size))
    pending_erases.sort()

    pending = []
    # A list keeps the cursor mutable without a Python 3-only closure keyword
    # (the Renode interpreter is IronPython 2).
    erase_index = [0]

    def flush_pending():
        for event in pending:
            write_index, offset, value, width = event
            _apply_write(image, offset, value, width)
        pending[:] = []

    def apply_erase(offset, size):
        start = max(0, offset)
        end = min(len(image), offset + size)
        if end > start:
            # Avoid list-to-bytes construction: Renode's IronPython 2 maps
            # bytes to str, which does not produce an integer fill buffer.
            fill = int(erase_fill) & 0xFF
            for index in range(start, end):
                image[index] = fill

    def process_erases_before(write_index):
        while erase_index[0] < len(pending_erases):
            writes_at, offset, size = pending_erases[erase_index[0]]
            if writes_at >= write_index:
                break
            if erase_flushes_domain:
                flush_pending()
            else:
                pending[:] = [
                    event for event in pending
                    if not _overlaps(event[1], event[3], offset, size)
                ]
            apply_erase(offset, size)
            erase_index[0] += 1

    for write_index, offset, value, width in normalized_trace:
        if write_index > int(fault_at):
            break
        process_erases_before(write_index)
        event = (write_index, offset, value, width)
        pending.append(event)
        bus_address = int(flash_base_addr) + offset
        if bus_address in barrier_addresses:
            flush_pending()
        else:
            while len(pending) > capacity:
                event = pending.pop(0)
                _apply_write(image, event[1], event[2], event[3])

    while erase_index[0] < len(pending_erases):
        writes_at, offset, size = pending_erases[erase_index[0]]
        if writes_at > int(fault_at):
            break
        if erase_flushes_domain:
            flush_pending()
        else:
            pending[:] = [
                event for event in pending
                if not _overlaps(event[1], event[3], offset, size)
            ]
        apply_erase(offset, size)
        erase_index[0] += 1

    # bytearray is usable from both CPython and IronPython and preserves
    # integer indexing for the CLR conversion performed by the runner.
    return bytearray(image), len(pending)
