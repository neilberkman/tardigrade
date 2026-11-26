# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Persistent-state computation for recovery-trace fault selection.

The runtime imports this module inside Renode, so keep it compatible with the
Python implementation bundled with Renode 1.16.1.  In particular, avoid
dataclasses, type annotations, and implementation-specific bytearray tricks.
"""

from __future__ import division

import hashlib
import binascii
import struct


class RecoveryStateError(ValueError):
    pass


_WRITE_FAULT_NAMES = {
    "w": "power_loss",
    "power_loss": "power_loss",
    "b": "bit_corruption",
    "bit_corruption": "bit_corruption",
    "s": "silent_write_failure",
    "silent_write_failure": "silent_write_failure",
    "r": "write_rejection",
    "x": "write_rejection",
    "write_rejection": "write_rejection",
    "g": "driver_error",
    "driver_error": "driver_error",
    "d": "write_disturb",
    "write_disturb": "write_disturb",
    "l": "wear_leveling_corruption",
    "wear_leveling_corruption": "wear_leveling_corruption",
}

_ERASE_FAULT_NAMES = {
    "w": "interrupted_erase",
    "power_loss": "interrupted_erase",
    "e": "interrupted_erase",
    "interrupted_erase": "interrupted_erase",
    "a": "multi_sector_atomicity",
    "multi_sector_atomicity": "multi_sector_atomicity",
}

_TORN_WORD_MODES = frozenset(
    (
        "half",
        "half_retain",
        "untouched",
        "erased",
        "programmed",
        "uncorrectable",
        "corrupted",
        "fixed",
        "partial_bits",
    )
)

_STATE_CHUNK_SIZE = 4096

try:
    _wide_integer = long
except NameError:
    _wide_integer = int

try:
    _string_types = (basestring,)
except NameError:
    _string_types = (str,)


def _coerce_integer(value):
    if isinstance(value, _string_types):
        return _wide_integer(value, 0)
    return _wide_integer(value)


def _u64(value):
    value = int(value)
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise RecoveryStateError("integer is outside the unsigned 64-bit range")
    return struct.pack(">Q", value)


def _tagged_hash(tag, *parts):
    digest = hashlib.sha256()
    digest.update(tag)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _coerce_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return bytes(bytearray((int(item) & 0xFF) for item in value))


def _little_endian_bytes(value, width):
    width = int(width)
    if width not in (1, 2, 4, 8):
        raise RecoveryStateError("write width must be 1, 2, 4, or 8 bytes")
    value = int(value)
    return bytes(bytearray((value >> (8 * index)) & 0xFF for index in range(width)))


def _little_endian_value(data):
    value = 0
    for index, byte_value in enumerate(bytearray(data)):
        value |= (int(byte_value) & 0xFF) << (8 * index)
    return value


class RegionState(object):
    """Immutable chunked bytes with an incrementally maintained Merkle root."""

    def __init__(self, name, base_address, chunks, chunk_size, levels=None, length=None):
        self.name = str(name)
        if not self.name:
            raise RecoveryStateError("persistent region name must not be empty")
        self.base_address = int(base_address)
        if self.base_address < 0:
            raise RecoveryStateError("persistent region base address must be non-negative")
        self.chunk_size = int(chunk_size)
        if self.chunk_size <= 0:
            raise RecoveryStateError("chunk size must be positive")
        self.chunks = tuple(_coerce_bytes(chunk) for chunk in chunks)
        self.length = int(
            sum(len(chunk) for chunk in self.chunks) if length is None else length
        )
        if self.length < 0:
            raise RecoveryStateError("persistent region length must be non-negative")
        if levels is None:
            self.levels = self._build_levels()
        else:
            self.levels = tuple(tuple(level) for level in levels)

    @classmethod
    def from_bytes(cls, name, base_address, data, chunk_size=_STATE_CHUNK_SIZE):
        raw = _coerce_bytes(data)
        chunk_size = int(chunk_size)
        if chunk_size != _STATE_CHUNK_SIZE:
            raise RecoveryStateError(
                "persistent-state chunk size is fixed at {} bytes".format(
                    _STATE_CHUNK_SIZE
                )
            )
        chunks = tuple(
            raw[offset : offset + chunk_size]
            for offset in range(0, len(raw), chunk_size)
        )
        return cls(name, base_address, chunks, chunk_size, length=len(raw))

    def _leaf_hash(self, index, data):
        return _tagged_hash(b"recovery-state-leaf\0", _u64(index), _u64(len(data)), data)

    def _build_levels(self):
        leaves = [self._leaf_hash(index, data) for index, data in enumerate(self.chunks)]
        if not leaves:
            leaves = [_tagged_hash(b"recovery-state-empty-region\0")]
        levels = [tuple(leaves)]
        current = leaves
        while len(current) > 1:
            parents = []
            for index in range(0, len(current), 2):
                left = current[index]
                right = current[index + 1] if index + 1 < len(current) else left
                parents.append(_tagged_hash(b"recovery-state-node\0", left, right))
            current = parents
            levels.append(tuple(current))
        return tuple(levels)

    @property
    def root(self):
        return self.levels[-1][0]

    def read(self, offset, length):
        offset = int(offset)
        length = int(length)
        self._check_range(offset, length)
        if length == 0:
            return b""
        first_chunk = offset // self.chunk_size
        last_chunk = (offset + length - 1) // self.chunk_size
        if first_chunk == last_chunk:
            start = offset % self.chunk_size
            return self.chunks[first_chunk][start : start + length]
        materialized = self.materialize()
        return materialized[offset : offset + length]

    def write_many(self, writes):
        normalized = []
        for offset, data in writes:
            raw = _coerce_bytes(data)
            offset = int(offset)
            self._check_range(offset, len(raw))
            if raw:
                normalized.append((offset, raw))
        if not normalized:
            return self

        new_chunks = list(self.chunks)
        changed = set()
        for offset, raw in normalized:
            cursor = 0
            while cursor < len(raw):
                absolute = offset + cursor
                chunk_index = absolute // self.chunk_size
                in_chunk = absolute % self.chunk_size
                count = min(len(raw) - cursor, len(new_chunks[chunk_index]) - in_chunk)
                chunk = bytearray(new_chunks[chunk_index])
                chunk[in_chunk : in_chunk + count] = raw[cursor : cursor + count]
                new_chunks[chunk_index] = bytes(chunk)
                changed.add(chunk_index)
                cursor += count

        new_levels = [list(level) for level in self.levels]
        for chunk_index in changed:
            new_levels[0][chunk_index] = self._leaf_hash(
                chunk_index, new_chunks[chunk_index]
            )
        changed_at_level = set(changed)
        for level_index in range(1, len(new_levels)):
            parent_indices = set(index // 2 for index in changed_at_level)
            child_level = new_levels[level_index - 1]
            for parent_index in parent_indices:
                child_index = parent_index * 2
                left = child_level[child_index]
                right = (
                    child_level[child_index + 1]
                    if child_index + 1 < len(child_level)
                    else left
                )
                new_levels[level_index][parent_index] = _tagged_hash(
                    b"recovery-state-node\0", left, right
                )
            changed_at_level = parent_indices

        return RegionState(
            self.name,
            self.base_address,
            tuple(new_chunks),
            self.chunk_size,
            levels=tuple(tuple(level) for level in new_levels),
            length=self.length,
        )

    def materialize(self):
        if not self.chunks:
            return b""
        return b"".join(self.chunks)[: self.length]

    def _check_range(self, offset, length):
        if offset < 0 or length < 0 or offset > self.length or length > self.length - offset:
            raise RecoveryStateError(
                "persistent region access [{}, {}) is outside {} bytes".format(
                    offset, offset + length, self.length
                )
            )


class PersistentState(object):
    """Everything a supported NVM backend retains across a cold reset."""

    def __init__(self, regions, uncorrectable_words=(), persistent_values=None):
        region_list = list(regions)
        region_names = [region.name for region in region_list]
        if len(region_names) != len(set(region_names)):
            raise RecoveryStateError("persistent region names must be unique")
        self.regions = tuple(sorted(region_list, key=lambda region: region.name))
        self.uncorrectable_words = frozenset(
            (str(region_name), int(offset))
            for region_name, offset in uncorrectable_words
        )
        values = persistent_values or {}
        self.persistent_values = tuple(
            sorted((str(name), _coerce_bytes(value)) for name, value in values.items())
        )
        self._identity = None
        for region_name, offset in self.uncorrectable_words:
            region = self.region(region_name)
            region._check_range(offset, 1)

    @classmethod
    def from_bytes(
        cls,
        data,
        name="nvm",
        base_address=0,
        chunk_size=_STATE_CHUNK_SIZE,
        uncorrectable_words=(),
        persistent_values=None,
    ):
        region = RegionState.from_bytes(name, base_address, data, chunk_size=chunk_size)
        marks = []
        for item in uncorrectable_words:
            if isinstance(item, tuple):
                marks.append(item)
            else:
                marks.append((name, int(item)))
        return cls(region_list_or_single(region), marks, persistent_values)

    def region(self, name="nvm"):
        name = str(name)
        for region in self.regions:
            if region.name == name:
                return region
        raise RecoveryStateError("unknown persistent region {!r}".format(name))

    def read(self, region_name, offset, length):
        return self.region(region_name).read(offset, length)

    def write(self, region_name, offset, data, clear_uncorrectable=True):
        region_name = str(region_name)
        raw = _coerce_bytes(data)
        replacement = self.region(region_name).write_many(((int(offset), raw),))
        regions = [replacement if region.name == region_name else region for region in self.regions]
        marks = self.uncorrectable_words
        if clear_uncorrectable and raw:
            marks = _clear_marks_in_range(marks, region_name, int(offset), len(raw))
        return PersistentState(
            regions,
            marks,
            persistent_values=dict(self.persistent_values),
        )

    def write_many(self, region_name, writes, clear_ranges=()):
        region_name = str(region_name)
        replacement = self.region(region_name).write_many(writes)
        regions = [replacement if region.name == region_name else region for region in self.regions]
        marks = self.uncorrectable_words
        for offset, length in clear_ranges:
            marks = _clear_marks_in_range(marks, region_name, int(offset), int(length))
        return PersistentState(
            regions,
            marks,
            persistent_values=dict(self.persistent_values),
        )

    def with_uncorrectable_words(self, words):
        return PersistentState(
            self.regions,
            words,
            persistent_values=dict(self.persistent_values),
        )

    def identity(self):
        if self._identity is None:
            digest = hashlib.sha256()
            digest.update(b"tardigrade-recovery-state-v1\0")
            digest.update(_u64(len(self.regions)))
            for region in self.regions:
                name = region.name.encode("utf-8")
                digest.update(_u64(len(name)))
                digest.update(name)
                digest.update(_u64(region.base_address))
                digest.update(_u64(region.length))
                digest.update(region.root)
            digest.update(_u64(len(self.uncorrectable_words)))
            for region_name, offset in sorted(self.uncorrectable_words):
                name = region_name.encode("utf-8")
                digest.update(_u64(len(name)))
                digest.update(name)
                digest.update(_u64(offset))
            digest.update(_u64(len(self.persistent_values)))
            for name_text, value in self.persistent_values:
                name = name_text.encode("utf-8")
                digest.update(_u64(len(name)))
                digest.update(name)
                digest.update(_u64(len(value)))
                digest.update(value)
            self._identity = digest.digest()
        return self._identity

    def identity_hex(self):
        return binascii.hexlify(self.identity()).decode("ascii")

    def materialize(self):
        return dict((region.name, region.materialize()) for region in self.regions)


def region_list_or_single(region):
    return (region,)


def _clear_marks_in_range(marks, region_name, offset, length):
    end = int(offset) + int(length)
    return frozenset(
        (marked_region, marked_offset)
        for marked_region, marked_offset in marks
        if marked_region != region_name or marked_offset < offset or marked_offset >= end
    )


def _normalize_operation(raw, kind=None, sequence=None):
    if not isinstance(raw, dict):
        raise RecoveryStateError("trace operation must be a mapping")
    operation = dict(raw)
    op_kind = str(kind or operation.get("kind") or operation.get("op") or "").lower()
    if op_kind not in ("write", "erase"):
        raise RecoveryStateError("trace operation kind must be write or erase")
    region = str(operation.get("region", "nvm"))
    offset = int(operation.get("offset", operation.get("flash_offset", -1)))
    if offset < 0:
        raise RecoveryStateError("trace operation offset must be non-negative")
    normalized = {
        "kind": op_kind,
        "region": region,
        "offset": offset,
    }
    if sequence is not None:
        normalized["sequence"] = int(sequence)
    if op_kind == "write":
        write_index = int(operation.get("write_index", operation.get("index", 0)))
        width = int(operation.get("width", operation.get("write_width", 0)))
        if write_index <= 0:
            raise RecoveryStateError("write trace indices must be positive")
        if width not in (1, 2, 4, 8):
            raise RecoveryStateError("write trace width must be 1, 2, 4, or 8")
        normalized.update(
            {
                "write_index": write_index,
                "operation_index": write_index - 1,
                "width": width,
                "value": _coerce_integer(operation.get("value", 0)),
            }
        )
    else:
        erase_index = int(operation.get("erase_index", operation.get("index", 0)))
        erase_size = int(operation.get("erase_size", operation.get("size", 0)))
        writes_at = int(
            operation.get("writes_at_this_point", operation.get("writes_at", 0))
        )
        if erase_index <= 0:
            raise RecoveryStateError("erase trace indices must be positive")
        if erase_size <= 0:
            raise RecoveryStateError("erase trace size must be positive")
        if writes_at < 0:
            raise RecoveryStateError("erase trace write position must be non-negative")
        normalized.update(
            {
                "erase_index": erase_index,
                "operation_index": erase_index - 1,
                "erase_size": erase_size,
                "writes_at_this_point": writes_at,
            }
        )
    return normalized


def merge_operation_traces(write_trace, erase_trace):
    """Return the deterministic device order represented by both traces.

    An erase records the completed-write count at the instant it begins.  It
    therefore follows write N and precedes write N+1.  Source order resolves
    multiple erases at the same write boundary.
    """

    writes = [_normalize_operation(item, kind="write") for item in write_trace]
    erases = [_normalize_operation(item, kind="erase") for item in erase_trace]
    for previous, current in zip(writes, writes[1:]):
        if current["write_index"] <= previous["write_index"]:
            raise RecoveryStateError("write trace indices must be strictly increasing")
    for previous, current in zip(erases, erases[1:]):
        if current["erase_index"] <= previous["erase_index"]:
            raise RecoveryStateError("erase trace indices must be strictly increasing")
        if current["writes_at_this_point"] < previous["writes_at_this_point"]:
            raise RecoveryStateError("erase trace write positions must be monotonic")

    merged = []
    erase_cursor = 0
    for write in writes:
        while (
            erase_cursor < len(erases)
            and erases[erase_cursor]["writes_at_this_point"] < write["write_index"]
        ):
            merged.append(erases[erase_cursor])
            erase_cursor += 1
        merged.append(write)
    merged.extend(erases[erase_cursor:])
    for sequence, operation in enumerate(merged):
        operation["sequence"] = sequence
    return merged


def apply_completed_operation(state, operation, erase_fill=0xFF):
    operation = _normalize_operation(operation, sequence=operation.get("sequence"))
    region_name = operation["region"]
    offset = operation["offset"]
    if operation["kind"] == "write":
        data = _little_endian_bytes(operation["value"], operation["width"])
        return state.write(region_name, offset, data, clear_uncorrectable=True)
    size = operation["erase_size"]
    fill = bytes(bytearray((int(erase_fill) & 0xFF,) * size))
    return state.write(region_name, offset, fill, clear_uncorrectable=True)


def _next_lcg(seed):
    return (int(seed) * 1103515245 + 12345) & 0xFFFFFFFF


def _fault_seed(offset, write_index, total_erases, corruption_seed):
    seed = int(corruption_seed) & 0xFFFFFFFF
    if seed == 0:
        seed = int(write_index) & 0xFFFFFFFF
    seed ^= int(offset) & 0xFFFFFFFF
    seed ^= (int(total_erases) * 2654435761) & 0xFFFFFFFF
    return seed & 0xFFFFFFFF


def _corrupt_torn_bytes(intended, operation_index, offset, seed):
    result = bytearray(intended)
    total_bits = len(result) * 8
    if total_bits <= 0:
        return bytes(result)
    state = int(seed) & 0xFFFFFFFF
    if state == 0:
        state = 0x5A3C96A5
    state ^= ((int(operation_index) & 0xFFFFFFFF) * 2654435761) & 0xFFFFFFFF
    state ^= ((int(offset) & 0xFFFFFFFF) * 2246822519) & 0xFFFFFFFF
    state &= 0xFFFFFFFF
    if state == 0:
        state = 0x9E3779B9
    state = _next_lcg(state)
    flip_count = min(total_bits, 3 + (state % 3))
    flipped = set()
    for _unused in range(flip_count):
        state = _next_lcg(state)
        bit_position = state % total_bits
        while bit_position in flipped:
            bit_position = (bit_position + 1) % total_bits
        flipped.add(bit_position)
        result[bit_position // 8] ^= 1 << (bit_position % 8)
    return bytes(result)


def _partial_bit_value(previous_value, target_value, width, seed,
                       operation_index, offset, domain):
    value_mask = (1 << (8 * int(width))) - 1
    previous_value = int(previous_value) & value_mask
    target_value = int(target_value) & value_mask
    changed = [
        bit for bit in range(int(width) * 8)
        if ((previous_value ^ target_value) & (1 << bit)) != 0
    ]
    if not changed:
        return previous_value
    state = int(seed) & 0xFFFFFFFF
    if state == 0:
        state = 0x5A3C96A5
    state ^= ((int(operation_index) & 0xFFFFFFFF) * 2654435761) & 0xFFFFFFFF
    state ^= ((int(offset) & 0xFFFFFFFF) * 2246822519) & 0xFFFFFFFF
    state ^= int(domain) & 0xFFFFFFFF
    state &= 0xFFFFFFFF
    if state == 0:
        state = 0x9E3779B9
    state = _next_lcg(state)
    selected_count = 1 if len(changed) == 1 else 1 + state % (len(changed) - 1)
    result = previous_value
    for index in range(selected_count):
        state = _next_lcg(state)
        swap_index = index + state % (len(changed) - index)
        selected_bit = changed[swap_index]
        changed[swap_index], changed[index] = changed[index], selected_bit
        mask = 1 << selected_bit
        result = (result & ~mask) | (target_value & mask)
    return result & value_mask


def _flash_fault_bytes(previous, intended, mode, erase_fill,
                       operation_index, offset, seed):
    previous = _coerce_bytes(previous)
    intended = _coerce_bytes(intended)
    if len(previous) != len(intended):
        raise RecoveryStateError("previous and intended flash words differ in width")
    normalized = str(mode or "fixed").strip().lower()
    if normalized in ("fixed", "untouched", "half", "half_retain"):
        return previous
    if normalized not in ("programmed", "partial_bits"):
        raise RecoveryStateError("unknown flash torn-word mode {!r}".format(normalized))
    width = len(previous)
    previous_value = _little_endian_value(previous)
    intended_value = _little_endian_value(intended)
    value_mask = (1 << (8 * width)) - 1
    fill = sum((int(erase_fill) & 0xFF) << (8 * index) for index in range(width))
    programmed = (
        (fill & previous_value & intended_value)
        | ((~fill & value_mask) & (previous_value | intended_value))
    ) & value_mask
    if normalized == "programmed":
        return _little_endian_bytes(programmed, width)
    partial = _partial_bit_value(
        previous_value, programmed, width, seed, operation_index,
        offset, 0x50524F47
    )
    return _little_endian_bytes(partial, width)


def _corrupt_erased_span(size, erase_fill, erase_index, offset, seed, writes_at, unit):
    result = bytearray((int(erase_fill) & 0xFF,) * int(size))
    state = int(seed) & 0xFFFFFFFF
    if state != 0:
        state ^= int(offset) & 0xFFFFFFFF
        state ^= (int(erase_index) * 2654435761) & 0xFFFFFFFF
    else:
        state = int(writes_at) & 0xFFFFFFFF
        state ^= int(offset) & 0xFFFFFFFF
        state ^= (int(erase_index) * 2654435761) & 0xFFFFFFFF
    state &= 0xFFFFFFFF
    unit = max(1, int(unit))
    for relative in range(0, int(size), unit):
        unit_length = min(unit, int(size) - relative)
        total_bits = unit_length * 8
        state = _next_lcg(state)
        flip_count = min(total_bits, 3 + (state % 3))
        flipped = set()
        attempts = 0
        while len(flipped) < flip_count and attempts < total_bits * 4:
            attempts += 1
            state = _next_lcg(state)
            bit_position = state % total_bits
            if bit_position in flipped:
                continue
            flipped.add(bit_position)
            result[relative + bit_position // 8] ^= 1 << (bit_position % 8)
    return bytes(result)


def _mram_fault_bytes(previous, intended, mode, erase_fill, operation_index, offset, seed):
    mode = str(mode or "half").strip().lower()
    if mode not in _TORN_WORD_MODES:
        raise RecoveryStateError("unknown MRAM torn-word mode {!r}".format(mode))
    previous = _coerce_bytes(previous)
    intended = _coerce_bytes(intended)
    if len(previous) != len(intended):
        raise RecoveryStateError("previous and intended MRAM words differ in width")
    if mode == "programmed":
        return intended
    if mode == "corrupted":
        return _corrupt_torn_bytes(intended, operation_index, offset, seed)
    if mode == "erased":
        return bytes(bytearray((int(erase_fill) & 0xFF,) * len(intended)))
    if mode in ("untouched", "uncorrectable"):
        return previous
    split = len(intended) // 2
    if mode == "half_retain":
        return intended[:split] + previous[split:]
    return intended[:split] + bytes(
        bytearray((int(erase_fill) & 0xFF,) * (len(intended) - split))
    )


def _apply_write_fault(
    state,
    operation,
    fault_type,
    backend_kind,
    torn_word_mode,
    erase_fill,
    corruption_seed,
    total_erases,
    page_size,
):
    fault_name = _WRITE_FAULT_NAMES.get(str(fault_type).strip().lower())
    if fault_name is None:
        raise RecoveryStateError("unsupported computed write fault {!r}".format(fault_type))
    region_name = operation["region"]
    offset = operation["offset"]
    width = operation["width"]
    write_index = operation["write_index"]
    previous = state.read(region_name, offset, width)
    intended = _little_endian_bytes(operation["value"], width)

    if fault_name == "power_loss":
        if str(backend_kind).lower() == "mram":
            faulted = _mram_fault_bytes(
                previous,
                intended,
                torn_word_mode,
                erase_fill,
                write_index,
                offset,
                corruption_seed,
            )
        else:
            faulted = _flash_fault_bytes(
                previous,
                intended,
                torn_word_mode,
                erase_fill,
                write_index,
                offset,
                corruption_seed,
            )
        result = state.write(region_name, offset, faulted, clear_uncorrectable=False)
        marks = set(result.uncorrectable_words)
        marks = set(_clear_marks_in_range(marks, region_name, offset, width))
        if str(torn_word_mode).strip().lower() == "uncorrectable":
            marks.add((region_name, offset))
        return result.with_uncorrectable_words(marks)

    old_value = _little_endian_value(previous)
    new_value = _little_endian_value(intended)
    value_mask = (1 << (8 * width)) - 1

    if fault_name in ("write_rejection", "driver_error"):
        return state

    if fault_name == "bit_corruption" and str(backend_kind).lower() == "mram":
        faulted = bytearray(intended)
        seed = int(corruption_seed) & 0xFFFFFFFF
        if seed == 0:
            seed = (write_index ^ offset) & 0xFFFFFFFF
        for index in range(len(faulted)):
            seed = _next_lcg(seed)
            if seed & 0x7 == 0:
                seed = _next_lcg(seed)
                mask = (seed >> 16) & 0xFF
                faulted[index] ^= mask if mask != 0 else 1
        return state.write(region_name, offset, bytes(faulted), clear_uncorrectable=True)

    if fault_name == "bit_corruption":
        seed = _fault_seed(offset, write_index, total_erases, corruption_seed)
        keep_mask = _next_lcg(seed)
        bits_to_flip = old_value & ~new_value
        faulted_value = old_value & ~(bits_to_flip & keep_mask & value_mask)
        return state.write(
            region_name,
            offset,
            _little_endian_bytes(faulted_value, width),
            clear_uncorrectable=True,
        )

    if fault_name == "silent_write_failure":
        faulted_value = value_mask if write_index % 2 == 0 else 0
        return state.write(
            region_name,
            offset,
            _little_endian_bytes(faulted_value, width),
            clear_uncorrectable=True,
        )

    writes = [(offset, intended)]
    if fault_name == "write_disturb":
        seed = _fault_seed(offset, write_index, total_erases, corruption_seed)
        disturb_mask = sum(0x11 << (8 * index) for index in range(width))
        region = state.region(region_name)
        for neighbor_offset in (offset - width, offset + width):
            if neighbor_offset < 0 or neighbor_offset > region.length - width:
                continue
            seed = _next_lcg(seed)
            neighbor = _little_endian_value(state.read(region_name, neighbor_offset, width))
            disturbed = neighbor & (~(seed & disturb_mask) & value_mask)
            writes.append((neighbor_offset, _little_endian_bytes(disturbed, width)))
        return state.write_many(
            region_name,
            writes,
            clear_ranges=((item_offset, len(data)) for item_offset, data in writes),
        )

    if fault_name == "wear_leveling_corruption":
        page_size = max(width, int(page_size))
        page_start = (offset // page_size) * page_size
        words_per_page = max(1, page_size // width)
        error_count = 2 + min(10, int(total_erases) // 8)
        seed = _fault_seed(offset, write_index, total_erases, corruption_seed)
        working = state.write(region_name, offset, intended, clear_uncorrectable=True)
        for _unused in range(error_count):
            seed = _next_lcg(seed)
            target_offset = page_start + (seed % words_per_page) * width
            if target_offset < 0 or target_offset > working.region(region_name).length - width:
                continue
            word = _little_endian_value(working.read(region_name, target_offset, width))
            seed = _next_lcg(seed)
            mask = seed & sum(0x01 << (8 * index) for index in range(width))
            if mask == 0:
                seed = _next_lcg(seed)
                mask = 1 << (seed % (8 * width))
            working = working.write(
                region_name,
                target_offset,
                _little_endian_bytes(word & (~mask & value_mask), width),
                clear_uncorrectable=True,
            )
        return working

    raise RecoveryStateError("computed write fault has no implementation")


def _apply_erase_fault(
    state,
    operation,
    fault_type,
    backend_kind,
    torn_word_mode,
    erase_fill,
    corruption_seed,
    program_unit,
):
    fault_name = _ERASE_FAULT_NAMES.get(str(fault_type).strip().lower())
    if fault_name is None:
        raise RecoveryStateError("unsupported computed erase fault {!r}".format(fault_type))
    region_name = operation["region"]
    offset = operation["offset"]
    size = operation["erase_size"]
    fill_byte = int(erase_fill) & 0xFF

    if fault_name == "multi_sector_atomicity":
        half = max(1, size // 2)
        quarter = max(1, size // 4)
        region = state.region(region_name)
        writes = [(offset, bytes(bytearray((fill_byte,) * half)))]
        clear_ranges = [(offset, half)]
        neighbor_offset = offset + size
        neighbor_size = min(quarter, max(0, region.length - neighbor_offset))
        if neighbor_size > 0:
            writes.append(
                (neighbor_offset, bytes(bytearray((fill_byte,) * neighbor_size)))
            )
            clear_ranges.append((neighbor_offset, neighbor_size))
        return state.write_many(region_name, writes, clear_ranges=clear_ranges)

    mode = str(torn_word_mode or "half").strip().lower()
    if mode not in _TORN_WORD_MODES:
        raise RecoveryStateError("unknown MRAM torn-word mode {!r}".format(mode))
    if mode == "untouched":
        return state
    if mode in ("erased", "programmed"):
        return state.write(
            region_name,
            offset,
            bytes(bytearray((fill_byte,) * size)),
            clear_uncorrectable=True,
        )
    if mode == "uncorrectable" and str(backend_kind).lower() == "mram":
        marks = set(state.uncorrectable_words)
        unit = max(1, int(program_unit))
        first = (offset // unit) * unit
        last = ((offset + size - 1) // unit) * unit
        for word_offset in range(first, last + 1, unit):
            marks.add((region_name, word_offset))
        return state.with_uncorrectable_words(marks)
    if mode == "corrupted":
        unit = max(1, int(program_unit))
        if str(backend_kind).lower() == "mram":
            corrupted = bytearray((fill_byte,) * size)
            for relative in range(0, size, unit):
                segment = bytes(corrupted[relative : relative + unit])
                changed = _corrupt_torn_bytes(
                    segment,
                    operation["erase_index"],
                    offset + relative,
                    corruption_seed,
                )
                corrupted[relative : relative + len(changed)] = changed
            corrupted = bytes(corrupted)
        else:
            corrupted = _corrupt_erased_span(
                size,
                fill_byte,
                operation["erase_index"],
                offset,
                corruption_seed,
                operation["writes_at_this_point"],
                unit,
            )
        return state.write(
            region_name, offset, corrupted, clear_uncorrectable=True
        )
    if mode == "partial_bits":
        unit = max(1, min(8, int(program_unit)))
        previous = bytearray(state.read(region_name, offset, size))
        for relative in range(0, size, unit):
            width = min(unit, size - relative)
            old_value = _little_endian_value(previous[relative : relative + width])
            erased_value = sum(fill_byte << (8 * index) for index in range(width))
            partial = _partial_bit_value(
                old_value,
                erased_value,
                width,
                corruption_seed,
                operation["erase_index"],
                offset + relative,
                0x45524153,
            )
            previous[relative : relative + width] = _little_endian_bytes(
                partial, width
            )
        return state.write(
            region_name, offset, bytes(previous), clear_uncorrectable=True
        )
    if mode == "fixed":
        if str(backend_kind).lower() == "cfi":
            return state
        mode = "half"
    half = size // 2
    if half <= 0 and size > 0:
        half = size
    return state.write(
        region_name,
        offset,
        bytes(bytearray((fill_byte,) * half)),
        clear_uncorrectable=True,
    )


def apply_interrupted_operation(
    state,
    operation,
    fault_type="power_loss",
    backend_kind="flash",
    torn_word_mode="half",
    erase_fill=0xFF,
    corruption_seed=0,
    total_erases=0,
    page_size=4096,
    program_unit=4,
):
    operation = _normalize_operation(operation, sequence=operation.get("sequence"))
    if operation["kind"] == "write":
        return _apply_write_fault(
            state,
            operation,
            fault_type,
            backend_kind,
            torn_word_mode,
            erase_fill,
            corruption_seed,
            total_erases,
            page_size,
        )
    return _apply_erase_fault(
        state,
        operation,
        fault_type,
        backend_kind,
        torn_word_mode,
        erase_fill,
        corruption_seed,
        program_unit,
    )


class RecoveryStateComputer(object):
    """Iteratively compute every cut state from one uncut recovery trace."""

    def __init__(
        self,
        initial_state,
        operations,
        fault_type="power_loss",
        backend_kind="flash",
        torn_word_mode="half",
        erase_fill=0xFF,
        corruption_seed=0,
        page_size=4096,
        program_unit=4,
    ):
        self.initial_state = initial_state
        self.operations = tuple(
            _normalize_operation(operation, sequence=index)
            for index, operation in enumerate(operations)
        )
        self.fault_type = fault_type
        self.backend_kind = backend_kind
        self.torn_word_mode = torn_word_mode
        self.erase_fill = int(erase_fill) & 0xFF
        self.corruption_seed = int(corruption_seed) & 0xFFFFFFFF
        self.page_size = int(page_size)
        self.program_unit = int(program_unit)

    def iter_cut_states(self):
        prefix = self.initial_state
        completed_erases = 0
        for operation in self.operations:
            candidate = apply_interrupted_operation(
                prefix,
                operation,
                fault_type=self.fault_type,
                backend_kind=self.backend_kind,
                torn_word_mode=self.torn_word_mode,
                erase_fill=self.erase_fill,
                corruption_seed=self.corruption_seed,
                total_erases=completed_erases,
                page_size=self.page_size,
                program_unit=self.program_unit,
            )
            yield operation, candidate
            prefix = apply_completed_operation(
                prefix, operation, erase_fill=self.erase_fill
            )
            if operation["kind"] == "erase":
                completed_erases += 1

    def final_state(self):
        state = self.initial_state
        for operation in self.operations:
            state = apply_completed_operation(state, operation, erase_fill=self.erase_fill)
        return state
