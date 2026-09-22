"""Validate the address layout used by a runtime fault campaign.

The module deliberately uses only the Python standard library and syntax
accepted by IronPython 2.7 so that the same checks can run on the host and
inside Renode.

The version 1 plan format is::

    {
        "version": 1,
        "nvm": {"base": 0x08000000, "size": 0x100000},
        "bootloader": {"elf": "bootloader.elf"},
        "slots": {
            "A": {"base": 0x08020000, "size": 0x20000,
                  "write_full": False},
        },
        "metadata": [{"name": "boot metadata", "base": ..., "size": ...}],
        "loads": [{"name": "slot A image", "path": "a.bin",
                   "address": 0x08020000, "slot": "A"}],
    }

All intervals are half-open.  ``parse_elf_load_intervals`` reports a PT_LOAD
segment's VMA using ``p_memsz``.  When its physical address differs, it also
reports the distinct LMA bytes backed by the file using ``p_filesz``.
"""

import os
import struct


try:
    integer_types = (int, long)  # noqa: F821 - defined by Python 2/IronPython
except NameError:  # pragma: no cover - exercised by Python 3 imports
    integer_types = (int,)

try:
    string_types = (basestring,)  # noqa: F821 - Python 2/IronPython
except NameError:  # pragma: no cover - exercised by Python 3 imports
    string_types = (str,)


PT_LOAD = 1
MAX_ADDRESS_END = 1 << 64


class LayoutValidationError(ValueError):
    """The ELF or declarative load plan is unsafe or malformed."""


def format_interval(region):
    """Return a stable, human-readable name and half-open hex interval."""

    return "%s [0x%x, 0x%x)" % (
        region["name"],
        region["start"],
        region["end"],
    )


def _byte_value(value):
    if isinstance(value, integer_types):
        return value
    return ord(value)


def _read_exact(stream, offset, size, description):
    try:
        stream.seek(offset)
        data = stream.read(size)
    except (IOError, OSError) as exc:
        raise LayoutValidationError(
            "cannot read %s at file offset 0x%x: %s" % (description, offset, exc)
        )
    if len(data) != size:
        raise LayoutValidationError(
            "malformed ELF: truncated %s at file interval [0x%x, 0x%x)"
            % (description, offset, offset + size)
        )
    return data


def _checked_elf_end(start, size, address_bits, name):
    limit = 1 << address_bits
    if start < 0 or size < 0 or start > limit or size > limit - start:
        address_space = {
            "name": "%d-bit address space" % address_bits,
            "start": 0,
            "end": limit,
        }
        candidate = {"name": name, "start": start, "end": start + size}
        raise LayoutValidationError(
            "%s overflows %s"
            % (format_interval(candidate), format_interval(address_space))
        )
    return start + size


def parse_elf_load_intervals(path):
    """Return normalized VMA/LMA intervals for all non-empty PT_LOAD entries.

    The return value is a list of dictionaries containing ``name``, ``start``,
    ``end``, ``kind``, and ``segment_index``.  A malformed ELF, a truncated
    file-backed segment, or an ELF with no non-empty PT_LOAD intervals fails
    closed with :class:`LayoutValidationError`.
    """

    try:
        stream = open(path, "rb")
    except (IOError, OSError) as exc:
        raise LayoutValidationError("cannot open bootloader ELF %r: %s" % (path, exc))

    try:
        ident = _read_exact(stream, 0, 16, "ELF identification")
        if ident[0:4] != b"\x7fELF":
            raise LayoutValidationError("malformed ELF: invalid magic in %r" % path)

        elf_class = _byte_value(ident[4])
        elf_data = _byte_value(ident[5])
        ident_version = _byte_value(ident[6])
        if elf_class not in (1, 2):
            raise LayoutValidationError(
                "malformed ELF: unsupported class %d in %r" % (elf_class, path)
            )
        if elf_data not in (1, 2):
            raise LayoutValidationError(
                "malformed ELF: unsupported endianness %d in %r" % (elf_data, path)
            )
        if ident_version != 1:
            raise LayoutValidationError(
                "malformed ELF: unsupported identification version %d in %r"
                % (ident_version, path)
            )

        byte_order = "<" if elf_data == 1 else ">"
        if elf_class == 1:
            address_bits = 32
            header_format = byte_order + "HHIIIIIHHHHHH"
            program_format = byte_order + "IIIIIIII"
            expected_header_size = 52
            expected_program_size = 32
            phoff_index = 4
            ehsize_index = 7
            phentsize_index = 8
            phnum_index = 9
        else:
            address_bits = 64
            header_format = byte_order + "HHIQQQIHHHHHH"
            program_format = byte_order + "IIQQQQQQ"
            expected_header_size = 64
            expected_program_size = 56
            phoff_index = 4
            ehsize_index = 7
            phentsize_index = 8
            phnum_index = 9

        header_tail_size = struct.calcsize(header_format)
        header = struct.unpack(
            header_format,
            _read_exact(stream, 16, header_tail_size, "ELF header"),
        )
        if header[2] != 1:
            raise LayoutValidationError(
                "malformed ELF: unsupported header version %d in %r"
                % (header[2], path)
            )

        program_offset = header[phoff_index]
        elf_header_size = header[ehsize_index]
        program_entry_size = header[phentsize_index]
        program_count = header[phnum_index]

        if elf_header_size < expected_header_size:
            raise LayoutValidationError(
                "malformed ELF: header size %d is smaller than %d"
                % (elf_header_size, expected_header_size)
            )
        if program_count == 0:
            raise LayoutValidationError("ELF %r has no PT_LOAD intervals" % path)
        if program_count == 0xFFFF:
            raise LayoutValidationError(
                "malformed ELF: extended program-header numbering is unsupported"
            )
        if program_entry_size < expected_program_size:
            raise LayoutValidationError(
                "malformed ELF: program-header size %d is smaller than %d"
                % (program_entry_size, expected_program_size)
            )

        file_size = os.fstat(stream.fileno()).st_size
        table_size = program_entry_size * program_count
        if program_offset > file_size or table_size > file_size - program_offset:
            raise LayoutValidationError(
                "malformed ELF: program header table file interval "
                "[0x%x, 0x%x) exceeds file interval [0x0, 0x%x)"
                % (program_offset, program_offset + table_size, file_size)
            )

        intervals = []
        for index in range(program_count):
            entry_offset = program_offset + index * program_entry_size
            raw = _read_exact(
                stream,
                entry_offset,
                expected_program_size,
                "program header %d" % index,
            )
            entry = struct.unpack(program_format, raw)
            if elf_class == 1:
                (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
                 _p_flags, _p_align) = entry
            else:
                (p_type, _p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
                 p_memsz, _p_align) = entry

            if p_type != PT_LOAD:
                continue
            if p_filesz > p_memsz:
                raise LayoutValidationError(
                    "malformed ELF: PT_LOAD[%d] p_filesz 0x%x exceeds p_memsz 0x%x"
                    % (index, p_filesz, p_memsz)
                )
            if p_offset > file_size or p_filesz > file_size - p_offset:
                raise LayoutValidationError(
                    "malformed ELF: PT_LOAD[%d] file interval [0x%x, 0x%x) "
                    "exceeds file interval [0x0, 0x%x)"
                    % (index, p_offset, p_offset + p_filesz, file_size)
                )

            if p_memsz:
                vma_name = "bootloader PT_LOAD[%d] VMA" % index
                intervals.append({
                    "name": vma_name,
                    "start": p_vaddr,
                    "end": _checked_elf_end(
                        p_vaddr, p_memsz, address_bits, vma_name
                    ),
                    "kind": "vma",
                    "segment_index": index,
                })

            if p_paddr != p_vaddr and p_filesz:
                lma_name = "bootloader PT_LOAD[%d] LMA" % index
                intervals.append({
                    "name": lma_name,
                    "start": p_paddr,
                    "end": _checked_elf_end(
                        p_paddr, p_filesz, address_bits, lma_name
                    ),
                    "kind": "lma",
                    "segment_index": index,
                })

        if not intervals:
            raise LayoutValidationError("ELF %r has no PT_LOAD intervals" % path)
        return intervals
    finally:
        stream.close()


def _as_integer(value, label):
    if isinstance(value, bool) or not isinstance(value, integer_types):
        raise LayoutValidationError("%s must be an integer" % label)
    return value


def _region(name, definition, base_key="base", size_key="size"):
    if not isinstance(definition, dict):
        raise LayoutValidationError("%s must be a mapping" % name)
    if base_key not in definition or size_key not in definition:
        raise LayoutValidationError(
            "%s must define %s and %s" % (name, base_key, size_key)
        )
    start = _as_integer(definition[base_key], "%s.%s" % (name, base_key))
    size = _as_integer(definition[size_key], "%s.%s" % (name, size_key))
    if start < 0 or size <= 0:
        raise LayoutValidationError(
            "%s requires a non-negative base and a positive size" % name
        )
    candidate = {"name": name, "start": start, "end": start + size}
    if start >= MAX_ADDRESS_END or size > MAX_ADDRESS_END - start:
        address_space = {
            "name": "64-bit address space",
            "start": 0,
            "end": MAX_ADDRESS_END,
        }
        raise LayoutValidationError(
            "%s overflows %s"
            % (format_interval(candidate), format_interval(address_space))
        )
    return candidate


def _overlaps(left, right):
    return left["start"] < right["end"] and right["start"] < left["end"]


def _contains(outer, inner):
    return outer["start"] <= inner["start"] and inner["end"] <= outer["end"]


def _require_inside(inner, outer):
    if not _contains(outer, inner):
        raise LayoutValidationError(
            "%s is outside %s"
            % (format_interval(inner), format_interval(outer))
        )


def _reject_overlap(left, right):
    if _overlaps(left, right):
        raise LayoutValidationError(
            "%s overlaps %s"
            % (format_interval(left), format_interval(right))
        )


def _validate_disjoint(regions):
    for left_index in range(len(regions)):
        for right_index in range(left_index + 1, len(regions)):
            _reject_overlap(regions[left_index], regions[right_index])


def _covered_by_bounds(region, bounds):
    """Return whether sorted bounds cover every byte of *region*."""

    cursor = region["start"]
    for bound in bounds:
        if bound["end"] <= cursor:
            continue
        if bound["start"] > cursor:
            return False
        cursor = max(cursor, bound["end"])
        if cursor >= region["end"]:
            return True
    return False


def _merge_intervals(regions):
    merged = []
    for region in sorted(regions, key=lambda item: (item["start"], item["end"])):
        if not merged or region["start"] > merged[-1]["end"]:
            merged.append({"start": region["start"], "end": region["end"]})
        else:
            merged[-1]["end"] = max(merged[-1]["end"], region["end"])
    return merged


def validate_ownership_plan(plan):
    """Normalize and validate durable byte ownership for a profile.

    Physical erase geometry is supplied as ``bounds`` but is not itself an
    owner.  Declared owners may overlap only through an explicit parent chain;
    peers remain disjoint.  The returned ``write_ranges`` are the exact union
    consumed by the runtime ``no_oob_writes`` invariant.
    """

    if not isinstance(plan, dict):
        raise LayoutValidationError("ownership plan must be a mapping")
    if plan.get("version") != 1:
        raise LayoutValidationError(
            "unsupported ownership plan version %r (expected 1)"
            % plan.get("version")
        )
    complete = plan.get("complete", False)
    if not isinstance(complete, bool):
        raise LayoutValidationError("ownership plan complete must be a boolean")

    raw_bounds = plan.get("bounds", [])
    if not isinstance(raw_bounds, list):
        raise LayoutValidationError("ownership plan bounds must be a list")
    bounds = []
    for index, definition in enumerate(raw_bounds):
        name = "ownership bound %d" % index
        if isinstance(definition, dict) and definition.get("name"):
            name = "ownership bound %s" % definition.get("name")
        bounds.append(_region(name, definition))
    bounds.sort(key=lambda item: (item["start"], item["end"]))
    _validate_disjoint(bounds)
    if complete and not bounds:
        raise LayoutValidationError(
            "complete ownership manifest requires memory.erase_regions bounds"
        )

    raw_geometry = plan.get("geometry", [])
    if not isinstance(raw_geometry, list):
        raise LayoutValidationError("ownership plan geometry must be a list")
    geometry = []
    for index, definition in enumerate(raw_geometry):
        name = "ownership geometry %d" % index
        if isinstance(definition, dict) and definition.get("name"):
            name = "ownership geometry %s" % definition.get("name")
        geometry.append(_region(name, definition))
    geometry.sort(key=lambda item: (item["start"], item["end"]))
    _validate_disjoint(geometry)
    if bounds:
        for region in geometry:
            if not _covered_by_bounds(region, bounds):
                raise LayoutValidationError(
                    "%s is outside declared durable-memory bounds"
                    % format_interval(region)
                )

    raw_regions = plan.get("regions", [])
    if not isinstance(raw_regions, list):
        raise LayoutValidationError("ownership plan regions must be a list")
    regions = []
    by_id = {}
    for index, definition in enumerate(raw_regions):
        if not isinstance(definition, dict):
            raise LayoutValidationError(
                "ownership plan regions[%d] must be a mapping" % index
            )
        owner_id = definition.get("id")
        if not isinstance(owner_id, string_types) or not owner_id.strip():
            raise LayoutValidationError(
                "ownership plan regions[%d].id must be non-empty" % index
            )
        owner_id = owner_id.strip()
        if owner_id in by_id:
            raise LayoutValidationError("duplicate ownership id %r" % owner_id)
        kind = definition.get("kind")
        if not isinstance(kind, string_types) or not kind.strip():
            raise LayoutValidationError(
                "ownership plan region %s.kind must be non-empty" % owner_id
            )
        parent = definition.get("parent")
        if parent is not None:
            if not isinstance(parent, string_types) or not parent.strip():
                raise LayoutValidationError(
                    "ownership plan region %s.parent must be non-empty" % owner_id
                )
            parent = parent.strip()
        interval = _region(
            "owner %s" % owner_id,
            definition,
            base_key="base",
            size_key="size",
        )
        interval.update({
            "id": owner_id,
            "kind": kind.strip(),
            "parent": parent,
        })
        regions.append(interval)
        by_id[owner_id] = interval

    if complete and not regions:
        raise LayoutValidationError(
            "complete ownership manifest must declare at least one owner"
        )

    for region in regions:
        parent_id = region.get("parent")
        if parent_id is None:
            continue
        if parent_id not in by_id:
            raise LayoutValidationError(
                "owner %s names unknown parent %s" % (region["id"], parent_id)
            )
        if parent_id == region["id"]:
            raise LayoutValidationError("owner %s cannot contain itself" % region["id"])
        _require_inside(region, by_id[parent_id])

    def ancestor(ancestor_id, child_id):
        seen = set()
        cursor = by_id[child_id].get("parent")
        while cursor is not None:
            if cursor in seen:
                raise LayoutValidationError(
                    "ownership parent cycle includes %s" % cursor
                )
            seen.add(cursor)
            if cursor == ancestor_id:
                return True
            cursor = by_id[cursor].get("parent")
        return False

    # Traverse every chain once so a cycle is rejected even when no overlapping
    # pair happens to query it.
    for region in regions:
        ancestor("__no_such_owner__", region["id"])

    for left_index in range(len(regions)):
        for right_index in range(left_index + 1, len(regions)):
            left = regions[left_index]
            right = regions[right_index]
            if not _overlaps(left, right):
                continue
            if ancestor(left["id"], right["id"]) or ancestor(
                right["id"], left["id"]
            ):
                continue
            raise LayoutValidationError(
                "%s overlaps peer %s without explicit containment"
                % (format_interval(left), format_interval(right))
            )

    if bounds:
        for region in regions:
            if not _covered_by_bounds(region, bounds):
                raise LayoutValidationError(
                    "%s is outside declared durable-memory bounds"
                    % format_interval(region)
                )

    normalized_regions = sorted(
        regions, key=lambda item: (item["start"], item["end"], item["id"])
    )
    return {
        "version": 1,
        "complete": complete,
        "status": "assessed" if complete else "not_assessed",
        "reason": (
            None
            if complete
            else "ownership manifest completeness was not asserted"
        ),
        "bounds": bounds,
        "geometry": geometry,
        "regions": normalized_regions,
        "write_ranges": _merge_intervals(normalized_regions),
    }


def validate_load_plan(plan):
    """Validate and normalize a version 1 declarative load plan.

    Returns a dictionary of normalized half-open regions.  The caller may use
    these returned addresses for debug reads and image loading, avoiding a
    second source of address constants.
    """

    if not isinstance(plan, dict):
        raise LayoutValidationError("load plan must be a mapping")
    if plan.get("version") != 1:
        raise LayoutValidationError(
            "unsupported load plan version %r (expected 1)" % plan.get("version")
        )

    nvm = _region("nvm", plan.get("nvm"))

    bootloader = plan.get("bootloader")
    if not isinstance(bootloader, dict):
        raise LayoutValidationError("bootloader must be a mapping")
    elf_path = bootloader.get("elf")
    if not isinstance(elf_path, string_types) or not elf_path:
        raise LayoutValidationError("bootloader.elf must be a non-empty path")
    boot_intervals = parse_elf_load_intervals(elf_path)

    slot_definitions = plan.get("slots")
    if not isinstance(slot_definitions, dict) or not slot_definitions:
        raise LayoutValidationError("slots must be a non-empty mapping")
    slots = {}
    full_writes = []
    for slot_name in sorted(slot_definitions):
        definition = slot_definitions[slot_name]
        region = _region("slot %s" % slot_name, definition)
        _require_inside(region, nvm)
        slots[slot_name] = region
        write_full = definition.get("write_full", False)
        if not isinstance(write_full, bool):
            raise LayoutValidationError(
                "slot %s.write_full must be a boolean" % slot_name
            )
        if write_full:
            full_writes.append({
                "name": "slot %s full write" % slot_name,
                "start": region["start"],
                "end": region["end"],
            })
    _validate_disjoint([slots[name] for name in sorted(slots)])

    metadata_definitions = plan.get("metadata", [])
    if not isinstance(metadata_definitions, list):
        raise LayoutValidationError("metadata must be a list")
    metadata = []
    for index, definition in enumerate(metadata_definitions):
        if not isinstance(definition, dict):
            raise LayoutValidationError("metadata[%d] must be a mapping" % index)
        metadata_name = definition.get("name", "metadata[%d]" % index)
        if not isinstance(metadata_name, string_types) or not metadata_name:
            raise LayoutValidationError("metadata[%d].name must be non-empty" % index)
        region = _region("metadata %s" % metadata_name, definition)
        _require_inside(region, nvm)
        metadata.append(region)
    _validate_disjoint(metadata)
    for slot_name in sorted(slots):
        for metadata_region in metadata:
            _reject_overlap(slots[slot_name], metadata_region)

    load_definitions = plan.get("loads", [])
    if not isinstance(load_definitions, list):
        raise LayoutValidationError("loads must be a list")
    loads = []
    for index, definition in enumerate(load_definitions):
        if not isinstance(definition, dict):
            raise LayoutValidationError("loads[%d] must be a mapping" % index)
        load_name = definition.get("name", "load[%d]" % index)
        if not isinstance(load_name, string_types) or not load_name:
            raise LayoutValidationError("loads[%d].name must be non-empty" % index)
        path = definition.get("path")
        if not isinstance(path, string_types) or not path:
            raise LayoutValidationError("load %s.path must be non-empty" % load_name)
        try:
            raw_size = os.path.getsize(path)
        except (IOError, OSError) as exc:
            raise LayoutValidationError(
                "cannot inspect load %s path %r: %s" % (load_name, path, exc)
            )
        # Renode's embedded IronPython can return a CLR integral value here.
        # Normalize it inside this module before the strict region validator;
        # values supplied by a load plan remain subject to exact type checks.
        try:
            size = int(str(raw_size), 10)
        except (TypeError, ValueError, OverflowError):
            raise LayoutValidationError(
                "load %s path %r returned a non-integer size" % (load_name, path)
            )
        load_region = _region(
            "load %s" % load_name,
            {"address": definition.get("address"), "size": size},
            base_key="address",
        )
        _require_inside(load_region, nvm)

        declared_slot = definition.get("slot")
        if declared_slot is not None:
            if declared_slot not in slots:
                raise LayoutValidationError(
                    "load %s names unknown slot %r" % (load_name, declared_slot)
                )
            _require_inside(load_region, slots[declared_slot])
        loads.append(load_region)

    write_regions = metadata + full_writes + loads
    for write_region in write_regions:
        for boot_interval in boot_intervals:
            _reject_overlap(write_region, boot_interval)

    # A boot interval wholly outside NVM may be a RAM VMA.  An interval that
    # straddles an NVM boundary is always an invalid physical layout.
    for boot_interval in boot_intervals:
        if _overlaps(boot_interval, nvm) and not _contains(nvm, boot_interval):
            _require_inside(boot_interval, nvm)

    return {
        "version": 1,
        "nvm": nvm,
        "bootloader": boot_intervals,
        "slots": slots,
        "metadata": metadata,
        "loads": loads,
        "writes": write_regions,
    }
