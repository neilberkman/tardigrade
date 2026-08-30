"""Persistent security-state erase-unit analysis and semantic cutpoints.

This module deliberately has no runtime fault implementation.  It describes
the physical erase domains declared by a profile and turns calibration
operations into ordinary power-loss cutpoints with an explanatory wire label.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


MAX_ADDRESS = 1 << 64
SECURITY_ROLES = frozenset(
    ("security_monotonic", "security_authorization", "security_secret")
)
ALL_ROLES = SECURITY_ROLES | frozenset(("recovery", "mutable"))


class SecurityStateLayoutError(ValueError):
    """A persistent-state erase layout cannot be mapped safely."""


def _integer(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise SecurityStateLayoutError("{} must be an integer".format(context))
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise SecurityStateLayoutError("{} must be an integer".format(context))


def _end(start: int, size: int, context: str) -> int:
    if start < 0 or size <= 0:
        raise SecurityStateLayoutError(
            "{} requires a non-negative address and a positive size".format(context)
        )
    if start >= MAX_ADDRESS or size > MAX_ADDRESS - start:
        raise SecurityStateLayoutError(
            "{} interval [0x{:x}, 0x{:x}) overflows the 64-bit address space".format(
                context, start, start + size
            )
        )
    return start + size


@dataclass(frozen=True)
class EraseRegion:
    start: int
    end: int
    erase_size: int

    @property
    def units(self) -> Tuple[Tuple[int, int], ...]:
        return tuple(
            (self.start + offset, self.start + offset + self.erase_size)
            for offset in range(0, self.end - self.start, self.erase_size)
        )


@dataclass(frozen=True)
class PersistentField:
    name: str
    base: int
    size: int
    role: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class PhysicalEraseUnit:
    start: int
    end: int
    region_index: int

    def as_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "end": self.end, "region_index": self.region_index}


@dataclass(frozen=True)
class PersistentStateLayout:
    erase_regions: Tuple[EraseRegion, ...]
    fields: Tuple[PersistentField, ...]

    @property
    def units(self) -> Tuple[PhysicalEraseUnit, ...]:
        result: List[PhysicalEraseUnit] = []
        for index, region in enumerate(self.erase_regions):
            result.extend(
                PhysicalEraseUnit(start, end, index)
                for start, end in region.units
            )
        return tuple(result)

    def units_for_field(self, field: PersistentField) -> Tuple[PhysicalEraseUnit, ...]:
        hits = tuple(
            unit for unit in self.units
            if unit.start < field.end and field.base < unit.end
        )
        if not hits:
            raise SecurityStateLayoutError(
                "field {!r} does not map to a physical erase unit".format(field.name)
            )
        cursor = field.base
        for unit in hits:
            if unit.start > cursor:
                raise SecurityStateLayoutError(
                    "field {!r} crosses an erase-region gap".format(field.name)
                )
            cursor = max(cursor, unit.end)
        if cursor < field.end:
            raise SecurityStateLayoutError(
                "field {!r} is not fully contained in declared erase regions".format(
                    field.name
                )
            )
        region_indexes = {unit.region_index for unit in hits}
        if len(region_indexes) > 1:
            regions = [self.erase_regions[index] for index in sorted(region_indexes)]
            if len({region.erase_size for region in regions}) != 1:
                raise SecurityStateLayoutError(
                    "field {!r} crosses erase regions with conflicting geometry".format(
                        field.name
                    )
                )
        return hits

    def resident_fields(self, unit: PhysicalEraseUnit) -> Tuple[PersistentField, ...]:
        return tuple(
            field for field in self.fields
            if unit.start < field.end and field.base < unit.end
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "erase_regions": [
                {"start": r.start, "end": r.end, "erase_size": r.erase_size}
                for r in self.erase_regions
            ],
            "fields": [
                {"name": f.name, "base": f.base, "size": f.size, "role": f.role}
                for f in self.fields
            ],
        }


def _overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def parse_persistent_state_layout(raw: Optional[Dict[str, Any]]) -> Optional[PersistentStateLayout]:
    """Parse and validate the optional ``persistent_state_layout`` block."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SecurityStateLayoutError("persistent_state_layout: expected mapping")
    unknown = sorted(set(raw) - {"erase_regions", "fields"})
    if unknown:
        raise SecurityStateLayoutError(
            "persistent_state_layout: unknown key(s): {}".format(", ".join(unknown))
        )
    raw_regions = raw.get("erase_regions")
    raw_fields = raw.get("fields")
    if not isinstance(raw_regions, list) or not raw_regions:
        raise SecurityStateLayoutError(
            "persistent_state_layout.erase_regions: expected non-empty list"
        )
    if not isinstance(raw_fields, list):
        raise SecurityStateLayoutError(
            "persistent_state_layout.fields: expected list"
        )

    regions: List[EraseRegion] = []
    previous_start = -1
    previous_end = -1
    for index, item in enumerate(raw_regions):
        context = "persistent_state_layout.erase_regions[{}]".format(index)
        if not isinstance(item, dict):
            raise SecurityStateLayoutError("{}: expected mapping".format(context))
        for key in ("start", "end", "erase_size"):
            if key not in item:
                raise SecurityStateLayoutError("{}.{}: missing required field".format(context, key))
        start = _integer(item["start"], context + ".start")
        end = _integer(item["end"], context + ".end")
        erase_size = _integer(item["erase_size"], context + ".erase_size")
        if start < 0 or end <= start:
            raise SecurityStateLayoutError("{} must have end > start".format(context))
        if end > MAX_ADDRESS:
            raise SecurityStateLayoutError("{}.end exceeds 64-bit address space".format(context))
        if erase_size <= 0:
            raise SecurityStateLayoutError("{}.erase_size must be positive".format(context))
        if (end - start) % erase_size:
            raise SecurityStateLayoutError(
                "{} interval length must be exactly divisible by erase_size".format(context)
            )
        if start <= previous_start or start < previous_end:
            raise SecurityStateLayoutError(
                "{} must be ordered and non-overlapping".format(context)
            )
        regions.append(EraseRegion(start, end, erase_size))
        previous_start, previous_end = start, end

    fields: List[PersistentField] = []
    field_names = set()
    for index, item in enumerate(raw_fields):
        context = "persistent_state_layout.fields[{}]".format(index)
        if not isinstance(item, dict):
            raise SecurityStateLayoutError("{}: expected mapping".format(context))
        for key in ("name", "base", "size", "role"):
            if key not in item:
                raise SecurityStateLayoutError("{}.{}: missing required field".format(context, key))
        name = str(item["name"]).strip()
        if not name:
            raise SecurityStateLayoutError("{}.name must be non-empty".format(context))
        if name in field_names:
            raise SecurityStateLayoutError("duplicate persistent field name {!r}".format(name))
        base = _integer(item["base"], context + ".base")
        size = _integer(item["size"], context + ".size")
        end = _end(base, size, context)
        role = str(item["role"]).strip()
        if role not in ALL_ROLES:
            raise SecurityStateLayoutError(
                "{}.role {!r} is unsupported; expected one of {}".format(
                    context, role, ", ".join(sorted(ALL_ROLES))
                )
            )
        field = PersistentField(name, base, size, role)
        for prior in fields:
            if _overlap(prior.base, prior.end, field.base, field.end):
                raise SecurityStateLayoutError(
                    "field {!r} overlaps field {!r}".format(field.name, prior.name)
                )
        fields.append(field)
        field_names.add(name)

    layout = PersistentStateLayout(tuple(regions), tuple(fields))
    for field in layout.fields:
        layout.units_for_field(field)
    return layout


def analyze_persistent_state_layout(layout: Optional[PersistentStateLayout]) -> Dict[str, Any]:
    """Return physical-unit mappings and candidate shared-unit findings."""
    if layout is None:
        return {"status": "unavailable", "units": [], "fields": [], "findings": []}
    field_units: Dict[str, List[PhysicalEraseUnit]] = {
        field.name: list(layout.units_for_field(field)) for field in layout.fields
    }
    units: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    for unit in layout.units:
        resident = list(layout.resident_fields(unit))
        unit_fields = [field.name for field in resident]
        units.append({**unit.as_dict(), "fields": unit_fields})
        security = [field for field in resident if field.role in SECURITY_ROLES]
        other = [field for field in resident if field.role in ("mutable", "recovery")]
        if security and other:
            findings.append(
                {
                    "code": "SECURITY_STATE_SHARED_ERASE_UNIT",
                    "candidate": True,
                    "unit": {"start": unit.start, "end": unit.end},
                    "fields": [
                        {"name": field.name, "base": field.base, "size": field.size, "role": field.role}
                        for field in resident
                    ],
                    "message": (
                        "security-role and mutable/recovery fields share physical "
                        "erase unit [0x{:x}, 0x{:x}); runtime campaign determines "
                        "whether the coupling is exploitable".format(unit.start, unit.end)
                    ),
                }
            )
    return {
        "status": "analyzed",
        "units": units,
        "fields": [
            {
                "name": field.name,
                "base": field.base,
                "end": field.end,
                "size": field.size,
                "role": field.role,
                "units": [{"start": unit.start, "end": unit.end} for unit in field_units[field.name]],
            }
            for field in layout.fields
        ],
        "findings": findings,
    }


def _trace_address(
    offset: int,
    flash_base: int,
    layout: PersistentStateLayout,
    trace_address_map: Optional[Sequence[Dict[str, int]]] = None,
) -> int:
    """Accept the historical relative trace offset and absolute traces."""
    offset = int(offset)
    candidate = int(flash_base) + offset
    # Keep this in lockstep with trace_utils._trace_absolute_address: mapped
    # ranges describe the backend's trace coordinate and their addend selects
    # the CPU-visible alias.  Unmapped traces retain the historical base.
    for mapping in trace_address_map or ():
        if int(mapping["offset_start"]) <= offset < int(mapping["offset_end"]):
            candidate = int(mapping["address_addend"]) + offset
            break
    if any(unit.start <= candidate < unit.end for unit in layout.units):
        return candidate
    if any(unit.start <= offset < unit.end for unit in layout.units):
        return offset
    return candidate


def select_security_state_erase_cutpoints(
    layout: Optional[PersistentStateLayout],
    write_entries: Sequence[Dict[str, Any]],
    erase_entries: Sequence[Dict[str, Any]],
    *,
    flash_base: int = 0,
    max_writes: Optional[int] = None,
    trace_address_map: Optional[Sequence[Dict[str, int]]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Select semantic cuts for flagged units from calibration traces.

    The returned records use ordinary write-index power-loss semantics.  Their
    ``wire_type`` carries the phase and physical unit for reporting.
    """
    analysis = analyze_persistent_state_layout(layout)
    if layout is None:
        return [], {"status": "unavailable", "reason": "persistent_state_layout is not declared"}
    flagged = [
        unit for unit in layout.units
        if any(
            field.role in SECURITY_ROLES
            for field in layout.resident_fields(unit)
        ) and any(
            field.role in ("mutable", "recovery")
            for field in layout.resident_fields(unit)
        )
    ]
    if not flagged:
        return [], {"status": "clean", "source": "layout", "cutpoints": []}

    writes = sorted(write_entries, key=lambda item: int(item.get("write_index", 0)))
    unit_erase: Dict[Tuple[int, int], int] = {}
    if erase_entries:
        for entry in erase_entries:
            start = _trace_address(
                int(entry.get("flash_offset", entry.get("offset", 0))),
                flash_base,
                layout,
                trace_address_map,
            )
            size = int(entry.get("erase_size", 0) or 0)
            candidates = [unit for unit in layout.units if unit.start <= start < unit.end]
            matched = list(candidates)
            if size:
                matched = [unit for unit in matched if unit.start == start and unit.end - unit.start == size]
            if not matched:
                declared = candidates[0] if candidates else None
                declared_text = (
                    "; declared unit [0x{:x}, 0x{:x})".format(declared.start, declared.end)
                    if declared is not None else ""
                )
                raise SecurityStateLayoutError(
                    "trace erase [0x{:x}, 0x{:x}) disagrees with declared erase geometry{}".format(
                        start, start + size, declared_text
                    )
                )
            unit = matched[0]
            if size and (start != unit.start or start + size != unit.end):
                raise SecurityStateLayoutError(
                    "trace erase [0x{:x}, 0x{:x}) disagrees with declared unit [0x{:x}, 0x{:x})".format(
                        start, start + size, unit.start, unit.end
                    )
                )
            writes_at = entry.get("writes_at_this_point")
            if writes_at is not None:
                unit_erase[(unit.start, unit.end)] = int(writes_at)
    source = "erase_trace" if erase_entries else "declared_geometry"
    if erase_entries and not unit_erase:
        raise SecurityStateLayoutError(
            "calibration erase trace has no write boundaries for security erase units"
        )

    cutpoints: List[Dict[str, Any]] = []
    for unit in flagged:
        key = (unit.start, unit.end)
        unit_writes = [
            entry for entry in writes
            if unit.start <= _trace_address(
                int(entry.get("flash_offset", 0)),
                flash_base,
                layout,
                trace_address_map,
            ) < unit.end
        ]
        erase_at = unit_erase.get(key)
        if erase_at is None:
            if unit_writes:
                # Calibration write indexes are one-based; fault_at is the
                # zero-based interrupted-write index.
                erase_at = int(unit_writes[0].get("write_index", 1)) - 1
            elif max_writes:
                erase_at = 0
            else:
                raise SecurityStateLayoutError(
                    "no calibration operation identifies flagged erase unit [0x{:x}, 0x{:x})".format(*key)
                )
        erase_write_count = int(erase_at)
        if key in unit_erase:
            erase_write_count = int(unit_erase[key])
        after_erase = [
            entry for entry in unit_writes
            if int(entry.get("write_index", 0)) > erase_write_count
        ]
        first_entry = (after_erase or unit_writes or [{"write_index": erase_write_count + 1}])[0]
        erase_fault_at = (
            # An erase recorded after N successful writes is observed before
            # write N+1.  The runtime's zero-based fault_at=N interrupts that
            # next write after replay has applied the erase.
            max(0, erase_write_count)
            if key in unit_erase else int(erase_at)
        )
        first = int(first_entry.get("write_index", erase_write_count + 1)) - 1
        cutpoints.append({"fault_at": erase_fault_at, "phase": "erase", "unit": {"start": unit.start, "end": unit.end}})
        cutpoints.append({"fault_at": first, "phase": "first_write_after_erase", "unit": {"start": unit.start, "end": unit.end}})
        for field in layout.resident_fields(unit):
            if field.role not in SECURITY_ROLES:
                continue
            field_writes = [
                entry for entry in unit_writes
                if field.base <= _trace_address(
                    int(entry.get("flash_offset", 0)),
                    flash_base,
                    layout,
                    trace_address_map,
                ) < field.end
            ]
            if not field_writes:
                if max_writes:
                    last = max(0, int(max_writes) - 1)
                else:
                    raise SecurityStateLayoutError(
                        "calibration write trace does not restore security field {!r}".format(field.name)
                    )
            else:
                last = int(field_writes[-1].get("write_index", 1)) - 1
            cutpoints.append({"fault_at": last, "phase": "last_security_restore", "field": field.name, "unit": {"start": unit.start, "end": unit.end}})

    unique: List[Dict[str, Any]] = []
    seen: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for point in sorted(cutpoints, key=lambda item: (item["fault_at"], item["unit"]["start"], item["phase"], item.get("field", ""))):
        # A power cut is physically identified by its zero-based point and
        # erase unit.  Do not schedule multiple runs merely because labels
        # describe the same cut; retain all semantic phases on one record.
        key = (point["fault_at"], point["unit"]["start"])
        prior = seen.get(key)
        if prior is not None:
            prior.setdefault("phases", [prior["phase"]])
            if point["phase"] not in prior["phases"]:
                prior["phases"].append(point["phase"])
            if point.get("field"):
                prior.setdefault("fields", [])
                if point["field"] not in prior["fields"]:
                    prior["fields"].append(point["field"])
            prior["wire_type"] = "w:ss:{}:0x{:x}{}".format(
                "+".join(prior["phases"]), prior["unit"]["start"],
                ":{}".format("+".join(prior.get("fields", [])))
                if prior.get("fields") else "",
            )
            continue
        point["phases"] = [point["phase"]]
        if point.get("field"):
            point["fields"] = [point["field"]]
        point["wire_type"] = "w:ss:{}:0x{:x}{}".format(
            point["phase"], point["unit"]["start"],
            ":{}".format(point["field"]) if point.get("field") else "",
        )
        seen[key] = point
        unique.append(point)
    return unique, {
        "status": "selected",
        "source": source,
        "flagged_units": [{"start": unit.start, "end": unit.end} for unit in flagged],
        "cutpoints": unique,
        "analysis": analysis,
    }


# Friendly aliases for callers and offline tooling.
analyze_security_state_layout = analyze_persistent_state_layout
build_security_state_erase_cutpoints = select_security_state_erase_cutpoints


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print the static report without starting a runtime campaign."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Analyze persistent security erase domains")
    parser.add_argument("profile", help="profile YAML path")
    args = parser.parse_args(argv)
    try:
        # Import lazily so this module remains a dependency-free analyzer.
        from profile_loader import load_profile
        profile = load_profile(args.profile)
        print(json.dumps(analyze_persistent_state_layout(profile.persistent_state_layout), indent=2, sort_keys=True))
    except Exception as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
