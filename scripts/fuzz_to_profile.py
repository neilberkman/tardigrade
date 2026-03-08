#!/usr/bin/env python3
"""Convert AFL/libFuzzer crash inputs into tardigrade profile YAML files.

Usage::

    python3 fuzz_to_profile.py \\
        --crash-input crashes/id:000000 \\
        --template profiles/naive_bare_copy.yaml \\
        --address-map address_map.yaml \\
        --output profiles/fuzz_crash_000.yaml

The crash input is a raw binary file produced by a fuzzer.  The
*address map* describes how to partition the crash bytes into flash
memory regions so they become ``pre_boot_state`` writes in the
generated profile.

Address map format (YAML)::

    # Each region maps a named area to a flash address + size.
    # Crash bytes are consumed sequentially across regions in order.
    regions:
      - name: metadata
        address: 0x10070000
        size: 16           # consume first 16 bytes of crash input
      - name: header
        address: 0x10038000
        size: 32           # next 32 bytes go here

    # Optional: bytes beyond all regions are ignored.

If no address map is provided, all crash bytes are mapped starting at
the metadata base address derived from the template profile (same
heuristic as ``cbmc_to_profile.py``).
"""

from __future__ import annotations

import argparse
import copy
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit(
        "PyYAML is required for fuzz_to_profile.py (pip install pyyaml)."
    ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert AFL/libFuzzer crash inputs into tardigrade profiles."
    )
    parser.add_argument(
        "--crash-input", required=True,
        help="Path to raw binary crash file from the fuzzer.",
    )
    parser.add_argument(
        "--template", required=True,
        help="Template profile YAML to copy.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Output profile path.",
    )
    parser.add_argument(
        "--address-map", default="",
        help="Optional YAML file describing how crash bytes map to flash regions.",
    )
    parser.add_argument(
        "--meta-base",
        type=lambda v: int(v, 0),
        default=None,
        help="Metadata base address override (e.g. 0x10070000). "
             "Used when no address map is provided.",
    )
    parser.add_argument(
        "--name-suffix", default="",
        help="Optional suffix appended to the profile name.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Address-map loading
# ---------------------------------------------------------------------------

def _load_region_map(path: Optional[str]) -> List[Dict[str, Any]]:
    """Load a region-based address map.

    Returns a list of ``{"name": str, "address": int, "size": int}`` dicts
    describing how to consume sequential crash bytes, or an empty list if
    no map is provided.
    """
    if not path:
        return []
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "regions" not in raw:
        raise RuntimeError(
            "Address map must be a YAML object with a 'regions' list."
        )
    regions_raw = raw["regions"]
    if not isinstance(regions_raw, list):
        raise RuntimeError("'regions' must be a list.")

    regions: List[Dict[str, Any]] = []
    for i, entry in enumerate(regions_raw):
        if not isinstance(entry, dict):
            raise RuntimeError("regions[{}]: expected a mapping.".format(i))
        name = str(entry.get("name", "region_{}".format(i)))
        addr = entry.get("address")
        size = entry.get("size")
        if addr is None or size is None:
            raise RuntimeError(
                "regions[{}] ('{}'): 'address' and 'size' are required.".format(i, name)
            )
        if isinstance(addr, str):
            addr = int(addr, 0)
        if isinstance(size, str):
            size = int(size, 0)
        regions.append({"name": name, "address": int(addr), "size": int(size)})
    return regions


# ---------------------------------------------------------------------------
# Meta-base derivation (same logic as cbmc_to_profile)
# ---------------------------------------------------------------------------

def _derive_meta_base(template: Dict[str, Any], override: Optional[int]) -> int:
    if override is not None:
        return override
    slots = (
        template.get("memory", {}).get("slots", {})
        if isinstance(template.get("memory"), dict)
        else {}
    )
    slot_ends: List[int] = []
    if isinstance(slots, dict):
        for entry in slots.values():
            if not isinstance(entry, dict):
                continue
            base = entry.get("base")
            size = entry.get("size")
            if base is None or size is None:
                continue
            b = int(base, 0) if isinstance(base, str) else int(base)
            s = int(size, 0) if isinstance(size, str) else int(size)
            slot_ends.append(b + s)
    if slot_ends:
        return max(slot_ends)
    return 0x10070000


# ---------------------------------------------------------------------------
# Crash bytes -> pre_boot_state
# ---------------------------------------------------------------------------

def _crash_bytes_to_writes_with_regions(
    data: bytes,
    regions: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Map crash bytes to pre_boot_state writes using a region map.

    Crash bytes are consumed sequentially: the first ``regions[0]["size"]``
    bytes go to ``regions[0]["address"]``, the next ``regions[1]["size"]``
    bytes go to ``regions[1]["address"]``, etc.  Bytes beyond all regions
    are ignored.
    """
    writes: List[Dict[str, str]] = []
    offset = 0
    for region in regions:
        addr = region["address"]
        size = region["size"]
        chunk = data[offset : offset + size]
        offset += size
        if not chunk:
            continue

        # Pad to 4-byte alignment
        padded = chunk + b"\x00" * ((4 - len(chunk) % 4) % 4)
        for i in range(0, len(padded), 4):
            if i >= len(chunk) and i > 0:
                # Don't emit pure-padding words beyond the actual data
                break
            word = struct.unpack_from("<I", padded, i)[0]
            writes.append({
                "address": "0x{:08X}".format(addr + i),
                "u32": "0x{:08X}".format(word),
            })
    return writes


def _crash_bytes_to_writes_flat(
    data: bytes,
    base_address: int,
) -> List[Dict[str, str]]:
    """Map all crash bytes to sequential addresses starting at *base_address*."""
    writes: List[Dict[str, str]] = []
    # Pad to 4-byte alignment
    padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
    for i in range(0, len(data), 4):
        word = struct.unpack_from("<I", padded, i)[0]
        writes.append({
            "address": "0x{:08X}".format(base_address + i),
            "u32": "0x{:08X}".format(word),
        })
    return writes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    crash_path = Path(args.crash_input)
    template_path = Path(args.template)
    output_path = Path(args.output)

    crash_data = crash_path.read_bytes()
    if not crash_data:
        raise RuntimeError("Crash input file is empty: {}".format(crash_path))

    template_data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    if not isinstance(template_data, dict):
        raise RuntimeError("Template profile must be a YAML mapping/object.")

    regions = _load_region_map(args.address_map or None)

    if regions:
        writes = _crash_bytes_to_writes_with_regions(crash_data, regions)
    else:
        meta_base = _derive_meta_base(template_data, args.meta_base)
        writes = _crash_bytes_to_writes_flat(crash_data, meta_base)

    if not writes:
        raise RuntimeError("No pre_boot_state writes generated from crash input.")

    profile = copy.deepcopy(template_data)
    base_name = str(profile.get("name") or "fuzz_crash")
    suffix = "_{}".format(args.name_suffix) if args.name_suffix else ""
    profile["name"] = "{}_fuzz{}".format(base_name, suffix)
    profile["description"] = (
        "{} (from fuzzer crash input {})".format(
            profile.get("description", "Fuzzer-derived profile"),
            crash_path.name,
        )
    )
    profile["pre_boot_state"] = writes
    expect = profile.setdefault("expect", {})
    if isinstance(expect, dict):
        expect["should_find_issues"] = True

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    print(
        "Generated {} with {} pre_boot_state writes from {} ({} bytes).".format(
            output_path,
            len(writes),
            crash_path.name,
            len(crash_data),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
