#!/usr/bin/env python3
"""Convert fuzzer crash inputs into tardigrade regression profiles.

Standalone CLI tool that takes a libFuzzer/AFL crash input file and a
base profile YAML, then produces a new profile that:

  - Loads the crash input as a staging image (binary file) or as
    pre_boot_state writes (for metadata-region crashes)
  - Sets success criteria to expect rejection (bootloader should reject
    the malformed image and fall back to the exec slot)
  - Adds metadata about the original crash (SHA-256 hash, fuzzer type,
    timestamp)

Usage::

    python3 fuzz_crash_to_profile.py \\
        --crash-input crashes/crash-abc123 \\
        --base-profile profiles/my_bootloader.yaml \\
        --output profiles/regression/fuzz_crash_abc123.yaml

    # With address map (crash bytes -> metadata region writes):
    python3 fuzz_crash_to_profile.py \\
        --crash-input crashes/crash-abc123 \\
        --base-profile profiles/my_bootloader.yaml \\
        --address-map address_map.yaml \\
        --output profiles/regression/fuzz_crash_abc123.yaml

    # Batch mode -- process all crash files in a directory:
    python3 fuzz_crash_to_profile.py \\
        --crash-dir crashes/ \\
        --base-profile profiles/my_bootloader.yaml \\
        --output-dir profiles/regression/

This tool is usable independently of the tardigrade audit runner.  The
generated profiles are standard tardigrade YAML and can be run with
``audit_bootloader.py`` or included in self-test suites.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit(
        "PyYAML is required for fuzz_crash_to_profile.py (pip install pyyaml)."
    ) from exc


# ---------------------------------------------------------------------------
# Crash metadata
# ---------------------------------------------------------------------------

def compute_crash_metadata(
    crash_data: bytes,
    crash_path: Path,
    fuzzer: Optional[str] = None,
) -> Dict[str, str]:
    """Compute metadata dict for a crash input.

    Returns a dict suitable for embedding in the profile YAML under
    ``fuzz_metadata``.
    """
    sha256 = hashlib.sha256(crash_data).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta: Dict[str, str] = {
        "crash_file": crash_path.name,
        "crash_sha256": sha256,
        "crash_size_bytes": str(len(crash_data)),
        "generated_at": now,
    }
    if fuzzer:
        meta["fuzzer"] = fuzzer
    # Heuristic: AFL crash filenames contain "id:" prefix
    if not fuzzer:
        name = crash_path.name
        if name.startswith("id:") or name.startswith("id_"):
            meta["fuzzer"] = "afl"
        elif name.startswith("crash-") or name.startswith("oom-") or name.startswith("timeout-"):
            meta["fuzzer"] = "libfuzzer"
    return meta


# ---------------------------------------------------------------------------
# Address-map loading (reused from fuzz_to_profile.py)
# ---------------------------------------------------------------------------

def load_region_map(path: Optional[str]) -> List[Dict[str, Any]]:
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
        raise ValueError(
            "Address map must be a YAML object with a 'regions' list."
        )
    regions_raw = raw["regions"]
    if not isinstance(regions_raw, list):
        raise ValueError("'regions' must be a list.")

    regions: List[Dict[str, Any]] = []
    for i, entry in enumerate(regions_raw):
        if not isinstance(entry, dict):
            raise ValueError("regions[{}]: expected a mapping.".format(i))
        name = str(entry.get("name", "region_{}".format(i)))
        addr = entry.get("address")
        size = entry.get("size")
        if addr is None or size is None:
            raise ValueError(
                "regions[{}] ('{}'): 'address' and 'size' are required.".format(i, name)
            )
        if isinstance(addr, str):
            addr = int(addr, 0)
        if isinstance(size, str):
            size = int(size, 0)
        regions.append({"name": name, "address": int(addr), "size": int(size)})
    return regions


# ---------------------------------------------------------------------------
# Crash bytes -> pre_boot_state writes
# ---------------------------------------------------------------------------

def crash_bytes_to_writes(
    data: bytes,
    regions: List[Dict[str, Any]],
    base_address: int = 0,
) -> List[Dict[str, str]]:
    """Convert crash bytes to pre_boot_state write entries.

    If *regions* is provided, bytes are consumed sequentially across
    regions.  Otherwise all bytes go to sequential addresses starting
    at *base_address*.
    """
    if regions:
        return _writes_with_regions(data, regions)
    return _writes_flat(data, base_address)


def _writes_with_regions(
    data: bytes,
    regions: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    writes: List[Dict[str, str]] = []
    offset = 0
    for region in regions:
        addr = region["address"]
        size = region["size"]
        chunk = data[offset : offset + size]
        offset += size
        if not chunk:
            continue
        padded = chunk + b"\x00" * ((4 - len(chunk) % 4) % 4)
        for i in range(0, len(padded), 4):
            if i >= len(chunk) and i > 0:
                break
            word = struct.unpack_from("<I", padded, i)[0]
            writes.append({
                "address": "0x{:08X}".format(addr + i),
                "u32": "0x{:08X}".format(word),
            })
    return writes


def _writes_flat(data: bytes, base_address: int) -> List[Dict[str, str]]:
    writes: List[Dict[str, str]] = []
    padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
    for i in range(0, len(data), 4):
        word = struct.unpack_from("<I", padded, i)[0]
        writes.append({
            "address": "0x{:08X}".format(base_address + i),
            "u32": "0x{:08X}".format(word),
        })
    return writes


# ---------------------------------------------------------------------------
# Staging image mode
# ---------------------------------------------------------------------------

def crash_as_staging_image(
    crash_data: bytes,
    crash_path: Path,
    output_dir: Path,
) -> str:
    """Write crash data as a staging image binary and return its path.

    The binary is placed in *output_dir* with a name derived from the
    crash file's SHA-256 hash for deduplication.
    """
    sha = hashlib.sha256(crash_data).hexdigest()[:16]
    image_name = "fuzz_staging_{}.bin".format(sha)
    image_path = output_dir / image_name
    image_path.write_bytes(crash_data)
    return str(image_path)


# ---------------------------------------------------------------------------
# Meta-base derivation
# ---------------------------------------------------------------------------

def derive_meta_base(template: Dict[str, Any], override: Optional[int]) -> int:
    """Derive the metadata base address from the template profile."""
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
    # Default metadata base when no slot geometry is available (512KB).
    return 0x00080000


# ---------------------------------------------------------------------------
# Profile generation
# ---------------------------------------------------------------------------

def generate_profile(
    crash_data: bytes,
    crash_path: Path,
    template: Dict[str, Any],
    regions: List[Dict[str, Any]],
    meta_base: Optional[int] = None,
    mode: str = "pre_boot_state",
    staging_image_path: Optional[str] = None,
    fuzzer: Optional[str] = None,
    name_suffix: Optional[str] = None,
    expect_rejection: bool = True,
) -> Dict[str, Any]:
    """Generate a tardigrade regression profile from a fuzzer crash input.

    Args:
        crash_data: Raw bytes from the crash input file.
        crash_path: Path to the original crash file (for metadata).
        template: Parsed base profile YAML dict.
        regions: Address-map regions (empty list for flat/staging mode).
        meta_base: Override metadata base address for flat mode.
        mode: ``"pre_boot_state"`` to inject as writes, ``"staging_image"``
              to replace the staging binary.
        staging_image_path: Path to the written staging image binary
                           (required when mode="staging_image").
        fuzzer: Fuzzer name override (``"libfuzzer"``, ``"afl"``, etc.).
        name_suffix: Optional suffix appended to the profile name.
        expect_rejection: If True (default), configure the profile to
                         expect the bootloader rejects the malformed input.

    Returns:
        A profile dict ready for YAML serialization.
    """
    profile = copy.deepcopy(template)

    # -- Name and description --
    base_name = str(profile.get("name") or "fuzz_regression")
    sha_short = hashlib.sha256(crash_data).hexdigest()[:8]
    suffix_parts = ["fuzz", sha_short]
    if name_suffix:
        suffix_parts.append(name_suffix)
    profile["name"] = "{}_{}".format(base_name, "_".join(suffix_parts))
    profile["description"] = (
        "Fuzzer regression: {} (from crash input {}, {} bytes)".format(
            profile.get("description", ""),
            crash_path.name,
            len(crash_data),
        )
    )

    # -- Crash metadata --
    profile["fuzz_metadata"] = compute_crash_metadata(
        crash_data, crash_path, fuzzer=fuzzer
    )

    # -- Inject the crash data --
    if mode == "staging_image":
        if staging_image_path is None:
            raise ValueError("staging_image_path required for staging_image mode")
        images = profile.get("images", {})
        if not isinstance(images, dict):
            images = {}
        images["staging"] = staging_image_path
        profile["images"] = images
        # Remove stale pre_boot_state -- staging_image mode replaces the
        # binary; leftover pre_boot_state writes would conflict.
        profile.pop("pre_boot_state", None)
    else:
        # pre_boot_state mode
        if regions:
            writes = crash_bytes_to_writes(crash_data, regions)
        else:
            base = derive_meta_base(template, meta_base)
            writes = crash_bytes_to_writes(crash_data, [], base_address=base)
        if not writes:
            raise ValueError("No pre_boot_state writes generated from crash input.")
        profile["pre_boot_state"] = writes

    # -- Success criteria for rejection testing --
    if expect_rejection:
        # The bootloader should reject the malformed input and boot from
        # the exec slot.  We keep vtor_in_slot as-is (typically "exec")
        # and mark that issues are expected if the bootloader is vulnerable.
        expect_block = profile.setdefault("expect", {})
        if isinstance(expect_block, dict):
            expect_block["should_find_issues"] = True

    return profile


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def find_crash_files(crash_dir: Path) -> List[Path]:
    """Find fuzzer crash input files in a directory.

    Recognizes AFL and libFuzzer naming conventions:
      - AFL: id:NNNNNN,* or id_NNNNNN,*
      - libFuzzer: crash-*, oom-*, timeout-*, slow-unit-*

    Falls back to all files if no recognized patterns are found.
    """
    recognized: List[Path] = []
    all_files: List[Path] = []

    for entry in sorted(crash_dir.iterdir()):
        if not entry.is_file():
            continue
        all_files.append(entry)
        name = entry.name
        if (
            name.startswith("id:")
            or name.startswith("id_")
            or name.startswith("crash-")
            or name.startswith("oom-")
            or name.startswith("timeout-")
            or name.startswith("slow-unit-")
        ):
            recognized.append(entry)

    return recognized if recognized else all_files


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert fuzzer crash inputs into tardigrade regression profiles.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Single crash:\n"
            "  %(prog)s --crash-input crash-abc --base-profile p.yaml -o out.yaml\n"
            "\n"
            "  # Batch:\n"
            "  %(prog)s --crash-dir crashes/ --base-profile p.yaml --output-dir reg/\n"
        ),
    )
    # -- Input sources (mutually exclusive) --
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--crash-input",
        help="Path to a single raw binary crash file from the fuzzer.",
    )
    input_group.add_argument(
        "--crash-dir",
        help="Directory containing crash files (batch mode).",
    )

    parser.add_argument(
        "--base-profile", required=True,
        help="Base profile YAML to derive regression profiles from.",
    )

    # -- Output --
    parser.add_argument(
        "-o", "--output",
        help="Output profile path (single-crash mode).",
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory for generated profiles (batch mode).",
    )

    # -- Mapping --
    parser.add_argument(
        "--address-map", default="",
        help="YAML file describing how crash bytes map to flash regions.",
    )
    parser.add_argument(
        "--meta-base",
        type=lambda v: int(v, 0),
        default=None,
        help="Metadata base address override (e.g. 0x00080000).",
    )

    # -- Mode --
    parser.add_argument(
        "--mode",
        choices=["pre_boot_state", "staging_image"],
        default="pre_boot_state",
        help="How to inject the crash data. 'pre_boot_state' writes it as "
             "NVM words; 'staging_image' replaces the staging binary. "
             "(default: pre_boot_state)",
    )

    # -- Options --
    parser.add_argument(
        "--fuzzer",
        choices=["libfuzzer", "afl", "honggfuzz", "other"],
        default=None,
        help="Override fuzzer type in metadata.",
    )
    parser.add_argument(
        "--no-expect-rejection", dest="expect_rejection",
        action="store_false", default=True,
        help="Don't set expect.should_find_issues=true.",
    )
    parser.add_argument(
        "--name-suffix", default="",
        help="Optional suffix appended to profile names.",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    base_path = Path(args.base_profile)
    template = yaml.safe_load(base_path.read_text(encoding="utf-8"))
    if not isinstance(template, dict):
        print("ERROR: Base profile must be a YAML mapping.", file=sys.stderr)
        return 1

    regions = load_region_map(args.address_map or None)

    if args.crash_input:
        # -- Single crash mode --
        crash_path = Path(args.crash_input)
        crash_data = crash_path.read_bytes()
        if not crash_data:
            print("ERROR: Crash input file is empty: {}".format(crash_path), file=sys.stderr)
            return 1

        output_path = Path(args.output) if args.output else Path(
            "fuzz_regression_{}.yaml".format(
                hashlib.sha256(crash_data).hexdigest()[:12]
            )
        )

        staging_image_path = None
        if args.mode == "staging_image":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            staging_image_path = crash_as_staging_image(
                crash_data, crash_path, output_path.parent
            )

        profile = generate_profile(
            crash_data=crash_data,
            crash_path=crash_path,
            template=template,
            regions=regions,
            meta_base=args.meta_base,
            mode=args.mode,
            staging_image_path=staging_image_path,
            fuzzer=args.fuzzer,
            name_suffix=args.name_suffix or None,
            expect_rejection=args.expect_rejection,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            yaml.safe_dump(profile, sort_keys=False), encoding="utf-8"
        )
        print("Generated {} ({} bytes crash -> {})".format(
            output_path, len(crash_data), args.mode
        ))
        return 0

    else:
        # -- Batch mode --
        crash_dir = Path(args.crash_dir)
        if not crash_dir.is_dir():
            print("ERROR: Not a directory: {}".format(crash_dir), file=sys.stderr)
            return 1

        output_dir = Path(args.output_dir) if args.output_dir else Path("fuzz_regression_profiles")
        output_dir.mkdir(parents=True, exist_ok=True)

        crash_files = find_crash_files(crash_dir)
        if not crash_files:
            print("No crash files found in {}".format(crash_dir), file=sys.stderr)
            return 1

        generated = 0
        skipped = 0
        for crash_path in crash_files:
            crash_data = crash_path.read_bytes()
            if not crash_data:
                skipped += 1
                continue

            sha_short = hashlib.sha256(crash_data).hexdigest()[:12]
            out_name = "fuzz_regression_{}.yaml".format(sha_short)
            out_path = output_dir / out_name

            staging_image_path = None
            if args.mode == "staging_image":
                staging_image_path = crash_as_staging_image(
                    crash_data, crash_path, output_dir
                )

            try:
                profile = generate_profile(
                    crash_data=crash_data,
                    crash_path=crash_path,
                    template=template,
                    regions=regions,
                    meta_base=args.meta_base,
                    mode=args.mode,
                    staging_image_path=staging_image_path,
                    fuzzer=args.fuzzer,
                    name_suffix=args.name_suffix or None,
                    expect_rejection=args.expect_rejection,
                )
            except ValueError as e:
                print("SKIP {}: {}".format(crash_path.name, e), file=sys.stderr)
                skipped += 1
                continue

            out_path.write_text(
                yaml.safe_dump(profile, sort_keys=False), encoding="utf-8"
            )
            generated += 1

        print("Batch complete: {} profiles generated, {} skipped from {}".format(
            generated, skipped, crash_dir
        ))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
