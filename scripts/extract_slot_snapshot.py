#!/usr/bin/env python3
"""Extract raw slot images from a persisted flash snapshot."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Iterable, Tuple

from profile_loader import ProfileConfig, load_profile


def flash_base_for_profile(profile: ProfileConfig) -> int:
    slot_bases = [int(slot.base) for slot in profile.memory.slots.values()]
    if slot_bases:
        return min([int(profile.bootloader_entry)] + slot_bases)
    return int(profile.bootloader_entry)


def extract_slot_bytes(
    profile: ProfileConfig,
    snapshot_bytes: bytes,
    slot_name: str,
) -> bytes:
    slot = profile.memory.slots.get(slot_name)
    if slot is None:
        raise KeyError("unknown slot '{}'".format(slot_name))
    flash_base = flash_base_for_profile(profile)
    start = int(slot.base) - flash_base
    end = start + int(slot.size)
    if start < 0 or end > len(snapshot_bytes):
        raise ValueError(
            "snapshot too small for slot '{}' (need [0x{:X}, 0x{:X}), have 0x{:X} bytes)".format(
                slot_name,
                start,
                end,
                len(snapshot_bytes),
            )
        )
    return snapshot_bytes[start:end]


def extract_slots(
    profile: ProfileConfig,
    snapshot_path: Path,
    output_dir: Path,
    slots: Iterable[str],
    prefix: str,
) -> list[Path]:
    snapshot_bytes = snapshot_path.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for slot_name in slots:
        out_path = output_dir / "{}_{}.bin".format(prefix, slot_name)
        out_path.write_bytes(extract_slot_bytes(profile, snapshot_bytes, slot_name))
        outputs.append(out_path)
    return outputs


def parse_span(text: str) -> Tuple[int, int]:
    raw = str(text or "").strip()
    if ":" not in raw:
        raise ValueError("span must use start:size format, got '{}'".format(raw))
    start_text, size_text = raw.split(":", 1)
    start = int(start_text, 0)
    size = int(size_text, 0)
    if size <= 0:
        raise ValueError("span size must be > 0, got {}".format(size))
    return start, size


def extract_flash_span(
    profile: ProfileConfig,
    snapshot_bytes: bytes,
    start_addr: int,
    size: int,
) -> bytes:
    flash_base = flash_base_for_profile(profile)
    start = int(start_addr) - flash_base
    end = start + int(size)
    if start < 0 or end > len(snapshot_bytes):
        raise ValueError(
            "snapshot too small for span [0x{:08X}, 0x{:08X}), have 0x{:X} bytes".format(
                int(start_addr),
                int(start_addr) + int(size),
                len(snapshot_bytes),
            )
        )
    return snapshot_bytes[start:end]


def extract_spans(
    profile: ProfileConfig,
    snapshot_path: Path,
    output_dir: Path,
    spans: Iterable[Tuple[int, int]],
    prefix: str,
) -> list[Path]:
    snapshot_bytes = snapshot_path.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for start_addr, size in spans:
        out_path = output_dir / "{}_span_{:08X}_{:X}.bin".format(
            prefix,
            int(start_addr),
            int(size),
        )
        out_path.write_bytes(
            extract_flash_span(profile, snapshot_bytes, start_addr, size)
        )
        outputs.append(out_path)
    return outputs


def span_to_pre_boot_state(start_addr: int, data: bytes) -> list[tuple[int, int]]:
    entries: list[tuple[int, int]] = []
    whole_words = len(data) // 4
    for index in range(whole_words):
        value = struct.unpack_from("<I", data, index * 4)[0]
        if value == 0xFFFFFFFF:
            continue
        entries.append((int(start_addr) + (index * 4), value))
    return entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract raw slot binaries from a persisted Tardigrade flash snapshot."
    )
    parser.add_argument("--profile", required=True, help="Path to the profile YAML.")
    parser.add_argument("--snapshot", required=True, help="Path to the persisted flash snapshot.")
    parser.add_argument(
        "--slot",
        action="append",
        dest="slots",
        default=[],
        help="Slot name to extract. May be specified multiple times. Defaults to all profile slots.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where extracted slot binaries should be written.",
    )
    parser.add_argument(
        "--prefix",
        default="snapshot",
        help="Filename prefix for extracted slot binaries.",
    )
    parser.add_argument(
        "--span",
        action="append",
        dest="spans",
        default=[],
        help="Arbitrary flash span to extract in start:size form (for example 0x08081F60:0xA0). May be repeated.",
    )
    parser.add_argument(
        "--emit-pre-boot-state",
        action="store_true",
        help="Print YAML pre_boot_state entries for extracted spans by omitting erased 0xFFFFFFFF words.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = load_profile(Path(args.profile))
    outputs: list[Path] = []
    if args.slots:
        outputs.extend(
            extract_slots(
                profile=profile,
                snapshot_path=Path(args.snapshot),
                output_dir=Path(args.output_dir),
                slots=args.slots,
                prefix=str(args.prefix),
            )
        )
    elif not args.spans:
        outputs.extend(
            extract_slots(
                profile=profile,
                snapshot_path=Path(args.snapshot),
                output_dir=Path(args.output_dir),
                slots=list(profile.memory.slots.keys()),
                prefix=str(args.prefix),
            )
        )
    if args.spans:
        parsed_spans = [parse_span(span) for span in args.spans]
        outputs.extend(
            extract_spans(
                profile=profile,
                snapshot_path=Path(args.snapshot),
                output_dir=Path(args.output_dir),
                spans=parsed_spans,
                prefix=str(args.prefix),
            )
        )
    for path in outputs:
        print(path)
    if args.emit_pre_boot_state and args.spans:
        snapshot_bytes = Path(args.snapshot).read_bytes()
        print("pre_boot_state:")
        for start_addr, size in parsed_spans:
            span_bytes = extract_flash_span(profile, snapshot_bytes, start_addr, size)
            for address, value in span_to_pre_boot_state(start_addr, span_bytes):
                print("  - {{ address: 0x{:08X}, u32: 0x{:08X} }}".format(address, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
