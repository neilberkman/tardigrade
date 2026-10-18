#!/usr/bin/env python3
"""Reject a signed MCUboot image whose handoff vector table is not real.

MCUboot jumps through the Cortex-M vector table located ``ih_hdr_size`` bytes
past the start of the executable slot.  Zephyr links the application vector
table at ``CONFIG_ROM_START_OFFSET``.  When an image is signed with a header
smaller than that offset, the bytes at ``ih_hdr_size`` are zero padding and
MCUboot branches to address 0 instead of starting the application.  Emulated
campaigns against such an image never observe an application handoff.

This check reads the application's Zephyr ``.config`` and fails unless the
signed header size equals ``CONFIG_ROM_START_OFFSET`` and the vector table at
that offset holds an initial stack pointer inside SRAM and a Thumb reset
handler inside the signed image. Zephyr builds that use mapped partitions do
not define ``CONFIG_FLASH_LOAD_OFFSET``; for those the reset handler only has
to lie inside flash.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List

IMAGE_MAGIC = 0x96F3B83D
HEADER_FORMAT = "<IIHHI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
REQUIRED_CONFIG = (
    "CONFIG_ROM_START_OFFSET",
    "CONFIG_FLASH_BASE_ADDRESS",
    "CONFIG_FLASH_SIZE",
    "CONFIG_SRAM_BASE_ADDRESS",
    "CONFIG_SRAM_SIZE",
)
_CONFIG_LINE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(0x[0-9a-fA-F]+|[0-9]+)$")


def read_zephyr_config(path: Path) -> Dict[str, int]:
    values: Dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _CONFIG_LINE.match(line.strip())
        if match:
            values[match.group(1)] = int(match.group(2), 0)
    return values


def check_image(image: bytes, config: Dict[str, int]) -> List[str]:
    """Return every handoff problem found; an empty list means the image is usable."""
    missing = [key for key in REQUIRED_CONFIG if key not in config]
    if missing:
        return ["application .config lacks {}".format(", ".join(missing))]
    if len(image) < HEADER_SIZE:
        return ["image is {} bytes, shorter than an MCUboot header".format(len(image))]

    magic, _load_addr, hdr_size, _protect_tlv_size, img_size = struct.unpack_from(
        HEADER_FORMAT, image, 0
    )
    if magic != IMAGE_MAGIC:
        return ["image magic is 0x{:08X}, expected 0x{:08X}".format(magic, IMAGE_MAGIC)]

    rom_start_offset = config["CONFIG_ROM_START_OFFSET"]
    errors: List[str] = []
    if hdr_size != rom_start_offset:
        errors.append(
            "ih_hdr_size is 0x{:X} but the application links its vector table at "
            "CONFIG_ROM_START_OFFSET=0x{:X}; sign with --header-size 0x{:X}".format(
                hdr_size, rom_start_offset, rom_start_offset
            )
        )
    if len(image) < hdr_size + 8:
        errors.append("image ends before the vector table at 0x{:X}".format(hdr_size))
        return errors

    initial_sp, reset_vector = struct.unpack_from("<II", image, hdr_size)
    sram_lo = config["CONFIG_SRAM_BASE_ADDRESS"]
    sram_hi = sram_lo + config["CONFIG_SRAM_SIZE"] * 1024
    if initial_sp & 0x3 or not sram_lo < initial_sp <= sram_hi:
        errors.append(
            "initial SP 0x{:08X} at image offset 0x{:X} is not a word-aligned "
            "address in SRAM 0x{:08X}..0x{:08X}".format(initial_sp, hdr_size, sram_lo, sram_hi)
        )

    flash_base = config["CONFIG_FLASH_BASE_ADDRESS"]
    if "CONFIG_FLASH_LOAD_OFFSET" in config:
        code_lo = flash_base + config["CONFIG_FLASH_LOAD_OFFSET"] + hdr_size
        code_hi = code_lo + img_size
        region = "the signed image"
    else:
        code_lo = flash_base + hdr_size
        code_hi = flash_base + config["CONFIG_FLASH_SIZE"] * 1024
        region = "flash"
    handler = reset_vector & ~1
    if not reset_vector & 1 or not code_lo <= handler < code_hi:
        errors.append(
            "reset vector 0x{:08X} at image offset 0x{:X} is not a Thumb address "
            "inside {} 0x{:08X}..0x{:08X}".format(
                reset_vector, hdr_size + 4, region, code_lo, code_hi
            )
        )
    return errors


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True, type=Path, help="signed MCUboot image")
    parser.add_argument(
        "--app-config",
        required=True,
        type=Path,
        help="Zephyr .config of the application build that produced the image",
    )
    args = parser.parse_args(argv)

    errors = check_image(args.image.read_bytes(), read_zephyr_config(args.app_config))
    if errors:
        for error in errors:
            print("ERROR: {}: {}".format(args.image, error), file=sys.stderr)
        return 1
    print("Vector table OK: {}".format(args.image))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
