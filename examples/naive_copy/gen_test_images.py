#!/usr/bin/env python3
"""Generate two minimal Cortex-M0+ images with distinct boot sentinels."""

import argparse
import struct
from pathlib import Path


EXEC_BASE = 0x10002000
SRAM_TOP = 0x20020000
RESET_OFFSET = 0x40
SENTINEL_OFFSET = 0x44
SLOT_A_SENTINEL = 0x534C4F41  # "SLOA"
SLOT_B_SENTINEL = 0x534C4F42  # "SLOB"


def make_image(sentinel: int) -> bytes:
    reset = EXEC_BASE + RESET_OFFSET + 1
    image = bytearray(b"\xff" * 0x100)
    vectors = [SRAM_TOP, reset] + [reset] * 14
    struct.pack_into("<16I", image, 0, *vectors)
    struct.pack_into("<H", image, RESET_OFFSET, 0xE7FE)  # b .
    struct.pack_into("<I", image, SENTINEL_OFFSET, sentinel)
    return bytes(image)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=".")
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "test_firmware_a.bin").write_bytes(make_image(SLOT_A_SENTINEL))
    (output / "test_firmware_b.bin").write_bytes(make_image(SLOT_B_SENTINEL))


if __name__ == "__main__":
    main()
