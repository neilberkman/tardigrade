#!/usr/bin/env python3
"""Generate initial_mram.bin with a valid exec vector table and Record A."""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: gen_initial_mram.py <output_path>")
    out_path = Path(sys.argv[1])

    image = bytearray(0x400)

    # Minimal valid Cortex-M vector table at 0x10100000 (exec slot base):
    # SP=0x20002000, Reset/NMI/HardFault -> 0x10100041 (Thumb `b .`).
    struct.pack_into("<IIII", image, 0x000, 0x20002000, 0x10100041, 0x10100041, 0x10100041)
    struct.pack_into("<H", image, 0x040, 0xE7FE)

    # Record A at 0x10100100: committed sequence 1 with IEEE CRC-32.
    rec_a_words = (
        0x52454331,  # magic ("REC1")
        1,           # seq
        0x10000001,  # state
        0x00000001,  # flags
        0x00000000,  # reserved0
        0x00000000,  # reserved1
        0xA5A50001,  # tag
    )
    payload = struct.pack("<7I", *rec_a_words)
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    image[0x100:0x120] = payload + struct.pack("<I", crc32)

    # Record B at 0x10100200 remains erased (0x00 bytes).
    out_path.write_bytes(bytes(image))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
