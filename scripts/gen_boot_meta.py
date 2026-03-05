#!/usr/bin/env python3
"""Generate a demo boot metadata blob (2 replicas of 256 bytes)."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

BOOT_META_MAGIC = 0x4F54414D
BOOT_META_REPLICA_SIZE = 256


def boot_meta_crc(words: list[int]) -> int:
    crc = 0xFFFFFFFF
    for word in words[:-1]:
        for shift in (0, 8, 16, 24):
            crc ^= (word >> shift) & 0xFF
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
                crc &= 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate boot metadata blob for demo A/B bootloader")
    parser.add_argument("--output", required=True, help="Output .bin path")
    parser.add_argument("--active-slot", type=int, default=0, choices=(0, 1))
    parser.add_argument("--target-slot", type=int, default=0, choices=(0, 1))
    parser.add_argument("--state", type=int, default=0, help="0=confirmed, 1=pending_test")
    parser.add_argument("--seq", type=int, default=1)
    parser.add_argument("--boot-count", type=int, default=0)
    parser.add_argument("--max-boot-count", type=int, default=3)
    args = parser.parse_args()

    words = [0] * (BOOT_META_REPLICA_SIZE // 4)
    words[0] = BOOT_META_MAGIC
    words[1] = args.seq & 0xFFFFFFFF
    words[2] = args.active_slot & 0xFFFFFFFF
    words[3] = args.target_slot & 0xFFFFFFFF
    words[4] = args.state & 0xFFFFFFFF
    words[5] = args.boot_count & 0xFFFFFFFF
    words[6] = args.max_boot_count & 0xFFFFFFFF
    words[-1] = boot_meta_crc(words)

    replica = struct.pack("<{}I".format(len(words)), *words)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(replica + replica)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
