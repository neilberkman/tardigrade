#!/usr/bin/env python3
"""Generate test firmware images with nxboot headers for Renode testing.

Creates properly headerized firmware images that the nxboot-style bootloader
can validate (magic, CRC, version, platform ID).  These are synthetic test
images with valid ARM Cortex-M0+ vector tables.

Usage:
    python3 gen_nxboot_images.py --output-dir .

Produces:
    nxboot_primary.bin   - image for primary slot (v1.0.0, external magic)
    nxboot_update.bin    - image for update slot  (v2.0.0, external magic)
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path


NXBOOT_HEADER_MAGIC = 0x534F584E  # "NXOS" LE
NXBOOT_HEADER_SIZE = 0x200  # 512 bytes
PLATFORM_ID = 0x0

# Memory layout for images that will be loaded into slots.
# The image payload starts after the header and contains a valid
# Cortex-M0+ vector table at offset 0.
SRAM_END = 0x20020000  # Initial SP value


def make_vector_table(slot_base: int, header_size: int) -> bytes:
    """Create a minimal valid ARM Cortex-M0+ vector table.

    The vector table must be valid when loaded at slot_base + header_size.
    """
    img_base = slot_base + header_size
    initial_sp = SRAM_END
    # Reset handler = img_base + 0x40 + 1 (thumb bit)
    reset_handler = img_base + 0x41

    # 16 entries: SP, Reset, 14 exception handlers
    entries = [initial_sp, reset_handler]
    # Fill remaining vectors with the same handler address
    for _ in range(14):
        entries.append(reset_handler)

    return struct.pack("<16I", *entries)


def make_reset_handler() -> bytes:
    """Minimal Cortex-M0+ reset handler: infinite loop (0xe7fe)."""
    # Pad to offset 0x40 then place the handler
    padding = b"\x00" * (0x40 - 0x40)  # vectors are 0x40 bytes
    handler = struct.pack("<H", 0xE7FE)  # b .  (infinite loop)
    return padding + handler


def make_firmware_payload(slot_base: int, header_size: int, size: int) -> bytes:
    """Create a firmware payload with valid vector table."""
    vt = make_vector_table(slot_base, header_size)
    handler = make_reset_handler()
    payload = vt + handler
    # Pad to requested size
    if len(payload) < size:
        payload += b"\xff" * (size - len(payload))
    return payload[:size]


def make_nxboot_image(
    slot_base: int,
    payload_size: int,
    version: tuple[int, int, int],
    header_size: int = NXBOOT_HEADER_SIZE,
) -> bytes:
    """Build a complete nxboot image (header + payload).

    The CRC covers bytes from offset 12 to the end of the image,
    matching the nxboot CRC algorithm.
    """
    payload = make_firmware_payload(slot_base, header_size, payload_size)

    # Build header (128 bytes of meaningful data)
    hdr = bytearray(header_size)
    # Fill with 0xFF (like erased flash)
    for i in range(header_size):
        hdr[i] = 0xFF

    # magic (4 bytes)
    struct.pack_into("<I", hdr, 0, NXBOOT_HEADER_MAGIC)
    # hdr_version (2 bytes: major=1, minor=0)
    hdr[4] = 1
    hdr[5] = 0
    # header_size (2 bytes)
    struct.pack_into("<H", hdr, 6, header_size)
    # crc placeholder (4 bytes at offset 8) — computed below
    struct.pack_into("<I", hdr, 8, 0)
    # size (4 bytes at offset 12)
    struct.pack_into("<I", hdr, 12, payload_size)
    # identifier (8 bytes at offset 16)
    struct.pack_into("<Q", hdr, 16, PLATFORM_ID)
    # extd_hdr_ptr (4 bytes at offset 24)
    struct.pack_into("<I", hdr, 24, 0)
    # img_version (6 bytes at offset 28)
    struct.pack_into("<HHH", hdr, 28, version[0], version[1], version[2])
    # pre_release string (94 bytes at offset 34) — leave as 0xFF

    # Compute CRC-32 over everything from offset 12 to end
    full_image = bytes(hdr) + payload
    crc_data = full_image[12:]
    crc = zlib.crc32(crc_data) & 0xFFFFFFFF

    # Write CRC back into header
    struct.pack_into("<I", hdr, 8, crc)

    return bytes(hdr) + payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate nxboot test images")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for generated images",
    )
    parser.add_argument(
        "--payload-size",
        type=lambda x: int(x, 0),
        default=0x4000,
        help="Firmware payload size in bytes (default: 16KB)",
    )
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Both images target the primary slot execution address since the
    # bootloader copies update -> primary before jumping.  The vector
    # table must be valid at the primary slot base, not the staging slot.
    primary_base = 0x10002000

    # Primary image (v1.0.0) — goes into primary slot
    primary = make_nxboot_image(primary_base, args.payload_size, (1, 0, 0))
    (out / "nxboot_primary.bin").write_bytes(primary)

    # Update image (v2.0.0) — goes into secondary, copied to primary to run
    update = make_nxboot_image(primary_base, args.payload_size, (2, 0, 0))
    (out / "nxboot_update.bin").write_bytes(update)

    print(f"Generated images in {out}:")
    print(f"  nxboot_primary.bin  ({len(primary)} bytes, v1.0.0)")
    print(f"  nxboot_update.bin   ({len(update)} bytes, v2.0.0)")


if __name__ == "__main__":
    main()
