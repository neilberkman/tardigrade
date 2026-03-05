#!/usr/bin/env python3
"""Generate a riotboot-compatible slot image with valid header + minimal firmware.

Usage:
    python3 gen_slot_image.py --slot 0 --version 1 --output slot0.bin
    python3 gen_slot_image.py --slot 1 --version 2 --output slot1.bin
"""

import argparse
import struct

RIOTBOOT_MAGIC = 0x544F4952  # "RIOT" LE
RIOTBOOT_HDR_LEN = 0x100     # 256 bytes
RIOTBOOT_LEN = 0x2000        # 8KB bootloader
ROM_LEN = 0x100000           # 1MB flash
SLOT_SIZE = (ROM_LEN - RIOTBOOT_LEN) // 2  # 0x7F000


def fletcher32(data_bytes):
    """Fletcher32 checksum over data_bytes (must be even length)."""
    words = struct.unpack("<{}H".format(len(data_bytes) // 2), data_bytes)
    sum1 = 0xFFFF
    sum2 = 0xFFFF
    i = 0
    while i < len(words):
        batch = min(359, len(words) - i)
        for j in range(batch):
            sum1 += words[i + j]
            sum2 += sum1
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
        i += batch
    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
    return (sum2 << 16) | sum1


def make_header(version, start_addr):
    """Build a 256-byte riotboot header."""
    # First 12 bytes for checksum
    payload = struct.pack("<III", RIOTBOOT_MAGIC, version, start_addr)
    chksum = fletcher32(payload)
    hdr = struct.pack("<IIII", RIOTBOOT_MAGIC, version, start_addr, chksum)
    # Pad to HDR_LEN
    hdr += b"\x00" * (RIOTBOOT_HDR_LEN - len(hdr))
    return hdr


def make_firmware(slot_base, version):
    """Build minimal Cortex-M4 firmware for a slot.

    The firmware image goes at slot_base + HDR_LEN.
    It sets VTOR to its own base, writes a marker, and enters WFI loop.
    """
    img_addr = slot_base + RIOTBOOT_HDR_LEN
    sp = 0x20040000  # Top of 256KB SRAM

    # Minimal thumb code at img_addr + 0x40 (after vector table):
    #   LDR R0, =0xE000ED08   ; VTOR register
    #   LDR R1, =img_addr     ; our vector table base
    #   STR R1, [R0]           ; set VTOR
    #   WFI                    ; halt
    code_offset = 0x40
    code_addr = img_addr + code_offset

    # Thumb instructions (little-endian)
    # movw r0, #0xED08
    # movt r0, #0xE000
    # movw r1, #(img_addr & 0xFFFF)
    # movt r1, #(img_addr >> 16)
    # str  r1, [r0]
    # wfi

    def movw(rd, imm16):
        """Encode MOVW Rd, #imm16 as 2 halfwords (Thumb-2)."""
        imm4 = (imm16 >> 12) & 0xF
        i = (imm16 >> 11) & 0x1
        imm3 = (imm16 >> 8) & 0x7
        imm8 = imm16 & 0xFF
        hw1 = 0xF240 | (i << 10) | imm4
        hw2 = (imm3 << 12) | (rd << 8) | imm8
        return struct.pack("<HH", hw1, hw2)

    def movt(rd, imm16):
        """Encode MOVT Rd, #imm16 as 2 halfwords (Thumb-2)."""
        imm4 = (imm16 >> 12) & 0xF
        i = (imm16 >> 11) & 0x1
        imm3 = (imm16 >> 8) & 0x7
        imm8 = imm16 & 0xFF
        hw1 = 0xF2C0 | (i << 10) | imm4
        hw2 = (imm3 << 12) | (rd << 8) | imm8
        return struct.pack("<HH", hw1, hw2)

    code = b""
    # MOVW R0, #0xED08
    code += movw(0, 0xED08)
    # MOVT R0, #0xE000
    code += movt(0, 0xE000)
    # MOVW R1, #(img_addr & 0xFFFF)
    code += movw(1, img_addr & 0xFFFF)
    # MOVT R1, #(img_addr >> 16)
    code += movt(1, (img_addr >> 16) & 0xFFFF)
    # STR R1, [R0] = 0x6001
    code += struct.pack("<H", 0x6001)
    # WFI = 0xBF30
    code += struct.pack("<H", 0xBF30)
    # WFI loop
    # B . (branch to self) = 0xE7FE
    code += struct.pack("<H", 0xE7FE)

    # Build vector table (64 bytes minimum)
    vectors = bytearray(code_offset)
    # Word 0: Initial SP
    struct.pack_into("<I", vectors, 0, sp)
    # Word 1: Reset vector (code_addr | 1 for Thumb)
    struct.pack_into("<I", vectors, 4, code_addr | 1)
    # Fill remaining vectors with infinite loop handler
    # Use a simple "B ." at the start of vectors area... actually just
    # point them all at code_addr for simplicity
    for i in range(2, code_offset // 4):
        struct.pack_into("<I", vectors, i * 4, code_addr | 1)

    firmware = bytes(vectors) + code
    return firmware


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--slot", type=int, required=True, choices=[0, 1])
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    slot_base = RIOTBOOT_LEN if args.slot == 0 else (RIOTBOOT_LEN + SLOT_SIZE)
    img_addr = slot_base + RIOTBOOT_HDR_LEN

    header = make_header(args.version, img_addr)
    firmware = make_firmware(slot_base, args.version)

    image = header + firmware

    with open(args.output, "wb") as f:
        f.write(image)

    print("Slot {}: base=0x{:08X} img=0x{:08X} version={} size={} bytes".format(
        args.slot, slot_base, img_addr, args.version, len(image)))
    print("Header checksum: 0x{:08X}".format(
        struct.unpack_from("<I", header, 12)[0]))


if __name__ == "__main__":
    main()
