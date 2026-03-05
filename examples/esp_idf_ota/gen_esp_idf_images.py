#!/usr/bin/env python3
"""Generate ESP-IDF OTA test images: otadata + slot firmware.

Usage:
    # Generate slot images (minimal firmware that sets VTOR and writes marker):
    python3 gen_esp_idf_images.py --slot 0 --output slot0.bin
    python3 gen_esp_idf_images.py --slot 1 --output slot1.bin

    # Generate otadata with specific state:
    python3 gen_esp_idf_images.py --otadata \
        --seq0 1 --state0 valid \
        --seq1 2 --state1 new \
        --output otadata.bin

otadata format: 8192 bytes (two 4KB sectors).
Each sector starts with a 32-byte esp_ota_select_entry_t:
    uint32_t ota_seq     (1-based, 0xFFFFFFFF = erased)
    uint8_t  seq_label[20]  (unused, 0xFF)
    uint32_t ota_state   (0=NEW, 1=PENDING_VERIFY, 2=VALID, 3=INVALID, 4=ABORTED, 0xFFFFFFFF=UNDEFINED)
    uint32_t crc         (CRC-32 of ota_seq only, ESP-IDF ROM CRC convention)
"""

import argparse
import struct

# Memory layout matching esp_idf_ota.c
# Writable regions are in NVMC-managed flash (0xC000-0xFFFFF)
OTADATA_SECTOR_SIZE = 0x1000  # 4KB
OTADATA_BASE = 0x000F8000
SLOT0_BASE = 0x0000C000
SLOT1_BASE = 0x00080000
SLOT_SIZE = 0x74000  # 464KB
SRAM_TOP = 0x20040000
COPY_ON_BOOT_BYTES = 0x2000  # Keep in sync with esp_idf_ota.c

# OTA states
OTA_STATES = {
    "new": 0x00000000,
    "pending_verify": 0x00000001,
    "valid": 0x00000002,
    "invalid": 0x00000003,
    "aborted": 0x00000004,
    "undefined": 0xFFFFFFFF,
}

# Marker address (test harness reads this)
MARKER_ADDR = 0x000FC000


def crc32_table():
    """Build CRC-32 table with polynomial 0xEDB88320."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        table.append(c)
    return table


_CRC_TABLE = crc32_table()


def esp_otadata_crc(ota_seq):
    """Compute CRC-32 of ota_seq the same way ESP-IDF ROM does.

    esp_rom_crc32_le(0xFFFFFFFF, &ota_seq, 4):
      ROM internally does crc = ~init = 0, process bytes, return ~crc.
    """
    data = struct.pack("<I", ota_seq)
    crc = 0x00000000
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def make_otadata_entry(ota_seq, ota_state):
    """Build a 32-byte esp_ota_select_entry_t."""
    if ota_seq == 0xFFFFFFFF:
        # Erased entry
        return b"\xFF" * 32

    crc = esp_otadata_crc(ota_seq)
    entry = struct.pack("<I", ota_seq)          # ota_seq
    entry += b"\xFF" * 20                        # seq_label (unused)
    entry += struct.pack("<I", ota_state)       # ota_state
    entry += struct.pack("<I", crc)             # crc
    assert len(entry) == 32
    return entry


def make_otadata(seq0, state0, seq1, state1):
    """Build 8192-byte otadata partition (two 4KB sectors)."""
    entry0 = make_otadata_entry(seq0, state0)
    entry1 = make_otadata_entry(seq1, state1)

    sector0 = entry0 + b"\xFF" * (OTADATA_SECTOR_SIZE - 32)
    sector1 = entry1 + b"\xFF" * (OTADATA_SECTOR_SIZE - 32)

    return sector0 + sector1


def movw(rd, imm16):
    """Encode Thumb-2 MOVW Rd, #imm16."""
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 0x1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    hw1 = 0xF240 | (i << 10) | imm4
    hw2 = (imm3 << 12) | (rd << 8) | imm8
    return struct.pack("<HH", hw1, hw2)


def movt(rd, imm16):
    """Encode Thumb-2 MOVT Rd, #imm16."""
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 0x1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    hw1 = 0xF2C0 | (i << 10) | imm4
    hw2 = (imm3 << 12) | (rd << 8) | imm8
    return struct.pack("<HH", hw1, hw2)


def make_slot_firmware(slot_base, slot_id):
    """Build minimal Cortex-M4 firmware for a slot.

    On boot: sets VTOR, writes slot_id marker to MARKER_ADDR, loops.
    """
    code_offset = 0x40

    code = b""
    # Preserve bootloader-selected VTOR; only write marker for observability.
    # This keeps boot-slot attribution based on bootloader behavior rather
    # than image self-relocation.
    code += movw(0, MARKER_ADDR & 0xFFFF)
    code += movt(0, (MARKER_ADDR >> 16) & 0xFFFF)
    code += movw(1, slot_id & 0xFFFF)
    code += movt(1, 0)
    code += struct.pack("<H", 0x6001)  # STR R1, [R0]

    # WFI loop
    code += struct.pack("<H", 0xBF30)  # WFI
    code += struct.pack("<H", 0xE7FE)  # B .

    # Vector table
    vectors = bytearray(code_offset)
    struct.pack_into("<I", vectors, 0, SRAM_TOP)
    code_addr = slot_base + code_offset
    struct.pack_into("<I", vectors, 4, code_addr | 1)
    for i in range(2, code_offset // 4):
        struct.pack_into("<I", vectors, i * 4, code_addr | 1)

    image = bytearray(bytes(vectors) + code)

    # Extend image with deterministic slot-specific payload so copy-on-boot
    # exercises many real writes instead of just the tiny vector/code region.
    target_size = max(COPY_ON_BOOT_BYTES, len(image))
    seed = (0x1F123BB5 ^ ((slot_id + 1) * 0x45D9F3B)) & 0xFFFFFFFF
    while len(image) < target_size:
        seed = (1664525 * seed + 1013904223) & 0xFFFFFFFF
        image.append((seed >> 16) & 0xFF)

    return bytes(image)


def main():
    parser = argparse.ArgumentParser(
        description="Generate ESP-IDF OTA test images"
    )
    sub = parser.add_subparsers(dest="mode")

    # Slot image mode
    slot_p = sub.add_parser("slot", help="Generate slot firmware image")
    slot_p.add_argument("--index", type=int, required=True, choices=[0, 1])
    slot_p.add_argument("--output", required=True)

    # OTAdata mode
    ota_p = sub.add_parser("otadata", help="Generate otadata partition")
    ota_p.add_argument("--seq0", type=int, default=0xFFFFFFFF)
    ota_p.add_argument("--state0", default="undefined", choices=OTA_STATES.keys())
    ota_p.add_argument("--seq1", type=int, default=0xFFFFFFFF)
    ota_p.add_argument("--state1", default="undefined", choices=OTA_STATES.keys())
    ota_p.add_argument("--output", required=True)

    args = parser.parse_args()

    if args.mode == "slot":
        base = SLOT0_BASE if args.index == 0 else SLOT1_BASE
        # slot_id: 0 for slot 0 (current), 1 for slot 1 (update)
        fw = make_slot_firmware(base, args.index)
        with open(args.output, "wb") as f:
            f.write(fw)
        print("Slot {}: base=0x{:08X} size={} bytes (copy window=0x{:X})".format(
            args.index, base, len(fw), COPY_ON_BOOT_BYTES))

    elif args.mode == "otadata":
        data = make_otadata(
            args.seq0, OTA_STATES[args.state0],
            args.seq1, OTA_STATES[args.state1],
        )
        with open(args.output, "wb") as f:
            f.write(data)
        print("OTAdata: sector0 seq={} state={}, sector1 seq={} state={}".format(
            args.seq0 if args.seq0 != 0xFFFFFFFF else "erased", args.state0,
            args.seq1 if args.seq1 != 0xFFFFFFFF else "erased", args.state1,
        ))
        if args.seq0 != 0xFFFFFFFF:
            print("  Entry 0 CRC: 0x{:08X}".format(esp_otadata_crc(args.seq0)))
        if args.seq1 != 0xFFFFFFFF:
            print("  Entry 1 CRC: 0x{:08X}".format(esp_otadata_crc(args.seq1)))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
