/*
 * boot_meta.h -- Minimal OTA metadata parser with an intentional bug.
 *
 * This is a self-contained example for demonstrating the CBMC-to-Tardigrade
 * pipeline.  The metadata structure tracks which firmware slot is active and
 * uses a CRC-32 for integrity.  The bug: the CRC is computed over the wrong
 * byte range (excludes the active_slot field), so a corrupted active_slot
 * value passes validation and boots from the wrong slot.
 *
 * Layout (16 bytes):
 *   [0..3]   magic       (0x4F54414D = "OTAM")
 *   [4..7]   seq         sequence counter
 *   [8..11]  active_slot 0 or 1
 *   [12..15] crc32       CRC-32 over bytes [0..11]
 */
#ifndef BOOT_META_H
#define BOOT_META_H

#include <stdint.h>
#include <string.h>

#define BOOT_META_MAGIC 0x4F54414Du
#define BOOT_META_SIZE  16

struct boot_meta {
    uint32_t magic;
    uint32_t seq;
    uint32_t active_slot;
    uint32_t crc32;
};

/* Simple CRC-32 (same polynomial as zlib). */
static uint32_t crc32_naive(const uint8_t *data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1u)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/*
 * Parse and validate boot metadata from a raw byte buffer.
 *
 * BUG: CRC is only computed over bytes [0..7] (magic + seq), NOT [0..11].
 * This means active_slot can be corrupted without the CRC catching it.
 *
 * Returns 0 on success (fills *out), nonzero on failure.
 */
static int boot_meta_parse(const uint8_t *buf, uint32_t buf_len,
                           struct boot_meta *out) {
    if (buf_len < BOOT_META_SIZE)
        return -1;

    memcpy(out, buf, sizeof(*out));

    if (out->magic != BOOT_META_MAGIC)
        return -2;

    if (out->active_slot > 1u)
        return -3;

    /*
     * BUG: should be crc32_naive(buf, 12) to cover magic+seq+active_slot.
     * Instead we only cover magic+seq (8 bytes), leaving active_slot
     * unprotected by the integrity check.
     */
    uint32_t expected_crc = crc32_naive(buf, 8);  /* WRONG: should be 12 */
    if (out->crc32 != expected_crc)
        return -4;

    return 0;
}

/*
 * Correct version for reference (used by the CBMC harness to show
 * the differential).
 */
static int boot_meta_parse_fixed(const uint8_t *buf, uint32_t buf_len,
                                 struct boot_meta *out) {
    if (buf_len < BOOT_META_SIZE)
        return -1;

    memcpy(out, buf, sizeof(*out));

    if (out->magic != BOOT_META_MAGIC)
        return -2;

    if (out->active_slot > 1u)
        return -3;

    /* CORRECT: CRC covers magic + seq + active_slot (12 bytes). */
    uint32_t expected_crc = crc32_naive(buf, 12);
    if (out->crc32 != expected_crc)
        return -4;

    return 0;
}

#endif /* BOOT_META_H */
