/*
 * Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr EEPROM storage target running on external 24-series I2C EEPROM
 * (Microchip 24LC256 via Zephyr's `atmel,at24` driver on nRF52840 TWI0 @ 0x50).
 *
 * Storage layout (64-byte page-aligned CRC-protected records):
 *   - Page 0 (0x0000..0x003F): Pre-cut anchor record A (key=1, payload[0]=0xDEADBEEF)
 *   - Page 1 (0x0040..0x007F): Pre-cut anchor record B (key=2, payload[0]=0x55667788)
 *   - Pages 2..5 (0x0080..0x017F): 4 journaled update pages written during runtime.
 *
 * On each boot:
 *   1. Reads back pre-cut anchor records A and B via eeprom_read() over I2C0
 *      and validates their magic and IEEE CRC-32.
 *   2. Scans journal pages 2..5 via eeprom_read(): any page left partially
 *      committed by a power cut during the EEPROM internal write cycle (t_WR)
 *      fails CRC-32 validation and is cleanly discarded in favor of the latest
 *      valid committed sequence.
 *   3. Writes 4 new 64-byte journal pages via eeprom_write() over I2C0.
 *   4. Re-reads pre-cut anchor records A and B via eeprom_read(), publishes the
 *      read-back values and verification status to SRAM at 0x2003F000..0x2003F00C,
 *      for the audit harness to evaluate directly.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/eeprom.h>
#include <zephyr/sys/crc.h>
#include <cmsis_core.h>
#include <stdint.h>
#include <string.h>

#define EEPROM_NODE            DT_ALIAS(eeprom_0)
#define EEPROM_PAGE_SIZE       64U
#define RECORD_MAGIC           0x45455052UL /* "EEPR" */

#define EXPECTED_ANCHOR_A      0xDEADBEEFUL
#define EXPECTED_ANCHOR_B      0x55667788UL

#define RESULT_SRAM_BASE       0x2003F000UL

struct eeprom_page_record {
    uint32_t magic;
    uint32_t key;
    uint32_t sequence;
    uint32_t payload[12];
    uint32_t crc32;
};

struct sram_verdict {
    volatile uint32_t magic;
    volatile uint32_t anchor_a_value;
    volatile uint32_t anchor_b_value;
    volatile uint32_t status_ok;
    volatile uint32_t latest_sequence;
};

static uint32_t compute_record_crc(const struct eeprom_page_record *rec)
{
    return crc32_ieee((const uint8_t *)rec,
                      sizeof(struct eeprom_page_record) - sizeof(uint32_t));
}

static bool record_is_valid(const struct eeprom_page_record *rec, uint32_t expected_key)
{
    if (rec->magic != RECORD_MAGIC) {
        return false;
    }
    if (expected_key != 0U && rec->key != expected_key) {
        return false;
    }
    return compute_record_crc(rec) == rec->crc32;
}

int main(void)
{
    struct sram_verdict *verdict = (struct sram_verdict *)RESULT_SRAM_BASE;
    const struct device *eeprom = DEVICE_DT_GET(EEPROM_NODE);
    struct eeprom_page_record rec_a;
    struct eeprom_page_record rec_b;
    int rc;

    verdict->magic = 0U;
    verdict->anchor_a_value = 0U;
    verdict->anchor_b_value = 0U;
    verdict->status_ok = 0U;
    verdict->latest_sequence = 0U;

    if (!device_is_ready(eeprom)) {
        verdict->magic = 0xBAD10001UL;
        goto halt;
    }

    /* 1. Read back pre-cut anchor records from pages 0 and 1. */
    rc = eeprom_read(eeprom, 0U * EEPROM_PAGE_SIZE, &rec_a, sizeof(rec_a));
    if (rc != 0 || !record_is_valid(&rec_a, 1U)) {
        verdict->magic = 0xBAD10002UL;
        goto halt;
    }
    rc = eeprom_read(eeprom, 1U * EEPROM_PAGE_SIZE, &rec_b, sizeof(rec_b));
    if (rc != 0 || !record_is_valid(&rec_b, 2U)) {
        verdict->magic = 0xBAD10003UL;
        goto halt;
    }

    /* 2. Scan journal pages 2..5; ignore any torn page interrupted mid-write-cycle. */
    uint32_t best_seq = 0U;
    for (uint32_t p = 2U; p < 6U; p++) {
        struct eeprom_page_record jrec;
        rc = eeprom_read(eeprom, p * EEPROM_PAGE_SIZE, &jrec, sizeof(jrec));
        if (rc == 0 && record_is_valid(&jrec, 3U)) {
            if (jrec.sequence > best_seq) {
                best_seq = jrec.sequence;
            }
        }
    }

    /* 3. Write 4 new 64-byte journal pages across pages 2..5. */
    for (uint32_t step = 0U; step < 4U; step++) {
        struct eeprom_page_record wrec;
        best_seq++;
        wrec.magic = RECORD_MAGIC;
        wrec.key = 3U;
        wrec.sequence = best_seq;
        for (uint32_t i = 0U; i < 12U; i++) {
            wrec.payload[i] = (0xA0000000UL | (best_seq << 8) | i) ^ rec_a.payload[0];
        }
        wrec.crc32 = compute_record_crc(&wrec);

        uint32_t target_page = 2U + (step & 3U);
        rc = eeprom_write(eeprom, target_page * EEPROM_PAGE_SIZE, &wrec, sizeof(wrec));
        if (rc != 0) {
            verdict->magic = 0xBAD10004UL;
            goto halt;
        }
    }

    /* 4. Re-read pre-cut anchor records A and B and verify integrity. */
    struct eeprom_page_record verify_a;
    struct eeprom_page_record verify_b;
    int ra = eeprom_read(eeprom, 0U * EEPROM_PAGE_SIZE, &verify_a, sizeof(verify_a));
    int rb = eeprom_read(eeprom, 1U * EEPROM_PAGE_SIZE, &verify_b, sizeof(verify_b));

    verdict->magic = RECORD_MAGIC;
    verdict->anchor_a_value = verify_a.payload[0];
    verdict->anchor_b_value = verify_b.payload[0];
    verdict->latest_sequence = best_seq;
    if (ra == 0 && rb == 0 &&
        record_is_valid(&verify_a, 1U) &&
        record_is_valid(&verify_b, 2U) &&
        verify_a.payload[0] == EXPECTED_ANCHOR_A &&
        verify_b.payload[0] == EXPECTED_ANCHOR_B) {
        verdict->status_ok = 1U;
    } else {
        verdict->status_ok = 0U;
    }

    (void)irq_lock();
halt:
    (void)irq_lock();
    while (1) {
        __NOP();
    }
    return 0;
}
