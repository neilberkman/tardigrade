/*
 * Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr NVS storage subsystem target running on external JEDEC SPI NOR flash
 * (jedec,spi-nor on nRF52840 SPI2).
 *
 * On each boot:
 *   1. Mounts the 3-sector (12 KiB) NVS filesystem on spi_nor0 (`nvs_storage`).
 *   2. Reads back the pre-cut anchor records (KEY_ANCHOR_1 = 0xC0FFEE11 and
 *      KEY_ANCHOR_2 = 0x5AFE2233) that were committed before the power cut.
 *   3. Performs a batch of NVS writes (and garbage-collection sector erase/rotation)
 *      so fault sweeps cut both SPI NOR Page Programs (0x02) and Sector Erases (0x20).
 *   4. Re-reads the pre-cut anchor records from SPI NOR flash, publishes the
 *      read-back values and verification verdict to SRAM at 0x2003F000..0x2003F00C,
 *      for the audit harness to evaluate directly.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/fs/nvs.h>
#include <cmsis_core.h>
#include <stdint.h>
#include <string.h>

#define NVS_PARTITION          nvs_storage
#define NVS_PARTITION_DEVICE   FIXED_PARTITION_DEVICE(NVS_PARTITION)
#define NVS_PARTITION_OFFSET   FIXED_PARTITION_OFFSET(NVS_PARTITION)

#define KEY_ANCHOR_1           0x0001U
#define KEY_ANCHOR_2           0x0002U
#define KEY_COUNTER            0x0010U
#define KEY_BLOB               0x0020U

#define EXPECTED_ANCHOR_1      0xC0FFEE11UL
#define EXPECTED_ANCHOR_2      0x5AFE2233UL
#define RESULT_MAGIC_SPINOR    0x5350494EUL /* "SPIN" */

#define RESULT_SRAM_BASE       0x2003F000UL

struct sram_verdict {
    volatile uint32_t magic;
    volatile uint32_t anchor1_value;
    volatile uint32_t anchor2_value;
    volatile uint32_t status_ok;
    volatile uint32_t counter_value;
};

int main(void)
{
    struct sram_verdict *verdict = (struct sram_verdict *)RESULT_SRAM_BASE;
    struct nvs_fs fs;
    struct flash_pages_info info;
    int rc;

    verdict->magic = 0U;
    verdict->anchor1_value = 0U;
    verdict->anchor2_value = 0U;
    verdict->status_ok = 0U;
    verdict->counter_value = 0U;

    memset(&fs, 0, sizeof(fs));
    fs.flash_device = NVS_PARTITION_DEVICE;
    if (!device_is_ready(fs.flash_device)) {
        verdict->magic = 0xBAD00001UL;
        goto halt;
    }

    fs.offset = NVS_PARTITION_OFFSET;
    rc = flash_get_page_info_by_offs(fs.flash_device, fs.offset, &info);
    if (rc != 0) {
        verdict->magic = 0xBAD00002UL;
        goto halt;
    }
    fs.sector_size = info.size;
    fs.sector_count = 3U;

    rc = nvs_mount(&fs);
    if (rc != 0) {
        verdict->magic = 0xBAD00003UL;
        goto halt;
    }

    /* Read back pre-cut anchor records from SPI NOR flash. */
    uint32_t a1 = 0U;
    uint32_t a2 = 0U;
    ssize_t r1 = nvs_read(&fs, KEY_ANCHOR_1, &a1, sizeof(a1));
    ssize_t r2 = nvs_read(&fs, KEY_ANCHOR_2, &a2, sizeof(a2));
    if (r1 != (ssize_t)sizeof(a1) || r2 != (ssize_t)sizeof(a2)) {
        verdict->magic = 0xBAD00004UL;
        verdict->anchor1_value = a1;
        verdict->anchor2_value = a2;
        goto halt;
    }

    /* Perform runtime NVS updates across the SPI NOR sectors (triggers both
     * 0x02 Page Programs and 0x20 4 KiB Sector Erase during NVS GC rotation).
     */
    uint32_t counter = 0U;
    (void)nvs_read(&fs, KEY_COUNTER, &counter, sizeof(counter));
    for (uint32_t step = 0U; step < 4U; step++) {
        counter++;
        rc = (int)nvs_write(&fs, KEY_COUNTER, &counter, sizeof(counter));
        if (rc < 0) {
            verdict->magic = 0xBAD00005UL;
            goto halt;
        }
    }

    uint32_t blob[4] = {
        0xA5A50000UL | (counter & 0xFFFFUL),
        0x5A5A0000UL | (counter & 0xFFFFUL),
        EXPECTED_ANCHOR_1 ^ counter,
        EXPECTED_ANCHOR_2 ^ counter,
    };
    rc = (int)nvs_write(&fs, KEY_BLOB, blob, sizeof(blob));
    if (rc < 0) {
        verdict->magic = 0xBAD00006UL;
        goto halt;
    }

    /* Re-read the pre-cut anchor records after runtime updates/recovery. */
    uint32_t verify_a1 = 0U;
    uint32_t verify_a2 = 0U;
    r1 = nvs_read(&fs, KEY_ANCHOR_1, &verify_a1, sizeof(verify_a1));
    r2 = nvs_read(&fs, KEY_ANCHOR_2, &verify_a2, sizeof(verify_a2));

    verdict->magic = RESULT_MAGIC_SPINOR;
    verdict->anchor1_value = verify_a1;
    verdict->anchor2_value = verify_a2;
    verdict->counter_value = counter;
    if (r1 == (ssize_t)sizeof(verify_a1) &&
        r2 == (ssize_t)sizeof(verify_a2) &&
        verify_a1 == EXPECTED_ANCHOR_1 &&
        verify_a2 == EXPECTED_ANCHOR_2) {
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
