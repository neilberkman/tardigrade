/*
 * Standalone riotboot-compatible bootloader for fault injection testing.
 *
 * Implements the exact same slot selection algorithm as RIOT OS riotboot:
 *   1. Iterate slots 0 and 1.
 *   2. Validate header: magic 0x544F4952 ("RIOT") + Fletcher32 checksum.
 *   3. Check start_addr matches expected slot image start.
 *   4. Boot the slot with the highest version.
 *   5. If no valid slot, enter infinite loop (brick).
 *
 * Header format (riotboot_hdr_t, 16 bytes):
 *   uint32_t magic_number;   // 0x544F4952
 *   uint32_t version;        // firmware version (higher = newer)
 *   uint32_t start_addr;     // address of firmware code (after header)
 *   uint32_t chksum;         // Fletcher32 of first 12 bytes
 *
 * Memory layout (nRF52840, 1MB flash):
 *   0x00000000 - 0x00001FFF  Bootloader (8KB)
 *   0x00002000 - 0x000020FF  Slot 0 header (256B)
 *   0x00002100 - 0x00080FFF  Slot 0 firmware (~508KB - 256B)
 *   0x00081000 - 0x000810FF  Slot 1 header (256B)
 *   0x00081100 - 0x000FFFFF  Slot 1 firmware (~508KB - 256B)
 *
 * This is a clean-room reimplementation of the algorithm from:
 *   https://github.com/RIOT-OS/RIOT/blob/master/bootloaders/riotboot/main.c
 * Licensed under LGPL v2.1 (same as RIOT OS).
 */

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* riotboot header                                                     */
/* ------------------------------------------------------------------ */

#define RIOTBOOT_MAGIC      0x544F4952U  /* "RIOT" little-endian */
#define RIOTBOOT_HDR_LEN    0x100        /* 256 bytes, padded for alignment */
#define NUM_SLOTS           2

typedef struct {
    uint32_t magic_number;
    uint32_t version;
    uint32_t start_addr;
    uint32_t chksum;
} riotboot_hdr_t;

/* ------------------------------------------------------------------ */
/* Flash layout                                                        */
/* ------------------------------------------------------------------ */

#define RIOTBOOT_LEN        0x2000       /* 8KB bootloader region */
#define ROM_LEN             0x100000     /* 1MB total flash */
#define SLOT_SIZE           ((ROM_LEN - RIOTBOOT_LEN) / NUM_SLOTS)  /* 0x7F000 = 508KB */

/* Slot 0: header at RIOTBOOT_LEN, image at RIOTBOOT_LEN + HDR_LEN */
#define SLOT0_HDR_ADDR      (RIOTBOOT_LEN)
#define SLOT0_IMG_ADDR      (RIOTBOOT_LEN + RIOTBOOT_HDR_LEN)

/* Slot 1: header at RIOTBOOT_LEN + SLOT_SIZE, image at that + HDR_LEN */
#define SLOT1_HDR_ADDR      (RIOTBOOT_LEN + SLOT_SIZE)
#define SLOT1_IMG_ADDR      (RIOTBOOT_LEN + SLOT_SIZE + RIOTBOOT_HDR_LEN)

/* ------------------------------------------------------------------ */
/* Fletcher32 checksum (exact RIOT implementation)                     */
/* ------------------------------------------------------------------ */

static uint32_t fletcher32(const uint16_t *data, unsigned len)
{
    uint32_t sum1 = 0xFFFF;
    uint32_t sum2 = 0xFFFF;

    while (len) {
        unsigned batch = (len > 359) ? 359 : len;
        len -= batch;
        while (batch--) {
            sum1 += *data++;
            sum2 += sum1;
        }
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    }

    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    return (sum2 << 16) | sum1;
}

/* ------------------------------------------------------------------ */
/* Header validation                                                   */
/* ------------------------------------------------------------------ */

static int riotboot_hdr_validate(const riotboot_hdr_t *hdr)
{
    if (hdr->magic_number != RIOTBOOT_MAGIC) {
        return -1;
    }
    /* Checksum covers first 3 fields (12 bytes = 6 uint16_t words) */
    uint32_t computed = fletcher32((const uint16_t *)hdr, 6);
    if (computed != hdr->chksum) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Boot: set MSP, branch to reset vector                               */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
static void boot_image(uint32_t image_addr)
{
    uint32_t sp = *(volatile uint32_t *)(image_addr);
    uint32_t pc = *(volatile uint32_t *)(image_addr + 4);
    /* Set VTOR to the image's vector table */
    *(volatile uint32_t *)0xE000ED08 = image_addr;
    __asm volatile (
        "MSR MSP, %0\n"
        "BX  %1\n"
        :
        : "r" (sp), "r" (pc | 1)
    );
    __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* Slot table                                                          */
/* ------------------------------------------------------------------ */

static const struct {
    uint32_t hdr_addr;
    uint32_t img_addr;
} slot_table[NUM_SLOTS] = {
    { SLOT0_HDR_ADDR, SLOT0_IMG_ADDR },
    { SLOT1_HDR_ADDR, SLOT1_IMG_ADDR },
};

/* ------------------------------------------------------------------ */
/* Main: select and boot highest-version valid slot                    */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
void riotboot_main(void)
{
    uint32_t best_version = 0;
    int best_slot = -1;

    for (int i = 0; i < NUM_SLOTS; i++) {
        const riotboot_hdr_t *hdr =
            (const riotboot_hdr_t *)slot_table[i].hdr_addr;

        /* Validate header integrity */
        if (riotboot_hdr_validate(hdr) != 0) {
            continue;
        }

        /* Check start_addr matches expected slot image address */
        if (hdr->start_addr != slot_table[i].img_addr) {
            continue;
        }

        /* Pick highest version */
        if (best_slot == -1 || hdr->version > best_version) {
            best_version = hdr->version;
            best_slot = i;
        }
    }

    if (best_slot >= 0) {
        boot_image(slot_table[best_slot].img_addr);
    }

    /* No valid slot — brick */
    while (1) {
        __asm volatile ("WFI");
    }
}
