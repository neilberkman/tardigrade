/*
 * ESP-IDF OTA bootloader model for fault injection testing.
 *
 * Implements the exact same OTA slot selection algorithm as ESP-IDF:
 *   - Dual otadata sectors (32 bytes each, in separate 4KB erase sectors)
 *   - ota_seq selects partition: slot = (ota_seq - 1) % num_slots
 *   - CRC-32 covers ota_seq only (4 bytes)
 *   - Rollback state machine: NEW -> PENDING_VERIFY -> VALID/ABORTED
 *   - Higher valid ota_seq wins
 *
 * otadata entry format (esp_ota_select_entry_t, 32 bytes):
 *   uint32_t ota_seq;        offset 0   sequence number (1-based)
 *   uint8_t  seq_label[20];  offset 4   unused (0xFF from erase)
 *   uint32_t ota_state;      offset 24  state enum
 *   uint32_t crc;            offset 28  CRC-32 of ota_seq only
 *
 * OTA state values:
 *   0x00000000  NEW             - just written, first boot pending
 *   0x00000001  PENDING_VERIFY  - booted once, awaiting app confirm
 *   0x00000002  VALID           - confirmed working
 *   0x00000003  INVALID         - explicitly rejected
 *   0x00000004  ABORTED         - was PENDING_VERIFY, bootloader aborted
 *   0xFFFFFFFF  UNDEFINED       - erased flash default
 *
 * Memory layout (nRF52840, 1MB flash, cortex_m4_flash_fast.repl):
 *   0x00000000 - 0x0000BFFF  Bootloader (48KB boot_rom region)
 *   0x0000C000 - 0x0007FFFF  OTA slot 0 (464KB, in NVMC-managed flash)
 *   0x00080000 - 0x000F3FFF  OTA slot 1 (464KB, in NVMC-managed flash)
 *   0x000F8000 - 0x000F8FFF  OTAdata sector 0 (4KB)
 *   0x000F9000 - 0x000F9FFF  OTAdata sector 1 (4KB)
 *   0x000FC000 - 0x000FFFFF  Marker / reserved (16KB)
 *
 * Reference: ESP-IDF bootloader_utility.c
 *   https://github.com/espressif/esp-idf/blob/master/components/bootloader_support/src/bootloader_utility.c
 *
 * This is a clean-room model of the algorithm, not ESP-IDF code.
 * Licensed under Apache 2.0 (same as ESP-IDF).
 *
 * Compile-time defect injection (via -DESP_DEFECT=N):
 *   0  NONE           Correct implementation (default)
 *   1  NO_CRC         Skip CRC validation (otadata + copy-on-boot image verify)
 *   2  SINGLE_SECTOR  Only read otadata sector 0, ignore sector 1
 *   3  NO_ABORT       Don't abort PENDING_VERIFY entries on reboot
 *   4  NO_FALLBACK    Don't try other slot if selected slot is invalid
 *   5  CRC_COVERS_STATE  CRC covers ota_seq+ota_state (8 bytes) instead of just ota_seq
 */

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Defect selection                                                    */
/* ------------------------------------------------------------------ */

#define ESP_DEFECT_NONE             0
#define ESP_DEFECT_NO_CRC           1
#define ESP_DEFECT_SINGLE_SECTOR    2
#define ESP_DEFECT_NO_ABORT         3
#define ESP_DEFECT_NO_FALLBACK      4
#define ESP_DEFECT_CRC_COVERS_STATE 5

#ifndef ESP_DEFECT
#define ESP_DEFECT  ESP_DEFECT_NONE
#endif

/* ------------------------------------------------------------------ */
/* OTA state enum                                                      */
/* ------------------------------------------------------------------ */

#define OTA_IMG_NEW             0x00000000U
#define OTA_IMG_PENDING_VERIFY  0x00000001U
#define OTA_IMG_VALID           0x00000002U
#define OTA_IMG_INVALID         0x00000003U
#define OTA_IMG_ABORTED         0x00000004U
#define OTA_IMG_UNDEFINED       0xFFFFFFFFU

/* ------------------------------------------------------------------ */
/* Memory layout                                                       */
/* ------------------------------------------------------------------ */

/*
 * Memory layout: all writable regions must be in the NVMC-managed flash
 * area (0x0C000-0xFFFFF on cortex_m4_flash_fast.repl) so that NVMC can
 * track writes/erases for fault injection.
 *
 *   0x00000000 - 0x0000BFFF  Bootloader (48KB boot_rom, read-only)
 *   0x0000C000 - 0x0007FFFF  OTA slot 0 (464KB)
 *   0x00080000 - 0x000F3FFF  OTA slot 1 (464KB)
 *   0x000F4000 - 0x000F4FFF  Reserved
 *   0x000F8000 - 0x000F8FFF  OTAdata sector 0 (4KB)
 *   0x000F9000 - 0x000F9FFF  OTAdata sector 1 (4KB)
 *   0x000FC000 - 0x000FFFFF  Marker / reserved (16KB)
 */
#define OTADATA_BASE        0x000F8000U
#define OTADATA_SECTOR_SIZE 0x1000U     /* 4KB per sector */
#define SLOT0_BASE          0x0000C000U
#define SLOT1_BASE          0x00080000U
#define SLOT_SIZE           0x74000U    /* 464KB each */
#define NUM_OTA_SLOTS       2U
#define FLASH_PAGE_SIZE     0x1000U

#define SRAM_START          0x20000000U
#define SRAM_END            0x20040000U

#define SCB_VTOR            0xE000ED08U

/* ------------------------------------------------------------------ */
/* NVMC registers (nRF52840 — required for flash writes)               */
/* ------------------------------------------------------------------ */

#define NVMC_BASE           0x4001E000U
#define NVMC_READY          (*(volatile uint32_t *)(NVMC_BASE + 0x400))
#define NVMC_CONFIG         (*(volatile uint32_t *)(NVMC_BASE + 0x504))
#define NVMC_ERASEPAGE      (*(volatile uint32_t *)(NVMC_BASE + 0x508))

#define NVMC_CONFIG_REN     0U  /* Read-enable */
#define NVMC_CONFIG_WEN     1U  /* Write-enable */
#define NVMC_CONFIG_EEN     2U  /* Erase-enable */

/* ------------------------------------------------------------------ */
/* Rollback config                                                     */
/* ------------------------------------------------------------------ */

#ifndef ROLLBACK_ENABLED
#define ROLLBACK_ENABLED    1
#endif

/* ------------------------------------------------------------------ */
/* Marker address for test harness (app writes here on boot)           */
/* ------------------------------------------------------------------ */

#define MARKER_ADDR         0x000FC000U  /* In reserved area at end of flash */

/*
 * Optional copy-on-boot update trigger.
 *
 * Profiles can pre-seed UPDATE_REQ_ADDR with UPDATE_REQ_MAGIC to force a
 * staging->exec copy path that exercises many writes. The bootloader clears
 * this flag before the copy, so a mid-copy power loss leaves a partial exec
 * image that is NOT automatically recopied on the next boot.
 */
#define UPDATE_REQ_ADDR     0x000FC040U
#define UPDATE_REQ_MAGIC    0x55445021U  /* "UPD!" */
#define COPY_ON_BOOT_BYTES  0x2000U      /* 8KB copy window */

/* ------------------------------------------------------------------ */
/* CRC-32 table (polynomial 0xEDB88320)                                */
/* ------------------------------------------------------------------ */

static uint32_t crc32_table[256];

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1)
                c = 0xEDB88320U ^ (c >> 1);
            else
                c >>= 1;
        }
        crc32_table[i] = c;
    }
}

/*
 * ESP-IDF's CRC: esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4)
 * ROM does: crc = ~init, process bytes, return ~crc
 * With init=0xFFFFFFFF: effective start=0, final XOR=0xFFFFFFFF
 */
__attribute__((unused))
static uint32_t esp_otadata_crc(uint32_t ota_seq)
{
    const uint8_t *data = (const uint8_t *)&ota_seq;
    uint32_t crc = 0x00000000U;  /* ~0xFFFFFFFF inside ROM */
    for (int i = 0; i < 4; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;   /* ~crc at end of ROM */
}

/* ------------------------------------------------------------------ */
/* otadata entry                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t ota_seq;
    uint8_t  seq_label[20];
    uint32_t ota_state;
    uint32_t crc;
} __attribute__((packed)) esp_ota_select_entry_t;

/* ------------------------------------------------------------------ */
/* Flash operations via NVMC                                           */
/* ------------------------------------------------------------------ */

static void nvmc_wait(void)
{
    while (NVMC_READY == 0)
        ;
}

static void flash_write_word(volatile uint32_t *addr, uint32_t value);

static void flash_erase_page(uint32_t page_addr)
{
    NVMC_CONFIG = NVMC_CONFIG_EEN;
    nvmc_wait();
    NVMC_ERASEPAGE = page_addr;
    nvmc_wait();
    NVMC_CONFIG = NVMC_CONFIG_REN;
    nvmc_wait();
}

static uint32_t crc32_region(uint32_t base, uint32_t size_bytes)
{
    const volatile uint8_t *data = (const volatile uint8_t *)base;
    uint32_t crc = 0x00000000U;
    for (uint32_t i = 0; i < size_bytes; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

static void flash_copy_region(uint32_t dst_base, uint32_t src_base, uint32_t size_bytes)
{
    uint32_t bytes = size_bytes & ~3U;

    if (bytes == 0 || bytes > SLOT_SIZE)
        return;

    for (uint32_t page = dst_base; page < dst_base + bytes; page += FLASH_PAGE_SIZE)
        flash_erase_page(page);

    for (uint32_t off = 0; off < bytes; off += 4U) {
        uint32_t w = *(const volatile uint32_t *)(src_base + off);
        flash_write_word((volatile uint32_t *)(dst_base + off), w);
    }
}

static int copy_on_boot_requested(void)
{
    uint32_t req = *(const volatile uint32_t *)UPDATE_REQ_ADDR;
    return req == UPDATE_REQ_MAGIC;
}

static void clear_copy_on_boot_request(void)
{
    flash_write_word((volatile uint32_t *)UPDATE_REQ_ADDR, 0x00000000U);
}

static uint32_t maybe_copy_staging_to_exec(uint32_t selected_boot_addr)
{
    uint32_t src_crc;
    uint32_t dst_crc;

    if (selected_boot_addr != SLOT1_BASE)
        return selected_boot_addr;

    if (!copy_on_boot_requested())
        return selected_boot_addr;

    /*
     * HARDENED: Perform the copy FIRST.
     * We don't clear the request until we know the destination is valid.
     * This ensures resilience against power loss mid-copy.
     */
    flash_copy_region(SLOT0_BASE, SLOT1_BASE, COPY_ON_BOOT_BYTES);

    src_crc = crc32_region(SLOT1_BASE, COPY_ON_BOOT_BYTES);
    dst_crc = crc32_region(SLOT0_BASE, COPY_ON_BOOT_BYTES);

#if ESP_DEFECT == ESP_DEFECT_NO_CRC
    /* DEFECT: skip copied-image CRC validation and trust the partial image. */
    (void)src_crc;
    (void)dst_crc;
    clear_copy_on_boot_request();
    return SLOT0_BASE;
#else
    /* Correct: only boot copied exec image if it matches staging exactly. */
    if (dst_crc == src_crc) {
        clear_copy_on_boot_request();
        return SLOT0_BASE;
    }
    /*
     * If CRC failed, we leave the request set so we can try again,
     * but we boot from the original staging image for now.
     */
    return SLOT1_BASE;
#endif
}

static void flash_write_word(volatile uint32_t *addr, uint32_t value)
{
    NVMC_CONFIG = NVMC_CONFIG_WEN;
    nvmc_wait();
    *addr = value;
    nvmc_wait();
    NVMC_CONFIG = NVMC_CONFIG_REN;
    nvmc_wait();
}

__attribute__((unused))
static void flash_write_otadata(uint32_t sector_addr,
                                const esp_ota_select_entry_t *entry)
{
    /* Erase the 4KB sector first */
    flash_erase_page(sector_addr);

    /* Write the 32-byte entry word-by-word */
    const uint32_t *src = (const uint32_t *)entry;
    volatile uint32_t *dst = (volatile uint32_t *)sector_addr;
    for (unsigned i = 0; i < sizeof(esp_ota_select_entry_t) / 4; i++) {
        flash_write_word(&dst[i], src[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Read otadata entries                                                 */
/* ------------------------------------------------------------------ */

static void read_otadata(esp_ota_select_entry_t out[2])
{
    const esp_ota_select_entry_t *s0 =
        (const esp_ota_select_entry_t *)OTADATA_BASE;

    for (unsigned i = 0; i < 8; i++)
        ((uint32_t *)&out[0])[i] = ((const uint32_t *)s0)[i];

#if ESP_DEFECT == ESP_DEFECT_SINGLE_SECTOR
    /* DEFECT: only read sector 0, fill sector 1 as erased.
     * No redundancy — if sector 0 is mid-erase during rewrite, state is lost. */
    for (unsigned i = 0; i < 8; i++)
        ((uint32_t *)&out[1])[i] = 0xFFFFFFFFU;
#else
    {
        const esp_ota_select_entry_t *s1 =
            (const esp_ota_select_entry_t *)(OTADATA_BASE + OTADATA_SECTOR_SIZE);
        for (unsigned i = 0; i < 8; i++)
            ((uint32_t *)&out[1])[i] = ((const uint32_t *)s1)[i];
    }
#endif
}

/* ------------------------------------------------------------------ */
/* Validate an otadata entry                                           */
/* ------------------------------------------------------------------ */

static int otadata_valid(const esp_ota_select_entry_t *e)
{
    /* Erased / uninitialized */
    if (e->ota_seq == 0xFFFFFFFFU)
        return 0;

    /* Explicitly bad states */
    if (e->ota_state == OTA_IMG_INVALID || e->ota_state == OTA_IMG_ABORTED)
        return 0;

#if ESP_DEFECT == ESP_DEFECT_NO_CRC
    /* DEFECT: skip CRC validation entirely.
     * Corrupted entries (partial writes) accepted as valid. */
    (void)0;
#elif ESP_DEFECT == ESP_DEFECT_CRC_COVERS_STATE
    /* DEFECT: CRC covers ota_seq + ota_state (8 bytes) instead of just ota_seq.
     * After bootloader writes new ota_state (e.g. PENDING_VERIFY), the CRC
     * no longer matches because it was computed over the OLD state value.
     * On next boot, the entry appears corrupt → wrong slot or brick. */
    {
        uint32_t buf[2] = { e->ota_seq, e->ota_state };
        const uint8_t *data = (const uint8_t *)buf;
        uint32_t crc = 0x00000000U;
        for (int i = 0; i < 8; i++)
            crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        crc ^= 0xFFFFFFFFU;
        if (e->crc != crc)
            return 0;
    }
#else
    /* Correct: CRC covers ota_seq only (4 bytes) */
    if (e->crc != esp_otadata_crc(e->ota_seq))
        return 0;
#endif

    return 1;
}

/* ------------------------------------------------------------------ */
/* Select active otadata entry (highest ota_seq wins)                  */
/* ------------------------------------------------------------------ */

static int select_otadata(const esp_ota_select_entry_t two[2],
                          int valid0, int valid1)
{
    if (valid0 && valid1)
        return (two[0].ota_seq >= two[1].ota_seq) ? 0 : 1;
    if (valid0)
        return 0;
    if (valid1)
        return 1;
    return -1;  /* neither valid */
}

/* ------------------------------------------------------------------ */
/* Vector table validation                                             */
/* ------------------------------------------------------------------ */

static int vector_looks_valid(uint32_t base)
{
    uint32_t sp = *(const volatile uint32_t *)(base);
    uint32_t rv = *(const volatile uint32_t *)(base + 4);
    uint32_t pc = rv & ~1U;
    int pc_in_any_slot = (
        (pc >= SLOT0_BASE && pc < SLOT0_BASE + SLOT_SIZE)
        || (pc >= SLOT1_BASE && pc < SLOT1_BASE + SLOT_SIZE)
    );

    return (sp >= SRAM_START && sp <= SRAM_END)
        && ((rv & 1U) == 1U)
        && pc_in_any_slot;
}

/* ------------------------------------------------------------------ */
/* Boot into a slot                                                    */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
static void boot_slot(uint32_t slot_base)
{
    uint32_t sp = *(volatile uint32_t *)(slot_base);
    uint32_t pc = *(volatile uint32_t *)(slot_base + 4);
    *(volatile uint32_t *)SCB_VTOR = slot_base;
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    __asm volatile(
        "MSR MSP, %0\n"
        "DSB\n"
        "ISB\n"
        "BX  %1\n"
        :
        : "r"(sp), "r"(pc | 1)
    );
    __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* Slot base address from index                                        */
/* ------------------------------------------------------------------ */

static uint32_t slot_base(unsigned idx)
{
    return (idx == 0) ? SLOT0_BASE : SLOT1_BASE;
}

/* ------------------------------------------------------------------ */
/* Main boot logic                                                     */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
void esp_ota_main(void)
{
    esp_ota_select_entry_t two[2];
    int valid[2];
    int active;
    uint32_t boot_index;
    uint32_t boot_addr;

    crc32_init();
    read_otadata(two);

#if ROLLBACK_ENABLED
    /*
     * Rollback step 1: abort any PENDING_VERIFY entries.
     * In ESP-IDF, this happens BEFORE slot selection. If the previously-booted
     * image was PENDING_VERIFY and didn't confirm, it gets ABORTED here, which
     * makes it invalid for selection — triggering rollback to the other entry.
     */
#if ESP_DEFECT == ESP_DEFECT_NO_ABORT
    /* DEFECT: skip aborting PENDING_VERIFY entries.
     * Unconfirmed image stays PENDING_VERIFY forever, keeps getting selected
     * and booted repeatedly. No rollback ever happens. */
    (void)0;
#else
    for (int i = 0; i < 2; i++) {
        if (two[i].ota_state == OTA_IMG_PENDING_VERIFY) {
            two[i].ota_state = OTA_IMG_ABORTED;
            uint32_t sector = OTADATA_BASE + (uint32_t)i * OTADATA_SECTOR_SIZE;
            flash_write_otadata(sector, &two[i]);
        }
    }
#endif
#endif

    valid[0] = otadata_valid(&two[0]);
    valid[1] = otadata_valid(&two[1]);
    active = select_otadata(two, valid[0], valid[1]);

    if (active < 0) {
        /*
         * No valid otadata: Exhaustive fallback sweep.
         * Real ESP-IDF probes ALL partitions (factory, OTA slots, and test app)
         * in this case. We probe both available slots.
         */
        if (vector_looks_valid(SLOT0_BASE))
            boot_slot(SLOT0_BASE);
        if (vector_looks_valid(SLOT1_BASE))
            boot_slot(SLOT1_BASE);

        /* Total brick */
        while (1) __asm volatile("WFI");
    }

    /* Map ota_seq to slot index */
    boot_index = (two[active].ota_seq - 1U) % NUM_OTA_SLOTS;
    boot_addr = slot_base(boot_index);

    /*
     * Optional copy-on-boot path for update stress testing.
     * This keeps existing otadata logic intact while adding a realistic
     * erase+copy+verify flow when UPDATE_REQ_ADDR is pre-seeded.
     */
    boot_addr = maybe_copy_staging_to_exec(boot_addr);
    if (boot_addr == SLOT0_BASE)
        boot_index = 0;
    else if (boot_addr == SLOT1_BASE)
        boot_index = 1;

#if ROLLBACK_ENABLED
    /*
     * Rollback step 2: transition NEW -> PENDING_VERIFY.
     * This write is the vulnerability window: if power is lost after writing
     * PENDING_VERIFY but before the app confirms, the NEXT boot will abort
     * this entry and roll back to the previous one.
     */
    if (two[active].ota_state == OTA_IMG_NEW) {
        two[active].ota_state = OTA_IMG_PENDING_VERIFY;
        uint32_t sector = OTADATA_BASE + (uint32_t)active * OTADATA_SECTOR_SIZE;
        flash_write_otadata(sector, &two[active]);
    }
#endif

    /* Validate and boot */
    if (vector_looks_valid(boot_addr))
        boot_slot(boot_addr);

#if ESP_DEFECT == ESP_DEFECT_NO_FALLBACK
    /* DEFECT: no fallback — if selected slot is invalid, brick immediately.
     * Real ESP-IDF tries all OTA slots before giving up. */
    while (1) __asm volatile("WFI");
#else
    /* Selected slot invalid — try the other slot */
    {
        uint32_t other_index = (boot_index + 1U) % NUM_OTA_SLOTS;
        uint32_t other_addr = slot_base(other_index);
        if (vector_looks_valid(other_addr))
            boot_slot(other_addr);
    }

    /* Nothing bootable — brick */
    while (1) __asm volatile("WFI");
#endif
}
