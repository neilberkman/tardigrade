/*
 * Standalone nxboot-style bootloader for Renode fault-injection testing.
 *
 * Reimplements the NuttX nxboot algorithm (three-partition, copy-based,
 * CRC-validated, magic-flip commit protocol) without any NuttX OS
 * dependencies.  Flash I/O is replaced with direct memory-mapped access.
 *
 * Memory map (Cortex-M0+ on Renode NVMemory):
 *   0x10000000 - 0x10001FFF  Bootloader code  (8KB)
 *   0x10002000 - 0x10024FFF  Primary slot     (140KB, slot 0)
 *   0x10025000 - 0x10047FFF  Secondary slot   (140KB, slot 1)
 *   0x10048000 - 0x1006AFFF  Tertiary slot    (140KB, slot 2)
 *   0x1006B000 - 0x1006B003  Confirm flag     (1 word: 1=app has confirmed)
 *   0x20000000 - 0x2001FFFF  SRAM             (128KB)
 *
 * The three-slot design is sized for Renode testing. Real nxboot
 * deployments use whatever the board's MTD partitions provide.
 *
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -O2 -ffreestanding \
 *       -nostdlib -Wl,--gc-sections -T linker_boot.ld \
 *       -o bootloader_nxboot.elf bootloader_nxboot.c
 *
 * Defect variants via compile-time #defines:
 *   NXBOOT_DEFECT=0  (none)           Correct implementation
 *   NXBOOT_DEFECT=1  (no_recovery)    Skip recovery creation before update
 *   NXBOOT_DEFECT=2  (no_revert)      Skip revert when unconfirmed
 *   NXBOOT_DEFECT=3  (no_crc)         Skip CRC validation entirely
 *
 * Reference: https://github.com/apache/nuttx-apps/tree/master/boot/nxboot
 */

#include <stdint.h>
#include "nxboot_standalone.h"

/* --- Memory map --- */
#define BOOT_BASE        ((uintptr_t)0x10000000u)
#define PRIMARY_BASE     ((uintptr_t)0x10002000u)
#define SECONDARY_BASE   ((uintptr_t)0x10025000u)
#define TERTIARY_BASE    ((uintptr_t)0x10048000u)
#define SLOT_SIZE        (0x23000u)              /* 140KB per slot */
#define CONFIRM_FLAG     ((uintptr_t)0x1006B000u)
#define ERASE_SECTOR     (0x1000u)               /* 4KB erase granularity */

#define SCB_VTOR_ADDR    ((uintptr_t)0xE000ED08u)
#define SRAM_START       ((uintptr_t)0x20000000u)
#define SRAM_END         ((uintptr_t)0x20020000u)

#define PLATFORM_ID      (0x0u)  /* Must match image header identifier */

/* --- Defect selection --- */
#ifndef NXBOOT_DEFECT
#define NXBOOT_DEFECT 0
#endif

#define DEFECT_NONE         0
#define DEFECT_NO_RECOVERY  1
#define DEFECT_NO_REVERT    2
#define DEFECT_NO_CRC       3

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector")))
const void* vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    0,
    0,
    0,
    0,
    Default_Handler,
    Default_Handler,
    0,
    Default_Handler,
    Default_Handler,
};

void Default_Handler(void)
{
    while(1)
    {
    }
}

/* --- CRC-32 (standard polynomial, same as nxboot) --- */
static uint32_t crc32_update(uint32_t crc, const uint8_t* data, uint32_t len)
{
    for(uint32_t i = 0u; i < len; i++)
    {
        crc ^= data[i];
        for(uint32_t b = 0u; b < 8u; b++)
        {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return crc;
}

/* --- Slot base address lookup --- */
static uintptr_t slot_base(uint32_t slot)
{
    if(slot == NXBOOT_SECONDARY) return SECONDARY_BASE;
    if(slot == NXBOOT_TERTIARY)  return TERTIARY_BASE;
    return PRIMARY_BASE;
}

/* --- Read image header from a slot --- */
static void read_header(uint32_t slot, nxboot_img_header_t* hdr)
{
    const uint8_t* src = (const uint8_t*)slot_base(slot);
    uint8_t* dst = (uint8_t*)hdr;
    for(uint32_t i = 0u; i < sizeof(nxboot_img_header_t); i++)
    {
        dst[i] = src[i];
    }
}

/* --- Validate image CRC --- */
static int validate_image(uint32_t slot)
{
#if NXBOOT_DEFECT == DEFECT_NO_CRC
    /* Defect: skip CRC validation entirely */
    (void)slot;
    return 1;
#else
    nxboot_img_header_t hdr;
    read_header(slot, &hdr);

    /* Check magic */
    if(hdr.magic != NXBOOT_HEADER_MAGIC && !IS_INTERNAL_MAGIC(hdr.magic))
    {
        return 0;
    }

    /* CRC covers from offset 0x0C (after CRC field) to end of image */
    uintptr_t base = slot_base(slot);
    uint32_t crc_offset = 12u; /* offsetof(crc) + sizeof(crc) = 8 + 4 */
    uint32_t total = hdr.header_size + hdr.size;
    if(total <= crc_offset || total > SLOT_SIZE)
    {
        return 0;
    }
    uint32_t crc_len = total - crc_offset;

    const uint8_t* data = (const uint8_t*)(base + crc_offset);
    uint32_t computed = crc32_update(0xFFFFFFFFu, data, crc_len) ^ 0xFFFFFFFFu;

    return (computed == hdr.crc) ? 1 : 0;
#endif
}

/* --- Vector table sanity check --- */
static int vector_looks_valid(uintptr_t base, uint32_t header_size)
{
    uintptr_t img_base = base + header_size;
    const uint32_t sp = *(const uint32_t*)(img_base + 0u);
    const uint32_t rv = *(const uint32_t*)(img_base + 4u);
    const uintptr_t pc = (uintptr_t)(rv & (~1u));

    return (sp >= SRAM_START && sp <= SRAM_END)
        && ((rv & 1u) == 1u)
        && (pc >= img_base && pc < (img_base + SLOT_SIZE - header_size));
}

/* --- Copy partition with magic flip --- */
static void copy_partition(uint32_t dst_slot, uint32_t src_slot, int is_update, uint32_t update_slot)
{
    uintptr_t dst = slot_base(dst_slot);
    uintptr_t src = slot_base(src_slot);

    /* Read source header to get magic for flip */
    nxboot_img_header_t hdr;
    read_header(src_slot, &hdr);

    /* Determine flipped magic */
    uint32_t new_magic;
    if(IS_INTERNAL_MAGIC(hdr.magic))
    {
        new_magic = NXBOOT_HEADER_MAGIC;
    }
    else
    {
        new_magic = NXBOOT_HEADER_MAGIC_INT;
        if(is_update)
        {
            new_magic |= (update_slot & 0x3u);
        }
    }

    /* Copy full slot word-by-word */
    volatile uint32_t* d = (volatile uint32_t*)dst;
    const volatile uint32_t* s = (const volatile uint32_t*)src;
    uint32_t words = SLOT_SIZE / 4u;

    /* Write first word (magic) with flipped value */
    d[0] = new_magic;

    /* Copy remaining words */
    for(uint32_t i = 1u; i < words; i++)
    {
        d[i] = s[i];
    }
}

/* --- Erase first sector of a slot (marks update as consumed) --- */
static void erase_first_sector(uint32_t slot)
{
    volatile uint32_t* base = (volatile uint32_t*)slot_base(slot);
    uint32_t words = ERASE_SECTOR / 4u;
    for(uint32_t i = 0u; i < words; i++)
    {
        base[i] = 0xFFFFFFFFu;
    }
}

/* --- Determine boot state (nxboot_get_state equivalent) --- */
static void get_state(nxboot_state_t* state)
{
    nxboot_img_header_t primary_hdr, secondary_hdr, tertiary_hdr;
    read_header(NXBOOT_PRIMARY,   &primary_hdr);
    read_header(NXBOOT_SECONDARY, &secondary_hdr);
    read_header(NXBOOT_TERTIARY,  &tertiary_hdr);

    /* Default: secondary=update, tertiary=recovery */
    state->update_slot   = NXBOOT_SECONDARY;
    state->recovery_slot = NXBOOT_TERTIARY;

    /* Determine slot roles */
    if(tertiary_hdr.magic == NXBOOT_HEADER_MAGIC)
    {
        /* External magic in tertiary — it's an update */
        state->update_slot   = NXBOOT_TERTIARY;
        state->recovery_slot = NXBOOT_SECONDARY;
    }
    else if(IS_INTERNAL_MAGIC(secondary_hdr.magic) && IS_INTERNAL_MAGIC(tertiary_hdr.magic))
    {
        /* Both have internal magic */
        if(IS_INTERNAL_MAGIC(primary_hdr.magic))
        {
            uint32_t recovery_ptr = primary_hdr.magic & 0x3u;
            if(recovery_ptr == NXBOOT_SECONDARY &&
               primary_hdr.crc == secondary_hdr.crc)
            {
                state->update_slot   = NXBOOT_TERTIARY;
                state->recovery_slot = NXBOOT_SECONDARY;
            }
        }
        else if(primary_hdr.magic == NXBOOT_HEADER_MAGIC)
        {
            if(primary_hdr.crc == secondary_hdr.crc)
            {
                state->update_slot   = NXBOOT_TERTIARY;
                state->recovery_slot = NXBOOT_SECONDARY;
            }
        }
    }
    else if(IS_INTERNAL_MAGIC(secondary_hdr.magic))
    {
        state->update_slot   = NXBOOT_TERTIARY;
        state->recovery_slot = NXBOOT_SECONDARY;
    }

    /* Check recovery validity */
    nxboot_img_header_t recovery_hdr;
    read_header(state->recovery_slot, &recovery_hdr);

    state->recovery_valid = validate_image(state->recovery_slot);
    state->recovery_present = (primary_hdr.crc == recovery_hdr.crc);

    /* Check confirmation */
    state->primary_confirmed = 0;
    if(primary_hdr.magic == NXBOOT_HEADER_MAGIC)
    {
        /* External magic = auto-confirmed */
        state->primary_confirmed = 1;
    }
    else if(IS_INTERNAL_MAGIC(primary_hdr.magic))
    {
        uint32_t recovery_ptr = primary_hdr.magic & 0x3u;
        if(recovery_ptr == NXBOOT_SECONDARY && IS_INTERNAL_MAGIC(secondary_hdr.magic))
        {
            state->primary_confirmed = (primary_hdr.crc == secondary_hdr.crc) ? 1 : 0;
        }
        else if(recovery_ptr == NXBOOT_TERTIARY && IS_INTERNAL_MAGIC(tertiary_hdr.magic))
        {
            state->primary_confirmed = (primary_hdr.crc == tertiary_hdr.crc) ? 1 : 0;
        }
    }

    /* Determine next boot action */
    nxboot_img_header_t update_hdr;
    read_header(state->update_slot, &update_hdr);
    int primary_valid = validate_image(NXBOOT_PRIMARY);

    state->next_boot = NXBOOT_UPDATE_NONE;

    /* Check for update */
    if(update_hdr.magic == NXBOOT_HEADER_MAGIC && validate_image(state->update_slot))
    {
        if(!primary_valid || primary_hdr.crc != update_hdr.crc)
        {
            state->next_boot = NXBOOT_UPDATE_UPDATE;
            return;
        }
        else
        {
            /* Same image already installed — erase update to prevent loop */
            erase_first_sector(state->update_slot);
        }
    }

    /* Check for revert */
    if(IS_INTERNAL_MAGIC(recovery_hdr.magic) && state->recovery_valid)
    {
        if((IS_INTERNAL_MAGIC(primary_hdr.magic) && !state->primary_confirmed) || !primary_valid)
        {
            state->next_boot = NXBOOT_UPDATE_REVERT;
            return;
        }
    }
}

/* --- Jump to primary image --- */
static void jump_to_primary(uint32_t header_size)
{
    uintptr_t img_base = PRIMARY_BASE + header_size;
    const uint32_t sp = *(const uint32_t*)(img_base + 0u);
    const uint32_t rv = *(const uint32_t*)(img_base + 4u);
    void (*entry)(void) = (void (*)(void))rv;

    *(volatile uint32_t*)SCB_VTOR_ADDR = (uint32_t)img_base;
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    __asm volatile("msr msp, %0" : : "r"(sp) : "memory");
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    entry();
}

/* --- Main boot logic --- */
void Reset_Handler(void)
{
    nxboot_state_t state;
    get_state(&state);

    if(state.next_boot == NXBOOT_UPDATE_REVERT)
    {
#if NXBOOT_DEFECT == DEFECT_NO_REVERT
        /* Defect: skip revert — boot broken primary */
#else
        /* Revert: copy recovery -> primary */
        if(state.recovery_valid)
        {
            copy_partition(NXBOOT_PRIMARY, state.recovery_slot, 0, 0);
        }
#endif
    }
    else if(state.next_boot == NXBOOT_UPDATE_UPDATE)
    {
#if NXBOOT_DEFECT == DEFECT_NO_RECOVERY
        /* Defect: skip recovery creation — go straight to update copy */
#else
        /* Create recovery if needed: copy primary -> recovery */
        if(state.primary_confirmed && validate_image(NXBOOT_PRIMARY))
        {
            if(!state.recovery_present || !state.recovery_valid)
            {
                copy_partition(state.recovery_slot, NXBOOT_PRIMARY, 0, 0);
                /* Validate the new recovery */
                if(!validate_image(state.recovery_slot))
                {
                    /* Recovery creation failed — abort update */
                    goto try_boot;
                }
            }
        }
#endif

        /* Copy update -> primary (magic flips to internal) */
        copy_partition(NXBOOT_PRIMARY, state.update_slot, 1, state.update_slot);

        /* Erase first sector of update slot (marks as consumed) */
        erase_first_sector(state.update_slot);
    }

try_boot:
    /* Validate and boot primary */
    {
        nxboot_img_header_t hdr;
        read_header(NXBOOT_PRIMARY, &hdr);

        if((hdr.magic == NXBOOT_HEADER_MAGIC || IS_INTERNAL_MAGIC(hdr.magic)) &&
           hdr.header_size >= sizeof(nxboot_img_header_t) &&
           hdr.header_size <= ERASE_SECTOR)
        {
            if(vector_looks_valid(PRIMARY_BASE, hdr.header_size))
            {
                jump_to_primary(hdr.header_size);
            }
        }
    }

    /* Boot failed — bricked */
    while(1)
    {
    }
}
