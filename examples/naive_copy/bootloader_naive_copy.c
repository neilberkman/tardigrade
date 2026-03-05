/*
 * Naive copy-to-address bootloader: the worst-case OTA pattern.
 *
 * This models firmware that has no real bootloader — it just copies from a
 * staging area to an execution address, then jumps.  No metadata, no CRC,
 * no fallback, no A/B slots.  A power loss during the copy = brick.
 *
 * This is the baseline "how bad can it get?" reference.  The audit tool
 * should show ~100% brick rate under fault injection, proving that any
 * firmware using this pattern is fundamentally unsafe.
 *
 * Three variants are provided via compile-time #defines:
 *
 *   NAIVE_BARE_COPY       (0) - copy staging->exec, jump. No validation at all.
 *   NAIVE_CRC_PRE_COPY    (1) - CRC-check staging image before copying.
 *                                Still bricks on power loss DURING copy.
 *   NAIVE_CRC_POST_COPY   (2) - CRC-check exec slot after copy, retry if bad.
 *                                Slightly better but still no fallback image.
 *
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -O2 -ffreestanding \
 *       -nostdlib -Wl,--gc-sections -T linker_boot.ld \
 *       -DNAIVE_MODE=0 -o bootloader_bare_copy.elf bootloader_naive_copy.c
 */

#include <stdint.h>

/* Memory map: aligned with the default M0 NVM demo platform for comparison */
#define EXEC_BASE         ((uintptr_t)0x10002000u)   /* Where firmware runs from */
#define STAGING_BASE      ((uintptr_t)0x10039000u)   /* Where OTA downloads land */
#define IMAGE_SIZE        (0x37000u)                  /* 220KB per slot */
#define PENDING_FLAG_ADDR ((uintptr_t)0x10070000u)    /* Single word: 1=update pending */
#define SCB_VTOR_ADDR     ((uintptr_t)0xE000ED08u)
#define SRAM_START        ((uintptr_t)0x20000000u)
#define SRAM_END          ((uintptr_t)0x20020000u)

/* CRC storage for variants that use it */
#define STAGING_CRC_ADDR  ((uintptr_t)0x10070004u)    /* Expected CRC of staging image */

#ifndef NAIVE_MODE
#define NAIVE_MODE 0
#endif

#define NAIVE_BARE_COPY    0
#define NAIVE_CRC_PRE_COPY 1
#define NAIVE_CRC_POST_COPY 2

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

/* --- CRC-32 (same polynomial as boot_meta.h) --- */
#if (NAIVE_MODE == NAIVE_CRC_PRE_COPY) || (NAIVE_MODE == NAIVE_CRC_POST_COPY)
static uint32_t crc32_region(uintptr_t base, uint32_t len)
{
    const uint8_t* data = (const uint8_t*)base;
    uint32_t crc = 0xFFFFFFFFu;

    for(uint32_t i = 0u; i < len; i++)
    {
        crc ^= data[i];
        for(uint32_t b = 0u; b < 8u; b++)
        {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }

    return crc ^ 0xFFFFFFFFu;
}
#endif

static int vector_looks_valid(uintptr_t base)
{
    const uint32_t sp = *(const uint32_t*)(base + 0u);
    const uint32_t rv = *(const uint32_t*)(base + 4u);
    const uintptr_t pc = (uintptr_t)(rv & (~1u));

    return (sp >= SRAM_START && sp <= SRAM_END)
        && ((rv & 1u) == 1u)
        && (pc >= base && pc < (base + IMAGE_SIZE));
}

static void copy_image(uintptr_t dst, uintptr_t src, uint32_t len)
{
    volatile uint32_t* d = (volatile uint32_t*)dst;
    const volatile uint32_t* s = (const volatile uint32_t*)src;

    for(uint32_t i = 0u; i < (len / 4u); i++)
    {
        d[i] = s[i];
    }
}

static void jump_to(uintptr_t base)
{
    const uint32_t sp = *(const uint32_t*)(base + 0u);
    const uint32_t rv = *(const uint32_t*)(base + 4u);
    void (*entry)(void) = (void (*)(void))rv;

    *(volatile uint32_t*)SCB_VTOR_ADDR = (uint32_t)base;
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    __asm volatile("msr msp, %0" : : "r"(sp) : "memory");
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    entry();
}

void Reset_Handler(void)
{
    volatile uint32_t* pending = (volatile uint32_t*)PENDING_FLAG_ADDR;

    if(*pending == 1u)
    {
        /*
         * Update is pending.  Copy staging image to execution slot.
         *
         * THIS IS THE VULNERABLE WINDOW.  If power fails anywhere during
         * this copy, the execution slot is partially written = brick.
         * There is no fallback image, no metadata to detect the partial
         * write, no recovery path.
         */

#if (NAIVE_MODE == NAIVE_CRC_PRE_COPY)
        /*
         * Variant: CRC-check the staging image before copying.
         * This prevents copying a corrupt download, but does NOT protect
         * against power loss DURING the copy.  Still bricks.
         */
        {
            uint32_t expected_crc = *(volatile uint32_t*)STAGING_CRC_ADDR;
            uint32_t actual_crc = crc32_region(STAGING_BASE, IMAGE_SIZE);
            if(actual_crc != expected_crc)
            {
                /* Staging image is corrupt.  Don't copy.  Try to boot existing. */
                *pending = 0u;
                goto try_boot;
            }
        }
#endif

        /* The fatal copy.  No atomicity, no recovery. */
        copy_image(EXEC_BASE, STAGING_BASE, IMAGE_SIZE);

#if (NAIVE_MODE == NAIVE_CRC_POST_COPY)
        /*
         * Variant: CRC-check the exec slot after copy.  If the copy was
         * interrupted (shouldn't happen if we got here, but...), detect it.
         * Problem: what do we do?  We already overwrote the exec slot.
         * The original image is gone.  All we can do is retry the copy,
         * but if the staging image is also corrupt, we're stuck.
         */
        {
            uint32_t expected_crc = *(volatile uint32_t*)STAGING_CRC_ADDR;
            uint32_t actual_crc = crc32_region(EXEC_BASE, IMAGE_SIZE);
            if(actual_crc != expected_crc)
            {
                /* Post-copy CRC mismatch.  Retry once. */
                copy_image(EXEC_BASE, STAGING_BASE, IMAGE_SIZE);
                /* If this also fails, we're bricked.  No fallback. */
            }
        }
#endif

        /* Clear pending flag after successful copy. */
        *pending = 0u;
    }

#if (NAIVE_MODE == NAIVE_CRC_PRE_COPY)
try_boot:
#endif

    /* Boot whatever is in the exec slot.  No validation = boot garbage. */
    if(vector_looks_valid(EXEC_BASE))
    {
        jump_to(EXEC_BASE);
    }

    /* Exec slot doesn't have valid vectors.  Bricked. */
    while(1)
    {
    }
}
