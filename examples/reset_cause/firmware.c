// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>

#define REG(address) (*(volatile uint32_t *)(address))

#if defined(NRF52840)
#define CAUSE REG(0x40000400)
#define BACKUP REG(0x4000051c)
#define CLEAR_FLAGS 0xffffffffu
#define POWER_ON_CAUSE 0x00000000u
#define SOFTWARE_CAUSE 0x00000004u
#define SLOT_EXEC_BASE 0x0000c000u
#define SLOT_EXEC_WORD REG(0x0000c008)
#define SWEEP_MODE_WORD REG(0x00010000)
static void write_exec_word(uint32_t value)
{
    REG(0x4001e504) = 1u;
    SLOT_EXEC_WORD = value;
    __asm volatile ("dsb" ::: "memory");
    REG(0x4001e504) = 0u;
}
#elif defined(STM32F4)
#define CAUSE REG(0x40023874)
#define BACKUP REG(0x40002850)
#define CLEAR_FLAGS (1u << 24)
#define POWER_ON_CAUSE 0x0e000000u
#define SOFTWARE_CAUSE 0x14000000u
#define SLOT_EXEC_BASE 0x08020000u
#define SLOT_EXEC_WORD REG(0x08020008)
#define SWEEP_MODE_WORD REG(0x08040000)
static void write_exec_word(uint32_t value)
{
    REG(0x40023c04) = 0x45670123u;
    REG(0x40023c04) = 0xcdef89abu;
    REG(0x40023c10) = 1u;
    SLOT_EXEC_WORD = value;
    __asm volatile ("dsb" ::: "memory");
    REG(0x40023c10) = 0u;
}
#else
#error Select NRF52840 or STM32F4
#endif

// The monitor can read the observations after each boot.
#define OBSERVED ((volatile uint32_t *)0x20000100)
#define RETAINED REG(0x20000200)
#define REQUEST_SOFTWARE_RESET REG(0x20000210)
#define SWEEP_MAGIC 0x53574550u

void boot(void)
{
    uint32_t cause = CAUSE;
    uint32_t retained = RETAINED;
    uint32_t backup = BACKUP;

    OBSERVED[0] = cause;
    OBSERVED[1] = retained;
    OBSERVED[2] = backup;
    OBSERVED[3] = 0u;
    CAUSE = CLEAR_FLAGS;
    RETAINED = 0x12345678u;
    BACKUP = 0x5au;

    if (SWEEP_MODE_WORD == SWEEP_MAGIC) {
        if (retained == 0u && cause == POWER_ON_CAUSE && backup == 0u) {
            __asm volatile ("dsb" ::: "memory");
            REG(0xe000ed0c) = 0x05fa0004u;
            while (1) {
                __asm volatile ("wfi");
            }
        }
        if (retained == 0x12345678u && cause == SOFTWARE_CAUSE && backup == 0x5au) {
            write_exec_word(0xacceded1u);
            OBSERVED[3] = 0xdeadbeefu;
            __asm volatile ("dsb" ::: "memory");
            REG(0xe000ed08) = SLOT_EXEC_BASE;
        } else if (retained == 0xa5a5a5a5u && cause == POWER_ON_CAUSE && backup == 0u) {
            OBSERVED[3] = 0xdeadbeefu;
            __asm volatile ("dsb" ::: "memory");
            REG(0xe000ed08) = SLOT_EXEC_BASE;
        }
        while (1) {
            __asm volatile ("wfi");
        }
    }

    while (REQUEST_SOFTWARE_RESET != 1) {
        // Wait for the monitor to sample this boot before requesting another.
    }
    REQUEST_SOFTWARE_RESET = 0;
    __asm volatile ("dsb" ::: "memory");
    REG(0xe000ed0c) = 0x05fa0004;
    while (1) {
        __asm volatile ("wfi");
    }
}

__attribute__((section(".vectors"), used))
static const uintptr_t vectors[] = {0x20001000, (uintptr_t)boot};
