// Copyright (c) 2026 Neil Berkman
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>

#define EXEC_BASE 0x10100000u
#define STAGING_BASE 0x10101000u
#define WORD(address) (*(volatile uint32_t *)(address))
#define UPDATE_PENDING WORD(0x10102000u)
#define ERASE_ADDRESS WORD(0x40000000u)
#define VTOR WORD(0xE000ED08u)
#define AIRCR WORD(0xE000ED0Cu)

static void launch_app(uint32_t vectors __attribute__((unused)))
    __attribute__((naked, noreturn));
static void launch_app(uint32_t vectors)
{
    __asm volatile (
        "ldr r1, [r0]\n"
        "msr msp, r1\n"
        "ldr r1, [r0, #4]\n"
        "bx r1\n"
    );
}

static void boot(void)
{
    if (UPDATE_PENDING == 1) {
        // Consume the request once so that a recovery boot can use the
        // original app when the erase was interrupted before it changed flash.
        UPDATE_PENDING = 0;
        ERASE_ADDRESS = EXEC_BASE;
        for (uint32_t offset = 0; offset < 0x100; offset += sizeof(uint32_t)) {
            WORD(EXEC_BASE + offset) = WORD(STAGING_BASE + offset);
        }

        AIRCR = 0x05FA0004u; // SYSRESETREQ
        for (;;) {
            __asm volatile ("nop");
        }
    }

    VTOR = EXEC_BASE;
    launch_app(EXEC_BASE);
}

__attribute__((used, section(".vectors")))
const uintptr_t vectors[] = { 0x20002000u, (uintptr_t)boot };
