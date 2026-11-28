// Copyright (c) 2026 Neil Berkman
// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>

#define WORD(address) (*(volatile uint32_t *)(address))
extern uint32_t __stack_top;
void Reset_Handler(void);

__attribute__((section(".isr_vector")))
const void *vectors[] = { &__stack_top, Reset_Handler };

__attribute__((noinline)) static void persist_counter(void)
{
    uint32_t start = WORD(0x40010000);
    uint32_t now;
    do {
        now = WORD(0x40010000);
    } while (now - start < 1000);
    WORD(0x10100118) = now;
}

void Reset_Handler(void)
{
    WORD(0xe000ed08) = 0x10000000;
    if (WORD(0x20000400) == 0x55504432) {
        WORD(0x10100108) = 1;
    } else {
        persist_counter();
        WORD(0x10100120) = 2;
    }
    WORD(0x20000100) = 0x50325041;
    WORD(0xe000ed08) = 0x10100000;
    for (;;) {
        __asm volatile("wfi");
    }
}
