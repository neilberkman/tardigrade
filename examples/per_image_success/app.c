// Copyright (c) 2026 Neil Berkman
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>

#define INHIBIT_OLD_LIVENESS (*(const volatile uint32_t *)0x10102004u)

__attribute__((section(".liveness"))) static volatile uint32_t alive;
__attribute__((section(".common"))) static volatile uint32_t started;

static void app(void)
{
    started = 1;

    // Leave several observation samples between handoff and liveness.
    for (uint32_t step = 0; step < 200000; ++step) {
        __asm volatile ("nop");
    }

    if (IMAGE_VERSION != 1 || INHIBIT_OLD_LIVENESS == 0) {
        alive = IMAGE_VERSION;
    }

    for (;;) {
        __asm volatile ("nop");
    }
}

__attribute__((used, section(".vectors")))
const uintptr_t vectors[] = { 0x20002000u, (uintptr_t)app };
