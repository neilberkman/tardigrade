#include <stdint.h>

#ifndef APP_VERSION
#define APP_VERSION 0
#endif

#ifndef PRE_RESET_DELAY_LOOPS
/* ~165 ms of emulated time at Renode's default 100 MIPS (2 insns/loop). */
#define PRE_RESET_DELAY_LOOPS 8250000u
#endif

#ifndef STARTUP_DELAY_LOOPS
/* ~37 ms of emulated time at Renode's default 100 MIPS (2 insns/loop). */
#define STARTUP_DELAY_LOOPS 1850000u
#endif

#ifndef HANG_BEFORE_PROGRESS
#define HANG_BEFORE_PROGRESS 0
#endif

#define EXEC_BASE        ((uintptr_t)0x10100000u)
#define STAGING_BASE     ((uintptr_t)0x10101000u)
#define UPDATE_TRIGGER   (*(volatile uint32_t *)0x10102000u)
#define SLOT_SIZE        0x1000u
#define SRAM_VECTORS     ((volatile uint32_t *)0x20000100u)
#define PROGRESS_COUNTER (*(volatile uint32_t *)0x20000200u)
#define VTOR             (*(volatile uint32_t *)0xE000ED08u)
#define AIRCR            (*(volatile uint32_t *)0xE000ED0Cu)

extern uint32_t __stack_top;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

void Reset_Handler(void);
void Default_Handler(void);

__attribute__((used, section(".app_version")))
const uint32_t app_version = APP_VERSION;

void Default_Handler(void)
{
    for(;;) { }
}

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
};

__attribute__((noinline, section(".ramfunc.delay")))
static void delay_loops(uint32_t count)
{
    if(count == 0u)
    {
        return;
    }
    __asm volatile(
        ".syntax unified\n"
        "1:\n"
        "subs %0, %0, #1\n"
        "bne 1b\n"
        : "+l"(count)
        :
        : "cc"
    );
}

__attribute__((noinline, section(".ramfunc.copy")))
static void copy_update(void)
{
    volatile uint32_t *destination = (volatile uint32_t *)EXEC_BASE;
    const uint32_t *source = (const uint32_t *)STAGING_BASE;
    uint32_t words = SLOT_SIZE / sizeof(uint32_t);
    uint32_t index;

    /* Leave the reset-critical words until the end and make offset 0x08 the
     * first faultable program. Offset 0x10 is deliberately last so boundary
     * faults retain a bootable reset vector while corrupting exact content. */
    destination[2] = source[2];
    for(index = 3; index < words; ++index)
    {
        if(index != 4)
        {
            destination[index] = source[index];
        }
    }
    destination[0] = source[0];
    destination[1] = source[1];
    destination[4] = source[4];
}

__attribute__((noinline, noreturn, section(".ramfunc.reset")))
static void request_reset(void)
{
    AIRCR = 0x05FA0004u;
    for(;;) { }
}

static void start_runtime(void)
{
    const uint32_t *vectors = (const uint32_t *)EXEC_BASE;
    uint32_t index;

    for(index = 0; index < 8; ++index)
    {
        SRAM_VECTORS[index] = vectors[index];
    }
    VTOR = (uintptr_t)SRAM_VECTORS;
    PROGRESS_COUNTER = 0u;
#if HANG_BEFORE_PROGRESS
    for(;;)
    {
        delay_loops(500u);
    }
#else
    delay_loops(STARTUP_DELAY_LOOPS);
    PROGRESS_COUNTER = 1u;
    UPDATE_TRIGGER = 0x52554E31u;
    for(;;)
    {
        ++PROGRESS_COUNTER;
        delay_loops(500u);
    }
#endif
}

void Reset_Handler(void)
{
    uint32_t *source = &_siramfunc;
    uint32_t *destination = &_sramfunc;

    while(destination < &_eramfunc)
    {
        *destination++ = *source++;
    }

    if(UPDATE_TRIGGER == 1u)
    {
        __asm volatile("cpsid i");
        PROGRESS_COUNTER = 0u;
        UPDATE_TRIGGER = 0u;
        delay_loops(PRE_RESET_DELAY_LOOPS);
        copy_update();
        request_reset();
    }

    start_runtime();
}
