#include <stdint.h>

#ifndef APP_VERSION
#define APP_VERSION 0
#endif

#ifndef REQUEST_RESET
#define REQUEST_RESET 1
#endif

#ifndef HANG_BEFORE_SCHEDULER
#define HANG_BEFORE_SCHEDULER 0
#endif

#define EXEC_BASE       ((uintptr_t)0x10100000u)
#define STAGING_BASE    ((uintptr_t)0x10101000u)
#define UPDATE_TRIGGER  (*(volatile uint32_t *)0x10102000u)
#define SLOT_SIZE       0x1000u
#define SRAM_VECTORS    ((volatile uint32_t *)0x20000100u)
#define SCHEDULER_FLAG  (*(volatile uint32_t *)0x20000200u)
#define TICK_COUNT      (*(volatile uint32_t *)0x20000204u)
#define VTOR            (*(volatile uint32_t *)0xE000ED08u)
#define AIRCR           (*(volatile uint32_t *)0xE000ED0Cu)

extern uint32_t __stack_top;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

void Reset_Handler(void);
void Default_Handler(void);
void Updated_NMI_Handler(void);
void Updated_HardFault_Handler(void);
void Updated_Aux_Handler(void);

void Default_Handler(void)
{
    for(;;) { }
}

void Updated_NMI_Handler(void)
{
    for(;;) { }
}

void Updated_HardFault_Handler(void)
{
    for(;;) { }
}

void Updated_Aux_Handler(void)
{
    for(;;) { }
}

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
#if APP_VERSION
    Updated_NMI_Handler,
    Updated_HardFault_Handler,
    Updated_Aux_Handler,
#else
    Default_Handler,
    Default_Handler,
    Default_Handler,
#endif
    Default_Handler,
    Default_Handler,
    Default_Handler,
};

__attribute__((noinline, section(".ramfunc")))
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

__attribute__((noinline, noreturn, section(".ramfunc")))
static void request_reset(void)
{
#if REQUEST_RESET
    AIRCR = 0x05FA0004u;
#endif
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
#if HANG_BEFORE_SCHEDULER
    for(;;) { }
#else
    SCHEDULER_FLAG = 1u;
    TICK_COUNT = 1u;
    UPDATE_TRIGGER = 0x52554E31u;
    for(;;)
    {
        ++TICK_COUNT;
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
        SCHEDULER_FLAG = 0u;
        TICK_COUNT = 0u;
        UPDATE_TRIGGER = 0u;
        copy_update();
        request_reset();
    }

    start_runtime();
}
