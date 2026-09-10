#include <stdint.h>

#define EXEC_BASE      ((uintptr_t)0x10100000u)
#define STAGING_BASE   ((uintptr_t)0x10102000u)
#define COPY_BYTES     256u
#define MARKER_ADDRESS ((uintptr_t)0x20000020u)
#define MARKER_VALUE   0x51A7C0DEu
#define VTOR_ADDRESS   ((uintptr_t)0xE000ED08u)

extern uint32_t __stack_top;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,
    Default_Handler,
};

void Default_Handler(void)
{
    for(;;) { }
}

__attribute__((noinline, section(".ramfunc")))
static void copy_and_boot(void)
{
    volatile uint64_t *dst = (volatile uint64_t *)EXEC_BASE;
    volatile const uint64_t *src = (volatile const uint64_t *)STAGING_BASE;
    for(uint32_t index = 0; index < COPY_BYTES / sizeof(uint64_t); ++index)
    {
        dst[index] = src[index];
    }
    *(volatile uint32_t *)MARKER_ADDRESS = MARKER_VALUE;
    *(volatile uint32_t *)VTOR_ADDRESS = EXEC_BASE;
    for(;;) { }
}

void Reset_Handler(void)
{
    uint32_t *source = &_siramfunc;
    uint32_t *destination = &_sramfunc;
    while(destination < &_eramfunc)
    {
        *destination++ = *source++;
    }
    copy_and_boot();
}
