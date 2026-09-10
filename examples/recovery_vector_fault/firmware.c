#include <stdint.h>

#define VECTOR_BASE    ((uintptr_t)0x10000000u)
#define NVMC_CONFIG    ((uintptr_t)0x4001E504u)
#define MARKER_ADDRESS ((uintptr_t)0x20000020u)
#define MARKER_VALUE   0xB007C0DEu
#define VTOR_ADDRESS   ((uintptr_t)0xE000ED08u)

extern uint32_t __stack_top;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

void Reset_Handler(void);
void Default_Handler(void);
void Brick_Handler(void);

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

void Brick_Handler(void)
{
    for(;;) { }
}

__attribute__((noinline, section(".ramfunc")))
static void program_reset_vector(void)
{
    volatile uint32_t *vectors = (volatile uint32_t *)VECTOR_BASE;

    /* Model a corrupted vector word immediately before its program operation. */
    vectors[1] = ((uintptr_t)Brick_Handler) | 1u;
    *(volatile uint32_t *)NVMC_CONFIG = 1u;
    vectors[1] = ((uintptr_t)Reset_Handler) | 1u;
    *(volatile uint32_t *)NVMC_CONFIG = 0u;

    *(volatile uint32_t *)MARKER_ADDRESS = MARKER_VALUE;
    *(volatile uint32_t *)VTOR_ADDRESS = VECTOR_BASE;
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
    program_reset_vector();
}
