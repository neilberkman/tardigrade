#include <stdint.h>

extern uint32_t __stack_top;

void Reset_Handler(void);

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
};

void Reset_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}
