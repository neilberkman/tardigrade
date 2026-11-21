#include <stdint.h>

#define EXEC_BASE ((uintptr_t)0x10100000u)

extern uint32_t __stack_top;

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

__attribute__((naked, noreturn))
static void jump_to_exec(void)
{
    __asm volatile(
        "ldr r0, =0x10100000\n"
        "ldr r1, [r0, #0]\n"
        "ldr r2, [r0, #4]\n"
        "msr msp, r1\n"
        "bx r2\n"
    );
}

void Reset_Handler(void)
{
    jump_to_exec();
}
