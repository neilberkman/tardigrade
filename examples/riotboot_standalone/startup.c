/*
 * Minimal Cortex-M4 startup for riotboot.
 * Sets up vector table and calls riotboot_main().
 */

#include <stdint.h>

extern void riotboot_main(void);

/* Stack top from linker script */
extern uint32_t _estack;

/* Default handler for unused interrupts */
static void Default_Handler(void) { while (1); }

/* Cortex-M4 vector table — only reset and fault vectors needed */
__attribute__((section(".isr_vector")))
void (* const vector_table[])(void) = {
    (void (*)(void))&_estack,  /* Initial SP */
    (void (*)(void))riotboot_main,  /* Reset handler */
    Default_Handler,           /* NMI */
    Default_Handler,           /* HardFault */
    Default_Handler,           /* MemManage */
    Default_Handler,           /* BusFault */
    Default_Handler,           /* UsageFault */
    0, 0, 0, 0,               /* Reserved */
    Default_Handler,           /* SVCall */
    Default_Handler,           /* Debug Monitor */
    0,                         /* Reserved */
    Default_Handler,           /* PendSV */
    Default_Handler,           /* SysTick */
};
