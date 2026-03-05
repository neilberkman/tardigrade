/*
 * Minimal Cortex-M4 startup for ESP-IDF OTA bootloader model.
 */

#include <stdint.h>

extern void esp_ota_main(void);
extern uint32_t _estack;

/* GCC -Os may emit memset for struct/array zero-init. */
void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static void Default_Handler(void) { while (1); }

__attribute__((section(".isr_vector")))
void (* const vector_table[])(void) = {
    (void (*)(void))&_estack,
    (void (*)(void))esp_ota_main,
    Default_Handler,    /* NMI */
    Default_Handler,    /* HardFault */
    Default_Handler,    /* MemManage */
    Default_Handler,    /* BusFault */
    Default_Handler,    /* UsageFault */
    0, 0, 0, 0,
    Default_Handler,    /* SVCall */
    Default_Handler,    /* Debug Monitor */
    0,
    Default_Handler,    /* PendSV */
    Default_Handler,    /* SysTick */
};
