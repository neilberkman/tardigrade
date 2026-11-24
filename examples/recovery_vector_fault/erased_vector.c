#include <stdint.h>

#define VECTOR_BASE    ((uintptr_t)0x10000000u)
#define NVMC_CONFIG    ((uintptr_t)0x4001E504u)
#define NVMC_ERASEPAGE ((uintptr_t)0x4001E508u)
#define MARKER_ADDRESS ((uintptr_t)0x20000020u)
#define MARKER_VALUE   0xB007C0DEu
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
    Default_Handler, /* NMI */
    Default_Handler, /* HardFault */
    Default_Handler, /* MemManage */
    Default_Handler, /* BusFault */
    Default_Handler, /* UsageFault */
    Default_Handler, /* Reserved */
};

void Default_Handler(void)
{
    for(;;) { }
}

__attribute__((noinline, section(".ramfunc")))
static void program_vector_table(void)
{
    volatile uint32_t *vectors = (volatile uint32_t *)VECTOR_BASE;

    /* If recovery booted after a power cut that reprogrammed Reset_Handler
     * (vectors[1]) before restoring HardFault (vectors[3]), trigger an
     * exception so the core vectors through the erased HardFault entry. */
    if(vectors[3] == 0xFFFFFFFFu)
    {
        *(volatile uint32_t *)VTOR_ADDRESS = VECTOR_BASE;
        __asm volatile("dsb\n\tisb\n\tudf #0");
        for(;;) { }
    }

    /* Erase the vector-table page (page 0 at 0x10000000; code lives in page 1
     * at 0x10001000) before reprogramming the vectors one write at a time. */
    *(volatile uint32_t *)NVMC_CONFIG = 2u;
    *(volatile uint32_t *)NVMC_ERASEPAGE = VECTOR_BASE;
    *(volatile uint32_t *)NVMC_CONFIG = 0u;

    /* Tracked write 0: restore initial SP (cut leaves SP, Reset, HardFault erased). */
    *(volatile uint32_t *)NVMC_CONFIG = 1u;
    vectors[0] = (uintptr_t)&__stack_top;
    *(volatile uint32_t *)NVMC_CONFIG = 0u;

    /* Tracked write 1: restore Reset vector (cut leaves Reset + HardFault erased). */
    *(volatile uint32_t *)NVMC_CONFIG = 1u;
    vectors[1] = ((uintptr_t)Reset_Handler) | 1u;
    *(volatile uint32_t *)NVMC_CONFIG = 0u;

    /* Tracked write 2: restore HardFault vector (cut leaves HardFault erased). */
    *(volatile uint32_t *)NVMC_CONFIG = 1u;
    vectors[3] = ((uintptr_t)Default_Handler) | 1u;
    *(volatile uint32_t *)NVMC_CONFIG = 0u;

    /* Tracked write 3: restore UsageFault vector (Renode 1.16.1 compat). */
    *(volatile uint32_t *)NVMC_CONFIG = 1u;
    vectors[6] = ((uintptr_t)Default_Handler) | 1u;
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
    program_vector_table();
}
