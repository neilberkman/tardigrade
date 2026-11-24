#include <stdint.h>

#define BOOT_BASE       ((uintptr_t)0x10000000u)
#define EXEC_BASE       ((uintptr_t)0x10100000u)
#define RECORD_BASE     ((uintptr_t)0x10101000u)
#define RECORD_HDR      (*(volatile uint32_t *)(RECORD_BASE + 0x000u))
#define RECORD_FTR      (*(volatile uint32_t *)(RECORD_BASE + 0x800u))

#define NVM_CTRL        (*(volatile uint32_t *)0x40001030u)
#define NVM_ERASE_SIZE  (*(volatile uint32_t *)0x40001034u)
#define NVM_ERASE_ADDR  (*(volatile uint32_t *)0x40001038u)
#define NVM_CTRL_ERASE_SECTOR (1u << 2)

#define MARKER_ADDR     (*(volatile uint32_t *)0x20000020u)
#define UPDATE_REQ_ADDR (*(volatile uint32_t *)0x20000030u)
#define VTOR_ADDR       (*(volatile uint32_t *)0xE000ED08u)

#define RECORD_MAGIC    0x52454331u /* "REC1" */
#define RECORD_COMMIT   0x444F4E45u /* "DONE" */
#define UPDATE_REQ_VAL  0x55504431u /* "UPD1" */
#define MARKER_OK       0xB007C0DEu

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);
void HardFault_Handler(void);

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,   /* NMI */
    HardFault_Handler, /* HardFault */
    Default_Handler,   /* MemManage */
    Default_Handler,   /* BusFault */
    HardFault_Handler, /* UsageFault (Renode 1.16.1 compat) */
    Default_Handler,
};

void Default_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

void HardFault_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
    VTOR_ADDR = (uint32_t)BOOT_BASE;

    /* Validate the persistent record before proceeding. An interrupted erase
     * (half or fully erased) or torn program leaves the record invalid; an
     * uncorrectable erase cut raises a bus error / HardFault on this read. */
    uint32_t magic = RECORD_HDR;
    uint32_t commit = RECORD_FTR;
    if(magic != RECORD_MAGIC || commit != RECORD_COMMIT)
    {
        for(;;)
        {
            __asm volatile("wfi");
        }
    }

    if(UPDATE_REQ_ADDR == UPDATE_REQ_VAL)
    {
        UPDATE_REQ_ADDR = 0u;

        /* Erase the 4 KiB persistent record sector before reprogramming. */
        NVM_CTRL = NVM_CTRL_ERASE_SECTOR;
        NVM_ERASE_SIZE = 0x1000u;
        NVM_ERASE_ADDR = (uint32_t)RECORD_BASE;
        NVM_CTRL = 0u;

        /* Reprogram the record header (lower half) and commit footer (upper half). */
        RECORD_HDR = RECORD_MAGIC;
        RECORD_FTR = RECORD_COMMIT;
    }

    MARKER_ADDR = MARKER_OK;
    VTOR_ADDR = (uint32_t)EXEC_BASE;
    for(;;)
    {
        __asm volatile("wfi");
    }
}
