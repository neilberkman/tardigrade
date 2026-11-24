#include <stdint.h>

#ifndef FAULT_BEFORE_CHECKS
#define FAULT_BEFORE_CHECKS 0
#endif

#ifndef FAULT_HANDLER_FORGES_CHECKS
#define FAULT_HANDLER_FORGES_CHECKS 0
#endif

#ifndef FAULT_HANDLER_VECTOR_ENTRY_SPIN
#define FAULT_HANDLER_VECTOR_ENTRY_SPIN 0
#endif

#ifndef FAULT_ON_SECOND_BOOT_BEFORE_CHECKS
#define FAULT_ON_SECOND_BOOT_BEFORE_CHECKS 0
#endif

#define EXEC_BASE           ((uintptr_t)0x10100000u)
#define CRASH_RECORD_BASE   ((uintptr_t)0x10102000u)
#define SRAM_VECTORS        ((volatile uint32_t *)0x20000100u)
#define SCHEDULER_FLAG      (*(volatile uint32_t *)0x20000200u)
#define TICK_COUNT          (*(volatile uint32_t *)0x20000204u)
#define CRASH_REQUEST       (*(volatile uint32_t *)0x20000400u)

#define VTOR                (*(volatile uint32_t *)0xE000ED08u)
#define CFSR                (*(volatile uint32_t *)0xE000ED28u)
#define HFSR                (*(volatile uint32_t *)0xE000ED2Cu)

#define CRASH_REQUEST_MAGIC 0xC0A50001u
#define CRASH_RECORD_MAGIC  0x43525348u /* "CRSH" */
#define CRASH_RECORD_COMMIT 0x444F4E45u /* "DONE" */
#define BOOT_SEEN_MAGIC     0xB0070001u

/* 4 distinct 16-byte MRAM program units in 0x10102000..0x1010203F.
 * Putting magic and commit in the upper half (+0x08) of units 0 and 3 means a
 * half-torn power loss during unit 0 tears magic to 0x00 (recoverable), while
 * cuts during units 1..3 leave magic committed without the commit footer. */
#define CRASH_REC_MAGIC     (*(volatile uint32_t *)(CRASH_RECORD_BASE + 0x08u))
#define CRASH_REC_CFSR      (*(volatile uint32_t *)(CRASH_RECORD_BASE + 0x10u))
#define CRASH_REC_TICKS     (*(volatile uint32_t *)(CRASH_RECORD_BASE + 0x20u))
#define CRASH_REC_COMMIT    (*(volatile uint32_t *)(CRASH_RECORD_BASE + 0x38u))
#define BOOT_SEEN_MARKER    (*(volatile uint32_t *)(CRASH_RECORD_BASE + 0x40u))

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);
void Fault_Handler(void);

void Default_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

#if FAULT_HANDLER_VECTOR_ENTRY_SPIN
__attribute__((naked, noreturn))
void HardFault_Spin(void)
{
    /* Shared halt stub installed at vector_table[3] (HardFault) so PC stops on
     * the exact vector entry instruction (pc & ~1) == (hardfault_vector & ~1). */
    __asm volatile("b .");
}
#endif

void Fault_Handler(void)
{
    uint32_t saved_cfsr = CFSR;
    uint32_t saved_hfsr = HFSR;
    /* Standard crash-dump behavior: capture and clear sticky fault bits. */
    CFSR = saved_cfsr;
    HFSR = saved_hfsr;

#if FAULT_HANDLER_FORGES_CHECKS
    SCHEDULER_FLAG = 1u;
    TICK_COUNT = 5u;
#endif

#if !FAULT_ON_SECOND_BOOT_BEFORE_CHECKS
    CRASH_REC_MAGIC = CRASH_RECORD_MAGIC;
    CRASH_REC_CFSR = saved_cfsr ^ saved_hfsr;
    CRASH_REC_TICKS = TICK_COUNT;
    CRASH_REC_COMMIT = CRASH_RECORD_COMMIT;
#endif

#if FAULT_HANDLER_VECTOR_ENTRY_SPIN
    HardFault_Spin();
#else
    for(;;)
    {
        __asm volatile("wfi");
    }
#endif
}

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler, /* NMI */
#if FAULT_HANDLER_VECTOR_ENTRY_SPIN
    HardFault_Spin,  /* HardFault */
#else
    Fault_Handler,   /* HardFault */
#endif
    Fault_Handler,   /* MemManage */
    Fault_Handler,   /* BusFault */
    Fault_Handler,   /* UsageFault */
    Default_Handler,
};

static void trigger_deliberate_fault(void)
{
    __asm volatile("udf #0");
    for(;;)
    {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
#if FAULT_HANDLER_VECTOR_ENTRY_SPIN
    /* Keep VTOR at the exec-slot vector table so recovery evidence inspects
     * hardfault_vector at EXEC_BASE + 12 against the stopped PC. */
    VTOR = EXEC_BASE;
#else
    const uint32_t *vectors = (const uint32_t *)EXEC_BASE;
    for(uint32_t index = 0u; index < 8u; ++index)
    {
        SRAM_VECTORS[index] = vectors[index];
    }
    VTOR = (uintptr_t)SRAM_VECTORS;
#endif

    SCHEDULER_FLAG = 0u;
    TICK_COUNT = 0u;

#if FAULT_BEFORE_CHECKS
    trigger_deliberate_fault();
#endif

#if FAULT_ON_SECOND_BOOT_BEFORE_CHECKS
    if(BOOT_SEEN_MARKER == BOOT_SEEN_MAGIC)
    {
        trigger_deliberate_fault();
    }
    BOOT_SEEN_MARKER = BOOT_SEEN_MAGIC;
#endif

    /* Simulate a startup crash-report parser that stalls on a torn record
     * (magic written without commit footer). */
    if(CRASH_REC_MAGIC == CRASH_RECORD_MAGIC
       && CRASH_REC_COMMIT != CRASH_RECORD_COMMIT)
    {
        for(;;)
        {
            __asm volatile("wfi");
        }
    }

    SCHEDULER_FLAG = 1u;
    for(uint32_t tick = 1u; tick <= 5u; ++tick)
    {
        TICK_COUNT = tick;
    }

#if !FAULT_ON_SECOND_BOOT_BEFORE_CHECKS
    if(CRASH_REQUEST == CRASH_REQUEST_MAGIC)
    {
        CRASH_REQUEST = 0u;
        trigger_deliberate_fault();
    }
#endif

    for(;;)
    {
        ++TICK_COUNT;
    }
}
