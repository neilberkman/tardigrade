#include <stdint.h>

#ifndef OSCILLATE_ON_TORN
#define OSCILLATE_ON_TORN 0
#endif

#ifndef FAIL_ON_SECOND_BOOT
#define FAIL_ON_SECOND_BOOT 0
#endif

#ifndef UNMET_CHECKS_ON_SECOND_BOOT
#define UNMET_CHECKS_ON_SECOND_BOOT 0
#endif

#define EXEC_BASE           ((uintptr_t)0x10100000u)
#define RECORD_BASE         ((uintptr_t)0x10102000u)
#define SRAM_VECTORS        ((volatile uint32_t *)0x20000100u)
#define SCHEDULER_FLAG      (*(volatile uint32_t *)0x20000200u)
#define TICK_COUNT          (*(volatile uint32_t *)0x20000204u)

#define VTOR                (*(volatile uint32_t *)0xE000ED08u)

/* Five distinct 16-byte MRAM program units in 0x10102000..0x1010204F.
 * Under default half-torn MRAM power loss, bytes +0x08..+0x0F of the
 * interrupted unit are torn to 0x00 while +0x00..+0x07 survive:
 *   - unit 0 (+0x08): REC_MAGIC   -> cut at fp 0 tears magic to 0 (clean boot)
 *   - unit 1 (+0x18): REC_HDR     -> cut at fp 1 leaves magic without header
 *                                    (unrepairable permanent brick)
 *   - unit 2 (+0x20): REC_PAYLOAD -> cut at fp 2 leaves repairable torn record
 *   - unit 3 (+0x30): REC_CRC     -> cut at fp 3 leaves repairable torn record
 *   - unit 4 (+0x48): REC_COMMIT  -> cut at fp 4 tears commit to 0 (repairable)
 */
#define REC_MAGIC           (*(volatile uint32_t *)(RECORD_BASE + 0x08u))
#define REC_HDR             (*(volatile uint32_t *)(RECORD_BASE + 0x18u))
#define REC_PAYLOAD         (*(volatile uint32_t *)(RECORD_BASE + 0x20u))
#define REC_CRC             (*(volatile uint32_t *)(RECORD_BASE + 0x30u))
#define REC_COMMIT          (*(volatile uint32_t *)(RECORD_BASE + 0x48u))

/* Recovery writes land in dedicated 16-byte units outside the Phase 1 write
 * range (plus clearing REC_MAGIC and REC_HDR). */
#define REPAIR_LOG          (*(volatile uint32_t *)(RECORD_BASE + 0x60u))
#define OSCILLATE_FLAG      (*(volatile uint32_t *)(RECORD_BASE + 0x70u))
#define SECOND_BOOT_FLAG    (*(volatile uint32_t *)(RECORD_BASE + 0x70u))
#define UPDATE_TRIGGER      (*(volatile uint32_t *)(RECORD_BASE + 0x80u))

#define REC_MAGIC_VAL       0x52454331u /* "REC1" */
#define REC_HDR_VAL         0x48445231u /* "HDR1" */
#define REC_PAYLOAD_VAL     0xA5A50002u
#define REC_CRC_VAL         0xC0DEC0DEu
#define REC_COMMIT_VAL      0x444F4E45u /* "DONE" */
#define REPAIR_LOG_VAL      0x434C5231u /* "CLR1" */

extern uint32_t __stack_top;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

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

void Fault_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler, /* NMI */
    Fault_Handler,   /* HardFault */
    Fault_Handler,   /* MemManage */
    Fault_Handler,   /* BusFault */
    Fault_Handler,   /* UsageFault */
    Default_Handler,
};

__attribute__((noinline, section(".ramfunc.update")))
static void write_record(void)
{
    REC_MAGIC = REC_MAGIC_VAL;
    REC_HDR = REC_HDR_VAL;
    REC_PAYLOAD = REC_PAYLOAD_VAL;
    REC_CRC = REC_CRC_VAL;
    REC_COMMIT = REC_COMMIT_VAL;
}

static void trigger_fault(void)
{
    __asm volatile("udf #0");
    for(;;)
    {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
    uint32_t *source = &_siramfunc;
    uint32_t *destination = &_sramfunc;
    while(destination < &_eramfunc)
    {
        *destination++ = *source++;
    }

    const uint32_t *vectors = (const uint32_t *)EXEC_BASE;
    for(uint32_t index = 0u; index < 8u; ++index)
    {
        SRAM_VECTORS[index] = vectors[index];
    }
    VTOR = (uintptr_t)SRAM_VECTORS;

    SCHEDULER_FLAG = 0u;
    TICK_COUNT = 0u;

    /* Clear the update trigger before entering write_record() so Phase 1
     * tracking_start_address (0x20000400) counts only the 5 record writes. */
    if(UPDATE_TRIGGER == 1u)
    {
        UPDATE_TRIGGER = 0u;
        write_record();
    }

    if(REC_MAGIC == REC_MAGIC_VAL && REC_COMMIT != REC_COMMIT_VAL)
    {
        if(REC_HDR != REC_HDR_VAL)
        {
            /* Unrepairable torn header: faults on every recovery boot. */
            trigger_fault();
        }
#if OSCILLATE_ON_TORN
        /* Faulty recovery that toggles an NVM flag instead of repairing the
         * torn record, causing alternating hard_fault / success across boots. */
        if(OSCILLATE_FLAG == 0u)
        {
            OSCILLATE_FLAG = 1u;
            trigger_fault();
        }
        OSCILLATE_FLAG = 0u;
#elif FAIL_ON_SECOND_BOOT
        /* Deferred failure: cycle 0 boots cleanly (success) and latches a
         * persistent flag; cycle 1 faults before memory checks hold. */
        if(SECOND_BOOT_FLAG != 0u)
        {
            trigger_fault();
        }
        SECOND_BOOT_FLAG = 1u;
#elif UNMET_CHECKS_ON_SECOND_BOOT
        /* Deferred memory-check failure: cycle 0 boots cleanly (success) and
         * latches a persistent flag; cycle 1 stays alive in exec without
         * raising SCHEDULER_FLAG or TICK_COUNT (memory_checks_unmet). */
        if(SECOND_BOOT_FLAG != 0u)
        {
            for(;;)
            {
                __asm volatile("nop");
            }
        }
        SECOND_BOOT_FLAG = 1u;
#else
        /* Repairable torn payload: perform 3 MRAM recovery writes to scrub the
         * torn record and log the repair, then fault on cycle 0 so cycle 1
         * boots cleanly from the repaired state. */
        REC_MAGIC = 0u;
        REC_HDR = 0u;
        REPAIR_LOG = REPAIR_LOG_VAL;
        trigger_fault();
#endif
    }

    SCHEDULER_FLAG = 1u;
    for(uint32_t tick = 1u; tick <= 5u; ++tick)
    {
        TICK_COUNT = tick;
    }

    for(;;)
    {
        ++TICK_COUNT;
    }
}
