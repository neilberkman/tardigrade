#include <stdint.h>

#define BOOT_BASE        ((uintptr_t)0x10000000u)
#define EXEC_BASE        ((uintptr_t)0x10100000u)
#define TARGET_WORDS     ((volatile uint32_t *)0x10100100u)
#define PROGRESS_WORDS   ((volatile uint32_t *)0x10100108u)
#define AUDIT_WORDS      ((volatile uint32_t *)0x10100110u)
#define TARGET_ADDRESS   (*(volatile uint64_t *)0x10100100u)
#define PROGRESS_ADDRESS (*(volatile uint64_t *)0x10100108u)
#define AUDIT_ADDRESS    (*(volatile uint64_t *)0x10100110u)

#define COUNTER_REG      (*(volatile uint32_t *)0x40010000u)
#define SUCCESS_MARKER   (*(volatile uint32_t *)0x20000100u)
#define UPDATE_REQUEST   (*(volatile uint32_t *)0x20000400u)
#define HOST_MSG_REG     (*(volatile uint32_t *)0x20000410u)
#define VTOR             (*(volatile uint32_t *)0xE000ED08u)

#define TARGET_LO           UINT32_C(0x56414C31)
#define TARGET_HI           UINT32_C(0x54524754)
#define TARGET_VALUE        UINT64_C(0x5452475456414C31)
#define PROGRESS_LO         UINT32_C(0x444F4E45)
#define PROGRESS_HI         UINT32_C(0x50524F47)
#define PROGRESS_DONE       UINT64_C(0x50524F47444F4E45)
#define UPDATE_MAGIC        UINT32_C(0x55504432)
#define HOST_RECOVERY_MAGIC UINT32_C(0x52454356)
#define SUCCESS_VALUE       UINT32_C(0x50325041)
#define QUANTUM_SHIFT       3u

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
    for(;;)
    {
        __asm volatile("wfi");
    }
}

__attribute__((noinline)) static void cut_fence(void)
{
    __asm volatile("nop");
}

static void write_mram_u64(volatile uint32_t *words, uint32_t lo, uint32_t hi)
{
    words[0] = lo;
    cut_fence();
    words[1] = hi;
    cut_fence();
}

void Reset_Handler(void)
{
    uint32_t boot_ticks = COUNTER_REG;
    uint32_t boot_quantum = boot_ticks & 0xFFFFu;
    uint32_t update_requested = (UPDATE_REQUEST == UPDATE_MAGIC);

    VTOR = BOOT_BASE;

    if(update_requested)
    {
        UPDATE_REQUEST = 0u;
        write_mram_u64(TARGET_WORDS, TARGET_LO, TARGET_HI);
        write_mram_u64(PROGRESS_WORDS, PROGRESS_LO, PROGRESS_HI);
    }

    if(PROGRESS_ADDRESS != PROGRESS_DONE)
    {
        uint32_t host_msg = HOST_MSG_REG;
        uint32_t low_word = (host_msg & 0xFFFF0000u) | (boot_quantum & 0xFFFFu);
        uint32_t high_word = ((host_msg & 0xFFFFu) << 16) | (boot_quantum & 0xFFFFu);
        write_mram_u64(AUDIT_WORDS, low_word, high_word);
        write_mram_u64(TARGET_WORDS, TARGET_LO, TARGET_HI);
        write_mram_u64(PROGRESS_WORDS, PROGRESS_LO, PROGRESS_HI);
    }

    if(TARGET_ADDRESS == TARGET_VALUE && PROGRESS_ADDRESS == PROGRESS_DONE)
    {
        uint64_t expected_audit = ((uint64_t)(HOST_RECOVERY_MAGIC & 0xFFFFu) << 48)
                                | (uint64_t)(HOST_RECOVERY_MAGIC & 0xFFFF0000u);
        if(update_requested || AUDIT_ADDRESS == expected_audit)
        {
            SUCCESS_MARKER = SUCCESS_VALUE;
            VTOR = EXEC_BASE;
        }
    }

    for(;;)
    {
        __asm volatile("wfi");
    }
}
