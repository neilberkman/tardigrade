#include <stdint.h>

#ifndef TARGET_ADDRESS_VALUE
#define TARGET_ADDRESS_VALUE 0x10100100u
#endif

#ifndef PROGRESS_ADDRESS_VALUE
#define PROGRESS_ADDRESS_VALUE 0x10100108u
#endif

#ifndef HOOK_ADDRESS_VALUE
#define HOOK_ADDRESS_VALUE 0x10100110u
#endif

#define BOOT_BASE        ((uintptr_t)0x10000000u)
#define EXEC_BASE        ((uintptr_t)0x10100000u)
#define TARGET_ADDRESS   (*(volatile uint64_t *)TARGET_ADDRESS_VALUE)
#define PROGRESS_ADDRESS (*(volatile uint64_t *)PROGRESS_ADDRESS_VALUE)
#define HOOK_ADDRESS     (*(volatile uint64_t *)HOOK_ADDRESS_VALUE)

#ifdef DEFERRED_TRACKING_FIXTURE
#define PRE_GATE_ADDRESS (*(volatile uint64_t *)0x10100138u)
#define PRE_GATE_VALUE   UINT64_C(0x5052454741544531)
#endif

#define SUCCESS_MARKER   (*(volatile uint32_t *)0x20000100u)
#define HOOK_SEEN_MARKER (*(volatile uint32_t *)0x20000104u)
#define UPDATE_REQUEST   (*(volatile uint32_t *)0x20000400u)
#define VTOR             (*(volatile uint32_t *)0xE000ED08u)

#define TARGET_VALUE  UINT64_C(0x5452475456414C31)
#define PROGRESS_DONE UINT64_C(0x50524F47444F4E45)
#define HOOK_VALUE    UINT64_C(0x484F4F4B4150504C)
#define UPDATE_MAGIC  UINT32_C(0x55504432)
#define SUCCESS_VALUE UINT32_C(0x50325041)
#define HOOK_SEEN     UINT32_C(0x484F4F4B)

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);
void HardFault_Handler(void);

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,
    HardFault_Handler,
};

void Default_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

__attribute__((naked)) void HardFault_Handler(void)
{
    /* Skip the faulting 16-bit load so recovery can rewrite the bad word. */
    __asm volatile(
        "mrs r0, msp\n"
        "ldr r1, [r0, #24]\n"
        "movs r2, #2\n"
        "add r1, r2\n"
        "str r1, [r0, #24]\n"
        "bx lr\n"
    );
}

#ifdef DEFERRED_TRACKING_FIXTURE
__attribute__((naked, noinline, used, section(".tracking_gate")))
static void tracking_gate(void)
{
    __asm volatile("bx lr");
}
#endif

void Reset_Handler(void)
{
    uint32_t update_requested;

    VTOR = BOOT_BASE;
    update_requested = UPDATE_REQUEST == UPDATE_MAGIC;

    if(update_requested)
    {
        UPDATE_REQUEST = 0u;
#ifdef DEFERRED_TRACKING_FIXTURE
        PRE_GATE_ADDRESS = PRE_GATE_VALUE;
#else
        TARGET_ADDRESS = TARGET_VALUE;
        PROGRESS_ADDRESS = PROGRESS_DONE;
#endif
    }

#ifdef DEFERRED_TRACKING_FIXTURE
    tracking_gate();
    if(update_requested)
    {
        TARGET_ADDRESS = TARGET_VALUE;
        PROGRESS_ADDRESS = PROGRESS_DONE;
    }
#endif

    /* The first recovery instruction touching MRAM reads cut one's word. */
    uint64_t target = TARGET_ADDRESS;
    if(PROGRESS_ADDRESS != PROGRESS_DONE)
    {
        TARGET_ADDRESS = TARGET_VALUE;
        PROGRESS_ADDRESS = PROGRESS_DONE;
        target = TARGET_ADDRESS;
    }

    if(target == TARGET_VALUE)
    {
        if(HOOK_ADDRESS == HOOK_VALUE)
        {
            HOOK_SEEN_MARKER = HOOK_SEEN;
        }
        SUCCESS_MARKER = SUCCESS_VALUE;
        VTOR = EXEC_BASE;
    }

    for(;;)
    {
        __asm volatile("wfi");
    }
}
