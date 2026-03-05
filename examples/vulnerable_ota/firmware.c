#include <stdint.h>

#define ACTIVE_BASE         ((uintptr_t)0x10000000u)
#define STAGING_BASE        ((uintptr_t)0x10038000u)
#define OTA_BYTES           (224u * 1024u)
#define OTA_WORDS           (OTA_BYTES / 8u)
#define PERSIST_MARKER_ADDR ((uintptr_t)0x10070000u)
#define BOOT_COUNTER_ADDR   ((uintptr_t)0x10070004u)

extern uint32_t __stack_top;
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _siramfunc;
extern uint32_t _sramfunc;
extern uint32_t _eramfunc;

void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector")))
const void* vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler, // NMI
    Default_Handler, // HardFault
    Default_Handler, // MemManage
    Default_Handler, // BusFault
    Default_Handler, // UsageFault
    0,
    0,
    0,
    0,
    Default_Handler, // SVCall
    Default_Handler, // Debug
    0,
    Default_Handler, // PendSV
    Default_Handler, // SysTick
};

void Default_Handler(void)
{
    while(1)
    {
    }
}

static void init_runtime(void)
{
    uint32_t* src;
    uint32_t* dst;

    src = &_sidata;
    dst = &_sdata;
    while(dst < &_edata)
    {
        *dst++ = *src++;
    }

    src = &_siramfunc;
    dst = &_sramfunc;
    while(dst < &_eramfunc)
    {
        *dst++ = *src++;
    }

    dst = &_sbss;
    while(dst < &_ebss)
    {
        *dst++ = 0;
    }
}

__attribute__((section(".ramfunc")))
static void copy_staging_to_active(void)
{
    volatile uint64_t* dst = (volatile uint64_t*)ACTIVE_BASE;
    volatile const uint64_t* src = (volatile const uint64_t*)STAGING_BASE;
    volatile uint32_t* boot_counter = (volatile uint32_t*)BOOT_COUNTER_ADDR;

    *boot_counter = *boot_counter + 1u;

    for(uint32_t i = 0; i < OTA_WORDS; i++)
    {
        dst[i] = src[i];
    }

    *(volatile uint32_t*)PERSIST_MARKER_ADDR = 0xC0FEBEEFu;
}

void Reset_Handler(void)
{
    init_runtime();
    copy_staging_to_active();

    while(1)
    {
    }
}
