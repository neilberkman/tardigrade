#include <stdint.h>

#ifndef HANDLE_READ_FAULT
#define HANDLE_READ_FAULT 0
#endif

#define BOOT_ROM_BASE     ((uintptr_t)0x10000000u)
#define EXEC_BASE         ((uintptr_t)0x10100000u)
#define RECORD_A_ADDR     ((uintptr_t)0x10100100u)
#define RECORD_B_ADDR     ((uintptr_t)0x10100200u)
#define RECORD_MAGIC      0x52454331u /* "REC1" */
#define RECORD_WORDS_U32  8u
#define RECORD_WORDS_U64  4u

#define MARKER_ADDRESS    (*(volatile uint32_t *)0x20000100u)
#define SELECTED_SEQ      (*(volatile uint32_t *)0x20000104u)
#define ECC_FAULT_HANDLED (*(volatile uint32_t *)0x20000108u)
#define UPDATE_REQUEST    (*(volatile uint32_t *)0x20000400u)
#define MARKER_VALUE      0x5245434Fu /* "RECO" */
#define UPDATE_MAGIC      0x55504431u /* "UPD1" */

#define VTOR_ADDRESS      (*(volatile uint32_t *)0xE000ED08u)
#define CFSR_ADDRESS      (*(volatile uint32_t *)0xE000ED28u)

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);
void HardFault_Handler(void);
void BusFault_Handler(void);

struct mram_record {
    uint32_t magic;
    uint32_t seq;
    uint32_t state;
    uint32_t flags;
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t tag;
    uint32_t crc32;
};

static uint32_t compute_crc32(const uint32_t *words, uint32_t count)
{
    uint32_t crc = 0xFFFFFFFFu;
    for(uint32_t i = 0; i < count; ++i)
    {
        uint32_t word = words[i];
        for(uint32_t b = 0; b < 4u; ++b)
        {
            crc ^= (word >> (8u * b)) & 0xFFu;
            for(uint32_t bit = 0; bit < 8u; ++bit)
            {
                if(crc & 1u)
                {
                    crc = (crc >> 1u) ^ 0xEDB88320u;
                }
                else
                {
                    crc >>= 1u;
                }
            }
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

#if HANDLE_READ_FAULT
static volatile uint32_t g_ecc_probe_active;
static volatile uint32_t g_ecc_probe_faulted;
static volatile uint32_t g_ecc_probe_resume_pc;

void ecc_fault_fixup(uint32_t *frame)
{
    if(g_ecc_probe_active)
    {
        g_ecc_probe_faulted = 1u;
        g_ecc_probe_active = 0u;
        frame[6] = g_ecc_probe_resume_pc;
        return;
    }
    for(;;)
    {
        __asm volatile("wfi");
    }
}

__attribute__((naked)) void HardFault_Handler(void)
{
    __asm volatile(
        "mrs r0, msp\n"
        "ldr r1, =ecc_fault_fixup\n"
        "bx r1\n"
    );
}

__attribute__((naked)) void BusFault_Handler(void)
{
    __asm volatile(
        "mrs r0, msp\n"
        "ldr r1, =ecc_fault_fixup\n"
        "bx r1\n"
    );
}

__attribute__((noinline))
static int read_mram_u32(uintptr_t addr, uint32_t *out)
{
    uint32_t val = 0u;
    g_ecc_probe_faulted = 0u;
    g_ecc_probe_active = 1u;
    __asm volatile(
        "adr r3, 2f\n"
        "str r3, [%[rpc]]\n"
        "ldr %[v], [%[a]]\n"
        "dsb\n"
        "isb\n"
        "b 3f\n"
        ".align 2\n"
        "2:\n"
        "movs %[v], #0\n"
        "3:\n"
        : [v] "=&l"(val)
        : [a] "l"(addr), [rpc] "l"(&g_ecc_probe_resume_pc)
        : "r3", "memory"
    );
    g_ecc_probe_active = 0u;
    if(g_ecc_probe_faulted)
    {
        return -1;
    }
    *out = val;
    return 0;
}
#else
void HardFault_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

void BusFault_Handler(void)
{
    for(;;)
    {
        __asm volatile("wfi");
    }
}

__attribute__((noinline))
static int read_mram_u32(uintptr_t addr, uint32_t *out)
{
    *out = *(volatile const uint32_t *)addr;
    return 0;
}
#endif

void Default_Handler(void)
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
    Default_Handler,    /* NMI */
    HardFault_Handler,  /* HardFault */
    Default_Handler,    /* MemManage */
    BusFault_Handler,   /* BusFault */
    Default_Handler,    /* UsageFault */
};

static void clear_record_slot(uintptr_t base)
{
    volatile uint64_t *dst = (volatile uint64_t *)base;
    for(uint32_t i = 0; i < RECORD_WORDS_U64; ++i)
    {
        dst[i] = 0ULL;
    }
}

static int load_record(uintptr_t base, struct mram_record *out, int *saw_read_fault)
{
    uint32_t raw[RECORD_WORDS_U32];
    if(read_mram_u32(base, &raw[0]) != 0)
    {
        *saw_read_fault = 1;
        return 0;
    }
    if(raw[0] != RECORD_MAGIC)
    {
        return 0;
    }
    for(uint32_t i = 1u; i < RECORD_WORDS_U32; ++i)
    {
        if(read_mram_u32(base + (i * sizeof(uint32_t)), &raw[i]) != 0)
        {
            *saw_read_fault = 1;
            return 0;
        }
    }
    if(compute_crc32(raw, RECORD_WORDS_U32 - 1u) != raw[RECORD_WORDS_U32 - 1u])
    {
        return 0;
    }
    out->magic = raw[0];
    out->seq = raw[1];
    out->state = raw[2];
    out->flags = raw[3];
    out->reserved0 = raw[4];
    out->reserved1 = raw[5];
    out->tag = raw[6];
    out->crc32 = raw[7];
    return 1;
}

static void program_record_b(void)
{
    uint32_t words[RECORD_WORDS_U32];
    words[0] = RECORD_MAGIC;
    words[1] = 2u;
    words[2] = 0x20000002u;
    words[3] = 0x00000002u;
    words[4] = 0x00000000u;
    words[5] = 0x00000000u;
    words[6] = 0xA5A50002u;
    words[7] = compute_crc32(words, RECORD_WORDS_U32 - 1u);

    volatile uint64_t *dst = (volatile uint64_t *)RECORD_B_ADDR;
    for(uint32_t i = 0u; i < RECORD_WORDS_U64; ++i)
    {
        uint64_t lo = (uint64_t)words[i * 2u];
        uint64_t hi = (uint64_t)words[i * 2u + 1u];
        dst[i] = lo | (hi << 32u);
    }
}

void Reset_Handler(void)
{
    VTOR_ADDRESS = BOOT_ROM_BASE;
#if HANDLE_READ_FAULT
    g_ecc_probe_active = 0u;
    g_ecc_probe_faulted = 0u;
    g_ecc_probe_resume_pc = 0u;
#endif
    if(UPDATE_REQUEST == UPDATE_MAGIC)
    {
        UPDATE_REQUEST = 0u;
        program_record_b();
    }

    struct mram_record rec_a;
    struct mram_record rec_b;
    int fault_a = 0;
    int fault_b = 0;
    int valid_a = load_record(RECORD_A_ADDR, &rec_a, &fault_a);
    int valid_b = load_record(RECORD_B_ADDR, &rec_b, &fault_b);

#if HANDLE_READ_FAULT
    if(fault_b)
    {
        ECC_FAULT_HANDLED = 1u;
        clear_record_slot(RECORD_B_ADDR);
    }
#endif

    uint32_t best_seq = 0u;
    int has_valid = 0;
    if(valid_a)
    {
        best_seq = rec_a.seq;
        has_valid = 1;
    }
    if(valid_b && (!has_valid || rec_b.seq > best_seq))
    {
        best_seq = rec_b.seq;
        has_valid = 1;
    }

    if(has_valid)
    {
        SELECTED_SEQ = best_seq;
        MARKER_ADDRESS = MARKER_VALUE;
        VTOR_ADDRESS = EXEC_BASE;
    }

    for(;;)
    {
        __asm volatile("wfi");
    }
}
