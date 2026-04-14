/*
 * Firmware-level fault injection harness: OTP anti-rollback advancement.
 *
 * Demonstrates testing firmware application code (not bootloader code)
 * with tardigrade.  The harness calls a single function under test,
 * writes a result marker to SRAM, and halts.  Tardigrade injects faults
 * during execution and checks the marker to determine pass/fail.
 *
 * Function under test: advance_rollback_floor()
 *   Programs OTP fuses until the popcount reaches the target value.
 *   Must detect blow failures (fuse physically fails to program) and
 *   abort with a bounded retry limit instead of looping forever.
 *
 * Memory map (matches cortex_m0_otp.repl):
 *   0x10000000  NVM (main storage, 512 KB)
 *   0x20000000  SRAM (128 KB)
 *   0x40002000  OTP eFuse region (256 bytes, word-granularity)
 *
 * Result marker at SRAM 0x20010000:
 *   0x00000001  = success (floor advanced to target)
 *   0x00000002  = failure (blow failed, aborted gracefully)
 *   0xDEAD0001  = stuck (infinite loop, timeout = finding)
 *   <not written> = crash / hardfault
 */

#include <stdint.h>

/* --- Memory map --- */
#define OTP_BASE        ((volatile uint32_t *)0x40002000u)
#define OTP_WORDS       64     /* 256 bytes / 4 bytes per word */
#define RESULT_ADDR     ((volatile uint32_t *)0x20010000u)

/* Result codes */
#define RESULT_SUCCESS  0x00000001u
#define RESULT_ABORTED  0x00000002u

/* --- OTP access primitives --- */

static uint32_t otp_read_word(int index)
{
    return OTP_BASE[index];
}

static void otp_blow_word(int index, uint32_t bits)
{
    /* OR-semantics: bits can only go 0->1 in OTP. */
    OTP_BASE[index] = OTP_BASE[index] | bits;
}

static int popcount32(uint32_t v)
{
    int c = 0;
    while (v) { c += v & 1; v >>= 1; }
    return c;
}

static int otp_total_popcount(void)
{
    int total = 0;
    for (int i = 0; i < OTP_WORDS; i++)
        total += popcount32(otp_read_word(i));
    return total;
}

/* --- Function under test --- */

/*
 * Advance the anti-rollback floor by blowing OTP fuses until the total
 * popcount reaches 'target'.
 *
 * Returns 0 on success, -1 if a blow operation fails to make progress
 * (retry limit exceeded).
 *
 * BUG VARIANT (for testing): remove the retry limit and this function
 * loops forever when otp_blow_nop fires.
 */
#ifndef MAX_BLOW_RETRIES
#define MAX_BLOW_RETRIES 10
#endif

static int advance_rollback_floor(int target)
{
    int current = otp_total_popcount();
    if (current >= target)
        return 0;  /* already at or past target */

    /* Find the first word with room for more bits. */
    for (int word = 0; word < OTP_WORDS && current < target; word++)
    {
        uint32_t val = otp_read_word(word);
        if (val == 0xFFFFFFFFu)
            continue;  /* fully blown */

        for (int bit = 0; bit < 32 && current < target; bit++)
        {
            if (val & (1u << bit))
                continue;  /* already blown */

            int retries = 0;
            otp_blow_word(word, 1u << bit);

            /* Verify the bit actually blew. */
            while (!(otp_read_word(word) & (1u << bit)))
            {
                retries++;
                if (retries >= MAX_BLOW_RETRIES)
                    return -1;  /* blow failed, abort */
                otp_blow_word(word, 1u << bit);
            }

            current++;
        }
    }

    return (current >= target) ? 0 : -1;
}

/* --- Harness entry point --- */

extern uint32_t __stack_top;

void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    &__stack_top,
    Reset_Handler,
    Default_Handler,  /* NMI */
    Default_Handler,  /* HardFault */
    Default_Handler,  /* MemManage */
    Default_Handler,  /* BusFault */
    Default_Handler,  /* UsageFault */
    0, 0, 0, 0,
    Default_Handler,  /* SVCall */
    Default_Handler,  /* Debug */
    0,
    Default_Handler,  /* PendSV */
    Default_Handler,  /* SysTick */
};

void Default_Handler(void) { while (1); }

void Reset_Handler(void)
{
    /* Call the function under test: advance floor to 5 bits. */
    int result = advance_rollback_floor(5);

    /* Write result marker. */
    if (result == 0)
        *RESULT_ADDR = RESULT_SUCCESS;
    else
        *RESULT_ADDR = RESULT_ABORTED;

    /* Halt. */
    while (1);
}
