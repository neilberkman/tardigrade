/*
 * cbmc_harness.c -- CBMC verification harness for boot_meta_parse().
 *
 * This harness asks CBMC to find metadata byte sequences where the
 * buggy parser accepts a corrupted active_slot value.  Specifically:
 *
 *   1. boot_meta_parse() succeeds (returns 0)
 *   2. The parsed active_slot differs from the "true" active_slot
 *      that would be read if the CRC covered all 12 bytes.
 *
 * If CBMC finds a counterexample, it means the CRC gap lets a
 * corrupted active_slot pass validation -- exactly the bug we planted.
 *
 * Run:
 *   cbmc cbmc_harness.c --trace --json-ui > cbmc_output.json
 *   cbmc cbmc_harness.c --trace --xml-ui  > cbmc_output.xml
 */

#include "boot_meta.h"

/* CBMC built-in for symbolic values. */
extern uint8_t nondet_uint8_t(void);

int main(void) {
    uint8_t meta_bytes[BOOT_META_SIZE];

    /* Let CBMC choose arbitrary metadata content. */
    for (int i = 0; i < BOOT_META_SIZE; i++)
        meta_bytes[i] = nondet_uint8_t();

    struct boot_meta parsed;
    int rc = boot_meta_parse(meta_bytes, BOOT_META_SIZE, &parsed);

    if (rc == 0) {
        /*
         * The buggy parser accepted this metadata.  Now check whether
         * the fixed parser would also accept it with the same result.
         * If the fixed parser rejects it (or produces a different
         * active_slot), we have found the CRC-gap bug.
         */
        struct boot_meta parsed_fixed;
        int rc_fixed = boot_meta_parse_fixed(meta_bytes, BOOT_META_SIZE,
                                             &parsed_fixed);

        /*
         * PROPERTY: if the buggy parser accepts metadata, the fixed
         * parser must also accept it AND agree on active_slot.
         * A counterexample here proves the CRC gap is exploitable.
         */
        __CPROVER_assert(
            rc_fixed == 0 && parsed.active_slot == parsed_fixed.active_slot,
            "CRC gap: buggy parser accepts metadata that fixed parser rejects"
        );
    }

    return 0;
}
