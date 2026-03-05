/*
 * Standalone nxboot header — models the NuttX nxboot bootloader algorithm.
 *
 * This reimplements the nxboot data structures and constants from
 * nuttx-apps/boot/nxboot/include/nxboot.h for bare-metal use without
 * any NuttX dependencies.  The algorithm is identical; only the flash
 * I/O layer is replaced with direct memory-mapped access.
 *
 * Three-partition copy-based bootloader:
 *   - Primary  (slot 0): where firmware executes from
 *   - Secondary (slot 1): update OR recovery (role swaps dynamically)
 *   - Tertiary  (slot 2): update OR recovery (role swaps dynamically)
 *
 * Key concepts:
 *   - External magic (0x534f584e "NXOS") = user-uploaded, auto-confirmed
 *   - Internal magic (0xaca0abb0 | recovery_ptr) = bootloader-managed
 *   - Confirmation = recovery copy exists with matching CRC
 *   - Revert = copy recovery -> primary if primary is unconfirmed
 *
 * Reference: https://github.com/apache/nuttx-apps/tree/master/boot/nxboot
 * License of this standalone reimplementation: Apache-2.0
 */

#ifndef NXBOOT_STANDALONE_H
#define NXBOOT_STANDALONE_H

#include <stdint.h>

/* --- Magic values --- */
#define NXBOOT_HEADER_MAGIC      (0x534f584eu)  /* "NXOS" LE */
#define NXBOOT_HEADER_MAGIC_INT  (0xaca0abb0u)  /* Internal magic base */

#define IS_INTERNAL_MAGIC(m)     (((m) & 0xfffffff0u) == NXBOOT_HEADER_MAGIC_INT)

/* --- Slot indices --- */
#define NXBOOT_PRIMARY    0u
#define NXBOOT_SECONDARY  1u
#define NXBOOT_TERTIARY   2u

/* --- Update types --- */
#define NXBOOT_UPDATE_NONE    0
#define NXBOOT_UPDATE_UPDATE  1
#define NXBOOT_UPDATE_REVERT  2

/* --- Header size --- */
#define NXBOOT_HEADER_SIZE   (0x200u)  /* 512 bytes */

/* --- Image header (128 bytes of meaningful data, padded to NXBOOT_HEADER_SIZE) --- */
typedef struct
{
    uint32_t magic;           /* NXBOOT_HEADER_MAGIC or NXBOOT_HEADER_MAGIC_INT | slot */
    uint8_t  hdr_ver_major;
    uint8_t  hdr_ver_minor;
    uint16_t header_size;     /* Total header size (default 0x200) */
    uint32_t crc;             /* CRC-32 from offset 0x0C to end of image */
    uint32_t size;            /* Image payload size (excludes header) */
    uint64_t identifier;      /* Platform ID — must match expected value */
    uint32_t extd_hdr_ptr;    /* Reserved (0) */
    uint16_t img_ver_major;
    uint16_t img_ver_minor;
    uint16_t img_ver_patch;
    uint8_t  pre_release[94]; /* Null-terminated string, 0xFF padded */
} nxboot_img_header_t;

/* --- Boot state (computed at runtime) --- */
typedef struct
{
    uint32_t update_slot;         /* Slot index for update role */
    uint32_t recovery_slot;       /* Slot index for recovery role */
    int      recovery_valid;      /* Recovery image passes full CRC check */
    int      recovery_present;    /* Recovery CRC matches primary CRC */
    int      primary_confirmed;   /* Primary is confirmed (see algorithm) */
    int      next_boot;           /* NXBOOT_UPDATE_NONE/UPDATE/REVERT */
} nxboot_state_t;

#endif /* NXBOOT_STANDALONE_H */
