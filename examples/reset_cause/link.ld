/* SPDX-License-Identifier: Apache-2.0 */
ENTRY(boot)
SECTIONS {
    . = ORIGIN_FLASH;
    .text : { KEEP(*(.vectors)) *(.text*) }
}
