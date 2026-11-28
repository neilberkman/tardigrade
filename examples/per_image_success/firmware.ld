/* Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 */

SECTIONS
{
    .vectors FLASH_BASE : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    ASSERT(ADDR(.text) + SIZEOF(.text) - FLASH_BASE <= 0x100, "image exceeds the copy window")
    .common 0x20000040 (NOLOAD) : { *(.common) }
    .liveness LIVENESS_ADDRESS (NOLOAD) : { *(.liveness) }
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) }
}
