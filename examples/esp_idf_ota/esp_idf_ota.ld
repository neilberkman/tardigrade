/* Linker script for ESP-IDF OTA bootloader model (nRF52840, 8KB bootloader) */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 0x2000   /* 8KB bootloader */
    RAM (rwx)   : ORIGIN = 0x20000000, LENGTH = 0x40000  /* 256KB SRAM */
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
    } > FLASH

    .data :
    {
        *(.data*)
    } > RAM AT > FLASH

    .bss :
    {
        *(.bss*)
        *(COMMON)
    } > RAM
}
