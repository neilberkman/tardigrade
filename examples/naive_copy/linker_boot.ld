ENTRY(Reset_Handler)

MEMORY
{
    BOOT (rx)  : ORIGIN = 0x10000000, LENGTH = 0x2000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x20000
}

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > BOOT

    .text :
    {
        *(.text*)
        *(.rodata*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame*)
    } > BOOT

    .data :
    {
        *(.data*)
    } > SRAM AT > BOOT

    .bss (NOLOAD) :
    {
        *(.bss*)
        *(COMMON)
    } > SRAM

    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
