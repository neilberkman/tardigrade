ENTRY(Reset_Handler)

MEMORY
{
    APP (rx) : ORIGIN = 0x10100000, LENGTH = 0x1000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > APP
    .text.reset : { KEEP(*(.text.Reset_Handler)) } > APP
    .text : { *(.text*) *(.rodata*) } > APP
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
