ENTRY(Reset_Handler)

MEMORY
{
    SLOT (rx)  : ORIGIN = 0x10100000, LENGTH = 0x100
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > SLOT
    .text : { *(.text*) *(.rodata*) } > SLOT
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
