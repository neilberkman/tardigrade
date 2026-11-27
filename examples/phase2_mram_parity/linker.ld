ENTRY(Reset_Handler)

MEMORY
{
    BOOT (rx)  : ORIGIN = 0x10000000, LENGTH = 0x1000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > BOOT
    .text : { *(.text*) *(.rodata*) } > BOOT
    .tracking_gate ORIGIN(BOOT) + 0x200 : { KEEP(*(.tracking_gate)) } > BOOT
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > SRAM
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
