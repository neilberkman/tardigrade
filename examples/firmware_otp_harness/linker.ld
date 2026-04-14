ENTRY(Reset_Handler)

MEMORY
{
    NVM  (rx)  : ORIGIN = 0x10000000, LENGTH = 0x80000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x20000
}

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > NVM

    .text :
    {
        *(.text*)
        *(.rodata*)
    } > NVM

    .data :
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > SRAM AT > NVM

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM

    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
