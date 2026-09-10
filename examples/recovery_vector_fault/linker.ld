ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 0x1000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .ramfunc :
    {
        _sramfunc = .;
        *(.ramfunc*)
        _eramfunc = .;
    } > SRAM AT > FLASH
    _siramfunc = LOADADDR(.ramfunc);
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
