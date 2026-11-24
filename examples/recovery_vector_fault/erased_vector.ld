ENTRY(Reset_Handler)

MEMORY
{
    VECTORS (rx) : ORIGIN = 0x10000000, LENGTH = 0x1000
    CODE (rx)    : ORIGIN = 0x10001000, LENGTH = 0x1000
    SRAM (rwx)   : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > VECTORS
    .text : { *(.text*) *(.rodata*) } > CODE
    .ramfunc :
    {
        _sramfunc = .;
        *(.ramfunc*)
        _eramfunc = .;
    } > SRAM AT > CODE
    _siramfunc = LOADADDR(.ramfunc);
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
