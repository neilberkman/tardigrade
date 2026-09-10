ENTRY(Reset_Handler)

MEMORY
{
    MRAM (rx)  : ORIGIN = 0x10000000, LENGTH = 0x1000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x2000
}

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > MRAM
    .text : { *(.text*) *(.rodata*) } > MRAM
    .ramfunc :
    {
        _sramfunc = .;
        *(.ramfunc*)
        _eramfunc = .;
    } > SRAM AT > MRAM
    _siramfunc = LOADADDR(.ramfunc);
    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
