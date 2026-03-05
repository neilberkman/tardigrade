*** Keywords ***
Create Generic Controller Machine
    Execute Command    include "${CURDIR}/../peripherals/NVMemoryController.cs"
    Execute Command    include "${CURDIR}/../peripherals/GenericNvmController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../platforms/cortex_m0_nvm_generic_ctrl.repl

*** Test Cases ***
Generic Controller Executes Write Command
    Create Generic Controller Machine
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10000020
    Execute Command    sysbus WriteDoubleWord 0x40001020 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000002
    ${status}=         Execute Command    sysbus ReadDoubleWord 0x40001018
    Should Be Equal As Numbers    ${status}    0x00000004
    ${read_back}=      Execute Command    sysbus ReadDoubleWord 0x10000020
    Should Be Equal As Numbers    ${read_back}    0xDEADBEEF

Generic Controller Honors FaultAtWordWrite
    Create Generic Controller Machine
    Execute Command    sysbus WriteQuadWord 0x10000020 0xFFFFFFFFFFFFFFFF
    Execute Command    nvm FaultAtWordWrite 2
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10000020
    Execute Command    sysbus WriteDoubleWord 0x40001020 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000002
    ${word}=           Execute Command    sysbus ReadQuadWord 0x10000020
    Should Be Equal As Numbers    ${word}    0x00000000DEADBEEF
