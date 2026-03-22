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

Generic Controller Command Drop Silently Skips Write
    Create Generic Controller Machine
    Execute Command    sysbus WriteDoubleWord 0x10000020 0xFFFFFFFF
    Execute Command    nvm_ctrl FaultAtCommandExecution 1
    Execute Command    nvm_ctrl CommandFaultMode 1
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10000020
    Execute Command    sysbus WriteDoubleWord 0x40001020 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000002
    ${status}=         Execute Command    sysbus ReadDoubleWord 0x40001018
    Should Be Equal As Numbers    ${status}    0x00000004
    ${fired}=          Execute Command    nvm_ctrl CommandFaultFired
    ${fired}=          Strip String    ${fired}
    Should Be Equal As Strings    ${fired}    True
    ${word}=           Execute Command    sysbus ReadDoubleWord 0x10000020
    Should Be Equal As Numbers    ${word}    0xFFFFFFFF

Generic Controller Drops Out Of Range Write Command
    Create Generic Controller Machine
    Execute Command    sysbus WriteDoubleWord 0x10000020 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10100000
    Execute Command    sysbus WriteDoubleWord 0x40001020 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000002
    ${status}=         Execute Command    sysbus ReadDoubleWord 0x40001018
    Should Be Equal As Numbers    ${status}    0x00000004
    ${illegal}=        Execute Command    nvm_ctrl IllegalOperation
    ${illegal}=        Strip String    ${illegal}
    Should Be Equal As Strings    ${illegal}    False
    ${word}=           Execute Command    sysbus ReadDoubleWord 0x10000020
    Should Be Equal As Numbers    ${word}    0x11223344
