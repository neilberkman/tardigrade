*** Settings ***
Library    OperatingSystem

*** Variables ***
${ROOT}    ${CURDIR}/..

*** Test Cases ***
RunFor Completes With Built-In MappedMemory
    [Documentation]    Control: proves RunFor works with built-in peripherals.
    [Timeout]    30s
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_mapped.repl
    # Write vector table + tight loop to 0x00000000 (boot alias).
    # flash_boot_alias is a separate MappedMemory, not an alias of flash.
    Execute Command    sysbus WriteDoubleWord 0x00000000 0x20020000
    Execute Command    sysbus WriteDoubleWord 0x00000004 0x00000009
    Execute Command    sysbus WriteDoubleWord 0x00000008 0xe7fe2042
    Execute Command    emulation RunFor "0.001"
    ${pc}=    Execute Command    cpu PC
    Log    MappedMemory PC after RunFor: ${pc}    console=True
    Should Not Be Equal As Strings    ${pc.strip()}    0x0    CPU should have executed

RunFor Completes With Dynamically Compiled Peripheral On Fetch Path
    [Documentation]    Regression test for native-AOT Renode deadlock.
    ...    emulation RunFor hangs when instruction fetches hit a dynamically
    ...    compiled C# peripheral (loaded via include). Works with built-in
    ...    MappedMemory and on Mono/.NET Renode. Deadlocks on native-AOT.
    [Timeout]    30s
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/GenericNvmController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_nvm.repl
    # Minimal Cortex-M0 vector table + infinite loop at 0x10000000:
    #   0x00: Initial SP = 0x20020000
    #   0x04: Reset vector = 0x10000009 (thumb)
    #   0x08: movs r0, #0x42  (0x2042)
    #   0x0A: b.n -2           (0xe7fe)
    Execute Command    sysbus WriteDoubleWord 0x10000000 0x20020000
    Execute Command    sysbus WriteDoubleWord 0x10000004 0x10000009
    Execute Command    sysbus WriteDoubleWord 0x10000008 0xe7fe2042
    Execute Command    emulation RunFor "0.001"
    ${pc}=    Execute Command    cpu PC
    Log    PC after RunFor: ${pc}    console=True
    Should Not Be Equal As Strings    ${pc.strip()}    0x0    CPU should have executed
