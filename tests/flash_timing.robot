*** Variables ***
${PERIPHERALS}    ${CURDIR}/../peripherals

*** Keywords ***
Create Timing Machine
    Execute Command    include "${PERIPHERALS}/ITardigradeFaultInjectable.cs"
    Execute Command    include "${PERIPHERALS}/FlashTiming.cs"
    Execute Command    include "${PERIPHERALS}/NVMemoryController.cs"
    Execute Command    include "${PERIPHERALS}/GenericNvmController.cs"
    Execute Command    include "${PERIPHERALS}/FaultTracker.cs"
    Execute Command    include "${PERIPHERALS}/CFIFlash.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../platforms/cortex_m0_nvm_generic_ctrl.repl
    Execute Command    machine LoadPlatformDescriptionFromString "nor: Tardigrade.CFIFlash @ sysbus 0x04000000 { size: 0x40000 }"
    # Thumb code in SRAM. Increment r2 on each busy poll and finish at a
    # distinct PC when register [r1] becomes nonzero.
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x28006808
    Execute Command    sysbus WriteDoubleWord 0x20000004 0x3201D101
    Execute Command    sysbus WriteDoubleWord 0x20000008 0xE7FEE7FA
    Execute Command    cpu PC 0x20000001
    Execute Command    cpu PerformanceInMips 1

Read Should Equal
    [Arguments]    ${command}    ${expected}
    ${raw}=    Execute Command    ${command}
    Should Be Equal As Integers    ${raw.strip()}    ${expected}

Start CFI Program
    [Arguments]    ${value}
    Execute Command    sysbus WriteDoubleWord 0x04000000 0x40
    Execute Command    sysbus WriteDoubleWord 0x04000000 ${value}

Start CFI Erase
    Execute Command    sysbus WriteDoubleWord 0x04000000 0x20
    Execute Command    sysbus WriteDoubleWord 0x04000000 0xD0

Measure CFI Erase
    [Arguments]    ${mode}
    Execute Command    cpu SetRegister 1 0x04000000
    Execute Command    cpu SetRegister 2 0
    Execute Command    cpu PC 0x20000001
    Execute Command    nor OperationTiming ${mode}
    Start CFI Erase
    ${start}=    Evaluate    time.monotonic()    modules=time
    Execute Command    emulation RunFor "1.0"
    ${seconds}=    Evaluate    time.monotonic() - ${start}    modules=time
    Log To Console    flash_benchmark mode=${mode} virtual_seconds=1 wall_seconds=${seconds}
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0x80
    Execute Command    emulation RunFor "0.000020"
    ${polls}=    Execute Command    cpu GetRegister 2
    Should Be True    (int($polls.strip(), 0) > 0) == ($mode == "Typical")
    Execute Command    emulation RunFor "0.000020"
    Read Should Equal    cpu GetRegister 2    ${polls.strip()}

Load Flash Controller
    [Arguments]    ${model}    ${registers}    ${properties}
    Execute Command    include "${PERIPHERALS}/${model}.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "bankA: Memory.MappedMemory @ sysbus 0x08000000 { size: 0x100000 }"
    Execute Command    machine LoadPlatformDescriptionFromString "bankB: Memory.MappedMemory @ sysbus 0x08100000 { size: 0x100000 }"
    Execute Command    machine LoadPlatformDescriptionFromString "ctl: Miscellaneous.${model} @ sysbus ${registers} { ${properties} }"

Start Firmware Store
    [Arguments]    ${address}    ${status_register}    ${busy_mask}    ${skip_count_branch}    ${count}=1
    # Store r3 once per word, then keep polling from SRAM. A branch to
    # itself can put Renode's translated core to sleep for the whole slice.
    FOR    ${i}    IN RANGE    ${count}
        ${pc}=    Evaluate    hex(0x20000200 + ${i} * 2)
        Execute Command    sysbus WriteWord ${pc} 0xc408
    END
    ${end}=    Evaluate    0x20000200 + ${count} * 2
    ${branch}=    Evaluate    hex(0xe000 | ((0x20000300 - (${end} + 4)) // 2))
    Execute Command    sysbus WriteWord ${end} ${branch}
    # ldr r0,[r1] / tst r0,r5 / branch to loop if ready /
    # adds r2,1 / b loop.
    Execute Command    sysbus WriteDoubleWord 0x20000300 0x42286808
    Execute Command    sysbus WriteWord 0x20000304 ${skip_count_branch}
    Execute Command    sysbus WriteWord 0x20000306 0x3201
    Execute Command    sysbus WriteWord 0x20000308 0xe7fa
    Execute Command    cpu SetRegister 1 ${status_register}
    Execute Command    cpu SetRegister 3 0x12345678
    Execute Command    cpu SetRegister 4 ${address}
    Execute Command    cpu SetRegister 5 ${busy_mask}
    Execute Command    cpu PC 0x20000201

Firmware Observed Busy Then Ready
    ${polls}=    Execute Command    cpu GetRegister 2
    Should Be True    int('''${polls}'''.strip(), 0) > 0
    Execute Command    emulation RunFor "0.000020"
    ${ready_count}=    Execute Command    cpu GetRegister 2
    Execute Command    emulation RunFor "0.000020"
    Read Should Equal    cpu GetRegister 2    ${ready_count.strip()}

Check F4 Device
    [Arguments]    ${model}    ${base}
    Create Timing Machine
    Load Flash Controller    ${model}    ${base}    Flash: bankA; FlashBaseAddress: 0x08000000; FlashSize: 0x100000
    Execute Command    ctl OperationTiming Typical
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0xcdef89ab
    Execute Command    sysbus WriteDoubleWord 0x08000000 0xffffffff
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x201
    Start Firmware Store    0x08000000    0x40023c0c    0x10000    0xd0fc
    Execute Command    emulation RunFor "0.000004"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    Execute Command    emulation RunFor "0.000016"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x202
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x10202
    Execute Command    cpu SetRegister 2 0
    Execute Command    emulation RunFor "0.249999"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    Firmware Observed Busy Then Ready
    Execute Command    sysbus WriteDoubleWord 0x08000000 0
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x10202
    Execute Command    emulation RunFor "0.125"
    Execute Command    ctl Reset
    Execute Command    emulation RunFor "0.125"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0xcdef89ab
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x10204
    Execute Command    emulation RunFor "7.999999"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff

    # An untimed image restore between boots establishes a new committed value.
    Execute Command    ctl OperationTiming Off
    Execute Command    sysbus WriteDoubleWord 0x08000000 0xabcdef12
    Execute Command    ctl OperationTiming Typical
    Execute Command    sysbus WriteDoubleWord 0x40023c10 0x201
    Start Firmware Store    0x08000000    0x40023c0c    0x10000    0xd0fc
    Execute Command    emulation RunFor "0.000004"
    Read Should Equal    sysbus ReadDoubleWord 0x40023c0c    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xabcdef12
    Execute Command    ctl Reset
    Execute Command    emulation RunFor "0.000030"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xabcdef12

Check H7 Device
    [Arguments]    ${model}    ${properties}
    Create Timing Machine
    Load Flash Controller    ${model}    0x52002000    ${properties}
    Execute Command    ctl OperationTiming Maximum
    Execute Command    sysbus WriteDoubleWord 0x52002004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x52002004 0xcdef89ab
    Execute Command    sysbus WriteDoubleWord 0x5200200c 0x32
    Start Firmware Store    0x08000000    0x52002010    1    0xd0fc    8
    Execute Command    emulation RunFor "0.000020"
    ${sr}=    Execute Command    sysbus ReadDoubleWord 0x52002010
    Should Be Equal As Integers    ${{int($sr.strip(), 0) & 5}}    5
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0
    Read Should Equal    sysbus ReadDoubleWord 0x52002110    0
    Execute Command    emulation RunFor "0.000200"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x0800001c    0x12345678
    Execute Command    sysbus WriteDoubleWord 0x5200200c 0x34
    Execute Command    sysbus WriteDoubleWord 0x5200200c 0xb4
    Execute Command    cpu SetRegister 2 0
    Execute Command    emulation RunFor "1.999999"
    ${sr}=    Execute Command    sysbus ReadDoubleWord 0x52002010
    Should Be Equal As Integers    ${{int($sr.strip(), 0) & 5}}    5
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    ${sr}=    Execute Command    sysbus ReadDoubleWord 0x52002010
    Should Be Equal As Integers    ${{int($sr.strip(), 0) & 5}}    0
    Firmware Observed Busy Then Ready
    Execute Command    sysbus WriteDoubleWord 0x08000000 0
    Execute Command    sysbus WriteDoubleWord 0x5200200c 0xb4
    Execute Command    emulation RunFor "0.100"
    Execute Command    ctl Reset
    Execute Command    emulation RunFor "2.0"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0

Check Serialized F4 Programs
    [Arguments]    ${model}    ${base}
    Create Timing Machine
    Load Flash Controller    ${model}    ${base}    Flash: bankA; FlashBaseAddress: 0x08000000; FlashSize: 0x100000
    Execute Command    cpu PerformanceInMips 100
    Execute Command    ctl SkipShadowScan true
    Execute Command    ctl PassthroughMode true
    Execute Command    ctl OperationTiming Maximum
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023c04 0xcdef89ab
    # Thumb loop in SRAM. Enable PG, store one word, poll BSY, clear PG,
    # decrement r6, and repeat. 200 serialized programs need at least 20 ms.
    Execute Command    sysbus WriteDoubleWord 0x20000200 0x60236017
    Execute Command    sysbus WriteDoubleWord 0x20000204 0x42286808
    Execute Command    sysbus WriteDoubleWord 0x20000208 0x6010d1fc
    Execute Command    sysbus WriteDoubleWord 0x2000020c 0xd1f73e01
    Execute Command    sysbus WriteWord 0x20000210 0xe7fe
    Execute Command    cpu SetRegister 1 0x40023c0c
    Execute Command    cpu SetRegister 2 0x40023c10
    Execute Command    cpu SetRegister 3 0x12345678
    Execute Command    cpu SetRegister 4 0x08000000
    Execute Command    cpu SetRegister 5 0x10000
    Execute Command    cpu SetRegister 6 200
    Execute Command    cpu SetRegister 7 0x201
    Execute Command    cpu PC 0x20000201
    Execute Command    emulation RunFor "0.010"
    ${remaining}=    Execute Command    cpu GetRegister 6
    Log To Console    serialized remaining_at_10ms=${remaining.strip()}
    Should Be True    int($remaining.strip(), 0) >= 100
    Execute Command    emulation RunFor "0.009999"
    ${remaining}=    Execute Command    cpu GetRegister 6
    Log To Console    serialized remaining_at_19999us=${remaining.strip()}
    Should Be True    int($remaining.strip(), 0) >= 1
    Execute Command    emulation RunFor "0.010"
    Read Should Equal    cpu GetRegister 6    0
    Read Should Equal    ctl TotalWordWrites    200

*** Test Cases ***
F4 Consecutive Firmware Program Windows
    Check Serialized F4 Programs    STM32F4FlashController    0x40023800

F4 Fast Consecutive Firmware Program Windows
    Check Serialized F4 Programs    STM32F4FastFlash    0x40023c00

CFI Word Program Finishes At The Typical Deadline
    Create Timing Machine
    Execute Command    nor OperationTiming Typical
    Execute Command    cpu SetRegister 1 0x04000000
    Start CFI Program    0x11223344
    Read Should Equal    sysbus ReadByte 0x04000000    0
    Execute Command    emulation RunFor "0.000209"
    Read Should Equal    sysbus ReadWord 0x04000000    0
    Read Should Equal    nor TotalWordWrites    0
    ${polls}=    Execute Command    cpu GetRegister 2
    Should Be True    int('''${polls}'''.strip(), 0) > 0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0x80
    Read Should Equal    nor TotalWordWrites    1
    Execute Command    sysbus WriteByte 0x04000000 0xFF
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0x11223344

CFI Maximum Erase And Reset
    Create Timing Machine
    Execute Command    cpu SetRegister 1 0x04000000
    Start CFI Program    0
    Execute Command    nor OperationTiming Maximum
    Start CFI Erase
    Execute Command    emulation RunFor "2.5"
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0
    Execute Command    nor Reset
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0
    Start CFI Erase
    Execute Command    emulation RunFor "4.999999"
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0x80
    Execute Command    sysbus WriteByte 0x04000000 0xFF
    Read Should Equal    sysbus ReadDoubleWord 0x04000000    0xFFFFFFFF

Generic NVM Latches The Command And Data Through Expiry
    Create Timing Machine
    Execute Command    cpu SetRegister 1 0x40001018
    Execute Command    nvm WriteLatencyMicros 100
    Execute Command    nvm EraseLatencyMicros 200
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10000020
    Execute Command    sysbus WriteDoubleWord 0x40001020 0x12345678
    Execute Command    sysbus WriteDoubleWord 0x40001014 2
    Execute Command    sysbus WriteDoubleWord 0x40001020 0x11111111
    Execute Command    emulation RunFor "0.000099"
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    0
    Read Should Equal    sysbus ReadDoubleWord 0x10000020    0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    4
    Read Should Equal    sysbus ReadDoubleWord 0x10000020    0x12345678
    Firmware Observed Busy Then Ready
    Execute Command    sysbus WriteDoubleWord 0x40001014 4
    Execute Command    emulation RunFor "0.000199"
    Read Should Equal    sysbus ReadDoubleWord 0x10000020    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x10000020    0
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    4
    Execute Command    sysbus WriteDoubleWord 0x40001014 2
    Execute Command    emulation RunFor "0.000050"
    Execute Command    nvm Reset
    Execute Command    emulation RunFor "0.000100"
    Read Should Equal    sysbus ReadDoubleWord 0x10000020    0

CFI Firmware Polls During A Timed Erase
    Create Timing Machine
    # Count busy reads continuously, including across changes in timing mode.
    Execute Command    sysbus WriteWord 0x20000004 0xd1fc
    Execute Command    sysbus WriteWord 0x20000008 0xe7fa
    Measure CFI Erase    Off
    Measure CFI Erase    Typical

STM32F4 Controller Holds BSY Until Program And Erase Complete
    Check F4 Device    STM32F4FlashController    0x40023800

STM32F4 Fast Controller Holds BSY Until Program And Erase Complete
    Check F4 Device    STM32F4FastFlash    0x40023c00

STM32H743 Controller Times One Flash Word And One Bank
    Check H7 Device    STM32H7FlashController    flash1: bankA; flash2: bankB

STM32H743 Fast Controller Times One Flash Word And One Bank
    Check H7 Device    STM32H7FastFlash    Flash1: bankA; Flash2: bankB

NRF52840 Buffered Programs And Maximum Page Erase
    Create Timing Machine
    Load Flash Controller    NRF52NVMC    0x4001e000    Flash: bankA; FlashBaseAddress: 0x08000000; FlashSize: 0x100000
    Execute Command    ctl OperationTiming Maximum
    Execute Command    sysbus WriteDoubleWord 0x4001e504 1
    Start Firmware Store    0x08000000    0x4001e400    1    0xd1fc    2
    Execute Command    emulation RunFor "0.000010"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    0
    Read Should Equal    sysbus ReadDoubleWord 0x4001e408    0
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0
    Execute Command    emulation RunFor "0.000040"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    0
    Read Should Equal    sysbus ReadDoubleWord 0x4001e408    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0
    Execute Command    emulation RunFor "0.000041"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0x12345678
    Execute Command    sysbus WriteDoubleWord 0x4001e504 0
    Execute Command    sysbus WriteDoubleWord 0x4001e504 2
    Execute Command    sysbus WriteDoubleWord 0x4001e508 0x08000000
    Execute Command    cpu SetRegister 2 0
    Execute Command    emulation RunFor "0.084999"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    0
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    Firmware Observed Busy Then Ready
    Execute Command    sysbus WriteDoubleWord 0x08000000 0
    Execute Command    sysbus WriteDoubleWord 0x4001e50c 1
    Execute Command    emulation RunFor "0.080"
    Execute Command    ctl Reset
    Execute Command    emulation RunFor "0.100"
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0

NVMemoryController Reports Program And Erase On Both Status Registers
    Create Timing Machine
    Execute Command    machine LoadPlatformDescriptionFromString "mctrl: NVMemoryController @ sysbus 0x40002000 { Nvm: nvm; FullMode: true }"
    Execute Command    cpu SetRegister 1 0x40002030
    Execute Command    nvm WriteLatencyMicros 40
    Execute Command    nvm EraseLatencyMicros 300
    Execute Command    sysbus WriteDoubleWord 0x10000010 0xaabbccdd
    Execute Command    emulation RunFor "0.000039"
    Read Should Equal    sysbus ReadDoubleWord 0x40002000    0x20c
    Read Should Equal    sysbus ReadDoubleWord 0x40002030    0
    Read Should Equal    sysbus ReadDoubleWord 0x10000010    0
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40002030    0x300
    Read Should Equal    sysbus ReadDoubleWord 0x10000010    0xaabbccdd
    Firmware Observed Busy Then Ready
    Execute Command    sysbus WriteDoubleWord 0x40002030 4
    Execute Command    sysbus WriteDoubleWord 0x40002034 16
    Execute Command    sysbus WriteDoubleWord 0x40002038 0x10
    Execute Command    emulation RunFor "0.000299"
    Read Should Equal    sysbus ReadDoubleWord 0x40002000    0x40c
    Read Should Equal    sysbus ReadDoubleWord 0x10000010    0xaabbccdd
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40002000    0xc
    Read Should Equal    sysbus ReadDoubleWord 0x10000010    0
    Execute Command    sysbus WriteDoubleWord 0x10000010 0x12345678
    Execute Command    emulation RunFor "0.000020"
    Execute Command    nvm Reset
    Execute Command    emulation RunFor "0.000021"
    Read Should Equal    sysbus ReadDoubleWord 0x10000010    0

CPU Issued Program Starts After Earlier Instructions In The Same Quantum
    Create Timing Machine
    Execute Command    nvm WriteLatencyMicros 100
    # Count down r4, store r3 at [r5], then increment r2 while the status
    # in [r1] is zero. At 1 MIPS the store issues after about 200 us.
    Execute Command    sysbus WriteDoubleWord 0x20000200 0xd1fd3c01
    Execute Command    sysbus WriteDoubleWord 0x20000204 0x6808602b
    Execute Command    sysbus WriteDoubleWord 0x20000208 0xd1012800
    Execute Command    sysbus WriteDoubleWord 0x2000020c 0xe7fa3201
    Execute Command    sysbus WriteWord 0x20000210 0xe7fe
    Execute Command    cpu SetRegister 1 0x40001018
    Execute Command    cpu SetRegister 2 0
    Execute Command    cpu SetRegister 3 0x663355aa
    Execute Command    cpu SetRegister 4 100
    Execute Command    cpu SetRegister 5 0x10000018
    Execute Command    cpu PC 0x20000201
    Execute Command    emulation RunFor "0.000240"
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    0
    Read Should Equal    sysbus ReadDoubleWord 0x10000018    0
    Execute Command    emulation RunFor "0.000080"
    Read Should Equal    sysbus ReadDoubleWord 0x40001018    4
    Read Should Equal    sysbus ReadDoubleWord 0x10000018    0x663355aa
    Read Should Equal    cpu PC    0x20000210
    ${polls}=    Execute Command    cpu GetRegister 2
    Should Be True    16 <= int('''${polls}'''.strip(), 0) <= 24

NRF52840 Reset Preserves The First Completed NVM Program
    Create Timing Machine
    Execute Command    include "${PERIPHERALS}/NRF52NVMC.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "ctl: Miscellaneous.NRF52NVMC @ sysbus 0x4001e000 { Nvm: nvm; NvmBaseAddress: 0x10000000 }"
    Execute Command    nvm WordSize 4
    Execute Command    ctl OperationTiming Maximum
    Execute Command    sysbus WriteDoubleWord 0x4001e504 1
    Start Firmware Store    0x10000000    0x4001e400    1    0xd1fc    2
    Execute Command    emulation RunFor "0.000015"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    0
    Read Should Equal    sysbus ReadDoubleWord 0x4001e408    0
    Execute Command    emulation RunFor "0.000045"
    Read Should Equal    sysbus ReadDoubleWord 0x10000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x10000004    0
    Read Should Equal    sysbus ReadDoubleWord 0x4001e408    1
    Execute Command    ctl Reset
    Execute Command    emulation RunFor "0.000050"
    Read Should Equal    sysbus ReadDoubleWord 0x4001e400    1
    Read Should Equal    sysbus ReadDoubleWord 0x10000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x10000004    0
    Firmware Observed Busy Then Ready

STM32F103 Controller Holds BSY Until HalfWord Program And Page Erase Complete
    Create Timing Machine
    Execute Command    include "${PERIPHERALS}/STM32F1FlashController.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "bankF1: Memory.MappedMemory @ sysbus 0x08000000 { size: 0x20000 }"
    Execute Command    machine LoadPlatformDescriptionFromString "ctl: Miscellaneous.STM32F1FlashController @ sysbus 0x40022000 { flash: bankF1; flashBaseAddress: 0x08000000; flashSize: 0x20000; pageSize: 0x400 }"
    Execute Command    ctl OperationTiming Typical
    # Active-high BSY polling loop at 0x20000300: ldr r0,[r1]; tst r0,r5; beq loop; adds r2,1; b loop.
    Execute Command    sysbus WriteDoubleWord 0x20000300 0x42286808
    Execute Command    sysbus WriteWord 0x20000304 0xd0fc
    Execute Command    sysbus WriteWord 0x20000306 0x3201
    Execute Command    sysbus WriteWord 0x20000308 0xe7fa
    # Unlock FPEC and erase page 0 (20 ms typical).
    Execute Command    sysbus WriteDoubleWord 0x40022004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022004 0xcdef89ab
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x08000000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000042
    Execute Command    cpu SetRegister 1 0x4002200c
    Execute Command    cpu SetRegister 2 0
    Execute Command    cpu SetRegister 5 1
    Execute Command    cpu PC 0x20000301
    Execute Command    emulation RunFor "0.019999"
    Read Should Equal    sysbus ReadDoubleWord 0x4002200c    1
    Read Should Equal    sysbus ReadWord 0x08000000    0x0000
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x4002200c    0x20
    Read Should Equal    sysbus ReadWord 0x08000000    0xffff
    Firmware Observed Busy Then Ready
    # Clear EOP, enable PG (bit 0), and execute a 16-bit half-word CPU store (53 us typical).
    Execute Command    sysbus WriteDoubleWord 0x4002200c 0x20
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    # strh r3, [r4] (0x8023) followed by branch to busy polling loop at 0x20000300.
    Execute Command    sysbus WriteWord 0x20000200 0x8023
    Execute Command    sysbus WriteWord 0x20000202 0xe07d
    Execute Command    sysbus WriteDoubleWord 0x20000300 0x42286808
    Execute Command    sysbus WriteWord 0x20000304 0xd0fc
    Execute Command    sysbus WriteWord 0x20000306 0x3201
    Execute Command    sysbus WriteWord 0x20000308 0xe7fa
    Execute Command    cpu SetRegister 1 0x4002200c
    Execute Command    cpu SetRegister 2 0
    Execute Command    cpu SetRegister 3 0xbeef
    Execute Command    cpu SetRegister 4 0x08000000
    Execute Command    cpu SetRegister 5 1
    Execute Command    cpu PC 0x20000201
    Execute Command    emulation RunFor "0.000052"
    Read Should Equal    sysbus ReadDoubleWord 0x4002200c    1
    Read Should Equal    sysbus ReadWord 0x08000000    0xffff
    Execute Command    emulation RunFor "0.000002"
    Read Should Equal    sysbus ReadDoubleWord 0x4002200c    0x20
    Read Should Equal    sysbus ReadWord 0x08000000    0xbeef
    Firmware Observed Busy Then Ready
    # Armed power-loss write cut on the next half-word write applies torn outcome and never completes after 70 us.
    Execute Command    ctl OperationTiming Maximum
    Execute Command    ctl FaultAtWordWrite 2
    Execute Command    cpu SetRegister 3 0x1234
    Execute Command    cpu SetRegister 4 0x08000002
    Execute Command    cpu PC 0x20000201
    Execute Command    emulation RunFor "0.000100"
    ${fired}=    Execute Command    ctl FaultFired
    Should Be Equal As Strings    ${fired.strip().lower()}    true
    Read Should Equal    sysbus ReadWord 0x08000000    0xbeef
    Read Should Equal    sysbus ReadWord 0x08000002    0xffff

STM32L476 Controller Holds BSY Until DoubleWord FastRow And Page Erase Complete
    Create Timing Machine
    Execute Command    include "${PERIPHERALS}/STM32L4FlashController.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "bankL4: Memory.MappedMemory @ sysbus 0x08000000 { size: 0x100000 }"
    Execute Command    machine LoadPlatformDescriptionFromString "ctl: Miscellaneous.STM32L4FlashController @ sysbus 0x40022000 { flash: bankL4; flashBaseAddress: 0x08000000; flashSize: 0x100000; pageSize: 0x800 }"
    Execute Command    ctl OperationTiming Typical
    # Active-high BSY polling loop at 0x20000300: ldr r0,[r1]; tst r0,r5; beq loop; adds r2,1; b loop.
    Execute Command    sysbus WriteDoubleWord 0x20000300 0x42286808
    Execute Command    sysbus WriteWord 0x20000304 0xd0fc
    Execute Command    sysbus WriteWord 0x20000306 0x3201
    Execute Command    sysbus WriteWord 0x20000308 0xe7fa
    # Unlock L4 flash and erase page 0 (22.02 ms = 22020 us typical, BSY is bit 16 of FLASH_SR at 0x40022010).
    Execute Command    sysbus WriteDoubleWord 0x40022008 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022008 0xcdef89ab
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01010002
    Execute Command    cpu SetRegister 1 0x40022010
    Execute Command    cpu SetRegister 2 0
    Execute Command    cpu SetRegister 5 0x10000
    Execute Command    cpu PC 0x20000301
    Execute Command    emulation RunFor "0.022019"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x00000000
    Execute Command    emulation RunFor "0.000001"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0xffffffff
    Firmware Observed Busy Then Ready
    # Clear EOP, set PG=1 | EOPIE=1, and store two 32-bit words (82 us typical for one 64-bit double-word).
    Execute Command    sysbus WriteDoubleWord 0x40022010 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01000001
    Start Firmware Store    0x08000000    0x40022010    0x10000    0xd0fc    2
    Execute Command    cpu SetRegister 2 0
    Execute Command    emulation RunFor "0.000080"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0xffffffff
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0xffffffff
    Execute Command    emulation RunFor "0.000005"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0x12345678
    Firmware Observed Busy Then Ready
    # Fast row programming (FSTPG=1 | EOPIE=1, 64 words = 32 double-words at 0x08000100, 1910 us typical).
    Execute Command    sysbus WriteDoubleWord 0x40022010 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01040000
    Start Firmware Store    0x08000100    0x40022010    0x10000    0xd0fc    64
    Execute Command    cpu SetRegister 2 0
    Execute Command    emulation RunFor "0.001900"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    0x10000
    Read Should Equal    sysbus ReadDoubleWord 0x08000100    0xffffffff
    Read Should Equal    sysbus ReadDoubleWord 0x080001fc    0xffffffff
    Execute Command    emulation RunFor "0.000100"
    Read Should Equal    sysbus ReadDoubleWord 0x40022010    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000100    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x080001fc    0x12345678
    Firmware Observed Busy Then Ready
    # Clear EOP and switch back to PG=1 | EOPIE=1 for the armed cut check.
    Execute Command    sysbus WriteDoubleWord 0x40022010 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01000001
    # Armed uncorrectable power-loss cut on the next double-word marks it uncorrectable and does not commit after 91 us.
    Execute Command    ctl OperationTiming Maximum
    Execute Command    ctl TornWordMode "uncorrectable"
    Execute Command    ctl FaultAtWordWrite 34
    Start Firmware Store    0x08000008    0x40022010    0x10000    0xd0fc    2
    Execute Command    emulation RunFor "0.000120"
    ${fired}=    Execute Command    ctl FaultFired
    Should Be Equal As Strings    ${fired.strip().lower()}    true
    Read Should Equal    ctl UncorrectableWordCount    1
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x08000008    0xffffffff

NRF52840 Typical Timing And Armed MidOperation Cut
    Create Timing Machine
    Load Flash Controller    NRF52NVMC    0x4001e000    Flash: bankA; FlashBaseAddress: 0x08000000; FlashSize: 0x100000
    Execute Command    ctl OperationTiming Typical
    Execute Command    ctl DiffLookahead 2147483647
    Execute Command    ctl FaultAtWordWrite 2
    Execute Command    sysbus WriteDoubleWord 0x08000000 0xffffffff
    Execute Command    sysbus WriteDoubleWord 0x08000004 0xffffffff
    Execute Command    sysbus WriteDoubleWord 0x4001e504 1
    Start Firmware Store    0x08000000    0x4001e400    1    0xd1fc    2
    Execute Command    emulation RunFor "0.000120"
    ${fired}=    Execute Command    ctl FaultFired
    Should Be Equal As Strings    ${fired.strip().lower()}    true
    Read Should Equal    ctl TotalWordWrites    2
    Read Should Equal    sysbus ReadDoubleWord 0x08000000    0x12345678
    Read Should Equal    sysbus ReadDoubleWord 0x08000004    0xffffffff
