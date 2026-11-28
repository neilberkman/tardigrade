*** Settings ***
Library    String

*** Variables ***
${ROOT}    ${CURDIR}/..

*** Keywords ***
Load All Builtin NVM Peripherals
    Execute Command    include "${ROOT}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${ROOT}/peripherals/FlashTiming.cs"
    Execute Command    include "${ROOT}/peripherals/FaultTracker.cs"
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/GenericNvmController.cs"
    Execute Command    include "${ROOT}/peripherals/MappedMRAMTracker.cs"
    Execute Command    include "${ROOT}/peripherals/An521NvmInterceptor.cs"
    Execute Command    include "${ROOT}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F1FlashController.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F4FastFlash.cs"
    Execute Command    include "${ROOT}/peripherals/STM32L4FlashController.cs"
    Execute Command    include "${ROOT}/peripherals/SPINORFlash.cs"
    Execute Command    include "${ROOT}/peripherals/I2CEEPROM.cs"

Read Normalized Bool
    [Arguments]    ${command}
    ${raw}=        Execute Command    ${command}
    ${text}=       Convert To String    ${raw}
    ${text}=       Strip String    ${text}
    ${text}=       Convert To Lower Case    ${text}
    RETURN    ${text}

*** Test Cases ***
NVMemoryController Tracks And Faults MMIO Erases Across Torn Word Modes
    Load All Builtin NVM Peripherals
    Execute Command    mach create "nvm_ctrl_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_nvm_flash.repl
    Execute Command    nvm ProgramAddressBase 0x10000000
    Execute Command    nvm_ctrl EraseTraceEnabled true

    # Populate sector at 0x10002000 (lower half + upper half).
    Execute Command    sysbus WriteDoubleWord 0x10002000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x10002800 0x55667788

    # 1. Default half mode: first half erased (0xFF), second half retained.
    Execute Command    nvm_ctrl TotalPageErases 0
    Execute Command    nvm_ctrl MramTornWordMode "half"
    Execute Command    nvm_ctrl FaultAtPageErase 1
    Execute Command    sysbus WriteDoubleWord 0x40001030 0x00000004
    Execute Command    sysbus WriteDoubleWord 0x40001034 0x00001000
    Execute Command    sysbus WriteDoubleWord 0x40001038 0x10002000

    ${fired}=          Read Normalized Bool    nvm_ctrl EraseFaultFired
    ${erases}=         Execute Command    nvm_ctrl TotalPageErases
    ${trace_cnt}=      Execute Command    nvm_ctrl EraseTraceCount
    ${low_half}=       Execute Command    sysbus ReadDoubleWord 0x10002000
    ${high_half}=      Execute Command    sysbus ReadDoubleWord 0x10002800
    ${last_addr}=      Execute Command    nvm_ctrl LastFaultAddress
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Numbers    ${erases}    1
    Should Be Equal As Numbers    ${trace_cnt}    1
    Should Be Equal As Numbers    ${low_half}    0xFFFFFFFF
    Should Be Equal As Numbers    ${high_half}    0x55667788
    Should Be Equal As Numbers    ${last_addr}    0x10002000

    # Post-erase-cut writes must be suppressed while EraseFaultFired is set.
    Execute Command    sysbus WriteDoubleWord 0x10002000 0xCAFEBABE
    ${suppressed}=     Execute Command    sysbus ReadDoubleWord 0x10002000
    Should Be Equal As Numbers    ${suppressed}    0xFFFFFFFF

    # 2. Untouched mode: pre-erase bytes preserved.
    Execute Command    nvm_ctrl EraseFaultFired false
    Execute Command    sysbus WriteDoubleWord 0x10002000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x10002800 0x55667788
    Execute Command    nvm_ctrl MramTornWordMode "untouched"
    Execute Command    nvm_ctrl FaultAtPageErase 2
    Execute Command    sysbus WriteDoubleWord 0x40001038 0x10002000
    ${u_low}=          Execute Command    sysbus ReadDoubleWord 0x10002000
    ${u_high}=         Execute Command    sysbus ReadDoubleWord 0x10002800
    Should Be Equal As Numbers    ${u_low}    0x11223344
    Should Be Equal As Numbers    ${u_high}    0x55667788

    # 3. Erased mode: full span erased (models cut between erase and program).
    Execute Command    nvm_ctrl EraseFaultFired false
    Execute Command    nvm_ctrl MramTornWordMode "erased"
    Execute Command    nvm_ctrl FaultAtPageErase 3
    Execute Command    sysbus WriteDoubleWord 0x40001038 0x10002000
    ${e_low}=          Execute Command    sysbus ReadDoubleWord 0x10002000
    ${e_high}=         Execute Command    sysbus ReadDoubleWord 0x10002800
    Should Be Equal As Numbers    ${e_low}    0xFFFFFFFF
    Should Be Equal As Numbers    ${e_high}    0xFFFFFFFF

    # 4. Uncorrectable mode on word erase: retains bytes and marks word uncorrectable.
    Execute Command    nvm_ctrl EraseFaultFired false
    Execute Command    sysbus WriteDoubleWord 0x10002000 0xA1A2A3A4
    Execute Command    nvm_ctrl MramTornWordMode "uncorrectable"
    Execute Command    nvm_ctrl FaultAtPageErase 4
    Execute Command    sysbus WriteDoubleWord 0x40001030 0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40001038 0x10002000
    ${unc_val}=        Execute Command    sysbus ReadDoubleWord 0x10002000
    ${unc_marked}=     Read Normalized Bool    nvm IsWordUncorrectable 0x2000
    ${unc_flag}=       Read Normalized Bool    nvm LastFaultMarkedUncorrectable
    Should Be Equal As Numbers    ${unc_val}    0xA1A2A3A4
    Should Be Equal As Strings    ${unc_marked}    true
    Should Be Equal As Strings    ${unc_flag}    true

MappedMRAMTracker Tracks And Faults Erases Across Torn Word Modes
    Load All Builtin NVM Peripherals
    Execute Command    mach create "mram_tracker_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_self_update.repl
    Execute Command    mramTracker ProgramAddressBase 0x10100000
    Execute Command    mramTracker EraseTraceEnabled true
    Execute Command    sysbus WriteQuadWord 0x10100000 0x1122334455667788
    Execute Command    sysbus WriteQuadWord 0x10100008 0x99AABBCCDDEEFF00
    Execute Command    mramTracker InvalidateShadow

    # 1. Half mode on 16-byte word erase (EraseFill=0x00): lower 8 bytes zeroed, upper 8 bytes retained.
    Execute Command    mramTracker TotalPageErases 0
    Execute Command    mramTracker MramTornWordMode "half"
    Execute Command    mramTracker FaultAtPageErase 1
    Execute Command    mramTracker EraseWord 0
    ${fired}=          Read Normalized Bool    mramTracker EraseFaultFired
    ${erases}=         Execute Command    mramTracker TotalPageErases
    ${trace_cnt}=      Execute Command    mramTracker EraseTraceCount
    ${lo}=             Execute Command    sysbus ReadQuadWord 0x10100000
    ${hi}=             Execute Command    sysbus ReadQuadWord 0x10100008
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Numbers    ${erases}    1
    Should Be Equal As Numbers    ${trace_cnt}    1
    Should Be Equal As Numbers    ${lo}    0x0000000000000000
    Should Be Equal As Numbers    ${hi}    0x99AABBCCDDEEFF00

    # 2. Uncorrectable mode on EraseWord marks unit and raises HardFault on CPU read.
    Execute Command    mramTracker EraseFaultFired false
    Execute Command    mramTracker WriteQuadWord 0 0x1122334455667788
    Execute Command    mramTracker WriteQuadWord 8 0x99AABBCCDDEEFF00
    Execute Command    mramTracker InvalidateShadow
    Execute Command    mramTracker MramTornWordMode "uncorrectable"
    Execute Command    mramTracker FaultAtPageErase 2
    Execute Command    mramTracker EraseWord 0
    ${is_marked}=      Read Normalized Bool    mramTracker IsWordUncorrectable 0
    ${marked_cnt}=     Execute Command    mramTracker UncorrectableWordCount
    Should Be Equal As Strings    ${is_marked}    true
    Should Be Equal As Numbers    ${marked_cnt}    1

    # 3. Corrupted mode flips deterministic bits from EraseFill.
    Execute Command    mramTracker EraseFaultFired false
    Execute Command    mramTracker ClearUncorrectableWords
    Execute Command    mramTracker MramTornWordMode "corrupted"
    Execute Command    mramTracker MramTornWordSeed 12345
    Execute Command    mramTracker FaultAtPageErase 3
    Execute Command    mramTracker EraseWord 0
    ${c_lo}=           Execute Command    sysbus ReadQuadWord 0x10100000
    ${c_hi}=           Execute Command    sysbus ReadQuadWord 0x10100008
    Should Be True     (${c_lo} != 0) or (${c_hi} != 0)

GenericNvmController Executes And Faults Erase Commands
    Load All Builtin NVM Peripherals
    Execute Command    mach create "generic_ctrl_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_nvm_generic_ctrl.repl
    Execute Command    nvm_ctrl PageSize 0x1000
    Execute Command    sysbus WriteDoubleWord 0x10002000 0x12345678
    Execute Command    sysbus WriteDoubleWord 0x10002800 0x9ABCDEF0
    Execute Command    nvm_ctrl MramTornWordMode "half"
    Execute Command    nvm_ctrl FaultAtPageErase 1
    # Issue sector erase command (EraseCommandValue = 0x3) at 0x10002000.
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10002000
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000003
    ${fired}=          Read Normalized Bool    nvm_ctrl EraseFaultFired
    ${erases}=         Execute Command    nvm_ctrl TotalPageErases
    ${low}=            Execute Command    sysbus ReadDoubleWord 0x10002000
    ${high}=           Execute Command    sysbus ReadDoubleWord 0x10002800
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Numbers    ${erases}    1
    Should Be Equal As Numbers    ${low}    0x00000000
    Should Be Equal As Numbers    ${high}    0x9ABCDEF0
    # Subsequent write command is suppressed after erase fault.
    Execute Command    sysbus WriteDoubleWord 0x4000101C 0x10002000
    Execute Command    sysbus WriteDoubleWord 0x40001020 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x40001014 0x00000002
    ${still_erased}=   Execute Command    sysbus ReadDoubleWord 0x10002000
    Should Be Equal As Numbers    ${still_erased}    0x00000000

An521NvmInterceptor Tracks And Faults Erases Across Torn Word Modes
    Load All Builtin NVM Peripherals
    Execute Command    mach create "an521_erases"
    Execute Command    machine LoadPlatformDescriptionFromString 'cpu: CPU.CortexM @ sysbus { cpuType: "cortex-m33"; nvic: nvic }; nvic: IRQControllers.NVIC @ sysbus 0xE000E000 { -> cpu@0 }; codeMem: Memory.MappedMemory @ sysbus 0x10000000 { size: 0x4000 }; faultFlash: Miscellaneous.An521NvmInterceptor @ sysbus 0x00000000 { BackingMemory: codeMem; FlashBaseAddress: 0x00000000; FlashSize: 0x4000; PageSize: 0x1000; EraseFill: 0xFF }'
    Execute Command    faultFlash EraseTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x10001000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x10001800 0x55667788
    Execute Command    faultFlash InvalidateShadow

    # Half mode: first half 0xFF, second half retained.
    Execute Command    faultFlash MramTornWordMode "half"
    Execute Command    faultFlash FaultAtPageErase 1
    Execute Command    faultFlash EraseSector 0x1000 0x1000
    ${fired}=          Read Normalized Bool    faultFlash EraseFaultFired
    ${erases}=         Execute Command    faultFlash TotalPageErases
    ${trace_cnt}=      Execute Command    faultFlash EraseTraceCount
    ${lo}=             Execute Command    sysbus ReadDoubleWord 0x00001000
    ${hi}=             Execute Command    sysbus ReadDoubleWord 0x00001800
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Numbers    ${erases}    1
    Should Be Equal As Numbers    ${trace_cnt}    1
    Should Be Equal As Numbers    ${lo}    0xFFFFFFFF
    Should Be Equal As Numbers    ${hi}    0x55667788

    # Untouched mode: retains pre-erase bytes.
    Execute Command    faultFlash EraseFaultFired false
    Execute Command    sysbus WriteDoubleWord 0x10001000 0x11223344
    Execute Command    faultFlash InvalidateShadow
    Execute Command    faultFlash MramTornWordMode "untouched"
    Execute Command    faultFlash FaultAtPageErase 2
    Execute Command    faultFlash EraseSector 0x1000 0x1000
    ${u_lo}=           Execute Command    sysbus ReadDoubleWord 0x00001000
    Should Be Equal As Numbers    ${u_lo}    0x11223344

    # Erased mode: full sector erased.
    Execute Command    faultFlash EraseFaultFired false
    Execute Command    faultFlash MramTornWordMode "erased"
    Execute Command    faultFlash FaultAtPageErase 3
    Execute Command    faultFlash EraseSector 0x1000 0x1000
    ${e_lo}=           Execute Command    sysbus ReadDoubleWord 0x00001000
    ${e_hi}=           Execute Command    sysbus ReadDoubleWord 0x00001800
    Should Be Equal As Numbers    ${e_lo}    0xFFFFFFFF
    Should Be Equal As Numbers    ${e_hi}    0xFFFFFFFF

NRF52NVMC And STM32F4FastFlash Honor Torn Erase Modes
    Load All Builtin NVM Peripherals
    Execute Command    mach create "nrf_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_mapped_faultctrl.repl
    Execute Command    sysbus WriteDoubleWord 0x10002000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x10002800 0x55667788
    Execute Command    sysbus WriteDoubleWord 0x4001E504 2

    # NRF52 untouched mode retains pre-erase bytes.
    Execute Command    faultFlash MramTornWordMode "untouched"
    Execute Command    faultFlash FaultAtPageErase 1
    Execute Command    sysbus WriteDoubleWord 0x4001E508 0x10002000
    ${n_u_lo}=         Execute Command    sysbus ReadDoubleWord 0x10002000
    ${n_u_hi}=         Execute Command    sysbus ReadDoubleWord 0x10002800
    Should Be Equal As Numbers    ${n_u_lo}    0x11223344
    Should Be Equal As Numbers    ${n_u_hi}    0x55667788

    # NRF52 corrupted mode writes deterministic corrupted bytes from EraseFill.
    Execute Command    faultFlash EraseFaultFired false
    Execute Command    faultFlash MramTornWordMode "corrupted"
    Execute Command    faultFlash MramTornWordSeed 777
    Execute Command    faultFlash FaultAtPageErase 2
    Execute Command    sysbus WriteDoubleWord 0x4001E508 0x10002000
    ${n_c_lo}=         Execute Command    sysbus ReadDoubleWord 0x10002000
    Should Not Be Equal As Numbers    ${n_c_lo}    0xFFFFFFFF
    Should Not Be Equal As Numbers    ${n_c_lo}    0x11223344

    # STM32F4FastFlash honors untouched, erased, and corrupted modes on sector erase.
    Execute Command    mach create "stm32_erases"
    Execute Command    machine LoadPlatformDescriptionFromString 'cpu: CPU.CortexM @ sysbus { cpuType: "cortex-m4"; nvic: nvic }; nvic: IRQControllers.NVIC @ sysbus 0xE000E000 { -> cpu@0 }; flash: Memory.MappedMemory @ sysbus 0x08000000 { size: 0x20000 }; faultFlash: Miscellaneous.STM32F4FastFlash @ sysbus 0x40023C00 { Flash: flash; FlashBaseAddress: 0x08000000; FlashSize: 0x20000; EraseFill: 0xFF }'
    # Unlock FLASH_CR (KEY1, KEY2 at offset 0x04).
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x08004000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x08006000 0x55667788

    # Untouched on Sector 1 (0x08004000..0x08007FFF): SER(2) | SNB(1<<3=8) | STRT(0x10000) = 0x1000A.
    Execute Command    faultFlash MramTornWordMode "untouched"
    Execute Command    faultFlash FaultAtPageErase 1
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0x0001000A
    ${s_u_lo}=         Execute Command    sysbus ReadDoubleWord 0x08004000
    ${s_u_hi}=         Execute Command    sysbus ReadDoubleWord 0x08006000
    Should Be Equal As Numbers    ${s_u_lo}    0x11223344
    Should Be Equal As Numbers    ${s_u_hi}    0x55667788

    # Erased on Sector 1: full 16 KiB sector erased.
    Execute Command    faultFlash EraseFaultFired false
    Execute Command    faultFlash MramTornWordMode "erased"
    Execute Command    faultFlash FaultAtPageErase 2
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0x0001000A
    ${s_e_lo}=         Execute Command    sysbus ReadDoubleWord 0x08004000
    ${s_e_hi}=         Execute Command    sysbus ReadDoubleWord 0x08006000
    Should Be Equal As Numbers    ${s_e_lo}    0xFFFFFFFF
    Should Be Equal As Numbers    ${s_e_hi}    0xFFFFFFFF

    # Corrupted on Sector 1: deterministic bit flips from EraseFill.
    Execute Command    faultFlash EraseFaultFired false
    Execute Command    faultFlash MramTornWordMode "corrupted"
    Execute Command    faultFlash MramTornWordSeed 999
    Execute Command    faultFlash FaultAtPageErase 3
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0x0001000A
    ${s_c_lo}=         Execute Command    sysbus ReadDoubleWord 0x08004000
    Should Not Be Equal As Numbers    ${s_c_lo}    0xFFFFFFFF

STM32F1 And STM32L4 Flash Controllers Track And Fault Page Erases
    Load All Builtin NVM Peripherals
    Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"
    Execute Command    mach create "stm32f1_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/stm32f103.repl
    Execute Command    faultFlash EraseTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40022004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022004 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x08001000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x08001200 0x55667788
    Execute Command    faultFlash TornWordMode "fixed"
    Execute Command    faultFlash FaultAtPageErase 1
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x08001000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000042
    ${f1_lo}=          Execute Command    sysbus ReadDoubleWord 0x08001000
    ${f1_hi}=          Execute Command    sysbus ReadDoubleWord 0x08001200
    ${f1_trace}=       Execute Command    faultFlash EraseTraceToString
    Should Be Equal As Numbers    ${f1_lo}    0xFFFFFFFF
    Should Be Equal As Numbers    ${f1_hi}    0x55667788
    Should Contain    ${f1_trace}    1:4096:0:1024

    Execute Command    mach create "stm32l4_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/stm32l476.repl
    Execute Command    faultFlash EraseTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40022008 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022008 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x08081000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x08081400 0x55667788
    Execute Command    faultFlash TornWordMode "fixed"
    Execute Command    faultFlash FaultAtPageErase 1
    # Bank 2 (BKER=1<<11=0x800), page 2 (PNB=2<<3=0x10), PER(0x2), STRT(0x10000) -> 0x00010812
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00010812
    ${l4_lo}=          Execute Command    sysbus ReadDoubleWord 0x08081000
    ${l4_hi}=          Execute Command    sysbus ReadDoubleWord 0x08081400
    ${l4_trace}=       Execute Command    faultFlash EraseTraceToString
    Should Be Equal As Numbers    ${l4_lo}    0xFFFFFFFF
    Should Be Equal As Numbers    ${l4_hi}    0x55667788
    Should Contain    ${l4_trace}    1:528384:0:2048
SPINORFlash Honors Torn Erase Modes Across 4K 32K And 64K Erases
    Load All Builtin NVM Peripherals
    Execute Command    include "${ROOT}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"
    Execute Command    mach create "spinor_erases"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/nrf52840_external_nvm.repl
    Execute Command    spiNor EraseTraceEnabled true
    Execute Command    spiNor BusyPollsPerErase 0

    # Pre-seed 4 KiB sector at 0x001000 (mapped at 0x60001000).
    Execute Command    sysbus WriteDoubleWord 0x60001000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x60001800 0x55667788

    # 1. Default half mode on 4 KiB sector erase (0x20): first 2 KiB erased, second 2 KiB retained.
    Execute Command    spiNor MramTornWordMode "half"
    Execute Command    spiNor FaultAtPageErase 1
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(b) for b in (0x20, 0x00, 0x10, 0x00)]; s.FinishTransmission()"
    ${fired}=          Read Normalized Bool    spiNor EraseFaultFired
    ${lo}=             Execute Command    sysbus ReadDoubleWord 0x60001000
    ${hi}=             Execute Command    sysbus ReadDoubleWord 0x60001800
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Numbers    ${lo}       0xFFFFFFFF
    Should Be Equal As Numbers    ${hi}       0x55667788

    # 2. Untouched mode on 32 KiB block erase (0x52): pre-erase data retained.
    Execute Command    spiNor EraseFaultFired false
    Execute Command    sysbus WriteDoubleWord 0x60008000 0xAABBCCDD
    Execute Command    sysbus WriteDoubleWord 0x6000C000 0xEEFF0011
    Execute Command    spiNor MramTornWordMode "untouched"
    Execute Command    spiNor FaultAtPageErase 2
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(b) for b in (0x52, 0x00, 0x80, 0x00)]; s.FinishTransmission()"
    ${u_lo}=           Execute Command    sysbus ReadDoubleWord 0x60008000
    ${u_hi}=           Execute Command    sysbus ReadDoubleWord 0x6000C000
    Should Be Equal As Numbers    ${u_lo}     0xAABBCCDD
    Should Be Equal As Numbers    ${u_hi}     0xEEFF0011

    # 3. Partial bits mode on 64 KiB block erase (0xD8).
    Execute Command    spiNor EraseFaultFired false
    Execute Command    sysbus WriteDoubleWord 0x60010000 0x00000000
    Execute Command    spiNor TornWordMode "partial_bits"
    Execute Command    spiNor TornWordSeed 42
    Execute Command    spiNor FaultAtPageErase 3
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(b) for b in (0xD8, 0x01, 0x00, 0x00)]; s.FinishTransmission()"
    ${p_lo}=           Execute Command    sysbus ReadDoubleWord 0x60010000
    Should Not Be Equal As Numbers    ${p_lo}    0x00000000
    Should Not Be Equal As Numbers    ${p_lo}    0xFFFFFFFF
