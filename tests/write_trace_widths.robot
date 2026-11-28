*** Settings ***

*** Keywords ***
Create STM32F4 Fast Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/STM32F4FastFlash.cs"
    Execute Command    include "${root}/peripherals/STM32F4RCCStub.cs"
    Execute Command    include "${root}/peripherals/STM32DummyUSART.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/stm32f4_fast.repl

Create STM32F4 Controller Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/STM32F4FlashController.cs"
    Execute Command    include "${root}/peripherals/STM32DummyUSART.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/stm32f4.repl

Create STM32H7 Fast Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${root}/peripherals/STM32H7FastFlash.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/stm32h743_fast.repl

Create STM32F1 Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${root}/peripherals/STM32F1FlashController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/stm32f103.repl

Create STM32L4 Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${root}/peripherals/STM32L4FlashController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/stm32l476.repl

Create NRF52 Fast Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/NVMemoryController.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${root}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${root}/peripherals/SPINORFlash.cs"
    Execute Command    include "${root}/peripherals/I2CEEPROM.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/cortex_m4_flash_fast.repl

Create AN521 Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/NVMemoryController.cs"
    Execute Command    include "${root}/peripherals/GenericNvmController.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/An521NvmInterceptor.cs"
    Execute Command    include "${root}/peripherals/Sse200MpcStub.cs"
    Execute Command    include "${root}/peripherals/CMSDKAPBWatchdog.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/mps2_an521.repl

*** Test Cases ***
STM32F4 Controller Clock Ready Bits Follow Enable Bits
    Create STM32F4 Controller Machine
    ${reset}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${reset}    0x00000003
    Execute Command    sysbus WriteDoubleWord 0x40023800 0x01010001
    ${enabled}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${enabled}    0x03030003
    Execute Command    sysbus WriteDoubleWord 0x40023800 0x00010001
    ${pll_disabled}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${pll_disabled}    0x00030003

STM32F4 Fast Clock Ready Bits Follow Enable Bits
    Create STM32F4 Fast Machine
    ${reset}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${reset}    0x00000003
    Execute Command    sysbus WriteDoubleWord 0x40023800 0x01010001
    ${enabled}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${enabled}    0x03030003
    Execute Command    sysbus WriteDoubleWord 0x40023800 0x00010001
    ${pll_disabled}=    Execute Command    sysbus ReadDoubleWord 0x40023800
    Should Be Equal As Numbers    ${pll_disabled}    0x00030003

STM32F4 Controller Trace Captures First And Second PG Writes
    Create STM32F4 Controller Machine
    # Force the normal count-only setting to prove trace mode overrides it.
    Execute Command    faultFlash SkipShadowScan true
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x40023C10 1
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0
    Execute Command    sysbus WriteDoubleWord 0x40023C10 1
    Execute Command    sysbus WriteDoubleWord 0x08000004 0x88776655
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0
    ${count}=    Execute Command    faultFlash WriteTraceCount
    Should Be Equal As Integers    ${count}    2
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    Should Contain    ${trace}    1:0:1144201745:4
    Should Contain    ${trace}    2:4:2289526357:4

STM32F4 Controller Fault Reverts Full Aligned Word
    Create STM32F4 Controller Machine
    Execute Command    sysbus WriteDoubleWord 0x08000000 0xFFFFFFFF
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x40023C10 1
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0
    ${value}=    Execute Command    sysbus ReadDoubleWord 0x08000000
    ${addr}=     Execute Command    faultFlash LastFaultAddress
    Should Be Equal As Numbers    ${value}    0xFFFFFFFF
    Should Be Equal As Numbers    ${addr}     0x08000000

STM32F4 Fast Trace Carries Reconstructed Word Width
    Create STM32F4 Fast Machine
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40023C04 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x40023C10 1
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x40023C10 0
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${value}=    Execute Command    sysbus ReadDoubleWord 0x08000000
    Should Contain    ${trace}    1:0:1144201745:4
    Should Be Equal As Numbers    ${value}    0x44332211

STM32H7 Fast Trace Carries Reconstructed Word Width
    Create STM32H7 Fast Machine
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x52002004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x52002004 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x5200200C 2
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x5200200C 0
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${value}=    Execute Command    sysbus ReadDoubleWord 0x08000000
    Should Contain    ${trace}    1:0:1144201745:4
    Should Be Equal As Numbers    ${value}    0x44332211

STM32H7 Fast PG Trace Includes Every Changed Aligned Word
    Create STM32H7 Fast Machine
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x52002004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x52002004 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x08000008 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x5200200C 2
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x08000004 0x88776655
    # This unchanged word must not become a spurious trace event.
    Execute Command    sysbus WriteDoubleWord 0x08000008 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x5200200C 0
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    Should Contain    ${trace}    1:0:1144201745:4
    Should Contain    ${trace}    2:4:2289526357:4
    Should Not Contain    ${trace}    3:

NRF52 Trace Carries Reconstructed Word Width
    Create NRF52 Fast Machine
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x4001E504 1
    Execute Command    sysbus WriteDoubleWord 0x0000C000 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x4001E504 0
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${value}=    Execute Command    sysbus ReadDoubleWord 0x0000C000
    Should Contain    ${trace}    1:0:1144201745:4
    Should Be Equal As Numbers    ${value}    0x44332211

NRF52 Ready Poll Flushes Consecutive WEN Writes Without REN Toggle
    Create NRF52 Fast Machine
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x49054804
    Execute Command    sysbus WriteDoubleWord 0x20000004 0x4B064A05
    Execute Command    sysbus WriteDoubleWord 0x20000008 0x680C6002
    Execute Command    sysbus WriteDoubleWord 0x2000000C 0x680C6043
    Execute Command    sysbus WriteDoubleWord 0x20000010 0xBF00E7FE
    Execute Command    sysbus WriteDoubleWord 0x20000014 0x0000C000
    Execute Command    sysbus WriteDoubleWord 0x20000018 0x4001E400
    Execute Command    sysbus WriteDoubleWord 0x2000001C 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x20000020 0x88776655
    Execute Command    faultFlash WriteTraceClear
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x4001E504 1
    Execute Command    cpu PC 0x20000001
    Execute Command    emulation RunFor "1us"
    ${count}=    Execute Command    faultFlash WriteTraceCount
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    Should Be Equal As Integers    ${count}    2
    Should Contain    ${trace}    1:0:1144201745:4
    Should Contain    ${trace}    2:4:2289526357:4

AN521 Trace Uses Canonical Aligned Post-State Words
    Create AN521 Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x10000004 0xFFFFFFFF
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteByte 0x10400001 0x12
    Execute Command    sysbus WriteWord 0x10400002 0x3456
    Execute Command    sysbus WriteDoubleWord 0x10400004 0x789ABCDE
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${first}=    Execute Command    sysbus ReadDoubleWord 0x10400000
    ${second}=    Execute Command    sysbus ReadDoubleWord 0x10400004
    Should Contain    ${trace}    1:0:4294906623:4
    Should Contain    ${trace}    2:0:878056191:4
    Should Contain    ${trace}    3:4:2023406814:4
    Should Be Equal As Numbers    ${first}    0x345612FF
    Should Be Equal As Numbers    ${second}    0x789ABCDE

AN521 Mapped Write Canonicalizes Cross Word Three Byte Chunk
    Create AN521 Machine
    # Prepare a tiny Thumb loop through the direct backing alias.  Tracing is
    # enabled only after setup so these initialization writes cannot appear in
    # the observed memory-hook trace.
    Execute Command    sysbus WriteDoubleWord 0x10001000 0x49044803
    Execute Command    sysbus WriteDoubleWord 0x10001004 0xE7FE6001
    Execute Command    sysbus WriteDoubleWord 0x10001010 0x10000023
    Execute Command    sysbus WriteDoubleWord 0x10001014 0x78563412
    Execute Command    sysbus WriteDoubleWord 0x10000020 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x10000024 0xFFFFFFFF
    Execute Command    faultFlash WriteTraceClear
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    cpu PC 0x10001001
    Execute Command    emulation RunFor "1us"
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${first}=    Execute Command    sysbus ReadDoubleWord 0x10000020
    ${second}=    Execute Command    sysbus ReadDoubleWord 0x10000024
    # The unaligned STR at +0x23 is accounted as a one-byte chunk followed by
    # a three-byte chunk. Both events use canonical aligned post-state dwords
    # so replay preserves the untouched bytes in each containing word.
    Should Contain    ${trace}    1:32:318767103:4
    Should Contain    ${trace}    2:36:4286076468:4
    Should Be Equal As Numbers    ${first}    0x12FFFFFF
    Should Be Equal As Numbers    ${second}    0xFF785634

STM32F1 Trace Carries Half-Word Width
    Create STM32F1 Machine
    # Erase page at 0x08001000 so it is 0xFFFF.
    Execute Command    sysbus WriteDoubleWord 0x40022004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022004 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x08001000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000042
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    # Thumb snippet in SRAM at 0x20000000:
    #   ldr r0, =0x08001000 (0x4802)
    #   ldr r1, =0xABCD     (0x4903)
    #   strh r1, [r0, #0]   (0x8001)
    #   b .                 (0xE7FE)
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x49034802
    Execute Command    sysbus WriteDoubleWord 0x20000004 0xE7FE8001
    Execute Command    sysbus WriteDoubleWord 0x2000000C 0x08001000
    Execute Command    sysbus WriteDoubleWord 0x20000010 0x0000ABCD
    Execute Command    faultFlash WriteTraceClear
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    cpu PC 0x20000001
    Execute Command    emulation RunFor "1us"
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${val}=      Execute Command    sysbus ReadWord 0x08001000
    Should Contain    ${trace}    1:4096:43981:2
    Should Be Equal As Numbers    ${val}    0xABCD

STM32L4 Trace Carries Double-Word Width
    Create STM32L4 Machine
    # Unlock and erase page 2 (offset 0x1000).
    Execute Command    sysbus WriteDoubleWord 0x40022008 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022008 0xCDEF89AB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00010012
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    # Thumb snippet in SRAM at 0x20000000:
    #   ldr r0, =0x08001000 (0x4802)
    #   ldr r1, =0x44332211 (0x4903)
    #   ldr r2, =0x88776655 (0x4A03)
    #   str r1, [r0, #0]    (0x6001)
    #   str r2, [r0, #4]    (0x6042)
    #   b .                 (0xE7FE)
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x49034802
    Execute Command    sysbus WriteDoubleWord 0x20000004 0x60014A03
    Execute Command    sysbus WriteDoubleWord 0x20000008 0xE7FE6042
    Execute Command    sysbus WriteDoubleWord 0x2000000C 0x08001000
    Execute Command    sysbus WriteDoubleWord 0x20000010 0x44332211
    Execute Command    sysbus WriteDoubleWord 0x20000014 0x88776655
    Execute Command    faultFlash WriteTraceClear
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    cpu PC 0x20000001
    Execute Command    emulation RunFor "1us"
    ${trace}=    Execute Command    faultFlash WriteTraceToString
    ${lo}=       Execute Command    sysbus ReadDoubleWord 0x08001000
    ${hi}=       Execute Command    sysbus ReadDoubleWord 0x08001004
    Should Contain    ${trace}    1:4096:9833440827789222417:8
    Should Be Equal As Numbers    ${lo}    0x44332211
    Should Be Equal As Numbers    ${hi}    0x88776655
SPINORFlash And I2CEEPROM Emit Explicit Chunk Widths In Write Trace
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${root}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${root}/peripherals/SPINORFlash.cs"
    Execute Command    include "${root}/peripherals/I2CEEPROM.cs"
    Execute Command    mach create "external_nvm_trace_widths"
    Execute Command    machine LoadPlatformDescription @${root}/platforms/nrf52840_external_nvm.repl
    Execute Command    spiNor WriteTraceEnabled true
    Execute Command    i2cEeprom WriteTraceEnabled true
    # SPI NOR: WREN (0x06), then Page Program (0x02) 6 bytes at 0x000010 -> 4-byte chunk + 2-byte chunk.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission()"
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(b) for b in (0x02, 0x00, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)]; s.FinishTransmission()"
    ${spi_trace}=    Execute Command    spiNor WriteTraceToString
    Should Contain    ${spi_trace}    1:16:1144201745:4
    Should Contain    ${spi_trace}    2:20:26197:2
    # I2C EEPROM: Page Write 6 bytes at 0x0020 -> 4-byte chunk + 2-byte chunk.
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x00, 0x20, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x77]); e.FinishTransmission()"
    ${i2c_trace}=    Execute Command    i2cEeprom WriteTraceToString
    Should Contain    ${i2c_trace}    1:32:3721182122:4
    Should Contain    ${i2c_trace}    2:36:30702:2
