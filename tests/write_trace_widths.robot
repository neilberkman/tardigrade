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

Create NRF52 Fast Machine
    ${root}=    Set Variable    ${CURDIR}/..
    Execute Command    include "${root}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${root}/peripherals/NVMemoryController.cs"
    Execute Command    include "${root}/peripherals/FaultTracker.cs"
    Execute Command    include "${root}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${root}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${root}/peripherals/TraceReplayEngine.cs"
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
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${root}/platforms/mps2_an521.repl

*** Test Cases ***
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
