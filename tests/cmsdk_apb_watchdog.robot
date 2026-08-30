*** Settings ***
*** Keywords ***
Create AN521 Watchdog Machine
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
CMSDK Watchdog Lock Interrupt Clear And Second Expiry Reset
    Create AN521 Watchdog Machine
    ${initial}=    Execute Command    sysbus ReadDoubleWord 0x40081000
    Should Be Equal As Numbers    ${initial}    0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x40081C00 0
    Execute Command    sysbus WriteDoubleWord 0x40081000 7
    ${locked}=    Execute Command    sysbus ReadDoubleWord 0x40081000
    Should Be Equal As Numbers    ${locked}    0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x40081C00 0x1ACCE551
    Execute Command    sysbus WriteDoubleWord 0x40081000 20
    Execute Command    sysbus WriteDoubleWord 0x40081008 1
    Execute Command    emulation RunFor "1us"
    ${raw}=    Execute Command    sysbus ReadDoubleWord 0x40081010
    ${masked}=    Execute Command    sysbus ReadDoubleWord 0x40081014
    Should Be Equal As Numbers    ${raw}    1
    Should Be Equal As Numbers    ${masked}    1
    Execute Command    sysbus WriteDoubleWord 0x4008100C 0
    ${cleared}=    Execute Command    sysbus ReadDoubleWord 0x40081010
    Should Be Equal As Numbers    ${cleared}    0
    Execute Command    sysbus WriteDoubleWord 0x40081000 2
    Execute Command    sysbus WriteDoubleWord 0x40081008 3
    Execute Command    emulation RunFor "1us"
    ${load_after_reset}=    Execute Command    sysbus ReadDoubleWord 0x40081000
    ${control_after_reset}=    Execute Command    sysbus ReadDoubleWord 0x40081008
    ${raw_after_reset}=    Execute Command    sysbus ReadDoubleWord 0x40081010
    Should Be Equal As Numbers    ${load_after_reset}    0xFFFFFFFF
    Should Be Equal As Numbers    ${control_after_reset}    0
    Should Be Equal As Numbers    ${raw_after_reset}    0
    Execute Command    sysbus WriteDoubleWord 0x40081000 2
    Execute Command    sysbus WriteDoubleWord 0x40081008 3
    Execute Command    emulation RunFor "1us"
    ${load_after_second_reset}=    Execute Command    sysbus ReadDoubleWord 0x40081000
    ${control_after_second_reset}=    Execute Command    sysbus ReadDoubleWord 0x40081008
    Should Be Equal As Numbers    ${load_after_second_reset}    0xFFFFFFFF
    Should Be Equal As Numbers    ${control_after_second_reset}    0

AN521 NVM Alias Applies Silent Write Fault And MPC LUT Is Indexed
    Create AN521 Watchdog Machine
    # The official 0x10400000 code alias is routed through the interceptor;
    # mode 2 must replace the first faulted write rather than merely report it.
    Execute Command    faultFlash WriteFaultMode 2
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x10400000 0xAABBCCDD
    ${faulted}=    Execute Command    sysbus ReadDoubleWord 0x10400000
    ${backing}=    Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${faulted}    0x00000000
    Should Be Equal As Numbers    ${backing}    0x00000000

    # AN521's SIE-200 register geometry is BLK_CFG=8 / BLK_MAX=511, and the
    # LUT selection is indexed rather than a single hard-coded word.
    ${cfg}=    Execute Command    sysbus ReadDoubleWord 0x58007014
    ${max}=    Execute Command    sysbus ReadDoubleWord 0x58007010
    Should Be Equal As Numbers    ${cfg}    8
    Should Be Equal As Numbers    ${max}    511
    Execute Command    sysbus WriteDoubleWord 0x58007018 7
    Execute Command    sysbus WriteDoubleWord 0x5800701C 0xA5A5A5A5
    ${lut7}=    Execute Command    sysbus ReadDoubleWord 0x5800701C
    Should Be Equal As Numbers    ${lut7}    0xA5A5A5A5
    Execute Command    sysbus WriteDoubleWord 0x58007018 511
    Execute Command    sysbus WriteDoubleWord 0x5800701C 0x5A5A5A5A
    ${lut511}=    Execute Command    sysbus ReadDoubleWord 0x5800701C
    Should Be Equal As Numbers    ${lut511}    0x5A5A5A5A

AN521 NVM Passthrough Preserves MMIO And Mapped Writes Without Faulting
    Create AN521 Watchdog Machine
    Execute Command    faultFlash WriteFaultMode 2
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    faultFlash PassthroughMode true

    # MMIO writes through the interceptor are persisted and counted, but the
    # armed silent-write fault is deliberately ignored during recovery.
    Execute Command    sysbus WriteDoubleWord 0x10400000 0x11223344
    ${mmio_value}=    Execute Command    sysbus ReadDoubleWord 0x10400000
    ${mmio_count}=    Execute Command    faultFlash TotalWordWrites
    ${mmio_fault}=    Execute Command    faultFlash FaultFired
    ${mmio_fault}=    Strip String    ${mmio_fault}
    Should Be Equal As Numbers    ${mmio_value}    0x11223344
    Should Be Equal As Numbers    ${mmio_count}    1
    Should Be Equal As Strings    ${mmio_fault}    False

    # Execute a tiny Thumb routine from direct secure MappedMemory. Its STR
    # reaches the CPU memory hook rather than WriteAccess, proving the mapped
    # fast path has the same passthrough semantics.
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash FaultFired false
    Execute Command    sysbus WriteDoubleWord 0x10001000 0x49044803
    Execute Command    sysbus WriteDoubleWord 0x10001004 0xE7FE6001
    Execute Command    sysbus WriteDoubleWord 0x10001010 0x10000000
    Execute Command    sysbus WriteDoubleWord 0x10001014 0xAABBCCDD
    Execute Command    cpu PC 0x10001001
    Execute Command    emulation RunFor "1us"
    ${mapped_value}=    Execute Command    sysbus ReadDoubleWord 0x10000000
    ${mapped_count}=    Execute Command    faultFlash TotalWordWrites
    ${mapped_fault}=    Execute Command    faultFlash FaultFired
    ${mapped_fault}=    Strip String    ${mapped_fault}
    Should Be Equal As Numbers    ${mapped_value}    0xAABBCCDD
    Should Be Equal As Numbers    ${mapped_count}    1
    Should Be Equal As Strings    ${mapped_fault}    False
