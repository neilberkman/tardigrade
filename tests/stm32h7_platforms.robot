*** Variables ***
${ROOT}    ${CURDIR}/..

*** Keywords ***
Load H7 Platform
    [Arguments]    ${platform}
    FOR    ${model}    IN    ITardigradeFaultInjectable    FaultTracker    TraceReplayEngine
    ...    STM32H7FlashController    STM32H7FastFlash    STM32H7PWRStub    STM32H7RCCStub
        Execute Command    include "${ROOT}/peripherals/${model}.cs"
    END
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/${platform}.repl

Register Should Equal
    [Arguments]    ${address}    ${expected}
    ${value}=    Execute Command    sysbus ReadDoubleWord ${address}
    Should Be Equal As Numbers    ${value}    ${expected}

Arm One Word DMA
    [Arguments]    ${stream}    ${source}    ${destination}
    ${count}=    Evaluate    ${stream} + 0x04
    ${peripheral}=    Evaluate    ${stream} + 0x08
    ${memory}=    Evaluate    ${stream} + 0x0C
    Execute Command    sysbus WriteDoubleWord ${count} 1
    Execute Command    sysbus WriteDoubleWord ${peripheral} ${source}
    Execute Command    sysbus WriteDoubleWord ${memory} ${destination}
    # Peripheral-to-memory, 32-bit source and destination, stream enabled.
    Execute Command    sysbus WriteDoubleWord ${stream} 0x5001

*** Test Cases ***
H743 Fast Provides RNG Status Data And Interrupt
    Load H7 Platform    stm32h743_fast
    Execute Command    emulation SetSeed 117
    Register Should Equal    0x48021804    0
    Execute Command    sysbus WriteDoubleWord 0x48021800 0xC
    Register Should Equal    0x48021804    1
    ${irq}=    Execute Command    python "print monitor.Machine['sysbus.rng'].IRQ.IsSet"
    Should Be Equal    ${irq.strip()}    True
    ${first}=    Execute Command    sysbus ReadDoubleWord 0x48021808
    ${second}=    Execute Command    sysbus ReadDoubleWord 0x48021808
    Should Not Be Equal As Numbers    ${first}    ${second}
    Execute Command    sysbus WriteDoubleWord 0x48021800 0
    Register Should Equal    0x48021804    0
    Register Should Equal    0x48021808    0
    ${irq}=    Execute Command    python "print monitor.Machine['sysbus.rng'].IRQ.IsSet"
    Should Be Equal    ${irq.strip()}    False

H743 Loads
    Load H7 Platform    stm32h743_tardigrade

H753 Routes SPI4 And Crypto To The Selected DMA Streams
    Load H7 Platform    stm32h753_tardigrade
    # Mux channel 7 drives DMA1 stream 7. Channel 8 drives DMA2 stream 0.
    Execute Command    sysbus WriteDoubleWord 0x4002081C 83
    Execute Command    sysbus WriteDoubleWord 0x40020820 77
    Execute Command    sysbus WriteDoubleWord 0x24000000 0x13572468
    Execute Command    sysbus WriteDoubleWord 0x24000004 0xCAFE9876
    Arm One Word DMA    0x400200B8    0x24000000    0x24000008
    Arm One Word DMA    0x40020410    0x24000004    0x2400000C
    Register Should Equal    0x24000008    0
    Register Should Equal    0x2400000C    0
    Execute Command    python "monitor.Machine['sysbus.spi4'].DMARecieve.Set(True)"
    Register Should Equal    0x24000008    0x13572468
    Register Should Equal    0x2400000C    0
    Execute Command    python "monitor.Machine['sysbus.crypto'].OutDMA.Set(True)"
    Register Should Equal    0x2400000C    0xCAFE9876

Nucleo H753ZI Loads
    Load H7 Platform    nucleo_h753zi_tardigrade
