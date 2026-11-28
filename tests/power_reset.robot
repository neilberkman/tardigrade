*** Settings ***
Library    OperatingSystem
Library    Process

*** Variables ***
${ROOT}              ${CURDIR}/..
${FIRMWARE_DIR}      ${ROOT}/examples/reset_cause
${EVIDENCE_DIR}      ${OUTPUT_DIR}

*** Keywords ***
Load Board
    [Arguments]    ${platform}    ${family}    @{models}
    FOR    ${model}    IN    @{models}
        Execute Command    include "${ROOT}/peripherals/${model}.cs"
    END
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/${platform}.repl
    IF    '${family}' != 'firmware'
        Execute Command    include "${ROOT}/peripherals/PowerResetDomain.cs"
        Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/reset/${family}.repl
    END

nRF Board
    [Arguments]    ${family}=nrf52840
    Load Board    cortex_m4_flash_fast    ${family}    ITardigradeFaultInjectable    NVMemoryController    FaultTracker    NRF52NVMC    NRF52UARTE    TraceReplayEngine

F4 Board
    [Arguments]    ${family}=stm32f4
    Load Board    stm32f4    ${family}    ITardigradeFaultInjectable    FaultTracker    STM32F4FlashController    STM32DummyUSART

Word Should Equal
    [Arguments]    ${address}    ${expected}
    ${actual}=    Execute Command    sysbus ReadDoubleWord ${address}
    Should Be Equal As Integers    ${actual}    ${expected}

Check Reset Flags
    [Arguments]    ${address}    ${clear}    ${power}    ${watchdog}    ${pin}    ${clock}=0
    Word Should Equal    ${address}    ${{$power | $clock}}
    Execute Command    sysbus WriteDoubleWord ${address} ${{int($clear, 0) | $clock}}
    Word Should Equal    ${address}    ${clock}
    Execute Command    powerDomain ResetFromPin
    Word Should Equal    ${address}    ${{$pin | $clock}}
    Execute Command    powerDomain ResetFromWatchdog
    Word Should Equal    ${address}    ${{$watchdog | $pin | $clock}}
    Execute Command    powerDomain PowerCycle
    Word Should Equal    ${address}    ${{$power | $clock}}

Check Backup Words
    [Arguments]    ${first}    ${last}
    FOR    ${address}    IN RANGE    ${first}    ${last + 1}    4
        Execute Command    sysbus WriteDoubleWord ${address} ${address % 65536 + 1}
    END
    Execute Command    machine Reset
    FOR    ${address}    IN RANGE    ${first}    ${last + 1}    4
        Word Should Equal    ${address}    ${address % 65536 + 1}
    END
    Execute Command    powerDomain VbatPresent true
    Execute Command    powerDomain PowerCycle
    FOR    ${address}    IN RANGE    ${first}    ${last + 1}    4
        Word Should Equal    ${address}    ${address % 65536 + 1}
    END
    Execute Command    powerDomain VbatPresent false
    Execute Command    powerDomain PowerCycle
    FOR    ${address}    IN RANGE    ${first}    ${last + 1}    4
        Word Should Equal    ${address}    0
    END

Run Reset Firmware
    [Arguments]    ${target}    ${software_flags}    ${power_flags}
    ${setup}=    Set Variable    ${EVIDENCE_DIR}/${target}-reset.resc
    ${result}=    Run Process    python3    ${ROOT}/scripts/reset_domain.py    ${ROOT}/examples/reset_cause/${target}.yaml    ${setup}
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    Execute Command    include "${setup}"
    Execute Command    sysbus LoadELF @${FIRMWARE_DIR}/${target}.elf
    Execute Command    emulation RunFor "0.001"
    ${first}=    Check Firmware Observation    ${power_flags}    0    0
    Execute Command    sysbus WriteDoubleWord 0x20000210 1
    Execute Command    emulation RunFor "0.01"
    ${second}=    Check Firmware Observation    ${software_flags}    0x12345678    0x5a
    Execute Command    powerDomain PowerCycle
    Execute Command    emulation RunFor "0.01"
    ${third}=    Check Firmware Observation    ${power_flags}    0xa5a5a5a5    0
    ${history}=    Execute Command    python "print ','.join(monitor.Machine['sysbus.powerDomain'].BootResetKinds)"
    ${kinds}=    Evaluate    $history.strip().split(',')
    Should Be Equal    ${kinds}    ${{['power_on', 'warm', 'power_loss']}}
    ${json}=    Evaluate    json.dumps([dict(reset_kind=k, **v) for k, v in zip($kinds, [$first, $second, $third])], indent=2)    modules=json
    Create File    ${EVIDENCE_DIR}/${target}-boots.json    ${json}

Check Firmware Observation
    [Arguments]    ${flags}    ${retained}    ${backup}
    ${cause}=    Execute Command    sysbus ReadDoubleWord 0x20000100
    ${ram}=    Execute Command    sysbus ReadDoubleWord 0x20000104
    ${reg}=    Execute Command    sysbus ReadDoubleWord 0x20000108
    Should Be Equal As Integers    ${cause}    ${flags}
    Should Be Equal As Integers    ${ram}    ${retained}
    Should Be Equal As Integers    ${reg}    ${backup}
    ${observation}=    Evaluate    dict(cause=int($cause, 0), retained=int($ram, 0), backup=int($reg, 0))
    RETURN    ${observation}

*** Test Cases ***
nRF Reset And Retention Registers
    nRF Board
    Execute Command    sysbus WriteDoubleWord 0x4000051c 0x123
    Execute Command    sysbus WriteDoubleWord 0x40000520 0x456
    Word Should Equal    0x4000051c    0x23
    Word Should Equal    0x40000520    0x56
    Execute Command    sysbus LoadELF @${FIRMWARE_DIR}/nrf52840.elf
    Execute Command    sysbus WriteDoubleWord 0x20000210 1
    Execute Command    emulation RunFor "0.01"
    Word Should Equal    0x40000520    0x56
    Execute Command    powerDomain ResetFromPin
    Execute Command    powerDomain ResetFromWatchdog
    Word Should Equal    0x40000400    3
    Execute Command    sysbus WriteDoubleWord 0x40000400 1
    Word Should Equal    0x40000400    2
    Word Should Equal    0x4000051c    0
    Word Should Equal    0x40000520    0
    Execute Command    sysbus WriteDoubleWord 0x4000051c 0xff
    Execute Command    sysbus WriteDoubleWord 0x40000520 0xff
    Execute Command    powerDomain PowerCycle
    Word Should Equal    0x40000400    0
    Word Should Equal    0x4000051c    0
    Word Should Equal    0x40000520    0

F4 Reset And Backup Domain
    F4 Board
    Check Reset Flags    0x40023874    0x01000000    ${0x0e000000}    ${0x20000000}    ${0x04000000}    ${0}
    Check Backup Words    ${0x40002850}    ${0x4000289c}
    Check Backup Words    ${0x40024000}    ${0x40024004}
    Check Backup Words    ${0x40024ffc}    ${0x40024ffc}

H7 Reset And Backup Domain
    Load Board    stm32h743_fast    stm32h7    ITardigradeFaultInjectable    FaultTracker    TraceReplayEngine    STM32H7FastFlash
    Check Reset Flags    0x580244d0    0x00010000    ${0x00fe0000}    ${0x04000000}    ${0x00420000}    ${0}
    Word Should Equal    0x58024530    0x00fe0000
    Execute Command    sysbus WriteByte 0x58024532 1
    Word Should Equal    0x580244d0    0
    Check Backup Words    ${0x58004050}    ${0x580040cc}
    Check Backup Words    ${0x38800000}    ${0x38800004}
    Check Backup Words    ${0x38800ffc}    ${0x38800ffc}

F1 Reset And Backup Domain
    Load Board    stm32f103    stm32f1    ITardigradeFaultInjectable    FaultTracker    TraceReplayEngine    STM32F1FlashController
    Check Reset Flags    0x40021024    0x01000000    ${0x0c000000}    ${0x20000000}    ${0x04000000}    ${0}
    Execute Command    sysbus WriteDoubleWord 0x40006c28 0xcafebeef
    Word Should Equal    0x40006c28    0xbeef
    Check Backup Words    ${0x40006c04}    ${0x40006c28}

L4 Reset And Backup Domain
    Load Board    stm32l476    stm32l4    ITardigradeFaultInjectable    FaultTracker    TraceReplayEngine    STM32L4FlashController
    Check Reset Flags    0x40021094    0x00800000    ${0x0c000000}    ${0x20000000}    ${0x04000000}    ${0x600}
    Check Backup Words    ${0x40002850}    ${0x400028cc}

nRF Firmware Observes Software Reset And Power Loss
    nRF Board    firmware
    Run Reset Firmware    nrf52840    4    0

F4 Firmware Observes Software Reset And Power Loss
    F4 Board    firmware
    Run Reset Firmware    stm32f4    0x14000000    0x0e000000

Built-In nRF Watchdog Supplies Its Reset Cause
    Load Board    nrf52840_nvmc_psel    nrf52840
    Execute Command    sysbus LoadELF @${FIRMWARE_DIR}/nrf52840.elf
    Execute Command    emulation RunFor "0.001"
    Execute Command    sysbus WriteDoubleWord 0x40010504 32
    Execute Command    sysbus WriteDoubleWord 0x4001050c 1
    Execute Command    sysbus WriteDoubleWord 0x40010000 1
    Execute Command    emulation RunFor "0.02"
    Word Should Equal    0x20000100    2
    Word Should Equal    0x20000108    0

Built-In Independent Watchdog Supplies Its Reset Cause
    Load Board    stm32l476    stm32l4    ITardigradeFaultInjectable    FaultTracker    TraceReplayEngine    STM32L4FlashController
    Execute Command    sysbus WriteDoubleWord 0x40021094 0x00800000
    Execute Command    sysbus WriteDoubleWord 0x40002850 0x6d
    # A two-byte infinite loop and vector table allow the guest to idle.
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x20001000
    Execute Command    sysbus WriteDoubleWord 0x08000004 0x08000009
    Execute Command    sysbus WriteDoubleWord 0x08000008 0xe7fee7fe
    Execute Command    cpu VectorTableOffset 0x08000000
    Execute Command    sysbus WriteDoubleWord 0x40003000 0x5555
    Execute Command    sysbus WriteDoubleWord 0x40003008 7
    Execute Command    sysbus WriteDoubleWord 0x40003000 0xaaaa
    Execute Command    sysbus WriteDoubleWord 0x40003000 0xcccc
    Execute Command    emulation RunFor "0.02"
    Word Should Equal    0x40021094    0x24000600
    Word Should Equal    0x40002850    0x6d

Every Listener Sees The Cut Around One Ordinary Reset
    nRF Board
    Execute Command    include "${ROOT}/tests/PowerResetWitness.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "first: PowerResetWitness @ sysbus"
    Execute Command    machine LoadPlatformDescriptionFromString "second: PowerResetWitness @ sysbus"
    Execute Command    powerDomain PowerCycle
    Execute Command    machine Reset
    FOR    ${listener}    IN    first    second
        ${events}=    Execute Command    ${listener} Events
        Should Be Equal    ${events.strip()}    off reset on reset
    END

Fault Sweep Brackets Power Loss Cut Around Machine Reset
    nRF Board
    Execute Command    include "${ROOT}/tests/PowerResetWitness.cs"
    Execute Command    machine LoadPlatformDescriptionFromString "witness: PowerResetWitness @ sysbus"
    Execute Command    powerDomain StartTrial
    Execute Command    powerDomain PreparePowerOn
    Execute Command    machine Reset
    Execute Command    machine Reset
    Execute Command    powerDomain BeginPowerLoss
    Execute Command    machine Reset
    Execute Command    powerDomain EndPowerLoss
    ${events}=    Execute Command    witness Events
    Should Be Equal    ${events.strip()}    reset reset off reset on
    ${history}=    Execute Command    python "print ','.join(monitor.Machine['sysbus.powerDomain'].BootResetKinds)"
    ${kinds}=    Evaluate    $history.strip().split(',')
    Should Be Equal    ${kinds}    ${{['power_on', 'warm', 'power_loss']}}

Retained Fill Stops At Both Unaligned Boundaries
    nRF Board
    Execute Command    powerDomain AddRetainedRegion 0x20000001 65538 0x5b
    Execute Command    powerDomain AddRetainedRegion 0x20010004 3
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x11223344
    Execute Command    sysbus WriteDoubleWord 0x20010000 0x55667788
    Execute Command    sysbus WriteDoubleWord 0x20010004 0x99aabbcc
    Execute Command    machine Reset
    Word Should Equal    0x20000000    0x11223344
    Word Should Equal    0x20010000    0x55667788
    Word Should Equal    0x20010004    0x99aabbcc
    Execute Command    powerDomain PowerCycle
    Word Should Equal    0x20000000    0x5b5b5b44
    Word Should Equal    0x20010000    0x555b5b5b
    Word Should Equal    0x20010004    0x99000000
