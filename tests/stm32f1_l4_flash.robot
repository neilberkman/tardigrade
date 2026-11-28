*** Settings ***
Library    String

*** Variables ***
${ROOT}                        ${CURDIR}/..
${STM32_PERIPHERALS_LOADED}    ${FALSE}

*** Keywords ***
Ensure STM32 Flash Peripherals Loaded
    IF    not ${STM32_PERIPHERALS_LOADED}
        Execute Command    include "${ROOT}/peripherals/ITardigradeFaultInjectable.cs"
        Execute Command    include "${ROOT}/peripherals/FlashTiming.cs"
        Execute Command    include "${ROOT}/peripherals/FaultTracker.cs"
        Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"
        Execute Command    include "${ROOT}/peripherals/STM32F1FlashController.cs"
        Execute Command    include "${ROOT}/peripherals/STM32L4FlashController.cs"
        Set Suite Variable    ${STM32_PERIPHERALS_LOADED}    ${TRUE}
    END

Create STM32F1 Machine
    Ensure STM32 Flash Peripherals Loaded
    Execute Command    Clear
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/stm32f103.repl

Create STM32L4 Machine
    Ensure STM32 Flash Peripherals Loaded
    Execute Command    Clear
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/stm32l476.repl

Unlock STM32F1 Flash
    Execute Command    sysbus WriteDoubleWord 0x40022004 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022004 0xCDEF89AB

Unlock STM32L4 Flash
    Execute Command    sysbus WriteDoubleWord 0x40022008 0x45670123
    Execute Command    sysbus WriteDoubleWord 0x40022008 0xCDEF89AB

Erase STM32F1 Page
    [Arguments]    ${page_addr}
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40022014 ${page_addr}
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000042
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000000

Erase STM32L4 Page
    [Arguments]    ${bank}    ${page_num}
    ${bker}=    Evaluate    (1 << 11) if int(${bank}) == 2 else 0
    ${pnb}=     Evaluate    (int(${page_num}) & 0xFF) << 3
    ${cr}=      Evaluate    0x00010002 | ${bker} | ${pnb}
    Execute Command    sysbus WriteDoubleWord 0x40022014 ${cr}
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000

Install STM32F1 Fault Vectors
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x20005000
    Execute Command    sysbus WriteDoubleWord 0x08000004 0x08000101
    Execute Command    sysbus WriteDoubleWord 0x08000008 0x08000201
    Execute Command    sysbus WriteDoubleWord 0x0800000C 0x08000205
    Execute Command    sysbus WriteWord 0x08000200 0xE7FE
    Execute Command    sysbus WriteWord 0x08000204 0xE7FE
    Execute Command    sysbus WriteDoubleWord 0xE000ED08 0x08000000

Install STM32L4 Fault Vectors
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x20018000
    Execute Command    sysbus WriteDoubleWord 0x08000004 0x08000101
    Execute Command    sysbus WriteDoubleWord 0x08000008 0x08000201
    Execute Command    sysbus WriteDoubleWord 0x0800000C 0x08000205
    Execute Command    sysbus WriteWord 0x08000200 0xE7FE
    Execute Command    sysbus WriteWord 0x08000204 0xE7FE
    Execute Command    sysbus WriteDoubleWord 0xE000ED08 0x08000000

Program STM32F1 HalfWord Via CPU
    [Arguments]    ${target_addr}    ${halfword_val}
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x49034802
    Execute Command    sysbus WriteDoubleWord 0x20000004 0xE7FE8001
    Execute Command    sysbus WriteDoubleWord 0x2000000C ${target_addr}
    Execute Command    sysbus WriteDoubleWord 0x20000010 ${halfword_val}
    Execute Command    nvic Reset
    Execute Command    cpu Reset
    Execute Command    cpu SP 0x20005000
    Execute Command    cpu PC 0x20000001
    Execute Command    emulation RunFor "2us"

Write STM32 Word Via CPU
    [Arguments]    ${target_addr}    ${word_val}    ${sp_addr}=0x20005000
    Execute Command    sysbus WriteDoubleWord 0x20000040 0x49024802
    Execute Command    sysbus WriteDoubleWord 0x20000044 0xE7FE6001
    Execute Command    sysbus WriteDoubleWord 0x2000004C ${target_addr}
    Execute Command    sysbus WriteDoubleWord 0x20000050 ${word_val}
    Execute Command    nvic Reset
    Execute Command    cpu Reset
    Execute Command    sysbus WriteDoubleWord 0xE000ED08 0x08000000
    Execute Command    cpu SP ${sp_addr}
    Execute Command    cpu PC 0x20000041
    Execute Command    emulation RunFor "2us"

Write STM32 Byte Via CPU
    [Arguments]    ${target_addr}    ${byte_val}    ${sp_addr}=0x20005000
    Execute Command    sysbus WriteDoubleWord 0x20000040 0x49024802
    Execute Command    sysbus WriteDoubleWord 0x20000044 0xE7FE7001
    Execute Command    sysbus WriteDoubleWord 0x2000004C ${target_addr}
    Execute Command    sysbus WriteDoubleWord 0x20000050 ${byte_val}
    Execute Command    nvic Reset
    Execute Command    cpu Reset
    Execute Command    sysbus WriteDoubleWord 0xE000ED08 0x08000000
    Execute Command    cpu SP ${sp_addr}
    Execute Command    cpu PC 0x20000041
    Execute Command    emulation RunFor "2us"

Program STM32L4 DoubleWord Via CPU
    [Arguments]    ${target_addr}    ${low_word}    ${high_word}
    Execute Command    sysbus WriteDoubleWord 0x20000000 0x49034802
    Execute Command    sysbus WriteDoubleWord 0x20000004 0x60014A03
    Execute Command    sysbus WriteDoubleWord 0x20000008 0xE7FE6042
    Execute Command    sysbus WriteDoubleWord 0x2000000C ${target_addr}
    Execute Command    sysbus WriteDoubleWord 0x20000010 ${low_word}
    Execute Command    sysbus WriteDoubleWord 0x20000014 ${high_word}
    Execute Command    nvic Reset
    Execute Command    cpu Reset
    Execute Command    cpu SP 0x20018000
    Execute Command    cpu PC 0x20000001
    Execute Command    emulation RunFor "2us"

Read Word Via CPU
    [Arguments]    ${target_addr}    ${sp_addr}=0x20018000
    Execute Command    sysbus WriteDoubleWord 0x20000100 0x68014801
    Execute Command    sysbus WriteDoubleWord 0x20000104 0x0000E7FE
    Execute Command    sysbus WriteDoubleWord 0x20000108 ${target_addr}
    Execute Command    nvic Reset
    Execute Command    cpu Reset
    Execute Command    sysbus WriteDoubleWord 0xE000ED08 0x08000000
    Execute Command    cpu SP ${sp_addr}
    Execute Command    cpu PC 0x20000101
    Execute Command    emulation RunFor "2us"

Read Normalized Bool
    [Arguments]    ${command}
    ${raw}=        Execute Command    ${command}
    ${text}=       Convert To String    ${raw}
    ${text}=       Strip String    ${text}
    ${text}=       Convert To Lower Case    ${text}
    RETURN    ${text}

*** Test Cases ***
STM32F1 Register Unlock Prefetch And RCC Ready Bits Follow RM0008
    Create STM32F1 Machine
    ${acr_reset}=      Execute Command    sysbus ReadDoubleWord 0x40022000
    ${cr_reset}=       Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${acr_reset}    0x00000030
    Should Be Equal As Numbers    ${cr_reset}     0x00000080

    Execute Command    sysbus WriteDoubleWord 0x40022000 0x00000002
    ${acr_no_prft}=    Execute Command    sysbus ReadDoubleWord 0x40022000
    Should Be Equal As Numbers    ${acr_no_prft}    0x00000002
    Execute Command    sysbus WriteDoubleWord 0x40022000 0x00000012
    ${acr_with_prft}=  Execute Command    sysbus ReadDoubleWord 0x40022000
    Should Be Equal As Numbers    ${acr_with_prft}    0x00000032

    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    ${cr_still_locked}=    Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${cr_still_locked}    0x00000080

    Unlock STM32F1 Flash
    ${cr_unlocked}=    Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${cr_unlocked}    0x00000000

    Execute Command    sysbus WriteDoubleWord 0x40021000 0x01010001
    ${rcc_cr}=         Execute Command    sysbus ReadDoubleWord 0x40021000
    Should Be Equal As Numbers    ${rcc_cr}    0x03030003
    Execute Command    sysbus WriteDoubleWord 0x40021004 0x00000002
    ${rcc_cfgr}=       Execute Command    sysbus ReadDoubleWord 0x40021004
    Should Be Equal As Numbers    ${rcc_cfgr}    0x0000000A

STM32F1 HalfWord Program And NonErased PGERR Rejection
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000

    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32F1 HalfWord Via CPU    0x08001000    0x1234
    ${val1}=           Execute Command    sysbus ReadWord 0x08001000
    ${sr1}=            Execute Command    sysbus ReadDoubleWord 0x4002200C
    ${writes1}=        Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${val1}       0x1234
    Should Be Equal As Numbers    ${sr1}        0x00000020
    Should Be Equal As Numbers    ${writes1}    1

    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020
    ${sr_cleared}=     Execute Command    sysbus ReadDoubleWord 0x4002200C
    Should Be Equal As Numbers    ${sr_cleared}    0x00000000

    Program STM32F1 HalfWord Via CPU    0x08001000    0x0010
    ${val_after}=      Execute Command    sysbus ReadWord 0x08001000
    ${sr_err}=         Execute Command    sysbus ReadDoubleWord 0x4002200C
    ${writes_after}=   Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${val_after}       0x1234
    Should Be Equal As Numbers    ${sr_err}          0x00000004
    Should Be Equal As Numbers    ${writes_after}    1

    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000004
    ${sr_err_cleared}=    Execute Command    sysbus ReadDoubleWord 0x4002200C
    Should Be Equal As Numbers    ${sr_err_cleared}    0x00000000

STM32F1 Page Erase Mass Erase And Torn Program Outcomes
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Execute Command    faultFlash EraseTraceEnabled true

    Execute Command    sysbus WriteDoubleWord 0x08001000 0x11112222
    Execute Command    sysbus WriteDoubleWord 0x08001400 0x33334444
    Erase STM32F1 Page    0x08001000
    ${p0}=             Execute Command    sysbus ReadDoubleWord 0x08001000
    ${p1}=             Execute Command    sysbus ReadDoubleWord 0x08001400
    Should Be Equal As Numbers    ${p0}    0xFFFFFFFF
    Should Be Equal As Numbers    ${p1}    0x33334444

    Execute Command    faultFlash PageSize 0x800
    Execute Command    sysbus WriteDoubleWord 0x08001000 0x11112222
    Execute Command    sysbus WriteDoubleWord 0x08001400 0x33334444
    Erase STM32F1 Page    0x08001000
    ${hd0}=            Execute Command    sysbus ReadDoubleWord 0x08001000
    ${hd1}=            Execute Command    sysbus ReadDoubleWord 0x08001400
    Should Be Equal As Numbers    ${hd0}    0xFFFFFFFF
    Should Be Equal As Numbers    ${hd1}    0xFFFFFFFF

    Execute Command    faultFlash PageSize 0x400
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    faultFlash TornWordMode "fixed"
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32F1 HalfWord Via CPU    0x08001000    0x0000
    ${cut_fixed}=      Execute Command    sysbus ReadWord 0x08001000
    ${fired_fixed}=    Read Normalized Bool    faultFlash FaultFired
    Should Be Equal    ${fired_fixed}    true
    Should Be Equal As Numbers    ${cut_fixed}    0xFFFF

    Execute Command    faultFlash FaultFired false
    Execute Command    faultFlash TornWordMode "partial_bits"
    Execute Command    faultFlash TornWordSeed 42
    Execute Command    faultFlash FaultAtWordWrite 2
    Program STM32F1 HalfWord Via CPU    0x08001002    0x0000
    ${cut_partial}=    Execute Command    sysbus ReadWord 0x08001002
    Should Not Be Equal As Numbers    ${cut_partial}    0xFFFF
    Should Not Be Equal As Numbers    ${cut_partial}    0x0000

    Execute Command    faultFlash FaultFired false
    Execute Command    sysbus WriteDoubleWord 0x08000000 0x12345678
    Execute Command    sysbus WriteDoubleWord 0x0801F000 0x87654321
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000044
    ${me0}=            Execute Command    sysbus ReadDoubleWord 0x08000000
    ${me1}=            Execute Command    sysbus ReadDoubleWord 0x0801F000
    Should Be Equal As Numbers    ${me0}    0xFFFFFFFF
    Should Be Equal As Numbers    ${me1}    0xFFFFFFFF

STM32L4 DoubleWord Program DualBank Erase And Fast Row Mode
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Erase STM32L4 Page    2    0
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB

    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Write STM32 Word Via CPU    0x08001000    0x11223344    0x20018000
    ${half_latched}=   Execute Command    sysbus ReadDoubleWord 0x08001000
    ${writes_half}=    Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${half_latched}    0xFFFFFFFF
    Should Be Equal As Numbers    ${writes_half}     0

    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000
    ${sr_pgserr}=      Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${sr_pgserr}    0x00000080
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000080

    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08001000    0x44332211    0x88776655
    ${dw_lo}=          Execute Command    sysbus ReadDoubleWord 0x08001000
    ${dw_hi}=          Execute Command    sysbus ReadDoubleWord 0x08001004
    ${writes_full}=    Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${dw_lo}          0x44332211
    Should Be Equal As Numbers    ${dw_hi}          0x88776655
    Should Be Equal As Numbers    ${writes_full}    1

    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08001000    0x11111111    0x22222222
    ${sr_progerr}=     Execute Command    sysbus ReadDoubleWord 0x40022010
    ${dw_preserved}=   Execute Command    sysbus ReadDoubleWord 0x08001000
    Should Be Equal As Numbers    ${sr_progerr}      0x00000008
    Should Be Equal As Numbers    ${dw_preserved}    0x44332211
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000008

    Program STM32L4 DoubleWord Via CPU    0x08001000    0x00000000    0x00000000
    ${dw_zero_lo}=     Execute Command    sysbus ReadDoubleWord 0x08001000
    ${dw_zero_hi}=     Execute Command    sysbus ReadDoubleWord 0x08001004
    Should Be Equal As Numbers    ${dw_zero_lo}    0x00000000
    Should Be Equal As Numbers    ${dw_zero_hi}    0x00000000
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000

    Execute Command    sysbus WriteDoubleWord 0x08080800 0xCAFEBABE
    Erase STM32L4 Page    2    1
    ${b2_erased}=      Execute Command    sysbus ReadDoubleWord 0x08080800
    ${b1_untouched}=   Execute Command    sysbus ReadDoubleWord 0x08001000
    Should Be Equal As Numbers    ${b2_erased}       0xFFFFFFFF
    Should Be Equal As Numbers    ${b1_untouched}    0x00000000

    # Fast row-programming mode (FSTPG = 1<<18 = 0x40000) with EOPIE=0: EOP remains 0.
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00040000
    Execute Command    sysbus WriteDoubleWord 0x20000080 0x49054804
    Execute Command    sysbus WriteDoubleWord 0x20000084 0xC0022240
    Execute Command    sysbus WriteDoubleWord 0x20000088 0x3A013101
    Execute Command    sysbus WriteDoubleWord 0x2000008C 0xE7FED1FB
    Execute Command    sysbus WriteDoubleWord 0x20000094 0x08080800
    Execute Command    sysbus WriteDoubleWord 0x20000098 0xA5A50000
    Execute Command    cpu Reset
    Execute Command    cpu SP 0x20018000
    Execute Command    cpu PC 0x20000081
    Execute Command    emulation RunFor "10us"
    ${fst_writes}=     Execute Command    faultFlash TotalWordWrites
    ${fst_w0}=         Execute Command    sysbus ReadDoubleWord 0x08080800
    ${fst_w63}=        Execute Command    sysbus ReadDoubleWord 0x080808FC
    ${fst_sr}=         Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${fst_writes}    32
    Should Be Equal As Numbers    ${fst_w0}        0xA5A50000
    Should Be Equal As Numbers    ${fst_w63}       0xA5A5003F
    Should Be Equal As Numbers    ${fst_sr}        0x00000000
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000

STM32L4 Interrupted DoubleWord Program Raises ECCD And NMI On Read
    Create STM32L4 Machine
    Install STM32L4 Fault Vectors
    Execute Command    cpu SP 0x20018000

    Unlock STM32L4 Flash
    Erase STM32L4 Page    2    2

    Execute Command    faultFlash TornWordMode "uncorrectable"
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08081010    0xCAFEBABE    0xDEADBEEF

    ${marked}=         Read Normalized Bool    faultFlash LastFaultMarkedUncorrectable
    ${is_uncorr}=      Read Normalized Bool    faultFlash IsAddressUncorrectable 0x08081010
    ${count}=          Execute Command    faultFlash UncorrectableWordCount
    Should Be Equal    ${marked}       true
    Should Be Equal    ${is_uncorr}    true
    Should Be Equal As Numbers    ${count}    1

    Execute Command    faultFlash FaultFired false
    Execute Command    faultFlash FaultAtWordWrite 999999
    Read Word Via CPU    0x08081014
    ${eccr}=           Execute Command    sysbus ReadDoubleWord 0x40022018
    ${read_cnt}=       Execute Command    faultFlash UncorrectableReadCount
    ${pc}=             Execute Command    cpu PC
    ${xpsr}=           Execute Command    cpu XProgramStatusRegister
    ${ipsr}=           Evaluate    int(${xpsr}) & 0x1FF
    Should Be Equal As Numbers    ${eccr}        0x80081010
    Should Be Equal As Numbers    ${read_cnt}    1
    Should Be Equal As Numbers    ${pc}          0x08000200
    Should Be Equal As Numbers    ${ipsr}        2

    Execute Command    sysbus WriteDoubleWord 0x40022018 0x80000000
    ${eccr_cleared}=   Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr_cleared}    0x00000000

    Erase STM32L4 Page    2    2
    ${count_after}=    Execute Command    faultFlash UncorrectableWordCount
    Should Be Equal As Numbers    ${count_after}    0

Defect 1 STM32F1 Zero Overwrite On NonErased HalfWord Succeeds Without PGERR
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32F1 HalfWord Via CPU    0x08001000    0x1234
    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020

    # PM0075 §2.3.3: programming 0x0000 over non-erased 0x1234 writes 0x0000 and leaves PGERR=0.
    Program STM32F1 HalfWord Via CPU    0x08001000    0x0000
    ${val}=       Execute Command    sysbus ReadWord 0x08001000
    ${sr}=        Execute Command    sysbus ReadDoubleWord 0x4002200C
    ${writes}=    Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${val}       0x0000
    Should Be Equal As Numbers    ${sr}        0x00000020
    Should Be Equal As Numbers    ${writes}    2

Defect 2 STM32F1 And STM32L4 Flash Alias At Zero Goes Through Controller And ECC
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000
    Execute Command    faultFlash WriteTraceEnabled true
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32F1 HalfWord Via CPU    0x00001000    0x5678
    ${f1_val}=       Execute Command    sysbus ReadWord 0x08001000
    ${f1_writes}=    Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${f1_val}       0x5678
    Should Be Equal As Numbers    ${f1_writes}    1
    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020
    Program STM32F1 HalfWord Via CPU    0x00001000    0x0001
    ${f1_reverted}=  Execute Command    sysbus ReadWord 0x08001000
    ${f1_sr}=        Execute Command    sysbus ReadDoubleWord 0x4002200C
    Should Be Equal As Numbers    ${f1_reverted}    0x5678
    Should Be Equal As Numbers    ${f1_sr}          0x00000004

    Create STM32L4 Machine
    Install STM32L4 Fault Vectors
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Write STM32 Word Via CPU    0x00001000    0x11223344    0x20018000
    ${l4_latched}=   Execute Command    sysbus ReadDoubleWord 0x08001000
    Should Be Equal As Numbers    ${l4_latched}    0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    faultFlash MarkWordUncorrectable 0x1010
    Read Word Via CPU    0x00001010
    ${l4_eccr}=      Execute Command    sysbus ReadDoubleWord 0x40022018
    ${l4_pc}=        Execute Command    cpu PC
    Should Be Equal As Numbers    ${l4_eccr}    0x80001010
    Should Be Equal As Numbers    ${l4_pc}      0x08000200

Defect 3 STM32F1 And STM32L4 Memory Access Hook Installed Only While Needed
    Create STM32F1 Machine
    ${f1_reset}=       Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${f1_reset}    false
    Unlock STM32F1 Flash
    ${f1_unlocked}=    Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${f1_unlocked}    true
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    ${f1_pg_on}=       Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${f1_pg_on}    true
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000080
    ${f1_locked}=      Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${f1_locked}    false

    Create STM32L4 Machine
    ${l4_reset}=       Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_reset}    false
    Unlock STM32L4 Flash
    ${l4_unlocked}=    Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_unlocked}    true
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    ${l4_pg_on}=       Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_pg_on}    true
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x80000000
    ${l4_locked}=      Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_locked}    false
    Execute Command    faultFlash MarkWordUncorrectable 0x1000
    ${l4_ecc_on}=      Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_ecc_on}    true
    Execute Command    faultFlash ClearUncorrectableWords
    ${l4_ecc_off}=     Read Normalized Bool    faultFlash MemoryAccessHookInstalled
    Should Be Equal    ${l4_ecc_off}    false

Defect 4 STM32F1 And STM32L4 Shadow Valid Before Reject Or Latch Revert
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001
    Program STM32F1 HalfWord Via CPU    0x08001000    0x1234
    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020
    Execute Command    faultFlash InvalidateShadow
    Program STM32F1 HalfWord Via CPU    0x08001000    0x0010
    ${f1_reverted}=    Execute Command    sysbus ReadWord 0x08001000
    Should Be Equal As Numbers    ${f1_reverted}    0x1234

    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Execute Command    faultFlash InvalidateShadow
    Write STM32 Word Via CPU    0x08001000    0x11223344    0x20018000
    ${l4_latched}=     Execute Command    sysbus ReadDoubleWord 0x08001000
    Should Be Equal As Numbers    ${l4_latched}    0xFFFFFFFF

Defect 5 STM32F1 And STM32L4 Wrong Key Sequence Locks Until Reset With Bus Error
    Create STM32F1 Machine
    Install STM32F1 Fault Vectors
    Execute Command    sysbus WriteDoubleWord 0x40022004 0x45670123
    Write STM32 Word Via CPU    0x40022004    0x11111111    0x20005000
    ${f1_pc}=      Execute Command    cpu PC
    ${f1_cfsr}=    Execute Command    sysbus ReadDoubleWord 0xE000ED28
    Should Be Equal As Numbers    ${f1_pc}    0x08000204
    ${f1_prec}=    Evaluate    int(${f1_cfsr}) & 0x200
    Should Be Equal As Numbers    ${f1_prec}    0x200
    Unlock STM32F1 Flash
    ${f1_cr}=      Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${f1_cr}    0x00000080

    Create STM32L4 Machine
    Install STM32L4 Fault Vectors
    Write STM32 Word Via CPU    0x40022008    0xDEAD1234    0x20018000
    ${l4_pc}=      Execute Command    cpu PC
    ${l4_cfsr}=    Execute Command    sysbus ReadDoubleWord 0xE000ED28
    Should Be Equal As Numbers    ${l4_pc}    0x08000204
    ${l4_prec}=    Evaluate    int(${l4_cfsr}) & 0x200
    Should Be Equal As Numbers    ${l4_prec}    0x200
    Unlock STM32L4 Flash
    ${l4_cr}=      Execute Command    sysbus ReadDoubleWord 0x40022014
    Should Be Equal As Numbers    ${l4_cr}    0xC0000000

Defect 6 STM32F1 NonHalfWord Write In PG Mode Raises Bus Error Without Program Or PGERR
    Create STM32F1 Machine
    Install STM32F1 Fault Vectors
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000
    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00000001

    Write STM32 Word Via CPU    0x08001000    0xAABBCCDD    0x20005000
    ${w_mem}=       Execute Command    sysbus ReadDoubleWord 0x08001000
    ${w_sr}=        Execute Command    sysbus ReadDoubleWord 0x4002200C
    ${w_writes}=    Execute Command    faultFlash TotalWordWrites
    ${w_pc}=        Execute Command    cpu PC
    ${w_cfsr}=      Execute Command    sysbus ReadDoubleWord 0xE000ED28
    Should Be Equal As Numbers    ${w_mem}       0xFFFFFFFF
    Should Be Equal As Numbers    ${w_sr}        0x00000000
    Should Be Equal As Numbers    ${w_writes}    0
    Should Be Equal As Numbers    ${w_pc}        0x08000204
    ${w_prec}=      Evaluate    int(${w_cfsr}) & 0x200
    Should Be Equal As Numbers    ${w_prec}      0x200

    Execute Command    sysbus WriteDoubleWord 0xE000ED28 0xFFFFFFFF
    Write STM32 Byte Via CPU    0x08001000    0xAA    0x20005000
    ${b_mem}=       Execute Command    sysbus ReadDoubleWord 0x08001000
    ${b_sr}=        Execute Command    sysbus ReadDoubleWord 0x4002200C
    ${b_pc}=        Execute Command    cpu PC
    Should Be Equal As Numbers    ${b_mem}    0xFFFFFFFF
    Should Be Equal As Numbers    ${b_sr}     0x00000000
    Should Be Equal As Numbers    ${b_pc}     0x08000204

Defect 7 STM32L4 Program Or Erase With Error Flags Set Raises PGSERR And Does Not Run
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08001000    0x44332211    0x88776655
    # Trigger PROGERR on 0x08001000 and leave PROGERR (0x08) set in FLASH_SR.
    Program STM32L4 DoubleWord Via CPU    0x08001000    0x11111111    0x22222222

    # Next program with PROGERR still set must set PGSERR (0x88) and not run.
    Program STM32L4 DoubleWord Via CPU    0x08001010    0x12345678    0x9ABCDEF0
    ${sr_prog}=        Execute Command    sysbus ReadDoubleWord 0x40022010
    ${unrun_prog}=     Execute Command    sysbus ReadDoubleWord 0x08001010
    ${writes_prog}=    Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${sr_prog}        0x00000088
    Should Be Equal As Numbers    ${unrun_prog}     0xFFFFFFFF
    Should Be Equal As Numbers    ${writes_prog}    1

    # Erase with error flags still set must also set PGSERR and not run.
    Erase STM32L4 Page    1    2
    ${unrun_erase}=    Execute Command    sysbus ReadDoubleWord 0x08001000
    Should Be Equal As Numbers    ${unrun_erase}    0x44332211

Defect 8 STM32L4 Interrupted Uncorrectable DoubleWord Rejects NonZero Reprogram With PROGERR
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    2    2
    Execute Command    faultFlash TornWordMode "uncorrectable"
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08081010    0xCAFEBABE    0xDEADBEEF

    Execute Command    faultFlash FaultFired false
    Execute Command    faultFlash FaultAtWordWrite 999999
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08081010    0x11111111    0x22222222
    ${sr}=          Execute Command    sysbus ReadDoubleWord 0x40022010
    ${uncorr}=      Read Normalized Bool    faultFlash IsAddressUncorrectable 0x08081010
    ${writes}=      Execute Command    faultFlash TotalWordWrites
    Should Be Equal As Numbers    ${sr}        0x00000008
    Should Be Equal    ${uncorr}    true
    Should Be Equal As Numbers    ${writes}    1

Defect 9 STM32L4 TornWordMode Setter Clears Uncorrectable Flag Across PerCut Mix
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    2    2
    Execute Command    faultFlash TornWordMode "uncorrectable"
    Execute Command    faultFlash FaultAtWordWrite 1
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08081010    0x00000000    0x00000000
    ${cut1_marked}=    Read Normalized Bool    faultFlash LastFaultMarkedUncorrectable
    Should Be Equal    ${cut1_marked}    true

    Execute Command    faultFlash ClearUncorrectableWords
    Execute Command    faultFlash FaultFired false
    Execute Command    faultFlash TornWordMode "partial_bits"
    Execute Command    faultFlash TornWordSeed 7
    Execute Command    faultFlash FaultAtWordWrite 2
    Program STM32L4 DoubleWord Via CPU    0x08081018    0x00000000    0x00000000
    ${cut2_marked}=    Read Normalized Bool    faultFlash LastFaultMarkedUncorrectable
    ${cut2_uncorr}=    Read Normalized Bool    faultFlash IsAddressUncorrectable 0x08081018
    Should Be Equal    ${cut2_marked}    false
    Should Be Equal    ${cut2_uncorr}    false

Defect 10 STM32F103 Flash Interrupt Is Wired To NVIC IRQ 4
    Create STM32F1 Machine
    Unlock STM32F1 Flash
    Erase STM32F1 Page    0x08001000
    Execute Command    sysbus WriteDoubleWord 0x4002200C 0x00000020
    Execute Command    sysbus WriteDoubleWord 0xE000E280 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x00001001
    Program STM32F1 HalfWord Via CPU    0x08001000    0x1234
    ${ispr0}=       Execute Command    sysbus ReadDoubleWord 0xE000E200
    ${irq_bits}=    Evaluate    int(${ispr0}) & 0x18
    Should Be Equal As Numbers    ${irq_bits}    0x10

Defect 11 STM32L4 Second Word Outside DoubleWord Sets PGAERR Not PGSERR
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Write STM32 Word Via CPU    0x08001000    0x11223344    0x20018000
    Write STM32 Word Via CPU    0x08001008    0x55667788    0x20018000
    ${sr}=    Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${sr}    0x00000020

Defect 12 STM32L4 EOP Is Set Only When EOPIE Is Enabled
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Erase STM32L4 Page    1    2
    ${sr_erase_no_eopie}=    Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${sr_erase_no_eopie}    0x00000000

    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08001000    0x44332211    0x88776655
    ${sr_prog_no_eopie}=     Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${sr_prog_no_eopie}     0x00000000

    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01000001
    Program STM32L4 DoubleWord Via CPU    0x08001008    0xAABBCCDD    0xEEFF0011
    ${sr_prog_with_eopie}=   Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${sr_prog_with_eopie}   0x00000001

Defect 13 STM32L4 ECCR Address Latches While ECCC Or ECCD Set And Correctable Words Clear
    Create STM32L4 Machine
    Install STM32L4 Fault Vectors
    Unlock STM32L4 Flash
    Erase STM32L4 Page    1    2
    Erase STM32L4 Page    2    2

    Execute Command    faultFlash MarkWordCorrectable 0x1020
    Execute Command    faultFlash MarkWordUncorrectable 0x81010
    Read Word Via CPU    0x08001020
    ${eccr1}=    Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr1}    0x40001020

    # Reading Bank 2 uncorrectable word while ECCC=1 must set ECCD without changing ADDR_ECC/BK_ECC.
    Read Word Via CPU    0x08081010
    ${eccr2}=    Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr2}    0xC0001020

    # ClearUncorrectableWords also clears correctableWords.
    Execute Command    faultFlash ClearUncorrectableWords
    Execute Command    sysbus WriteDoubleWord 0x40022018 0xC0000000
    Read Word Via CPU    0x08001020
    ${eccr_after_clear}=    Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr_after_clear}    0x00000000

    # Programming and erasing also clear correctableWords.
    Execute Command    faultFlash MarkWordCorrectable 0x1020
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000001
    Program STM32L4 DoubleWord Via CPU    0x08001020    0x11111111    0x22222222
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x00000000
    Read Word Via CPU    0x08001020
    ${eccr_after_prog}=     Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr_after_prog}     0x00000000

    Execute Command    faultFlash MarkWordCorrectable 0x1028
    Erase STM32L4 Page    1    2
    Read Word Via CPU    0x08001028
    ${eccr_after_erase}=    Execute Command    sysbus ReadDoubleWord 0x40022018
    Should Be Equal As Numbers    ${eccr_after_erase}    0x00000000

Defect 14 STM32L4 Fast Row PROGERR Does Not Count Word Or Set End Of Row EOP
    Create STM32L4 Machine
    Unlock STM32L4 Flash
    Erase STM32L4 Page    2    1
    Execute Command    sysbus WriteDoubleWord 0x080808F8 0x12345678
    Execute Command    faultFlash InvalidateShadow
    Execute Command    faultFlash TotalWordWrites 0
    Execute Command    sysbus WriteDoubleWord 0x40022010 0x0000C3FB
    Execute Command    sysbus WriteDoubleWord 0x40022014 0x01040000
    Execute Command    sysbus WriteDoubleWord 0x20000080 0x49054804
    Execute Command    sysbus WriteDoubleWord 0x20000084 0xC0022240
    Execute Command    sysbus WriteDoubleWord 0x20000088 0x3A013101
    Execute Command    sysbus WriteDoubleWord 0x2000008C 0xE7FED1FB
    Execute Command    sysbus WriteDoubleWord 0x20000094 0x08080800
    Execute Command    sysbus WriteDoubleWord 0x20000098 0xA5A50000
    Execute Command    cpu Reset
    Execute Command    cpu SP 0x20018000
    Execute Command    cpu PC 0x20000081
    Execute Command    emulation RunFor "10us"
    ${fst_err_writes}=    Execute Command    faultFlash TotalWordWrites
    ${fst_err_sr}=        Execute Command    sysbus ReadDoubleWord 0x40022010
    Should Be Equal As Numbers    ${fst_err_writes}    31
    Should Be Equal As Numbers    ${fst_err_sr}        0x00000208

Defect 15 STM32F103 And STM32L476 Platform SRAM Sizes And SRAM2 Alias Match Silicon
    Create STM32F1 Machine
    ${f1_sram}=      Execute Command    sram Size
    Should Be Equal As Numbers    ${f1_sram}    0x5000

    Create STM32L4 Machine
    ${l4_sram1}=     Execute Command    sram Size
    ${l4_sram2}=     Execute Command    sram2 Size
    Should Be Equal As Numbers    ${l4_sram1}    0x18000
    Should Be Equal As Numbers    ${l4_sram2}    0x8000
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xA55A1234
    ${alias_val}=    Execute Command    sysbus ReadDoubleWord 0x20018000
    Should Be Equal As Numbers    ${alias_val}    0xA55A1234
