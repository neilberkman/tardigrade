*** Settings ***
Library    String

*** Variables ***
${ROOT}    ${CURDIR}/..

*** Keywords ***
Load MRAM Peripherals
    Execute Command    include "${ROOT}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${ROOT}/peripherals/FlashTiming.cs"
    Execute Command    include "${ROOT}/peripherals/FaultTracker.cs"
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/MappedMRAMTracker.cs"

Read Normalized Bool
    [Arguments]    ${command}
    ${raw}=        Execute Command    ${command}
    ${text}=       Convert To String    ${raw}
    ${text}=       Strip String    ${text}
    ${text}=       Convert To Lower Case    ${text}
    RETURN    ${text}

*** Test Cases ***
NVMemory Uncorrectable Cut Marks Word Raises Bus Error On CPU Read And Clears On Program Or Erase
    Load MRAM Peripherals
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_mram.repl
    # Pre-populate word 0 (0x10100000..0x10100007) before arming the power_loss cut.
    Execute Command    mram ProgramAddressBase 0x10100000
    Execute Command    sysbus WriteQuadWord 0x10100000 0x1122334455667788
    Execute Command    mram MramTornWordMode "uncorrectable"
    Execute Command    mram WriteFaultMode 0
    Execute Command    mram TotalWordWrites 0
    Execute Command    mram FaultAtWordWrite 1
    # Trigger power_loss cut mid-program on word 0.
    Execute Command    sysbus WriteQuadWord 0x10100000 0xAABBCCDDEEFF0011

    ${marked_flag}=    Read Normalized Bool    mram LastFaultMarkedUncorrectable
    ${marked_cnt}=     Execute Command    mram UncorrectableWordCount
    ${is_marked}=      Read Normalized Bool    mram IsWordUncorrectable 0
    ${is_addr_marked}=    Read Normalized Bool    mram IsAddressUncorrectable 0x10100004
    ${fault_snap_words}=    Execute Command    mram FaultUncorrectableWordsToString
    Should Be Equal As Strings    ${marked_flag}    true
    Should Be Equal As Numbers    ${marked_cnt}    1
    Should Be Equal As Strings    ${is_marked}    true
    Should Be Equal As Strings    ${is_addr_marked}    true
    Should Contain    ${fault_snap_words}    0:0x10100000

    # Tooling reads return stored (untouched) bytes without raising or counting as CPU reads.
    ${tool_lo}=        Execute Command    sysbus ReadDoubleWord 0x10100000
    ${tool_hi}=        Execute Command    sysbus ReadDoubleWord 0x10100004
    ${tool_reads}=     Execute Command    mram UncorrectableReadCount
    Should Be Equal As Numbers    ${tool_lo}    0x55667788
    Should Be Equal As Numbers    ${tool_hi}    0x11223344
    Should Be Equal As Numbers    ${tool_reads}    0

    # Load a minimal Cortex-M0+ program in boot ROM that reads 0x10100004 (inside marked word 0):
    #   Reset_Handler @ 0x10000040: ldr r0, [pc, #12] (0x10100004); ldr r1, [r0]; dsb; isb;
    #                               ldr r2, [pc, #12] (0x20000100); movs r3, #1; str r3, [r2]; b .
    #   HardFault_Handler @ 0x10000060: ldr r2, [pc, #8] (0x20000100); ldr r3, [pc, #8] (0xFA017003); str r3, [r2]; b .
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x10000000, 0x20002000); b.WriteDoubleWord(0x10000004, 0x10000041); b.WriteDoubleWord(0x10000008, 0x10000061); b.WriteDoubleWord(0x1000000C, 0x10000061); b.WriteDoubleWord(0x00000000, 0x20002000); b.WriteDoubleWord(0x00000004, 0x10000041); b.WriteDoubleWord(0x00000008, 0x10000061); b.WriteDoubleWord(0x0000000C, 0x10000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x0004),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(0x10000000+o, v) for o,v in code]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x10000041
    Execute Command    emulation RunFor "0.005"

    ${res_fault}=      Execute Command    sysbus ReadDoubleWord 0x20000100
    ${ipsr_fault}=     Execute Command    python "print(int(monitor.Machine['sysbus.cpu'].XProgramStatusRegister) & 0x1FF)"
    ${cpu_reads}=      Execute Command    mram UncorrectableReadCount
    ${read_word_addr}=    Execute Command    mram LastUncorrectableReadWordAddress
    Should Be Equal As Numbers    ${res_fault}    0xFA017003
    Should Be Equal As Numbers    ${ipsr_fault}    3
    Should Be Equal As Numbers    ${cpu_reads}    1
    Should Be Equal As Numbers    ${read_word_addr}    0x10100000

    # Programming the word clears the mark, and a subsequent CPU read succeeds without faulting.
    Execute Command    mram FaultAtWordWrite 0x7FFFFFFF
    Execute Command    sysbus WriteQuadWord 0x10100000 0xDEADBEEFCAFEBABE
    ${after_prog_cnt}=    Execute Command    mram UncorrectableWordCount
    ${after_prog_mk}=     Read Normalized Bool    mram IsWordUncorrectable 0
    Should Be Equal As Numbers    ${after_prog_cnt}    0
    Should Be Equal As Strings    ${after_prog_mk}    false

    Execute Command    machine Reset
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x10000000, 0x20002000); b.WriteDoubleWord(0x10000004, 0x10000041); b.WriteDoubleWord(0x10000008, 0x10000061); b.WriteDoubleWord(0x1000000C, 0x10000061); b.WriteDoubleWord(0x00000000, 0x20002000); b.WriteDoubleWord(0x00000004, 0x10000041); b.WriteDoubleWord(0x00000008, 0x10000061); b.WriteDoubleWord(0x0000000C, 0x10000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x0004),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(0x10000000+o, v) for o,v in code]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x10000041
    Execute Command    emulation RunFor "0.005"
    ${res_ok}=         Execute Command    sysbus ReadDoubleWord 0x20000100
    Should Be Equal As Numbers    ${res_ok}    1

    # Erasing the word (or sector) also clears the mark.
    Execute Command    mram MarkWordUncorrectable 0
    ${re_marked}=      Execute Command    mram UncorrectableWordCount
    Should Be Equal As Numbers    ${re_marked}    1
    Execute Command    mram EraseSector 0 0x1000
    ${after_erase}=    Execute Command    mram UncorrectableWordCount
    Should Be Equal As Numbers    ${after_erase}    0

MappedMRAMTracker Uncorrectable Cut Marks Word Raises Bus Error On CPU Read And Clears On Program Or Erase
    Load MRAM Peripherals
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_self_update.repl
    Execute Command    mramTracker ProgramAddressBase 0x10100000
    Execute Command    sysbus WriteQuadWord 0x10100000 0x1122334455667788
    Execute Command    sysbus WriteQuadWord 0x10100008 0x99AABBCCDDEEFF00
    Execute Command    mramTracker InvalidateShadow
    Execute Command    mramTracker MramTornWordMode "uncorrectable"
    Execute Command    mramTracker WriteFaultMode 0
    Execute Command    mramTracker TotalWordWrites 0
    Execute Command    mramTracker FaultAtWordWrite 1

    # CPU program writes 0x10100000 -> triggers power_loss cut at write 1, then loops.
    #   Reset @ 0x00000040: ldr r0, [pc, #4] (0x10100000); ldr r1, [pc, #8] (0xDEADBEEF); str r1, [r0]; b .
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x00000041); b.WriteDoubleWord(0xC, 0x00000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4801),(0x42,0x4902),(0x44,0x6001),(0x46,0xE7FE),(0x48,0x0000),(0x4A,0x1010),(0x4C,0xBEEF),(0x4E,0xDEAD)]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x00000041
    Execute Command    emulation RunFor "0.005"

    ${fired}=          Read Normalized Bool    mramTracker FaultEverFired
    ${marked_flag}=    Read Normalized Bool    mramTracker LastFaultMarkedUncorrectable
    ${marked_cnt}=     Execute Command    mramTracker UncorrectableWordCount
    ${is_marked}=      Read Normalized Bool    mramTracker IsWordUncorrectable 0
    ${fault_snap_words}=    Execute Command    mramTracker FaultUncorrectableWordsToString
    Should Be Equal As Strings    ${fired}    true
    Should Be Equal As Strings    ${marked_flag}    true
    Should Be Equal As Numbers    ${marked_cnt}    1
    Should Be Equal As Strings    ${is_marked}    true
    Should Contain    ${fault_snap_words}    0:0x10100000

    # Tooling reads return stored (untouched) bytes and do not raise or increment CPU read count.
    ${tool_lo}=        Execute Command    sysbus ReadDoubleWord 0x10100000
    ${tool_hi}=        Execute Command    sysbus ReadDoubleWord 0x1010000C
    ${tool_reads}=     Execute Command    mramTracker UncorrectableReadCount
    Should Be Equal As Numbers    ${tool_lo}    0x55667788
    Should Be Equal As Numbers    ${tool_hi}    0x99AABBCC
    Should Be Equal As Numbers    ${tool_reads}    0

    # Recovery boot: CPU reads 0x1010000C (inside 16-byte marked word 0) -> enters HardFault_Handler.
    Execute Command    mramTracker FaultAtWordWrite 0x7FFFFFFF
    Execute Command    machine Reset
    Execute Command    mramTracker ClearUncorrectableReadLog
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x00000041); b.WriteDoubleWord(0x8, 0x00000061); b.WriteDoubleWord(0xC, 0x00000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x000C),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x00000041
    Execute Command    emulation RunFor "0.005"

    ${res_fault}=      Execute Command    sysbus ReadDoubleWord 0x20000100
    ${ipsr_fault}=     Execute Command    python "print(int(monitor.Machine['sysbus.cpu'].XProgramStatusRegister) & 0x1FF)"
    ${cpu_reads}=      Execute Command    mramTracker UncorrectableReadCount
    ${read_word_addr}=    Execute Command    mramTracker LastUncorrectableReadWordAddress
    Should Be Equal As Numbers    ${res_fault}    0xFA017003
    Should Be Equal As Numbers    ${ipsr_fault}    3
    Should Be Equal As Numbers    ${cpu_reads}    1
    Should Be Equal As Numbers    ${read_word_addr}    0x10100000

    # Re-programming word 0 clears the mark; erasing also clears the mark.
    Execute Command    mramTracker WriteDoubleWord 0 0xCAFEBABE
    ${cleared_prog}=   Execute Command    mramTracker UncorrectableWordCount
    Should Be Equal As Numbers    ${cleared_prog}    0
    Execute Command    mramTracker MarkWordUncorrectable 0
    Execute Command    mramTracker EraseWord 0
    ${cleared_erase}=    Execute Command    mramTracker UncorrectableWordCount
    Should Be Equal As Numbers    ${cleared_erase}    0

    # Subsequent CPU read succeeds cleanly without faulting.
    Execute Command    machine Reset
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x00000041); b.WriteDoubleWord(0x8, 0x00000061); b.WriteDoubleWord(0xC, 0x00000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x000C),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x00000041
    Execute Command    emulation RunFor "0.005"
    ${res_ok}=         Execute Command    sysbus ReadDoubleWord 0x20000100
    Should Be Equal As Numbers    ${res_ok}    1

MRAM Corrupted Mode Matches Deterministically Across NVMemory And MappedMRAMTracker
    Load MRAM Peripherals
    # 1. NVMemory corrupted mode with 16-byte word and explicit seed.
    Execute Command    mach create "nvm_corrupt"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_mram.repl
    Execute Command    mram WordSize 16
    Execute Command    mram ProgramAddressBase 0x10100000
    Execute Command    mram MramTornWordMode "corrupted"
    Execute Command    mram MramTornWordSeed 305419896
    Execute Command    mram WriteFaultMode 0
    Execute Command    mram TotalWordWrites 0
    Execute Command    mram FaultAtWordWrite 1
    Execute Command    python "from System import Array,Byte; m=monitor.Machine['sysbus.mram']; m.WriteBytes(0, Array[Byte]([0xA5]*16), 0, 16)"
    ${nvm_hex}=        Execute Command    python "m=monitor.Machine['sysbus.mram']; print(''.join('%02x' % b for b in m.LastFaultPostFaultBytes))"
    ${nvm_uncorr}=     Execute Command    mram UncorrectableWordCount
    Should Be Equal As Numbers    ${nvm_uncorr}    0
    Should Not Be Equal As Strings    ${nvm_hex}    a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5

    # 2. MappedMRAMTracker corrupted mode with identical 16-byte word and seed.
    Execute Command    mach create "mapped_corrupt"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_self_update.repl
    Execute Command    mramTracker ProgramAddressBase 0x10100000
    Execute Command    python "from System import Array,Byte; b=monitor.Machine['sysbus.mramStorage']; b.WriteBytes(0, Array[Byte]([0xA5]*16), 0, 16)"
    Execute Command    sysbus WriteDoubleWord 0x10100000 0xA5A5A5A5
    Execute Command    mramTracker InvalidateShadow
    Execute Command    mramTracker MramTornWordMode "corrupted"
    Execute Command    mramTracker MramTornWordSeed 305419896
    Execute Command    mramTracker WriteFaultMode 0
    Execute Command    mramTracker TotalWordWrites 0
    Execute Command    mramTracker FaultAtWordWrite 1
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x00000041)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4801),(0x42,0x4902),(0x44,0x6001),(0x46,0xE7FE),(0x48,0x0000),(0x4A,0x1010),(0x4C,0xA5A5),(0x4E,0xA5A5)]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x00000041
    Execute Command    emulation RunFor "0.005"
    ${mapped_hex}=     Execute Command    python "m=monitor.Machine['sysbus.mramTracker']; print(''.join('%02x' % b for b in m.LastFaultPostFaultBytes))"
    ${mapped_uncorr}=    Execute Command    mramTracker UncorrectableWordCount
    Should Be Equal As Numbers    ${mapped_uncorr}    0
    Should Be Equal As Strings    ${mapped_hex}    ${nvm_hex}

NVMemory Cortex-M4 Routes Uncorrectable CPU Read To BusFault When Enabled
    Load MRAM Peripherals
    Execute Command    mach create "nvm_m4_bf"
    Execute Command    machine LoadPlatformDescriptionFromString 'cpu: CPU.CortexM @ sysbus { cpuType: "cortex-m4"; nvic: nvic }; nvic: IRQControllers.NVIC @ sysbus 0xE000E000 { -> cpu@0 }; boot: Memory.MappedMemory @ sysbus 0x00000000 { size: 0x1000 }; mram: Memory.NVMemory @ sysbus 0x10100000 { Size: 0x1000; WordSize: 8 }; sram: Memory.MappedMemory @ sysbus 0x20000000 { size: 0x2000 }'
    Execute Command    mram ProgramAddressBase 0x10100000
    Execute Command    mram MramTornWordMode "uncorrectable"
    Execute Command    mram FaultAtWordWrite 1
    Execute Command    sysbus WriteQuadWord 0x10100000 0xAABBCCDDEEFF0011
    Execute Command    mram FaultAtWordWrite 0x7FFFFFFF
    # Enable SHCSR.BUSFAULTENA (bit 17 = 0x20000).
    Execute Command    sysbus WriteDoubleWord 0xE000ED24 0x00020000
    # Vector table: Reset @ 0x41, HardFault @ 0x61 (0xFA017003), BusFault @ 0x81 (0xFA017005).
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x00000041); b.WriteDoubleWord(0xC, 0x00000061); b.WriteDoubleWord(0x14, 0x00000081)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x0000),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01),(0x80,0x4A02),(0x82,0x4B03),(0x84,0x6013),(0x86,0xE7FE),(0x88,0xBF00),(0x8A,0xBF00),(0x8C,0x0100),(0x8E,0x2000),(0x90,0x7005),(0x92,0xFA01)]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x00000041
    Execute Command    emulation RunFor "0.005"

    ${res_bf}=         Execute Command    sysbus ReadDoubleWord 0x20000100
    ${ipsr_bf}=        Execute Command    python "print(int(monitor.Machine['sysbus.cpu'].XProgramStatusRegister) & 0x1FF)"
    ${cfsr_bf}=        Execute Command    sysbus ReadDoubleWord 0xE000ED28
    Should Be Equal As Numbers    ${res_bf}    0xFA017005
    Should Be Equal As Numbers    ${ipsr_bf}    5
    Should Be Equal As Numbers    ${cfsr_bf}    0x00000200

MRAM Trace Replay Uncorrectable Cut Marks Word Raises Bus Error On CPU Read And Clears On Program Or Erase
    Load MRAM Peripherals
    Execute Command    mach create "mram_replay_uncorr"
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/cortex_m0_mram.repl
    Execute Command    mram ProgramAddressBase 0x10100000
    Execute Command    mram MramTornWordMode "uncorrectable"
    # Replay a 2-write MRAM trace cut at write 2 (offset 8) using the runner's exact replay logic.
    Execute Command    python "import ast; src=open(r'${ROOT}/scripts/run_runtime_fault_sweep.py').read(); tree=ast.parse(src); wanted={'_corrupt_mram_torn_bytes','_trace_replay_mram_torn_value'}; ns={}; exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted]), 'rr', 'exec'), ns, ns); from System import Array, Byte; m=monitor.Machine['sysbus.mram']; img=bytearray(int(m.Size)); img[0:8]=bytearray([0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88]); img[8:16]=bytearray([0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11]); prev=int(0x1122334455667788); torn=ns['_trace_replay_mram_torn_value'](0xAABBCCDDEEFF0011, 8, 0xFF, 'uncorrectable', prev); img[8:16]=bytearray([(torn>>(8*i))&0xFF for i in range(8)]); m.WriteBytes(0, Array[Byte](list(img)), 0, len(img)); m.MarkWordUncorrectable(8)"

    ${marked_cnt}=     Execute Command    mram UncorrectableWordCount
    ${is_marked}=      Read Normalized Bool    mram IsWordUncorrectable 8
    ${is_w0_marked}=   Read Normalized Bool    mram IsWordUncorrectable 0
    Should Be Equal As Numbers    ${marked_cnt}    1
    Should Be Equal As Strings    ${is_marked}    true
    Should Be Equal As Strings    ${is_w0_marked}    false

    # Tooling read returns stored pre-program bytes without raising or counting as CPU read.
    ${tool_lo}=        Execute Command    sysbus ReadDoubleWord 0x10100008
    ${tool_hi}=        Execute Command    sysbus ReadDoubleWord 0x1010000C
    ${tool_reads}=     Execute Command    mram UncorrectableReadCount
    Should Be Equal As Numbers    ${tool_lo}    0x55667788
    Should Be Equal As Numbers    ${tool_hi}    0x11223344
    Should Be Equal As Numbers    ${tool_reads}    0

    # CPU recovery read of 0x10100008 raises HardFault on Cortex-M0+.
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x10000000, 0x20002000); b.WriteDoubleWord(0x10000004, 0x10000041); b.WriteDoubleWord(0x10000008, 0x10000061); b.WriteDoubleWord(0x1000000C, 0x10000061); b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x10000041); b.WriteDoubleWord(0x8, 0x10000061); b.WriteDoubleWord(0xC, 0x10000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x0008),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(0x10000000+o, v) for o,v in code]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x10000041
    Execute Command    emulation RunFor "0.005"

    ${res_fault}=      Execute Command    sysbus ReadDoubleWord 0x20000100
    ${ipsr_fault}=     Execute Command    python "print(int(monitor.Machine['sysbus.cpu'].XProgramStatusRegister) & 0x1FF)"
    ${cpu_reads}=      Execute Command    mram UncorrectableReadCount
    ${read_word_addr}=    Execute Command    mram LastUncorrectableReadWordAddress
    Should Be Equal As Numbers    ${res_fault}    0xFA017003
    Should Be Equal As Numbers    ${ipsr_fault}    3
    Should Be Equal As Numbers    ${cpu_reads}    1
    Should Be Equal As Numbers    ${read_word_addr}    0x10100008

    # Programming word at offset 8 clears the mark, and a subsequent CPU read succeeds; EraseWord also clears.
    Execute Command    sysbus WriteQuadWord 0x10100008 0xDEADBEEFCAFEBABE
    ${after_prog}=     Execute Command    mram UncorrectableWordCount
    Should Be Equal As Numbers    ${after_prog}    0
    Execute Command    machine Reset
    Execute Command    python "b=monitor.Machine.SystemBus; b.WriteDoubleWord(0x10000000, 0x20002000); b.WriteDoubleWord(0x10000004, 0x10000041); b.WriteDoubleWord(0x10000008, 0x10000061); b.WriteDoubleWord(0x1000000C, 0x10000061); b.WriteDoubleWord(0x0, 0x20002000); b.WriteDoubleWord(0x4, 0x10000041); b.WriteDoubleWord(0x8, 0x10000061); b.WriteDoubleWord(0xC, 0x10000061)"
    Execute Command    python "b=monitor.Machine.SystemBus; code=[(0x40,0x4804),(0x42,0x6801),(0x44,0xF3BF),(0x46,0x8F4F),(0x48,0xF3BF),(0x4A,0x8F6F),(0x4C,0x4A02),(0x4E,0x2301),(0x50,0x6013),(0x52,0xE7FE),(0x54,0x0008),(0x56,0x1010),(0x58,0x0100),(0x5A,0x2000),(0x60,0x4A02),(0x62,0x4B03),(0x64,0x6013),(0x66,0xE7FE),(0x68,0xBF00),(0x6A,0xBF00),(0x6C,0x0100),(0x6E,0x2000),(0x70,0x7003),(0x72,0xFA01)]; [b.WriteWord(0x10000000+o, v) for o,v in code]; [b.WriteWord(o, v) for o,v in code]"
    Execute Command    cpu SP 0x20002000
    Execute Command    cpu PC 0x10000041
    Execute Command    emulation RunFor "0.005"
    ${res_ok}=         Execute Command    sysbus ReadDoubleWord 0x20000100
    Should Be Equal As Numbers    ${res_ok}    1
    Execute Command    mram MarkWordUncorrectable 8
    Execute Command    mram EraseWord 8
    ${after_erase}=    Execute Command    mram UncorrectableWordCount
    Should Be Equal As Numbers    ${after_erase}    0
