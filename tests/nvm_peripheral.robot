*** Keywords ***
Create NVM Machine
    Execute Command    include "${CURDIR}/../peripherals/NVMemoryController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../platforms/cortex_m0_nvm.repl

Create Flash Machine
    Execute Command    include "${CURDIR}/../peripherals/NVMemoryController.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../platforms/cortex_m0_nvm_flash.repl

*** Test Cases ***
NVM Persists Across Reset
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    Execute Command    nvm Reset
    ${read_back}=      Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${read_back}    0xAABBCCDD

NVM Write Requires Erase First
    Create NVM Machine
    Execute Command    sysbus WriteQuadWord 0x10000000 0xFFEEDDCCBBAA9988
    Execute Command    sysbus WriteDoubleWord 0x10000004 0x11223344
    ${word}=           Execute Command    sysbus ReadQuadWord 0x10000000
    Should Be Equal As Numbers    ${word}    0x11223344BBAA9988

NVM Partial Write Leaves Corruption
    Create NVM Machine
    Execute Command    sysbus WriteQuadWord 0x10000000 0xA1A2A3A4A5A6A7A8
    Execute Command    nvm_ctrl InjectPartialWrite 0x10000000
    ${word}=           Execute Command    sysbus ReadQuadWord 0x10000000
    Should Not Be Equal As Numbers    ${word}    0xA1A2A3A4A5A6A7A8

NV Read Port Returns Same Data
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000020 0xDEADBEEF
    ${alias}=          Execute Command    sysbus ReadDoubleWord 0x10080020
    Should Be Equal As Numbers    ${alias}    0xDEADBEEF

NV Read Alias Drops Writes
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000040 0x12345678
    Execute Command    sysbus WriteDoubleWord 0x10080040 0xFFFFFFFF
    ${original}=       Execute Command    sysbus ReadDoubleWord 0x10000040
    Should Be Equal As Numbers    ${original}    0x12345678
    ${alias}=          Execute Command    sysbus ReadDoubleWord 0x10080040
    Should Be Equal As Numbers    ${alias}    0x12345678

Flash Sector Erase
    Create Flash Machine
    # Write known data across the first sector (0x1000 bytes)
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xDEADBEEF
    Execute Command    sysbus WriteDoubleWord 0x10000100 0xCAFEBABE
    Execute Command    sysbus WriteDoubleWord 0x10000FFC 0x12345678
    # Erase the sector via controller
    Execute Command    nvm_ctrl EraseSector 0x10000000
    # Entire sector should read as 0xFF (flash erase fill)
    ${word0}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${word0}    0xFFFFFFFF
    ${word1}=          Execute Command    sysbus ReadDoubleWord 0x10000100
    Should Be Equal As Numbers    ${word1}    0xFFFFFFFF
    ${word2}=          Execute Command    sysbus ReadDoubleWord 0x10000FFC
    Should Be Equal As Numbers    ${word2}    0xFFFFFFFF

Flash Partial Erase
    Create Flash Machine
    # Fill first sector with known pattern
    Execute Command    sysbus WriteDoubleWord 0x10000000 0x11111111
    Execute Command    sysbus WriteDoubleWord 0x10000800 0x22222222
    Execute Command    sysbus WriteDoubleWord 0x10000FFC 0x33333333
    # Inject partial erase — first half erased, second half retained
    Execute Command    nvm_ctrl InjectPartialErase 0x10000000
    # First half of sector (offset 0x000) should be 0xFF
    ${first_half}=     Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${first_half}    0xFFFFFFFF
    # Second half of sector (offset 0x800) should retain original data
    ${second_half}=    Execute Command    sysbus ReadDoubleWord 0x10000800
    Should Be Equal As Numbers    ${second_half}    0x22222222
    # Last word of sector should also retain original data
    ${last_word}=      Execute Command    sysbus ReadDoubleWord 0x10000FFC
    Should Be Equal As Numbers    ${last_word}    0x33333333

Flash Erase Fill
    Create Flash Machine
    # Fresh flash memory should read as 0xFF without any writes
    ${fresh}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${fresh}    0xFFFFFFFF
    ${fresh2}=         Execute Command    sysbus ReadDoubleWord 0x10001000
    Should Be Equal As Numbers    ${fresh2}    0xFFFFFFFF

Flash Partial Write Uses EraseFill
    Create Flash Machine
    # Write known data (4-byte word on flash)
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    # Inject partial write — second half of the 4-byte word should become 0xFF
    Execute Command    nvm_ctrl InjectPartialWrite 0x10000000
    ${word}=           Execute Command    sysbus ReadDoubleWord 0x10000000
    # First 2 bytes preserved (0xCCDD), last 2 bytes erased to 0xFFFF
    Should Be Equal As Numbers    ${word}    0xFFFFCCDD

Read Fault Corrupts First Read
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    # Arm read fault at NVM offset 0, seed 3 => flip bit 0 => 0xAABBCCDC
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultEnabled true
    ${corrupted}=      Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${corrupted}    0xAABBCCDC

Read Fault Is One Shot
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultEnabled true
    # First read fires the fault
    Execute Command    sysbus ReadDoubleWord 0x10000000
    ${fired}=          Execute Command    nvm ReadFaultFired
    Should Be Equal As Strings    ${fired}    True
    # Second read returns correct data
    ${clean}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${clean}    0xAABBCCDD

Read Fault Does Not Modify Storage
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xDEADBEEF
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultEnabled true
    # Trigger the fault via read
    ${corrupted}=      Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Not Be Equal As Numbers    ${corrupted}    0xDEADBEEF
    # Re-arm by clearing the fired flag — but read the ALIAS port which
    # delegates to the same NVM without going through ApplyReadFault on the
    # alias (alias ReadDoubleWord delegates to target which WILL apply fault).
    # Instead, just verify: after fault fired, storage is correct on next read.
    ${clean}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${clean}    0xDEADBEEF

Read Fault Disabled By Default
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    # Set address and seed but do NOT enable
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    ${clean}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${clean}    0xAABBCCDD
    # Confirm fault did not fire
    ${fired}=          Execute Command    nvm ReadFaultFired
    Should Be Equal As Strings    ${fired}    False

Read Fault Only At Armed Address
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    Execute Command    sysbus WriteDoubleWord 0x10000100 0x11223344
    # Arm at offset 0x100 (sysbus 0x10000100)
    Execute Command    nvm ReadFaultAddress 0x100
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultEnabled true
    # Read at offset 0 — should be clean (not armed)
    ${clean}=          Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${clean}    0xAABBCCDD
    # Fault should not have fired yet
    ${fired}=          Execute Command    nvm ReadFaultFired
    Should Be Equal As Strings    ${fired}    False
    # Read at armed offset 0x100 — should be corrupted
    ${corrupted}=      Execute Command    sysbus ReadDoubleWord 0x10000100
    Should Not Be Equal As Numbers    ${corrupted}    0x11223344

Read Fault Skip Count
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultSkipCount 2
    Execute Command    nvm ReadFaultEnabled true
    # First two reads of armed address are clean (skip count = 2)
    ${r1}=             Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${r1}    0xAABBCCDD
    ${r2}=             Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${r2}    0xAABBCCDD
    # Third read fires the fault
    ${r3}=             Execute Command    sysbus ReadDoubleWord 0x10000000
    Should Be Equal As Numbers    ${r3}    0xAABBCCDC

Read Fault Total Reads Counter
    Create NVM Machine
    Execute Command    sysbus WriteDoubleWord 0x10000000 0xAABBCCDD
    Execute Command    nvm ReadFaultAddress 0
    Execute Command    nvm ReadFaultSeed 3
    Execute Command    nvm ReadFaultSkipCount 100
    Execute Command    nvm ReadFaultEnabled true
    # Read the armed address 3 times (none will fire due to high skip count)
    Execute Command    sysbus ReadDoubleWord 0x10000000
    Execute Command    sysbus ReadDoubleWord 0x10000000
    Execute Command    sysbus ReadDoubleWord 0x10000000
    ${total}=          Execute Command    nvm ReadFaultTotalReads
    Should Be Equal As Numbers    ${total}    3
