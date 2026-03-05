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
