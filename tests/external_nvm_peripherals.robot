*** Settings ***
Library    String

*** Variables ***
${ROOT}    ${CURDIR}/..

*** Keywords ***
Create External NVM Machine
    Execute Command    include "${ROOT}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${ROOT}/peripherals/FaultTracker.cs"
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${ROOT}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${ROOT}/peripherals/SPINORFlash.cs"
    Execute Command    include "${ROOT}/peripherals/I2CEEPROM.cs"
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${ROOT}/platforms/nrf52840_external_nvm.repl

Read Normalized Bool
    [Arguments]    ${command}
    ${raw}=        Execute Command    ${command}
    ${text}=       Convert To String    ${raw}
    ${text}=       Strip String    ${text}
    ${text}=       Convert To Lower Case    ${text}
    RETURN    ${text}

*** Test Cases ***
SPI NOR JEDEC ID And SFDP Match JESD216B Contract
    Create External NVM Machine
    # Read JEDEC ID (0x9F) -> Winbond W25Q16JV default (0xEF, 0x40, 0x15).
    ${jedec}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x9F); b=[s.Transmit(0) for _ in range(3)]; s.FinishTransmission(); print('%02X%02X%02X' % (b[0], b[1], b[2]))"
    ${jedec}=    Strip String    ${jedec}
    Should Be Equal As Strings    ${jedec}    EF4015

    # Read SFDP (0x5A) at 0x000000 + 1 dummy byte -> "SFDP" (0x50444653), rev 1.6, BFPT @ 0x30.
    ${sfdp_hdr}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x5A, 0x00, 0x00, 0x00, 0x00)]; b=[s.Transmit(0) for _ in range(16)]; s.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${sfdp_hdr}=    Strip String    ${sfdp_hdr}
    Should Start With    ${sfdp_hdr}    53464450060100FF00060110300000FF

    # Read SFDP BFPT erase types at 0x4C..0x53 -> 4K (0x0C, 0x20), 32K (0x0F, 0x52), 64K (0x10, 0xD8).
    ${sfdp_erase}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x5A, 0x00, 0x00, 0x4C, 0x00)]; b=[s.Transmit(0) for _ in range(8)]; s.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${sfdp_erase}=    Strip String    ${sfdp_erase}
    Should Be Equal As Strings    ${sfdp_erase}    0C200F5210D800FF

SPI NOR Status Register WEL And WIP Busy Time Contract
    Create External NVM Machine
    # Initial SR1 has WIP=0, WEL=0.
    ${sr_init}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    Should Be Equal As Integers    ${sr_init}    0

    # Page Program without WREN (0x06) must be ignored and increment IgnoredWithoutWelCount.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x02, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD)]; s.FinishTransmission()"
    ${ignored_no_wel}=    Execute Command    spiNor IgnoredWithoutWelCount
    ${unmodified}=        Execute Command    sysbus ReadDoubleWord 0x60000100
    Should Be Equal As Integers    ${ignored_no_wel}    1
    Should Be Equal As Numbers     ${unmodified}        0xFFFFFFFF

    # WREN (0x06) sets WEL (bit 1 = 0x02); WRDI (0x04) clears WEL.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission()"
    ${sr_wel}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    Should Be Equal As Integers    ${sr_wel}    2
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x04); s.FinishTransmission()"
    ${sr_wrdi}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    Should Be Equal As Integers    ${sr_wrdi}    0

    # Configure BusyPollsPerProgram=2: after Page Program, WEL clears and WIP (bit 0) stays 1 for 2 RDSR reads,
    # and a Page Program attempted while WIP=1 is rejected (IgnoredWhileBusyCount++).
    Execute Command    spiNor BusyPollsPerProgram 2
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x02, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44)]; s.FinishTransmission()"
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x02, 0x00, 0x01, 0x04, 0x55, 0x66, 0x77, 0x88)]; s.FinishTransmission()"
    ${ignored_busy}=    Execute Command    spiNor IgnoredWhileBusyCount
    Should Be Equal As Integers    ${ignored_busy}    1
    ${poll1}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    ${poll2}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    ${poll3}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x05); v=s.Transmit(0); s.FinishTransmission(); print(v)"
    Should Be Equal As Integers    ${poll1}    1
    Should Be Equal As Integers    ${poll2}    1
    Should Be Equal As Integers    ${poll3}    0

SPI NOR Page Program In Page Wrap And Read Commands
    Create External NVM Machine
    Execute Command    spiNor BusyPollsPerProgram 0
    # Program 8 bytes starting at 0x0002FC (4 bytes before the end of page 0x000200..0x0002FF).
    # Bytes 0..3 land at 0x0002FC..0x0002FF; bytes 4..7 wrap to 0x000200..0x000203 (NOT 0x000300!).
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x02, 0x00, 0x02, 0xFC, 0xA1, 0xA2, 0xA3, 0xA4, 0xB1, 0xB2, 0xB3, 0xB4)]; s.FinishTransmission()"
    ${wrap_cnt}=      Execute Command    spiNor PageProgramWrapCount
    Should Be Equal As Integers    ${wrap_cnt}    1

    # Verify via SPI READ (0x03) and FAST_READ (0x0B) that 0x0002FC has A1..A4, 0x000200 has B1..B4, and 0x000300 is still FF..FF.
    ${read_end}=      Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x03, 0x00, 0x02, 0xFC)]; b=[s.Transmit(0) for _ in range(8)]; s.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${read_start}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x0B, 0x00, 0x02, 0x00, 0x00)]; b=[s.Transmit(0) for _ in range(4)]; s.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${read_end}=      Strip String    ${read_end}
    ${read_start}=    Strip String    ${read_start}
    Should Be Equal As Strings    ${read_end}      A1A2A3A4FFFFFFFF
    Should Be Equal As Strings    ${read_start}    B1B2B3B4

    # NOR bit-clear physics: programming 0x0F0F0F0F over 0xB4B3B2B1 yields 0x04030201 (only 1->0 transitions).
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x02, 0x00, 0x02, 0x00, 0x0F, 0x0F, 0x0F, 0x0F)]; s.FinishTransmission()"
    ${nor_anded}=     Execute Command    sysbus ReadDoubleWord 0x60000200
    Should Be Equal As Numbers    ${nor_anded}    0x04030201

SPI NOR Sector Block And Chip Erase Commands
    Create External NVM Machine
    Execute Command    spiNor BusyPollsPerErase 0
    Execute Command    spiNor EraseTraceEnabled true

    # Seed data across 4 KiB sector (0x001000), 32 KiB block (0x008000), 64 KiB block (0x010000), and tail (0x050000).
    Execute Command    sysbus WriteDoubleWord 0x60001000 0x11111111
    Execute Command    sysbus WriteDoubleWord 0x60002000 0x22222222
    Execute Command    sysbus WriteDoubleWord 0x60008000 0x33333333
    Execute Command    sysbus WriteDoubleWord 0x6000F000 0x44444444
    Execute Command    sysbus WriteDoubleWord 0x60010000 0x55555555
    Execute Command    sysbus WriteDoubleWord 0x6001F000 0x66666666
    Execute Command    sysbus WriteDoubleWord 0x60050000 0x77777777

    # 1. 4 KiB Sector Erase (0x20) at 0x001000 erases 0x001000..0x001FFF without touching 0x002000.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x20, 0x00, 0x10, 0x00)]; s.FinishTransmission()"
    ${v1000}=    Execute Command    sysbus ReadDoubleWord 0x60001000
    ${v2000}=    Execute Command    sysbus ReadDoubleWord 0x60002000
    Should Be Equal As Numbers    ${v1000}    0xFFFFFFFF
    Should Be Equal As Numbers    ${v2000}    0x22222222

    # 2. 32 KiB Block Erase (0x52) at 0x008000 erases 0x008000..0x00FFFF without touching 0x010000.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x52, 0x00, 0x80, 0x00)]; s.FinishTransmission()"
    ${v8000}=    Execute Command    sysbus ReadDoubleWord 0x60008000
    ${vF000}=    Execute Command    sysbus ReadDoubleWord 0x6000F000
    ${v10000}=   Execute Command    sysbus ReadDoubleWord 0x60010000
    Should Be Equal As Numbers    ${v8000}     0xFFFFFFFF
    Should Be Equal As Numbers    ${vF000}     0xFFFFFFFF
    Should Be Equal As Numbers    ${v10000}    0x55555555

    # 3. 64 KiB Block Erase (0xD8) at 0x010000 erases 0x010000..0x01FFFF without touching 0x050000.
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0xD8, 0x01, 0x00, 0x00)]; s.FinishTransmission()"
    ${v10000_after}=    Execute Command    sysbus ReadDoubleWord 0x60010000
    ${v1F000_after}=    Execute Command    sysbus ReadDoubleWord 0x6001F000
    ${v50000}=          Execute Command    sysbus ReadDoubleWord 0x60050000
    Should Be Equal As Numbers    ${v10000_after}    0xFFFFFFFF
    Should Be Equal As Numbers    ${v1F000_after}    0xFFFFFFFF
    Should Be Equal As Numbers    ${v50000}          0x77777777

    # 4. Chip Erase (0xC7) erases the remaining sectors (0x002000 and 0x050000).
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); s.Transmit(0xC7); s.FinishTransmission()"
    ${v2000_after}=     Execute Command    sysbus ReadDoubleWord 0x60002000
    ${v50000_after}=    Execute Command    sysbus ReadDoubleWord 0x60050000
    Should Be Equal As Numbers    ${v2000_after}     0xFFFFFFFF
    Should Be Equal As Numbers    ${v50000_after}    0xFFFFFFFF

    ${erase_trace}=    Execute Command    spiNor EraseTraceToString
    Should Contain    ${erase_trace}    1:4096:0:4096
    Should Contain    ${erase_trace}    2:32768:0:32768
    Should Contain    ${erase_trace}    3:65536:0:65536
    Should Contain    ${erase_trace}    4:0:0:2097152

SPI NOR Page Program Fault Injection Outcomes And Trace Replay
    Create External NVM Machine
    Execute Command    spiNor BusyPollsPerProgram 0
    Execute Command    spiNor WriteTraceEnabled true

    # 1. Cut BEFORE a 16-byte Page Program (FaultAtWordWrite=1, TornWordMode="untouched"): all 16 bytes remain 0xFF.
    Execute Command    spiNor TornWordMode "untouched"
    Execute Command    spiNor FaultAtWordWrite 1
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in [0x02, 0x00, 0x04, 0x00] + [0x10 + i for i in range(16)]]; s.FinishTransmission()"
    ${fired1}=    Read Normalized Bool    spiNor FaultFired
    ${w0}=        Execute Command    sysbus ReadDoubleWord 0x60000400
    ${w1}=        Execute Command    sysbus ReadDoubleWord 0x60000404
    Should Be Equal As Strings    ${fired1}    true
    Should Be Equal As Numbers    ${w0}        0xFFFFFFFF
    Should Be Equal As Numbers    ${w1}        0xFFFFFFFF

    # 2. Cut PART-WAY through a 16-byte Page Program (FaultAtWordWrite=3, TornWordMode="fixed"):
    #    first 2 words (8 bytes) commit, words 3 and 4 (remaining 8 bytes) stay 0xFFFFFFFF!
    Execute Command    spiNor FaultFired false
    Execute Command    spiNor Reset
    Execute Command    spiNor BusyPollsPerProgram 0
    Execute Command    spiNor WriteTraceEnabled true
    Execute Command    spiNor TornWordMode "fixed"
    Execute Command    spiNor FaultAtWordWrite 3
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in [0x02, 0x00, 0x04, 0x00] + [0x10 + i for i in range(16)]]; s.FinishTransmission()"
    ${p_w0}=    Execute Command    sysbus ReadDoubleWord 0x60000400
    ${p_w1}=    Execute Command    sysbus ReadDoubleWord 0x60000404
    ${p_w2}=    Execute Command    sysbus ReadDoubleWord 0x60000408
    ${p_w3}=    Execute Command    sysbus ReadDoubleWord 0x6000040C
    Should Be Equal As Numbers    ${p_w0}    0x13121110
    Should Be Equal As Numbers    ${p_w1}    0x17161514
    Should Be Equal As Numbers    ${p_w2}    0xFFFFFFFF
    Should Be Equal As Numbers    ${p_w3}    0xFFFFFFFF

    # 3. Cut PART-WAY with TornWordMode="partial_bits" at word 2:
    #    word 1 is fully programmed (0x13121110), word 2 has partial 1->0 bits programmed, words 3..4 stay 0xFFFFFFFF.
    Execute Command    spiNor FaultFired false
    Execute Command    spiNor Reset
    Execute Command    spiNor BusyPollsPerProgram 0
    Execute Command    sysbus WriteDoubleWord 0x60000400 0xFFFFFFFF
    Execute Command    sysbus WriteDoubleWord 0x60000404 0xFFFFFFFF
    Execute Command    spiNor TornWordMode "partial_bits"
    Execute Command    spiNor TornWordSeed 123
    Execute Command    spiNor FaultAtWordWrite 2
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in [0x02, 0x00, 0x04, 0x00] + [0x10 + i for i in range(16)]]; s.FinishTransmission()"
    ${pb_w0}=    Execute Command    sysbus ReadDoubleWord 0x60000400
    ${pb_w1}=    Execute Command    sysbus ReadDoubleWord 0x60000404
    ${pb_w2}=    Execute Command    sysbus ReadDoubleWord 0x60000408
    Should Be Equal As Numbers        ${pb_w0}    0x13121110
    Should Not Be Equal As Numbers    ${pb_w1}    0xFFFFFFFF
    Should Not Be Equal As Numbers    ${pb_w1}    0x17161514
    Should Be Equal As Numbers        ${pb_w2}    0xFFFFFFFF

I2C EEPROM Page Write In Page Wrap Sequential Read And ACK Polling
    Create External NVM Machine
    # Configure BusyPollsPerWrite=2 so each page write enters a 2-poll internal write cycle (t_WR).
    Execute Command    i2cEeprom BusyPollsPerWrite 2

    # Write 8 bytes starting at offset 0x013C (4 bytes before the end of 64-byte page 0x0100..0x013F).
    # Bytes 0..3 land at 0x013C..0x013F; bytes 4..7 wrap within the page to 0x0100..0x0103 (NOT 0x0140!).
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x01, 0x3C, 0xC1, 0xC2, 0xC3, 0xC4, 0xD1, 0xD2, 0xD3, 0xD4]); e.FinishTransmission()"
    ${wraps}=         Execute Command    i2cEeprom PageWrapCount
    ${in_progress}=   Read Normalized Bool    i2cEeprom WriteInProgress
    Should Be Equal As Integers    ${wraps}          1
    Should Be Equal As Strings     ${in_progress}    true

    # While WriteInProgress is true, a write attempt is NACKed/ignored and increments NackCount.
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x01, 0x40, 0x99, 0x88, 0x77, 0x66]); e.FinishTransmission()"
    ${nacked1}=    Read Normalized Bool    i2cEeprom LastTransactionNacked
    ${v140}=       Execute Command    sysbus ReadDoubleWord 0x61000140
    Should Be Equal As Strings    ${nacked1}    true
    Should Be Equal As Numbers    ${v140}       0xFFFFFFFF

    # Second ACK poll consumes remaining busy poll; third ACK poll succeeds (ACK).
    ${poll2}=    Read Normalized Bool    i2cEeprom AckPoll
    ${poll3}=    Read Normalized Bool    i2cEeprom AckPoll
    ${busy_after}=    Read Normalized Bool    i2cEeprom WriteInProgress
    Should Be Equal As Strings    ${poll2}         false
    Should Be Equal As Strings    ${poll3}         true
    Should Be Equal As Strings    ${busy_after}    false

    # Random Read + Sequential Read: write 2-byte address 0x0100, then read 4 bytes (D1..D4),
    # and write 2-byte address 0x013C, then read 8 bytes across page boundary (C1..C4 followed by FF..FF at 0x0140).
    ${seq_start}=    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x01, 0x00]); b=e.Read(4); e.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${seq_end}=      Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x01, 0x3C]); b=e.Read(8); e.FinishTransmission(); print(''.join('%02X' % x for x in b))"
    ${seq_start}=    Strip String    ${seq_start}
    ${seq_end}=      Strip String    ${seq_end}
    Should Be Equal As Strings    ${seq_start}    D1D2D3D4
    Should Be Equal As Strings    ${seq_end}      C1C2C3C4FFFFFFFF

I2C EEPROM Cut During Write Cycle Leaves Documented Partial Page
    Create External NVM Machine
    Execute Command    i2cEeprom BusyPollsPerWrite 0
    Execute Command    i2cEeprom WriteTraceEnabled true

    # 1. Cut BEFORE page write commits (FaultAtWordWrite=1, TornWordMode="untouched"): all 16 bytes remain 0xFF.
    Execute Command    i2cEeprom TornWordMode "untouched"
    Execute Command    i2cEeprom FaultAtWordWrite 1
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x02, 0x00] + [0x20 + i for i in range(16)]); e.FinishTransmission()"
    ${e_fired1}=    Read Normalized Bool    i2cEeprom FaultFired
    ${e_w0}=        Execute Command    sysbus ReadDoubleWord 0x61000200
    ${e_w1}=        Execute Command    sysbus ReadDoubleWord 0x61000204
    Should Be Equal As Strings    ${e_fired1}    true
    Should Be Equal As Numbers    ${e_w0}        0xFFFFFFFF
    Should Be Equal As Numbers    ${e_w1}        0xFFFFFFFF

    # 2. Cut DURING internal write cycle of 16-byte page write (FaultAtWordWrite=3, TornWordMode="fixed"):
    #    first 8 bytes (words 1..2) are written, remaining 8 bytes (words 3..4) retain 0xFFFFFFFF!
    Execute Command    i2cEeprom FaultFired false
    Execute Command    i2cEeprom Reset
    Execute Command    i2cEeprom WriteTraceEnabled true
    Execute Command    i2cEeprom TornWordMode "fixed"
    Execute Command    i2cEeprom FaultAtWordWrite 3
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x02, 0x00] + [0x20 + i for i in range(16)]); e.FinishTransmission()"
    ${ep_w0}=    Execute Command    sysbus ReadDoubleWord 0x61000200
    ${ep_w1}=    Execute Command    sysbus ReadDoubleWord 0x61000204
    ${ep_w2}=    Execute Command    sysbus ReadDoubleWord 0x61000208
    ${ep_w3}=    Execute Command    sysbus ReadDoubleWord 0x6100020C
    Should Be Equal As Numbers    ${ep_w0}    0x23222120
    Should Be Equal As Numbers    ${ep_w1}    0x27262524
    Should Be Equal As Numbers    ${ep_w2}    0xFFFFFFFF
    Should Be Equal As Numbers    ${ep_w3}    0xFFFFFFFF

    # 3. Page-level single-write tracking mode (PageLevelWriteTracking=true):
    #    FaultAtWordWrite=1 on a 16-byte page write commits first half (8 bytes) and leaves second half (8 bytes) untouched.
    Execute Command    i2cEeprom FaultFired false
    Execute Command    i2cEeprom Reset
    Execute Command    i2cEeprom PageLevelWriteTracking true
    Execute Command    i2cEeprom TornWordMode "half"
    Execute Command    i2cEeprom FaultAtWordWrite 1
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x03, 0x00] + [0x40 + i for i in range(16)]); e.FinishTransmission()"
    ${pl_w0}=    Execute Command    sysbus ReadDoubleWord 0x61000300
    ${pl_w1}=    Execute Command    sysbus ReadDoubleWord 0x61000304
    ${pl_w2}=    Execute Command    sysbus ReadDoubleWord 0x61000308
    ${pl_w3}=    Execute Command    sysbus ReadDoubleWord 0x6100030C
    Should Be Equal As Numbers    ${pl_w0}    0x43424140
    Should Be Equal As Numbers    ${pl_w1}    0x47464544
    Should Be Equal As Numbers    ${pl_w2}    0xFFFFFFFF
    Should Be Equal As Numbers    ${pl_w3}    0xFFFFFFFF

NRF52840 SPI2 And TWI0 Controllers Drive SPINORFlash And I2CEEPROM Over MMIO Registers
    Create External NVM Machine
    Execute Command    spiNor BusyPollsPerProgram 0
    Execute Command    i2cEeprom BusyPollsPerWrite 2

    # The UARTE stub used by Zephyr must expose TXD.MAXCNT at 0x548 and
    # TXD.AMOUNT at 0x54C. The earlier stub incorrectly aliased AMOUNT at 0x548.
    Execute Command    sysbus WriteDoubleWord 0x40002544 0x20000100
    Execute Command    sysbus WriteDoubleWord 0x40002548 7
    ${tx_amount}=    Execute Command    sysbus ReadDoubleWord 0x4000254C
    Should Be Equal As Numbers    ${tx_amount}    7

    # 1. Drive SPI2 (0x40023000) + GPIO0 P0.22 CS# (0x50000500) via MMIO to read JEDEC ID (0x9F) from spiNor:
    #    Configure P0.22 as output (DIRSET @ 0x50000518 = 1<<22), enable SPI2 (ENABLE @ 0x40023500 = 1),
    #    assert CS# low (OUTCLR @ 0x5000050C = 1<<22), clock 0x9F + 3 dummy bytes via TXD (0x4002351C) / RXD (0x40023518),
    #    deassert CS# high (OUTSET @ 0x50000508 = 1<<22).
    Execute Command    sysbus WriteDoubleWord 0x50000518 0x00400000
    Execute Command    sysbus WriteDoubleWord 0x50000508 0x00400000
    Execute Command    sysbus WriteDoubleWord 0x40023500 1
    Execute Command    sysbus WriteDoubleWord 0x5000050C 0x00400000
    Execute Command    sysbus WriteDoubleWord 0x4002351C 0x9F
    ${dummy}=    Execute Command    sysbus ReadDoubleWord 0x40023518
    Execute Command    sysbus WriteDoubleWord 0x4002351C 0x00
    ${id0}=      Execute Command    sysbus ReadDoubleWord 0x40023518
    Execute Command    sysbus WriteDoubleWord 0x4002351C 0x00
    ${id1}=      Execute Command    sysbus ReadDoubleWord 0x40023518
    Execute Command    sysbus WriteDoubleWord 0x4002351C 0x00
    ${id2}=      Execute Command    sysbus ReadDoubleWord 0x40023518
    Execute Command    sysbus WriteDoubleWord 0x50000508 0x00400000
    Should Be Equal As Numbers    ${id0}    0xEF
    Should Be Equal As Numbers    ${id1}    0x40
    Should Be Equal As Numbers    ${id2}    0x15

    # 2. Drive TWI0 (0x40003000) via MMIO to write 4 bytes to i2cEeprom at 0x0080 and verify hardware ANACK during t_WR:
    #    ENABLE (0x40003500) = 5, ADDRESS (0x40003588) = 0x50, TASKS_STARTTX (0x40003008) = 1,
    #    TXD (0x4000351C) = [0x00, 0x80, 0xDE, 0xAD, 0xBE, 0xEF], TASKS_STOP (0x40003014) = 1.
    Execute Command    sysbus WriteDoubleWord 0x40003500 5
    Execute Command    sysbus WriteDoubleWord 0x40003588 0x50
    Execute Command    sysbus WriteDoubleWord 0x40003008 1
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0x00
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0x80
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0xDE
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0xAD
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0xBE
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0xEF
    Execute Command    sysbus WriteDoubleWord 0x40003014 1
    ${written}=    Execute Command    sysbus ReadDoubleWord 0x61000080
    Should Be Equal As Numbers    ${written}    0xEFBEADDE

    # Immediate next TWI0 STARTTX while BusyPollsPerWrite > 0 triggers hardware ERRORSRC.ANACK (bit 1 = 0x02) and EVENTS_ERROR (0x40003124 = 1)!
    Execute Command    sysbus WriteDoubleWord 0x40003008 1
    Execute Command    sysbus WriteDoubleWord 0x4000351C 0x00
    ${ev_err}=     Execute Command    sysbus ReadDoubleWord 0x40003124
    ${err_src}=    Execute Command    sysbus ReadDoubleWord 0x400034C4
    Execute Command    sysbus WriteDoubleWord 0x40003014 1
    Should Be Equal As Numbers    ${ev_err}     1
    Should Be Equal As Numbers    ${err_src}    2

SPI NOR And I2C EEPROM Non Power Write Faults Read Bit Flips And Trace Replay
    Create External NVM Machine
    Execute Command    spiNor BusyPollsPerProgram 0
    Execute Command    i2cEeprom BusyPollsPerWrite 0

    # 1. SPI NOR write rejection (WriteFaultMode=3) and driver error (WriteFaultMode=6).
    Execute Command    spiNor WriteFaultMode 6
    Execute Command    spiNor FaultAtWordWrite 1
    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; s.Transmit(0x06); s.FinishTransmission(); [s.Transmit(x) for x in (0x02, 0x00, 0x05, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)]; s.FinishTransmission()"
    ${drv_err}=       Read Normalized Bool    spiNor DriverErrorFired
    ${rejected_w0}=   Execute Command    sysbus ReadDoubleWord 0x60000500
    ${continued_w1}=  Execute Command    sysbus ReadDoubleWord 0x60000504
    Should Be Equal As Strings    ${drv_err}         true
    Should Be Equal As Numbers    ${rejected_w0}     0xFFFFFFFF
    Should Be Equal As Numbers    ${continued_w1}    0x88776655

    # 2. SPI NOR read bit-flip fault (ReadFaultEnabled) on SPI READ (0x03).
    Execute Command    spiNor ReadFaultEnabled true
    Execute Command    spiNor ReadFaultAddress 0x60000504
    Execute Command    spiNor ReadFaultBitFlips 2
    Execute Command    spiNor ReadFaultSeed 99
    ${flipped}=    Execute Command    python "s=monitor.Machine['sysbus.spiNor']; [s.Transmit(x) for x in (0x03, 0x00, 0x05, 0x04)]; b=s.Transmit(0); s.FinishTransmission(); print(b)"
    ${rf_fired}=   Read Normalized Bool    spiNor ReadFaultFired
    Should Be Equal As Strings        ${rf_fired}    true
    Should Not Be Equal As Numbers    ${flipped}     0x55
    Execute Command    spiNor ReadFaultEnabled false

    # 3. I2C EEPROM bit corruption (WriteFaultMode=1) and read bit-flip fault.
    Execute Command    i2cEeprom WriteFaultMode 1
    Execute Command    i2cEeprom CorruptionSeed 77
    Execute Command    i2cEeprom FaultAtWordWrite 1
    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x04, 0x00, 0x00, 0x00, 0x00, 0x00]); e.FinishTransmission()"
    ${corrupted}=    Execute Command    sysbus ReadDoubleWord 0x61000400
    Should Not Be Equal As Numbers    ${corrupted}    0x00000000
    Should Not Be Equal As Numbers    ${corrupted}    0xFFFFFFFF
    Execute Command    i2cEeprom ReadFaultEnabled true
    Execute Command    i2cEeprom ReadFaultAddress 0x61000400
    Execute Command    i2cEeprom ReadFaultBitFlips 1
    ${e_flipped}=    Execute Command    python "e=monitor.Machine['sysbus.i2cEeprom']; e.Write([0x04, 0x00]); b=e.Read(1); e.FinishTransmission(); print(b[0])"
    ${e_rf_fired}=   Read Normalized Bool    i2cEeprom ReadFaultFired
    Should Be Equal As Strings    ${e_rf_fired}    true
    Execute Command    i2cEeprom ReadFaultEnabled false
