# Flash operation durations

A program time applies once per physical program unit. Erase time applies once per selected page, sector, bank, or chip. Controller register writes and status reads have separate bus costs.

## nRF52840 NVMC

| Operation | Typical | Maximum |
| --- | ---: | ---: |
| Program one aligned 32-bit word | 41 µs (uses published max) | 41 µs |
| Erase one 4 KiB page | 85 ms (uses published max) | 85 ms |
| Erase all flash | 169 ms (uses published max) | 169 ms |

The datasheet lists only the maximum for each operation using the external high-frequency oscillator (HFXO). Both `Typical` and `Maximum` use those durations. The internal oscillator adds its frequency tolerance. The NVMC functional description also documents the stall on instruction fetch from flash during programming. [nRF52840 Product Specification 4413_417 v1.9, §4.3.10.1, Flash programming](https://docs-be.nordicsemi.com/bundle/nRF52840_PS_v1.9/raw/resource/enus/nRF52840_PS_v1.9.pdf), [NVMC electrical specification, HTML table](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/nvmc.html)

## STM32F103

`STM32F1FlashController` models the STM32F103x8/xB medium-density Flash program/erase controller (FPEC) with 16-bit half-word programming (`FLASH_CR.PG`) and 1 KiB page or mass erases (`FLASH_CR.PER` / `FLASH_CR.MER` + `FLASH_CR.STRT`), reporting busy status on `FLASH_SR.BSY` (bit 0). Table 28 of DS5319 specifies `tprog` (Min 40 µs, Typ 52.5 µs, Max 70 µs) and specifies `Min = 20 ms`, `Max = 40 ms` for both `tERASE` and `tME` with the `Typ` column left blank (`—`), so `Typical` uses 53 µs (52.5 µs rounded to integer microseconds) for half-word programming and 20 ms for page and mass erases. [RM0008 Rev 21, §3.3.3](https://www.st.com/resource/en/reference_manual/cd00171190.pdf), [PM0075 Rev 2, §2.3](https://www.st.com/resource/en/programming_manual/cd00283419.pdf), [DS5319 Rev 19, §5.3.9 Table 28](https://www.st.com/resource/en/datasheet/stm32f103rb.pdf)

| Operation | Typical | Maximum |
| --- | ---: | ---: |
| Program one 16-bit half-word (`tprog`) | 53 µs (52.5 µs nominal) | 70 µs |
| Erase one 1 KiB page (`tERASE`) | 20 ms (published min; typ unspecified) | 40 ms |
| Mass erase (`tME`) | 20 ms (published min; typ unspecified) | 40 ms |

## STM32L476

`STM32L4FlashController` models the STM32L476xx dual-bank 72-bit ECC Flash controller with 64-bit double-word programming (`FLASH_CR.PG`), 32-double-word (256-byte) fast row programming (`FLASH_CR.FSTPG`), 2 KiB page erases (`FLASH_CR.PER`), and single-bank or dual-bank mass erases (`FLASH_CR.MER1` / `FLASH_CR.MER2`), reporting busy status on `FLASH_SR.BSY` (bit 16). Sub-microsecond nominal values in Table 63 are rounded to the nearest integer microsecond for the 1 MHz operation timer. [RM0351 Rev 9, §3.3.6–3.3.7](https://www.st.com/resource/en/reference_manual/dm00083560.pdf), [DS10198 Rev 8, §6.3.10 Table 63](https://www.st.com/resource/en/datasheet/stm32l476rg.pdf)

| Operation | Typical | Maximum |
| --- | ---: | ---: |
| Program one 64-bit double-word (`tprog`) | 82 µs (81.69 µs nominal) | 91 µs (90.76 µs nominal) |
| Fast row program, 32 double-words (`tprog_row`, `FSTPG=1`) | 1.91 ms (1,910 µs) | 2.12 ms (2,120 µs) |
| Normal row program, 32 double-words (32 × `tprog`, `PG=1`) | 2.61 ms | 2.90 ms |
| Erase one 2 KiB page (`tERASE`) | 22.02 ms (22,020 µs) | 24.47 ms (24,470 µs) |
| Bank or mass erase (`tME`) | 22.13 ms (22,130 µs) | 24.59 ms (24,590 µs) |

## STM32F429

Each entry gives typical / maximum at the parallelism selected by FLASH_CR.PSIZE. These figures apply to both F4 controller implementations when modeling the F429. The word-program maximum was characterized after 100,000 erase cycles. [DS9405 Rev 14, Table 48](https://www.st.com/resource/en/datasheet/dm00071990.pdf)

| Operation | ×8 | ×16 | ×32 |
| --- | ---: | ---: | ---: |
| Program | 16 / 100 µs | 16 / 100 µs | 16 / 100 µs |
| Erase 16 KiB | 400 / 800 ms | 300 / 600 ms | 250 / 500 ms |
| Erase 64 KiB | 1200 / 2400 ms | 700 / 1400 ms | 550 / 1100 ms |
| Erase 128 KiB | 2 / 4 s | 1.3 / 2.6 s | 1 / 2 s |
| Bank or mass erase | 16 / 32 s | 11 / 22 s | 8 / 16 s |

With external VPP, Table 49 lists 16 / 100 µs for double-word programming, typical sector erases of 230, 490 and 875 ms, and a typical mass erase of 6.9 s. It leaves the erase maxima blank. [DS9405, Tables 48–49](https://www.st.com/resource/en/datasheet/stm32f429ig.pdf)

## STM32H743 and STM32H753

Both H7 implementations represent a two-bank device. One program operation covers 32 data bytes plus 10 ECC bits. Eight 32-bit bus stores can fill one flash word. Timing each store as a complete program would charge the latency eight times. The program maxima were characterized after 10,000 erase cycles. [DS12110 Rev 11, Tables 43 and 140](https://www.st.com/resource/en/datasheet/stm32h743ii.pdf), [DS12117 Rev 10, Tables 42 and 139](https://www.st.com/resource/en/datasheet/stm32h753zi.pdf), [RM0433, §4](https://www.st.com/resource/en/reference_manual/dm00314099.pdf)

| Operation | ×8 | ×16 | ×32 | ×64 |
| --- | ---: | ---: | ---: | ---: |
| Program one flash word | 290 / 580 µs | 180 / 360 µs | 130 / 260 µs | 100 / 200 µs |
| Erase 128 KiB | 2 / 4 s | 1.8 / 3.6 s | 1.1 / 2.2 s | 1 / 2 s |
| Mass erase | 13 / 26 s | 8 / 16 s | 6 / 12 s | 5 / 10 s |

## Parallel CFI NOR

The model returns manufacturer ID 0x89 and device ID 0x18. It has configurable capacity and a four-byte data path. The 28F128J3 datasheet specifies these times for the unbuffered program command and for erasing a 128 KiB block. The typical measurement uses 25 °C and nominal voltages. The maximum uses voltage and temperature corners after 100,000 cycles. [28F128J3 datasheet 290667-020, §7.3 Table 10](https://media.digikey.com/pdf/Data%20Sheets/Intel%20PDFs/28F128J3%2C%20256J3%2C%20320J3%2C%20640J3.pdf)

| Operation | Typical | Maximum |
| --- | ---: | ---: |
| Byte program, word/byte command | 210 µs | 630 µs |
| Block erase | 1 s | 5 s |

CFI query fields 0x1F and 0x23 encode a word-program timeout and its maximum multiplier as powers of two. The untimed model reports 16 / 256 µs. With either timing selection, the fields report 256 / 1024 µs so the advertised deadlines cover the modeled durations. Block-erase timeouts at 0x21 and 0x25 stay at 1024 / 16384 ms.

## Generic NVM, MRAM, and AN521

`NVMemory`, `NVMemoryController`, `GenericNvmController`, and `MappedMRAMTracker` are configurable storage and controller models. Their platform descriptions select a program-unit width and erase behavior without identifying a manufacturer, part number, or speed grade. A physical timing table requires that additional information. MRAM can overwrite a word directly. An erase exposed by the test controller may represent a software fill.

`An521NvmInterceptor` backs the flash API with the board's code SRAM. A flash sector-erase time does not apply to this alias. The board memory description identifies SSRAM1 as synchronous SRAM. [AN521, DAI 0521A, §3.4.1](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/DAI0521A_example_sse200_subsystem_for_v2m_mps2.pdf)

`OTPMemory` models generic one-time-programmable storage. It has a programming granularity and no physical erase command. A blow-pulse duration requires a specific fuse macro.

## Cut and reset semantics during timed operations

- **Unarmed reset (`Reset()`)**: cancels any active operation timer and discards uncommitted program or erase data while preserving all prior operations whose timers have already expired.
- **Armed power-loss / write / erase cut (`FaultAtWordWrite` or `FaultAtPageErase`)**: all operations prior to the armed index run with their full configured duration and commit on timer expiry. When the armed target operation starts, the cut interrupts that in-progress operation immediately, applies the configured torn-program, interrupted-erase, or uncorrectable-ECC outcome to backing storage and `FaultFlashSnapshot`, latches power loss, and suppresses the completion timer so the interrupted operation never silently finishes after the cut.
