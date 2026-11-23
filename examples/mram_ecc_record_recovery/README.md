# MRAM ECC Uncorrectable Record Recovery Example

This example models a dual-record state store in word-ECC MRAM (`platforms/cortex_m0_mram.repl`, 8-byte MRAM program words):

- **Record A** (`0x10100100`, 32 bytes / four 8-byte words) holds a committed valid record (`seq = 1`) with an IEEE CRC-32 trailer.
- **Record B** (`0x10100200`, 32 bytes / four 8-byte words) is initially erased and is programmed with `seq = 2` during an update triggered by volatile SRAM flag `0x20000400 = 0x55504431`.
- After a power loss, recovery scans Record A and Record B to select the highest-sequence record with a valid magic word and CRC-32, then sets `0x20000100 = 0x5245434F` and hands off `VTOR = 0x10100000`.

## Variants

- **`profile_unhandled.yaml`** (`firmware_unhandled.elf`, `HANDLE_READ_FAULT=0`): recovery dereferences Record B directly and leaves `HardFault_Handler` as an infinite loop.
  - Under `half`, `half_retain`, `untouched`, `erased`, `programmed`, and `corrupted`, every fault point returns bytes without faulting, CRC-32 rejects partial/corrupted Record B (or accepts completed `programmed` Record B), and recovery passes with zero findings.
  - Under `mram_torn_word: uncorrectable`, every fault cut leaves the interrupted Record B word marked unreadable; recovery reads it, takes an unhandled bus error (`hard_fault`), and the sweep reports findings with `uncorrectable_read.outcome == "faulted"`.
- **`profile_handled.yaml`** (`firmware_handled.elf`, `HANDLE_READ_FAULT=1`): recovery reads MRAM through a fault-guarded helper whose `HardFault_Handler` catches the bus error, returns an error to the scanner, clears the torn Record B slot by reprogramming it to zero, and falls back to Record A.
  - Under `mram_torn_word: uncorrectable`, every fault point recovers and passes with `uncorrectable_read.outcome == "recovered"`, `handled == true`, and `cleared_by_recovery == true`.

## Rebuilding

```bash
make -C examples/mram_ecc_record_recovery
```
