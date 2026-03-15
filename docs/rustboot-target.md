# rustBoot Target Design

## Background

rustBoot is an MIT-licensed secure bootloader written in Rust, targeting
Cortex-M microcontrollers. It implements a swap-scratch OTA update algorithm
with firmware integrity validation. The project is relatively young compared
to MCUboot and has several known reliability issues under power-loss
scenarios.

## Architecture

### Partition layout

rustBoot uses 3 flash partitions:

```
+-------------------+
| BOOT partition    |  Active firmware + trailer
+-------------------+
| UPDATE partition  |  Staging area for new firmware + trailer
+-------------------+
| SWAP partition    |  Scratch space for sector-level swap
+-------------------+
```

### Trailer format

BOOT and UPDATE each have an identical trailer at the end of the partition:

```
End of partition:
  [-4..-1]        magic: "BOOT" (0x544F4F42 LE)
  [-5]            state byte
  [-5-N..-6]      per-sector flags (packed nibbles)
```

State byte values:

- `0xFF` -- New (erased/no update pending)
- `0x70` -- Updating (swap in progress)
- `0x10` -- Testing (new image installed, awaiting confirmation)
- `0x00` -- Success (confirmed, stable)

### Per-sector flags

Sector flags track swap progress at sector granularity. Two flags are packed
per byte as 4-bit nibbles (low nibble = even sector, high nibble = odd
sector).

Nibble values, in progression order:

- `0x0F` -- New (not yet processed)
- `0x07` -- Swapping (sector being copied to SWAP)
- `0x03` -- Backup (sector backed up, ready for overwrite)
- `0x00` -- Updated (swap complete for this sector)

### Swap algorithm (swap-scratch)

1. Mark BOOT as Updating, UPDATE as Updating
2. For each sector i:
   a. Copy BOOT[i] to SWAP (flag = Swapping)
   b. Copy UPDATE[i] to BOOT[i] (flag = Backup)
   c. Copy SWAP to UPDATE[i] (flag = Updated)
3. Mark BOOT as Testing, UPDATE as Updating
4. Boot new image from BOOT
5. Application confirms -> mark BOOT as Success
6. If no confirmation on next boot -> reverse swap (rollback)

## Known bugs and tardigrade detection

### Bug #77: Interrupted swap brick

**Vulnerability**: Power loss during the sector copy loop (step 2) can leave
the BOOT partition with a mix of old and new sectors. rustBoot does not
implement swap resume -- on the next boot, it sees BOOT in Updating state
but cannot determine which sectors were already swapped. The device is
bricked.

**Detection**: The `rustboot_boot_not_empty` invariant checks that BOOT has
valid magic after recovery boot. A write-fault sweep across the swap copy
loop will find fault points where BOOT is left without valid firmware.

### Bug #79: Corrupted boot image runs

**Vulnerability**: If the BOOT image is corrupted (bad hash) but the state
byte still reads Testing or Success, rustBoot may attempt to boot the
corrupted image without re-validating. The state byte alone is used to
decide whether to boot or roll back, without re-checking image integrity.

**Detection**: The `rustboot_testing_has_rollback_path` invariant checks
that the Testing/Updating state pair is consistent. Bit-corruption fault
injection against the state byte will reveal cases where the state machine
enters an invalid configuration.

### Bug #80: Damaged update brick

**Vulnerability**: If the UPDATE partition image is corrupted during
download and rustBoot begins swapping it into BOOT, the device can end
up with corrupted firmware in BOOT and no valid rollback image. rustBoot
validates the update image hash before starting the swap, but a fault
during the validation-to-swap transition could bypass the check.

**Detection**: Write-fault injection during the hash validation and swap
initiation window. The `rustboot_boot_not_empty` invariant catches the
resulting brick.

## Build instructions

rustBoot targets nRF52840 via cargo:

```bash
# Clone rustBoot
git clone https://github.com/AmarTabakovic/rustBoot.git
cd rustBoot

# Build bootloader for nRF52840
cd boards/bootloaders/nrf52840
cargo build --release

# ELF output at:
# target/thumbv7em-none-eabihf/release/nrf52840
```

Requirements:

- Rust nightly with `thumbv7em-none-eabihf` target
- `cargo-binutils` for objcopy
- ARM GCC toolchain for linking

## Renode platform mapping

rustBoot on nRF52840 maps directly to tardigrade's existing infrastructure:

- **CPU**: Cortex-M4F (nRF52840) -- standard Renode CortexM
- **Flash controller**: NRF52NVMC (already implemented in tardigrade with
  write tracking, fault injection, erase tracking, trace replay)
- **Platform file**: Existing `cortex_m4_flash_fast.repl` or nRF52840 repl
- **Flash size**: 1MB (0x00000000 - 0x000FFFFF)

Partition mapping for the checked-in nRF52840 rustBoot build:

```
0x00000000 - 0x0002EFFF  Bootloader / immutable region
0x0002F000 - 0x00056FFF  BOOT partition (160KB)
0x00057000 - 0x00057FFF  SWAP partition (4KB)
0x00058000 - 0x0007FFFF  UPDATE partition (160KB)
0x00080000 - 0x000FFFFF  Unused / config
```

Profile YAML variables:

```yaml
flash_backend: faultFlash
slot_exec_base: 0x0002F000
slot_exec_size: 0x00028000
slot_staging_base: 0x00058000
slot_staging_size: 0x00028000
state_probe:
  script: targets/rustboot/probe.py
invariant_providers:
  - targets/rustboot/invariants.py
```

Note: the current rustBoot probe defaults are pinned to this checked-in
nRF52840 layout. The current fast nRF52 backend also infers write indices
from NVMC mode transitions; rustBoot's nRF52840 HAL leaves NVMC in
write-enable mode across flash writes, so the first working repo profile
currently uses `interrupted_erase` coverage instead of write-indexed
`power_loss` points. The checked-in ELF also does not export stable
unmangled hash-bypass symbols, so the current profile runs without
`sweep_hash_bypass_symbols`.

## Estimated work for a working profile

### Phase 1: Bootloader ELF + basic sweep (~2 days)

Build rustBoot for nRF52840, get it running in Renode on the existing
nRF52840 platform. Create a profile YAML with the partition layout above.
Run a calibration pass to identify the erase trace during a normal OTA
swap, then do an erase-fault sweep. The checked-in profile now does this
and is expected to find issues. Extending this to write-indexed power-loss
coverage still requires a rustBoot-aware nRF52 fast backend.

Deliverables:

- rustBoot ELF built for nRF52840
- Profile YAML with partition addresses and probe/invariant paths
- Calibration erase trace showing swap progress
- Initial erase-fault sweep results showing brick rate

### Phase 2: Differential validation against known bugs (~1 day)

Build rustBoot at commits before and after each bug fix (#77, #79, #80).
Run the same sweep on broken vs fixed commits. Confirm tardigrade detects
the vulnerability on the broken commit and shows 0 bricks on the fixed.

Deliverables:

- Broken/fixed ELF pairs for each bug
- Differential sweep results

### Phase 3: Nibble corruption and bit-level faults (~1 day)

Enable bit-corruption fault mode against the trailer region. The packed
nibble layout is a known weak point -- a single bit flip in a flag byte
can corrupt two sectors' progress tracking simultaneously.

Deliverables:

- Bit-corruption profile variant
- Results showing packed-nibble vulnerability surface

## References

- rustBoot repository: https://github.com/AmarTabakovic/rustBoot
- Issue #77 (interrupted swap): https://github.com/AmarTabakovic/rustBoot/issues/77
- Issue #79 (corrupted boot): https://github.com/AmarTabakovic/rustBoot/issues/79
- Issue #80 (damaged update): https://github.com/AmarTabakovic/rustBoot/issues/80
- rustBoot design doc: https://github.com/AmarTabakovic/rustBoot/blob/main/docs/design.md
