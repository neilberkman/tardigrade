# Writing Profiles

This guide walks through creating a tardigrade profile for your bootloader, from minimal to advanced. By the end you'll know how to describe your memory layout, define success, configure fault injection, and add semantic checks that catch state-correctness bugs.

## Starting point

Every profile is a YAML file with `schema_version: 1`. The simplest useful profile needs five things: a platform, a bootloader ELF, memory layout, at least one slot image, and success criteria.

```yaml
schema_version: 1
name: my_bootloader_upgrade
description: "Power-loss resilience during firmware upgrade"

platform: platforms/cortex_m4_flash_fast.repl
flash_backend: faultFlash

bootloader:
  elf: path/to/bootloader.elf
  entry: 0x00000000

memory:
  sram: { start: 0x20000000, end: 0x20040000 }
  write_granularity: 4
  page_size: 0x1000
  slots:
    exec: { base: 0x0000C000, size: 0x76000 }
    staging: { base: 0x00082000, size: 0x76000 }

images:
  exec: path/to/current_firmware.bin
  staging: path/to/new_firmware.bin

success_criteria:
  vtor_in_slot: exec

fault_sweep:
  mode: runtime
  evaluation_mode: execute
  max_writes: auto

expect:
  should_find_issues: false
```

Run it:

```bash
python3 scripts/audit_bootloader.py --profile my_profile.yaml --quick
```

`--quick` runs 3 fault points as a smoke test. If it passes, drop `--quick` for the full heuristic sweep.

## Profile inheritance

A profile can extend a base profile with `base_profile`. The child profile deep-merges on top of the base: dicts merge recursively, lists and scalars in the child replace the base value. The base path is resolved relative to the child profile's directory.

```yaml
# profiles/mcuboot_pr2100_broken.yaml
base_profile: mcuboot_head_upgrade.yaml
name: mcuboot_pr2100_broken
bootloader:
  elf: path/to/broken_commit.elf
expect:
  should_find_issues: true
```

This inherits everything from `mcuboot_head_upgrade.yaml` (platform, memory layout, images, fault_sweep, etc.) and overrides only the fields specified. Chains are supported -- a base can itself declare a `base_profile`. Cycles are detected and rejected. Maximum chain depth is 10.

## Choosing a platform

Tardigrade ships several platform backends. Pick the one that matches your NVM technology:

| Platform file                               | Backend                                           | NVM type                               | Write granularity |
| ------------------------------------------- | ------------------------------------------------- | -------------------------------------- | ----------------- |
| `platforms/cortex_m4_flash_fast.repl`       | `faultFlash` (NVMC)                               | NOR flash                              | 4 bytes           |
| `platforms/cortex_m4_flash.repl`            | `faultFlash` (NVMC) + `nvm_ctrl` (NVMemory)       | NOR flash (NVMemory for slot data)     | 4 bytes           |
| `platforms/cortex_m0_nvm.repl`              | `nvm_ctrl` (NVMemory)                             | Generic NVM                            | 8 bytes           |
| `platforms/cortex_m0_nvm_flash.repl`        | `nvm_ctrl` (NVMemoryController)                   | NVMemory with flash controller         | 4 bytes           |
| `platforms/cortex_m0_nvm_generic_ctrl.repl` | `nvm_ctrl` (GenericNvmController)                 | NVMemory with command-register ctrl    | 8 bytes           |
| `platforms/cortex_m0_mapped.repl`           | `flash` (MappedMemory)                            | MappedMemory (no fault controller)     | N/A               |
| `platforms/cortex_m0_mapped_faultctrl.repl` | `faultFlash` (NVMC)                               | MappedMemory + NVMC fault controller   | 4 bytes           |
| `platforms/cortex_m0_hybrid.repl`           | `flash` (MappedMemory) + `nvm_sidecar` (NVMemory) | Hybrid MappedMemory + NVMemory         | 8 bytes           |
| `platforms/stm32f4.repl`                    | STM32F4 flash                                     | NOR flash                              | 4 bytes           |
| `platforms/stm32h743_tardigrade.repl`       | `faultFlash` (STM32H7FlashController)             | STM32H743 dual-bank NOR flash          | 4 bytes           |
| `platforms/stm32h753_tardigrade.repl`       | `faultFlash` (STM32H7FlashController)             | STM32H753 dual-bank NOR flash + crypto | 4 bytes           |
| `platforms/nucleo_h753zi_tardigrade.repl`   | STM32H7 flash                                     | NOR flash                              | 4 bytes           |
| `platforms/nrf52840_nvmc_psel.repl`         | Built-in nRF52840 NVMC                            | nRF52840 NOR flash                     | 4 bytes           |
| `platforms/cortex_m0_otp.repl`              | OTPMemory                                         | OTP fuses                              | 4 bytes           |

The STM32H7 and STM32F4 platforms use separate flash controller peripherals (`STM32H7FlashController.cs`, `STM32F4FlashController.cs`) listed under `extra_peripherals`. The OTP platform enables OTP fuse-blow fault types.

`flash_backend` must name the sysbus peripheral that tardigrade instruments for fault injection. This is required.

## Memory layout

### Slots

`memory.slots` defines named regions. The two standard names are `exec` (active/primary) and `staging` (download/secondary). Some bootloaders use a third slot:

```yaml
memory:
  sram: { start: 0x20000000, end: 0x240A0000 }
  write_granularity: 8
  slots:
    exec: { base: 0x08040000, size: 0x80000 }
    staging: { base: 0x080C0000, size: 0x80000 }
    tertiary: { base: 0x08140000, size: 0x80000 }
```

`write_granularity` is the minimum write unit in bytes (4 for typical NOR flash, 8 for MRAM).

`page_size` is the effective erase unit used by state evaluation and as a fallback geometry hint for semantic cutpoints like `swap_progress`. On uniform flash, this is usually the real sector size. On non-uniform flash, calibration erase traces are preferred because they provide the actual per-sector map; `page_size` is only a fallback.

### How to find your slot addresses

From your linker script or partition table. For MCUboot, the DTS overlay defines `boot_partition`, `slot0_partition`, and `slot1_partition`. For custom bootloaders, grep your linker script for `ORIGIN` and `LENGTH` of each firmware region.

## Images

`images` maps slot names to binary files. These are raw firmware binaries (not ELFs) loaded into the corresponding slots before the sweep starts.

```yaml
images:
  exec: path/to/current.bin
  staging: path/to/update.bin
```

For upgrade scenarios, `exec` has the old image and `staging` has the new one. For revert scenarios, swap them (the "new" image is in exec, "old" is in staging, and the bootloader should swap back).

If your bootloader reads image headers from the binary, include them. If it reads metadata from a separate trailer region, use `pre_boot_state` or `update_trigger` instead.

## Different-sized images

Some bootloader bugs only manifest when the two slot images have different sizes. For example, MCUboot PR [#2109](https://github.com/mcu-tools/mcuboot/pull/2109) corrupts headers after an interrupted swap-scratch resume because `boot_read_image_headers` reloads from the wrong slot -- but same-sized images hide the bug since both headers describe identical lengths.

To test with asymmetric images, use different binaries in the `images:` section:

```yaml
images:
  exec: path/to/app_19kb.bin # smaller image in exec
  staging: path/to/app_36kb.bin # larger image in staging
```

No special profile flag is needed -- the size difference comes from the image files themselves. The build script `scripts/build_mcuboot_head_matrix.sh` produces size-asymmetric pairs by truncating the slot1 payload to a specific size (e.g., 36KB vs the full ~19KB app), ensuring every MCUboot HEAD matrix config exercises geometry-dependent code paths.

If your bootloader validates image hashes (MCUboot does), the hash in the image header must match the actual payload. You cannot simply pad an arbitrary binary -- the image must be properly signed/hashed at the new size.

## Residual image testing (direct-XIP)

Direct-XIP bootloaders execute firmware in-place from flash or MRAM. When a new (smaller) image replaces an old (larger) one, stale bytes from the previous image may remain in the slot tail. On MRAM (no erase cycle) this is guaranteed. On flash, it depends on whether the OTA process erases the full slot before writing.

The bootloader typically only hashes `image_size` bytes. The slot tail is executable but unauthenticated -- a crafted small image could branch to known stale code in the tail.

The `residual_image` section simulates this scenario by loading a prior (larger) image first, then overwriting with the actual (smaller) image. Tail bytes from the prior image remain:

```yaml
residual_image:
  slot: staging # which slot to contaminate
  prior_image: path/to/old_large.bin # the prior (larger) image
  fill_pattern: 0x00 # optional: fill slot before prior image
```

`slot` must name a slot defined in `memory.slots`. `prior_image` is the path to the larger binary that was previously in the slot. `fill_pattern` optionally fills the entire slot with a byte value before loading the prior image (use `0x00` for MRAM or `0xFF` for flash to simulate a full erase).

### Detecting stale tail execution

Use `max_reset_vector_offset` in `success_criteria` to flag if the reset vector points beyond the authenticated image boundary:

```yaml
success_criteria:
  vtor_in_slot: exec
  max_reset_vector_offset: 0x1000 # image_size of the new (small) image
```

After boot, tardigrade reads the reset vector (word at VTOR+4) and computes its offset from the slot base. If the offset exceeds `max_reset_vector_offset`, the boot is flagged as `wrong_image` -- the CPU would execute unauthenticated stale code.

### Example: naive vs erased

A naive bootloader that does not erase the slot before writing:

```yaml
residual_image:
  slot: staging
  prior_image: examples/test_image.bin

success_criteria:
  vtor_in_slot: exec
  max_reset_vector_offset: 248

expect:
  should_find_issues: true
  control_outcome: wrong_image
```

A safe bootloader that erases the full slot (simulated with `fill_pattern: 0x00`):

```yaml
residual_image:
  slot: staging
  prior_image: examples/test_image.bin
  fill_pattern: 0x00

success_criteria:
  vtor_in_slot: exec
  max_reset_vector_offset: 248
```

## Pre-boot state and update triggers

### Raw writes

`pre_boot_state` writes specific 32-bit values to NVM addresses before the bootloader runs. Use this to set up metadata, trailer flags, or any state the bootloader reads:

```yaml
pre_boot_state:
  - { address: 0x000F8000, u32: 0x00000001 }
  - { address: 0x000F801C, u32: 0x4743989A }
```

### Declarative triggers

For MCUboot, `update_trigger` generates the correct trailer bytes automatically:

```yaml
# Upgrade: write GOOD magic to staging trailer (triggers TEST swap)
update_trigger:
  type: mcuboot_trailer_magic
  slot: staging

# Revert: GOOD magic + copy_done=1 on exec (triggers REVERT)
update_trigger:
  type: mcuboot_trailer_magic
  slot: exec
  copy_done: 1
```

MCUboot builds with `BOOT_MAX_ALIGN` larger than 8 use a different trailer magic encoding. Set `max_align` to match your MCUboot configuration:

```yaml
update_trigger:
  type: mcuboot_trailer_magic
  slot: staging
  max_align: 32
```

Default is 8. The value must fit in a 16-bit field (max 65535). When set, tardigrade generates the align-aware magic bytes (`struct.pack("<H", max_align)` + fixed suffix) instead of the default 4-word GOOD magic.

RIOTboot headers are also supported:

```yaml
update_trigger:
  type: riotboot_header
  slot: staging
  version: 2
```

### Automatic trigger discovery

If you do not want to hand-seed trailer bytes, omit `update_trigger` or set it to `auto`:

```yaml
update_trigger: auto
```

When `pre_boot_state` is empty, tardigrade treats `update_trigger: auto` and a missing `update_trigger` the same way. Before the real calibration run, it tries a short trigger cascade until one strategy produces real slot data movement:

1. No trigger
2. Trailer magic only
3. Trailer magic + swap metadata
4. Offset image placement + trailer magic
5. Offset image placement + trailer metadata

MCUboot profiles also get a compiled flash-map and erase-sector-layout preflight first. If the ELF's built-in slot layout or the sector geometry does not match the profile's declared slots, tardigrade stops early instead of brute-forcing triggers against the wrong geometry.

This is coverage-gated. Trailer-only writes are not enough: a strategy only succeeds if calibration reaches slot data movement. If every strategy fails, tardigrade reports `INCONCLUSIVE -- could not trigger firmware update` rather than claiming a clean run.

Use explicit `pre_boot_state` or an explicit `update_trigger:` mapping when you need a specific seeded state (for example, a resume-from-interrupted-swap scenario). Those explicit seeds disable auto-discovery.

## Success criteria

How tardigrade decides if the device recovered after a fault.

### VTOR detection (recommended default)

```yaml
success_criteria:
  vtor_in_slot: exec
```

After the recovery boot, tardigrade polls the ARM VTOR register. If it points into the `exec` slot, the device booted correctly. Use `vtor_in_slot: any` if booting to either slot is acceptable (e.g., rollback to staging is a valid recovery).

`vector_table_offset` adjusts for bootloaders that place the vector table after a header:

```yaml
success_criteria:
  vtor_in_slot: exec
  vector_table_offset: 0x400 # nxboot: 1KB image header
```

### Marker address

For bootloaders that don't relocate VTOR, check a specific memory address after boot:

```yaml
success_criteria:
  marker_address: 0x0000C014
  marker_value: 0x00000001
```

### Image hash

Verify the correct image ended up in the slot (catches wrong-image bugs like PR #2199):

```yaml
success_criteria:
  vtor_in_slot: exec
  image_hash: true
  expected_image: staging # after upgrade, exec should contain what was in staging
```

### Boot register values

Capture and verify hardware register state at boot time. Useful for checking MPU configuration, peripheral lock bits, or clock settings:

```yaml
boot_registers:
  - { address: 0xE000ED94, name: mpu_ctrl }
  - { address: 0xE000ED9C, name: mpu_rbar }
  - { address: 0xE000EDA0, name: mpu_rasr }

success_criteria:
  vtor_in_slot: exec
  boot_register_values:
    mpu_ctrl: 0x00000007 # MPU enabled, PRIVDEFENA, HFNMIENA
```

Registers are captured at VTOR detection time. The `boot_registers_match` invariant compares against expected values.

#### Pre-writes for banked registers

Some registers (e.g., MPU_RBAR and MPU_RASR on ARMv6-M) are banked -- the value returned depends on which region MPU_RNR currently selects. Use `boot_register_pre_writes` to write specific values before the capture reads:

```yaml
boot_register_pre_writes:
  - { address: 0xE000ED98, value: 0x00000000 } # select MPU region 0

boot_registers:
  - { address: 0xE000ED94, name: mpu_ctrl }
  - { address: 0xE000ED9C, name: mpu_rbar }
  - { address: 0xE000EDA0, name: mpu_rasr }
```

Each entry is written via `bus.WriteDoubleWord` before any register reads occur.

### Config checks

Verify arbitrary memory locations after boot — useful for checking peripheral registers, config regions, or status flags:

```yaml
success_criteria:
  config_checks:
    - { address: 0x40001030, expected: 0x00000001 } # exact match
    - { address: 0x20000100, nonzero: true } # any nonzero value
    - { address: 0x20000200, range_min: 1, range_max: 255 } # range check
    - { address: 0x40002000, mask: 0x0F, expected_masked: 0x05 } # masked bits
```

## Fault sweep configuration

### Basics

```yaml
fault_sweep:
  mode: runtime
  evaluation_mode: execute # full recovery boot (vs "state" for NVM-only inference)
  max_writes: auto # calibrate automatically
  run_duration: "2.0" # seconds of emulation for calibration
  max_step_limit: 20000000 # CPU instruction limit
```

`max_writes: auto` runs the firmware once and counts NVM writes. Set a fixed number if you know it. `max_writes_cap` (default 100000) is a safety limit.

### Fault types

```yaml
fault_sweep:
  fault_types: [power_loss, bit_corruption, interrupted_erase]
```

Default is `[power_loss]`. Available types (25 total):

| Fault type                 | What it does                                   | Backend requirement  |
| -------------------------- | ---------------------------------------------- | -------------------- |
| `power_loss`               | Truncate write at fault point                  | All                  |
| `swap_progress`            | Cut power at swap-iteration boundary           | All                  |
| `bit_corruption`           | NOR-physics bit flips (1-to-0)                 | All                  |
| `interrupted_erase`        | Partial page erase                             | NVMC, NVMemory       |
| `command_drop`             | Silently dropped NVM controller command        | GenericNvmController |
| `silent_write_failure`     | Write accepted but data not stored             | All                  |
| `driver_error`             | Write rejected and error status raised         | All                  |
| `rc_injection`             | Write rejected and return code forced non-zero | MCUboot execute      |
| `write_disturb`            | Adjacent cell corruption                       | All                  |
| `write_rejection`          | Write dropped with no driver-visible error     | All                  |
| `multi_sector_atomicity`   | Cross-page partial erase                       | All                  |
| `wear_leveling_corruption` | Wear-leveling metadata corruption              | All                  |
| `reset_at_time`            | CPU reset at a time offset                     | All                  |
| `read_bit_flip`            | Transient read corruption                      | NVMemory, MRAM       |
| `instruction_skip`         | Voltage-glitch instruction skip (NOP)          | All                  |
| `nvs_corruption`           | NVS/config region corruption                   | All                  |
| `i2c_nack`                 | I2C NACK on secure element transaction         | I2CFaultProxy        |
| `i2c_timeout`              | I2C bus timeout                                | I2CFaultProxy        |
| `i2c_bit_flip`             | I2C data bit flip in transit                   | I2CFaultProxy        |
| `i2c_truncated`            | Truncated I2C transaction                      | I2CFaultProxy        |
| `i2c_wrong_address`        | I2C response from wrong address                | I2CFaultProxy        |
| `otp_partial_program`      | Partial OTP fuse blow                          | OTPMemory            |
| `otp_stuck_bit`            | OTP bit stuck at 0 or 1                        | OTPMemory            |
| `otp_read_disturb`         | OTP read returns wrong value                   | OTPMemory            |
| `otp_overblow`             | OTP fuse blown past threshold                  | OTPMemory            |

### Swap progress (semantic cutpoints)

`swap_progress` is the first semantic fault selector beyond raw write indices. Instead of "cut power at write N", it means "let the bootloader make real swap progress, interrupt it at the next slot-sector boundary, then reboot and observe resume behavior."

```yaml
fault_sweep:
  mode: runtime
  evaluation_mode: execute
  fault_types: [swap_progress]
  max_writes: auto
```

This is aimed at resume-path bugs: off-by-one sector indexing, wrong-slot resume, stale trailer cleanup, rollback loops, and similar state-machine failures that only appear on the boot after interruption.

Implementation details:

- Calibration must run, because `swap_progress` is derived from the clean write/erase trace.
- Tardigrade prefers calibration erase data to detect real sector boundaries.
- If no erase trace is available, tardigrade falls back to uniform `memory.page_size` buckets.
- On non-uniform flash such as STM32F4, the erase trace is the important source of truth; `page_size` fallback is only approximate.
- A clean result also requires coverage. If calibration only touches slot trailers/metadata, only touches flash outside the declared slots, or performs no NVM activity at all, tardigrade fails the run instead of reporting a clean `PASS`.

### Instruction skip (voltage glitch)

The `instruction_skip` fault type models a voltage-glitch attack that causes the CPU to skip one or more instructions. Each fault point is an instruction address rather than an NVM write index. The harness replaces the target instruction with Thumb NOPs (`0xBF00`), boots the firmware, and checks whether the system still recovers.

For instruction\_skip testing, the tool automatically suppresses sysbus warnings from wild-pointer dereferences caused by NOP'd instructions. NOP'd crypto or big-number code often corrupts pointer registers, causing reads/writes to unmapped addresses. These are expected denial-of-service outcomes (HardFault on real silicon) and do not require platform REPL changes. `sweep_hash_bypass_symbols` is also automatically disabled when `instruction_skip` is in `fault_types`, since hash bypass patches break image validation and make instruction-skip findings meaningless.

`driver_error` is a non-halting write fault. The target write does not land, but the peripheral raises a software-visible error flag/register. On nRF52 NVMC paths this currently behaves like `write_rejection` from the driver's point of view because the Zephyr NVMC driver only polls READY and does not inspect the injected error flag. The distinction is still useful in sweep results because it separates "data dropped silently" from "peripheral reported an error that software ignored."

`rc_injection` is a non-halting MCUboot-specific execute fault. It reuses the write-rejection data path so the target write does not land, then forces the active `flash_area_write()` call to return `-EIO` (`r0 = 0xFFFFFFFB`) when control returns to MCUboot. This directly tests the assert-only error-handling claim even on platforms where the flash driver would otherwise return success.

This requires an `instruction_skip_config` block inside `fault_sweep`:

```yaml
fault_sweep:
  fault_types: [power_loss, instruction_skip]
  instruction_skip_config:
    target_addresses:
      - { symbol: Reset }
      - { start: 0x00000100, end: 0x00000400 }
      - { start: 0x00001000, end: 0x00001200 }
    skip_count: 1
    severity_model: security
```

Each `target_addresses` entry may be either an explicit `{ start, end }` range or a `{ symbol }` query. `symbol` specs support two matching modes: plain strings use substring matching (`{ symbol: Validate }` matches every function whose name contains `Validate`), while fnmatch glob patterns use case-sensitive glob matching (`{ symbol: "bootutil_img_validate*" }` matches `bootutil_img_validate` and `bootutil_img_validate_encrypted_uniflash` but not `do_bootutil_img_validate`). A string is treated as a glob if it contains `*`, `?`, or `[`. Mixed lists are supported.

When a symbol matches multiple functions, tardigrade includes every matching range and logs the resolved addresses at profile-load time. If a query matches nothing, profile loading fails with a clear error that lists the available function symbols. For `STT_FUNC` entries with `st_size: 0`, tardigrade infers the end address from the next function symbol.

`target_addresses` ultimately resolves to address ranges to scan. Tardigrade walks those ranges as Thumb instructions, not raw halfwords: second halfwords of 32-bit Thumb instructions are skipped automatically and never become standalone fault points. `start` must be halfword-aligned. `skip_count` controls how many consecutive instructions to NOP (default 1). A single skipped 32-bit instruction automatically patches both halfwords to `0xBF00`.

Instruction-skip fault points are always run in execute mode (full CPU boot) -- trace replay is not applicable since the fault is CPU-level, not NVM-level.

To find good target ranges, disassemble your bootloader ELF and identify critical code paths: hash validation, signature checks, version comparisons, or metadata parsing. Narrow ranges produce faster sweeps; whole-function ranges give broader coverage.

`severity_model` controls whether crash-only instruction skips are treated as informational noise or as findings:

- `security` (default): only `security_bypass` outcomes count as findings. Crash-only results are reported as `dos_crash` / `dos_recovery` advisories and do not fail the verdict.
- `availability`: crash-only instruction skips remain findings. Use this for safety-critical systems where denial of service is itself unacceptable.

```yaml
fault_sweep:
  fault_types: [instruction_skip]
  instruction_skip_config:
    target_addresses:
      - { symbol: bootutil_img_validate }
    severity_model: availability
```

With the default `security` model, a hardened bootloader can produce a verdict like:

```text
PASS — 0 security bypass points (253 DoS crash points, expected for glitch model)
```

Only true bypasses such as `wrong_image`, `rollback_accepted`, or equivalent verification escapes fail the sweep.

#### Verification probes

`verification_probes` add deterministic layer-by-layer return-value capture to instruction-skip sweeps. This is useful when a skipped instruction might breach one verification function but a later function still catches the tampered image.

```yaml
fault_sweep:
  fault_types: [instruction_skip]
  instruction_skip_config:
    target_addresses:
      - { symbol: bootutil_img_validate }
  verification_probes:
    - symbol: bootutil_img_validate
      return_register: r0
      success_value: 0
      label: hash_validation
    - symbol: "boot_validate_slot.isra.3"
      return_register: r0
      success_value: 0
      label: slot_validation
```

For compatibility with older prompts and notes, tardigrade also accepts the legacy wrapper form:

```yaml
fault_sweep:
  fault_types: [instruction_skip]
  verification_bypass_probe:
    enabled: true
    probe_functions:
      - symbol: bootutil_img_validate
        expected_success_value: 0
        layer: hash_validation
```

`verification_bypass_probe.probe_functions[*].layer` maps to the probe label, and `expected_success_value` maps to `success_value`. Use either `verification_probes` or `verification_bypass_probe`, not both.

Each probe attaches to the function symbol, records the return register on the first completed call, and emits structured telemetry in the result JSON:

- `verification_probes`
- `verification_probe_classification`
- `verification_defense_in_depth`
- `verification_bypass_labels`
- `verification_bypass_detected`
- `verification_full_bypass`

This lets tardigrade distinguish:

- CPU crash before verification
- first layer held
- first layer breached but later layer caught it
- full end-to-end bypass

### Sweep strategy

Default is `heuristic` — classifies writes by address and samples densely near trailer/metadata regions, sparsely over bulk data. Override with `sweep_strategy: exhaustive` for full coverage (slower).

### Hash bypass

If your bootloader validates image hashes (SHA-256, CRC), the Phase 2 recovery boot spends most of its time in crypto. Bypass it for speed:

```yaml
fault_sweep:
  sweep_hash_bypass_symbols: ["bootutil_img_validate"]
```

Symbol names support fnmatch glob patterns (e.g., `bootutil_img_validate*`). Plain strings use substring matching as before. Patches the named function to return 0 immediately, but only for faulted sweep runs. Control boots, calibration, and `partial_staging` keep normal validation behavior. Add `--no-hash-bypass` on the CLI to disable the optimization entirely.

### Heuristic tuning

```yaml
fault_sweep:
  heuristic_config:
    tier2_step: 3 # sample every Nth write in boundary regions
    tier3_step: 100 # sample every Nth write in bulk data
    target_points: 500 # cap total points (overrides step calculations)
    critical_regions:
      - { start: 0x00081FE0, end: 0x00082000 } # always Tier 0
      - { symbol: boot_set_confirmed } # resolve from bootloader ELF
```

`critical_regions` promotes matching writes into Tier 0, alongside `memory.bootloader_region`. Use this when you already know that certain metadata writes are security-critical and should never be thinned by the heuristic. Each entry may be either:

- `{ start, end }` explicit bus-address range
- `{ symbol }` substring query resolved against bootloader ELF function symbols

Symbol resolution uses the same `STT_FUNC` substring matching as `instruction_skip_config`. Matching writes are counted in `critical_region_writes` and included in `tier0_count` in the heuristic summary.

### Reset mode

```yaml
fault_sweep:
  reset_mode: cold # default: warm
```

`warm` does `machine Reset` (CPU reset, NVM persists). `cold` saves NVM state, resets the entire machine, then restores NVM — models a full power cycle where volatile state (SRAM, peripheral registers) is lost.

### Phase 2 timing

```yaml
fault_sweep:
  phase2_time_slice: "0.05" # emulation slice for recovery boot (default: calibration_time_slice)
  progress_stall_timeout_s: 10.0 # wall-clock timeout for zero-progress stall detection
```

`phase2_time_slice` controls the emulation time per slice during Phase 2 recovery boot. Defaults to the calibration slice. Larger values mean fewer IPC round-trips but coarser progress detection. `progress_stall_timeout_s` is the wall-clock timeout for detecting a stalled bootloader (zero NVM writes across consecutive slices). When a stall is detected with the PC inside a slot, the outcome is `no_boot` (bricked); with active writes, it's `timeout` (needs more time).

### Write-back durability model

Real storage stacks (FTL, NOR flash with write buffering, eMMC) often buffer writes in RAM before committing to physical storage. A bootloader that assumes write-through durability can have latent bugs invisible to direct fault injection. The NuttX nxboot vulnerability (92/94 failure rate) was caused by exactly this: `CONFIG_FTL_WRITEBUFFER=y` buffered writes that the bootloader assumed were durable.

```yaml
fault_sweep:
  durability_model: writeback
  writeback:
    buffer_capacity: auto # writes buffered before eviction (default: one erase sector)
    erase_flushes_domain: false # does an erase force a buffer flush?
    barriers: # addresses that force a buffer flush
      - address: "0x10002000"
```

**`durability_model`**: `"direct"` (default) or `"writeback"`. Direct mode writes go straight to flash. Writeback mode interposes a volatile buffer — writes accumulate and are discarded on power loss unless explicitly flushed by a barrier.

**`buffer_capacity`**: Number of write operations the buffer holds before evicting the oldest. `"auto"` (default) sets it to one erase sector worth of writes (`erase_size / write_granularity`). Set an explicit integer for a known buffer depth.

**`barriers`**: List of addresses that force a complete buffer flush when written. Models explicit `fsync()` / cache-flush instructions. Each entry has an `address` key (hex or decimal).

**`erase_flushes_domain`**: When `true`, erase operations flush the write buffer for the affected domain. Set `true` for storage stacks where erases are synchronous barriers.

The writeback model only affects the faulted flash state used for Phase 2 recovery boot. Phase 1 execution sees all writes (optimistic) — this is conservative: if the bootloader survives writeback mode, it would also survive on real hardware where reads might return stale data.

Diagnostics include a barrier audit (detects missing flush barriers between update phases), per-fault dirty-domain state, and a `commit_ratio` metric.

### Read fault injection

```yaml
fault_sweep:
  read_fault_config:
    target_regions: [exec, staging] # which slots to inject read faults in
    bit_flip_count: 1 # bits to flip per faulted read
    fault_probability: 0.01 # probability of fault per read operation
    seed: 42 # deterministic PRNG seed
```

Injects bit-flip faults on CPU reads from NVM, modeling read-disturb effects. Requires a backend that intercepts CPU reads (NVMemory or MRAMMemory — fast-path backends like NVMC expose flash via MappedMemory that the CPU reads directly). Execute-mode only.

## Multi-boot and confirm/rollback

Many bootloaders require the application to confirm a new image within N boots, otherwise they roll back. Model this with `boot_cycles` and `boot_cycle_hook`:

```yaml
fault_sweep:
  boot_cycles: 3
  boot_cycle_hook: path/to/confirm_hook.py
  expected_rollback_at_cycle: 2
```

`boot_cycles` runs the recovery boot N times. Between each boot, `boot_cycle_hook` runs a Python script that can write to NVM (simulating app confirmation). `expected_rollback_at_cycle` tells the `successful_rollback` invariant when rollback should complete.

A hook script is a Python file with a `run(monitor)` function:

```python
def run(monitor):
    # Simulate app confirming the new image by writing to otadata
    monitor.Parse("sysbus WriteDoubleWord 0x000F8000 0x00000002")
```

## Write-order constraints

Assert that calibration writes happen in the correct order -- e.g., inactive replica updated before active:

```yaml
write_order_constraints:
  - first: { start: 0x00080100, size: 0x20 }
    then: { start: 0x00080000, size: 0x20 }
    label: "inactive replica before active"
```

Checked against the calibration write trace. Violations are reported before the sweep starts.

#### Bidirectional constraints

For dual-replica metadata where the active/inactive role alternates (e.g., based on sequence numbers), use `bidirectional: true`. The constraint passes if either region is fully written before the other starts. It only violates when writes to both regions are interleaved:

```yaml
write_order_constraints:
  - first: { start: 0x00080000, size: 0x20 }
    then: { start: 0x00080100, size: 0x20 }
    bidirectional: true
    label: "replicas must not interleave"
```

## State probes and semantic assertions

### State probes

A state probe is a Python script that reads NVM after each fault point and exports structured state. This enables semantic assertions and invariants that go beyond boot/no-boot.

```yaml
state_probe:
  script: targets/nxboot/probe.py
```

The probe script must define `probe(monitor) -> dict` that reads memory via `monitor.Parse()` and returns a dict. The returned state is available to assertions and invariants as `nvm_state`.

### Semantic assertions

Path-based expectations over the probe output:

```yaml
semantic_assertions:
  control: # checked on the control run (no fault)
    semantic_state.roles.primary_confirmed: false
    semantic_state.roles.recovery_valid: true
    multi_boot_analysis.final_outcome: success
```

A point fails if any assertion doesn't match, even if the device booted.

## Invariants

### Built-in invariants

Tardigrade ships 14 postcondition invariants. Enable them by name:

```yaml
invariants:
  - at_least_one_bootable # single fault can't brick both slots
  - boot_matches_metadata # boot slot matches what metadata says
  - metadata_single_fault_consistency # at least one metadata replica survives
  - slot_integrity # booted slot has valid ARM vectors
  - multi_boot_converges # repeated boots settle to a stable state
  - successful_rollback # rollback completes by expected cycle
  - metadata_seq_monotonic # sequence numbers don't regress
  - slot_hash_consistent # recorded hash matches actual image
  - rollback_version_bounded # anti-rollback floor doesn't spike
  - no_unauthorized_state_promotion # no testing-to-accepted without trial boot
  - boot_registers_match # captured registers match expected values
  - boot_target_matches_metadata # boot slot matches metadata active slot
  - last_known_good_preserved # at least one slot has a valid image
  - no_oob_writes # no writes outside allowed regions
```

Use `invariants: [strict]` to enable all of them.

### Custom invariant providers

For target-specific checks, write an invariant provider module:

```python
# targets/my_bootloader/invariants.py
from invariants import InvariantViolation

def check_my_custom_property(result, **_):
    nvm = result.nvm_state
    if not isinstance(nvm, dict):
        return
    if nvm.get("some_flag") == "bad_value":
        raise InvariantViolation(
            invariant_name="my_custom_property",
            description="Flag was corrupted by fault",
            result=result,
            details={"some_flag": nvm.get("some_flag")},
        )

def register_invariants():
    return {
        "my_custom_property": check_my_custom_property,
    }
```

Reference it from the profile:

```yaml
invariant_providers:
  - targets/my_bootloader/invariants.py
invariants:
  - my_custom_property
  - at_least_one_bootable
```

The module must define either `register_invariants()` returning a `{name: callable}` dict, or a module-level `INVARIANTS` dict.

## Expect block

The `expect` block tells the self-test harness whether this profile _should_ find issues:

```yaml
expect:
  should_find_issues: false # resilient bootloader: expect no bricks
  control_outcome: success # unfaulted run should boot successfully
```

For known-vulnerable code (differential testing), set `should_find_issues: true`. The self-test fails if the sweep doesn't find issues.

### Control-only issues

Some bugs manifest in the control path (unfaulted boot) rather than under fault injection. For example, MCUboot PR #2199's stuck-revert bug produces `wrong_image` on the control boot itself, with zero fault-induced issue points. Use `allow_control_only_issues` to tell tardigrade that a broken control outcome counts as a valid finding:

```yaml
expect:
  should_find_issues: true
  control_outcome: wrong_image
  allow_control_only_issues: true
```

When `allow_control_only_issues: true` and the control boot matches `control_outcome`, tardigrade treats the profile as having found issues even if the fault sweep itself produces no additional issue points. Without this flag, a sweep with zero fault-induced issues would fail the `should_find_issues: true` assertion.

## Advanced features

### Metadata fault injection

Inject faults during the pre-boot metadata/setup writes (before the main firmware runs):

```yaml
fault_sweep:
  metadata_fault:
    enabled: true
    fault_types: [power_loss]
metadata_fault_regions:
  - { name: trailer_a, start: 0x00081FF0, size: 16 }
  - { name: trailer_b, start: 0x000F7FF0, size: 16 }
```

### Phase 2 and hook faults

Inject faults during the recovery boot's own writes, or during between-boot hook writes:

```yaml
fault_sweep:
  phase2_fault:
    enabled: true
    fault_types: [power_loss]
    max_points: 100
  hook_fault:
    enabled: true
    fault_types: [power_loss]
    max_points: 50
```

Gotcha: `phase2_fault` does not sweep the full Cartesian product of every
single-fault point against every recovery write. It uses representative phase-1
points (first/middle/last from the main write plan) and then sweeps recovery
indices across `max_points`. This keeps the execute-mode search bounded while
still exercising the second-stage recovery machinery.

### Multi-fault sweeps

Test compound failures (two sequential faults):

```yaml
fault_sweep:
  multi_fault:
    enabled: true
    max_faults_per_run: 2
    strategy: pairwise_interesting
    max_pairs: 5000
```

Gotcha: `pairwise_interesting` is seeded by the issue-producing points from the
preceding single-fault sweep. If the single-fault campaign finds no interesting
points, the default fallback is `boundary_pairs`, which still exercises the
multi-fault runtime path using boundary points from the original sweep.

Reference smoke profiles:

- `profiles/mcuboot_head_move_nrf52_revert_phase2fault_selftest.yaml`
- `profiles/mcuboot_head_move_nrf52_upgrade_multifault_selftest.yaml`

### Initial states

Expand one profile into multiple sweep runs with different starting conditions:

```yaml
initial_states:
  - name: fresh_upgrade
    update_trigger:
      type: mcuboot_trailer_magic
      slot: staging
  - name: pending_revert
    update_trigger:
      type: mcuboot_trailer_magic
      slot: exec
      copy_done: 1
```

### Extra peripherals

Load custom Renode C# peripherals (e.g., flash controllers with non-standard behavior):

```yaml
extra_peripherals:
  - peripherals/STM32H7FlashController.cs
```

### NVM controller

For MRAM platforms with a separate command-register controller:

```yaml
nvm_controller: flash_ctrl
```

Enables `command_drop` fault type on MRAM paths.

### OTP peripheral

For platforms with one-time-programmable fuse memory (anti-rollback counters, security fuses):

```yaml
otp_peripheral: sysbus.otp
```

Enables the OTP fault types (`otp_partial_program`, `otp_stuck_bit`, `otp_read_disturb`, `otp_overblow`). Requires the `OTPMemory.cs` peripheral on the platform. See [`docs/otp-backend.md`](otp-backend.md) for the OTP fault model.

### I2C fault injection

For platforms with I2C-attached secure elements (e.g., ATECC608 for ECDSA signature verification):

```yaml
fault_sweep:
  fault_types: [power_loss, i2c_nack, i2c_timeout]
  i2c_fault_config:
    peripheral_name: sysbus.i2c_proxy
    target_address: 0x60
    fault_types:
      [i2c_nack, i2c_timeout, i2c_bit_flip, i2c_truncated, i2c_wrong_address]
```

`peripheral_name` is the sysbus name of the `I2CFaultProxy.cs` peripheral. `target_address` is the 7-bit I2C address of the device to fault (0-127). The proxy intercepts I2C transactions to the target and injects the configured fault types. See [`docs/i2c-fault-model.md`](i2c-fault-model.md) for the I2C fault model.

### Success criteria overrides

Override success criteria for specific fault types. Useful when certain fault classes are expected to produce different outcomes:

```yaml
success_criteria_overrides:
  bit_corruption:
    vtor_in_slot: any
  i2c_nack:
    vtor_in_slot: exec
```

Each key is a fault type name; the value is a partial success criteria dict that overrides the top-level `success_criteria` for that fault type.

### Partial staging

Model interrupted or overlapping staging-image writes (the update was only partially downloaded before the fault):

```yaml
fault_sweep:
  partial_staging:
    enabled: true
```

`partial_staging` always runs with normal image validation behavior. Even if the profile sets `sweep_hash_bypass_symbols`, those bypass patches apply only to faulted runtime sweep points, not to partial-staging checks.

### NVS region

Model a separate config/NVS region that gets corrupted independently of firmware slots:

```yaml
nvs_region:
  address: 0x000F0000
  size: 0x8000
  snapshot: path/to/nvs_snapshot.bin
```

Used with `nvs_corruption` fault sweep config for NVS-specific fault injection modes (bit flip, partial erase, truncation).

### Bootloader region

Model the bootloader's own code region for self-update or integrity fault scenarios:

```yaml
bootloader_region:
  base: 0x00000000
  size: 0xC000
```

Enables Tier 0 heuristic classification: writes targeting the bootloader
region are always included in the fault point set regardless of the
heuristic sampling strategy. Note that `bootloader_region_write` is a
classification label, not an injectable fault type -- the actual fault
injection uses `power_loss`, `bit_corruption`, etc. at those write indices.

### Multi-component

Coordinate fault analysis across independently-updatable firmware components (e.g., app MCU + radio coprocessor):

```yaml
multi_component:
  fault_matrix: cross_product
  components:
    - name: app_mcu
      platform: platforms/cortex_m4_flash_fast.repl
      bootloader: { elf: app_boot.elf, entry: 0x00000000 }
      memory: { ... }
      images: { ... }
    - name: radio
      platform: platforms/cortex_m0_nvm.repl
      bootloader: { elf: radio_boot.elf, entry: 0x10000000 }
      memory: { ... }
      images: { ... }
```

Each component is swept independently; `fault_matrix: cross_product` tests fault combinations across components.

### Security policy

Model anti-rollback and TOCTOU scenarios:

```yaml
security_policy:
  anti_rollback: true
  minimum_version: 5
  toctou_protection: true
```

## State fuzzer

The `state_fuzzer` block generates random and boundary-value metadata states to stress-test bootloader invariants. Instead of replaying a single known-good metadata configuration, it synthesizes many plausible and deliberately invalid metadata blobs, writes them as `pre_boot_state`, and runs the sweep for each -- catching bootloaders that crash or misbehave on unexpected metadata combinations.

### Configuration

```yaml
state_fuzzer:
  enabled: true
  iterations: 200 # number of random states to generate (default: 100)
  seed: 42 # PRNG seed for reproducibility (default: 0)
  metadata_model: ab_replica # built-in model name, or inline model (see below)
```

`metadata_model` can be either a built-in name (`ab_replica`) or an inline model that describes the metadata region layout:

```yaml
state_fuzzer:
  enabled: true
  iterations: 50
  seed: 0
  metadata_model:
    base_address: 0x00080000
    fill: 0xFF # fill byte for unspecified offsets (default: 0xFF)
    fields:
      - { name: magic, offset: 0, size: 4, valid: [0x4F54414D] }
      - { name: seq, offset: 4, size: 4, type: uint32 }
      - { name: active_slot, offset: 8, size: 4, valid: [0, 1] }
      - { name: state, offset: 16, size: 4, valid_range: [0, 4] }
      - { name: crc, offset: 252, size: 4, type: computed_crc32 }
```

Each field requires `name`, `offset`, and `size`. Optional properties:

- `valid`: list of allowed values (fuzzer picks from these for valid states, generates out-of-range values for invalid states)
- `valid_range`: `[min, max]` inclusive range of allowed values
- `type`: `uint32` (generic integer) or `computed_crc32` (auto-computed CRC-32 over preceding fields; must be the final field; at most one per model)

The fuzzer generates a mix of fully valid states, single-field boundary violations, and random combinations, then checks whether the bootloader handles each gracefully.

## Interpreting results

### Verdicts

The top-level verdict is `PASS` or `FAIL`. This is what CI gates on.

- **PASS + `should_find_issues: false`**: No bricks, no wrong-image, no invariant violations. The bootloader survived all faults.
- **PASS + `should_find_issues: true`**: Issues were found (expected for known-vulnerable code).
- **FAIL**: Unexpected result — either issues found when none expected, or no issues found when expected.

For write/erase-style campaigns, a clean `PASS` also requires calibration coverage. If calibration never shows slot data movement, tardigrade treats the run as a failed setup rather than evidence that the bootloader is clean.

### Boot outcomes

Each fault point produces one of:

| Outcome       | Meaning                                                 |
| ------------- | ------------------------------------------------------- |
| `success`     | Device booted to the correct slot                       |
| `wrong_image` | Device booted but to the wrong slot or with wrong image |
| `no_boot`     | Device did not reach any valid vector table             |
| `wrong_pc`    | PC ended up outside all known slots                     |
| `hard_fault`  | CFSR indicated a HardFault                              |

### Failure classes

Outcomes are grouped into classes:

| Class               | Meaning                                                |
| ------------------- | ------------------------------------------------------ |
| `recoverable`       | Device booted successfully to the expected slot        |
| `wrong_image`       | Booted but with wrong firmware — state-correctness bug |
| `silent_corruption` | Booted successfully but invariant/assertion violated   |
| `unrecoverable`     | Device did not boot — brick                            |

### Report JSON structure

```
summary.runtime_sweep.total_points      -- how many fault points tested
summary.runtime_sweep.bricks            -- unrecoverable failures
summary.runtime_sweep.issue_points      -- any non-success result
summary.runtime_sweep.brick_rate        -- bricks / total
summary.runtime_sweep.timing            -- per-phase timing breakdown
runtime_sweep_results[]                 -- per-point detail
  .fault_at                             -- which write was faulted
  .fault_type                           -- power_loss, bit_corruption, etc.
  .boot_outcome                         -- success/wrong_image/no_boot/...
  .fault_class                          -- recoverable/wrong_image/unrecoverable
  .signals                              -- raw harness signals (VTOR, markers, etc.)
  .postmortem_partition_dump            -- (no_boot only) slot header/trailer data
  .resume_trace                         -- (no_boot only) PC samples from second boot
```

Use `scripts/render_results_html.py` to render the JSON as a browsable HTML report.

## CBMC bridge: formal verification to fault injection

`scripts/cbmc_to_profile.py` converts CBMC counterexamples into tardigrade profiles. The pipeline: CBMC proves a fault sequence _could_ cause corruption at the source level, then tardigrade runs the compiled firmware under that sequence to confirm whether it manifests in practice.

### Workflow

1. Write a CBMC harness that models your metadata parser with nondeterministic NVM contents.
2. Run CBMC to get a counterexample (JSON or XML output).
3. Convert to a tardigrade profile:

```bash
python3 scripts/cbmc_to_profile.py \
    --cbmc-output cbmc_output.json \
    --template    my_base_profile.yaml \
    --address-map address_map.yaml \
    --meta-size 16 \
    --output      /tmp/cbmc_generated.yaml
```

4. Run the generated profile:

```bash
python3 scripts/audit_bootloader.py --profile /tmp/cbmc_generated.yaml
```

The tool extracts byte-level array assignments from the counterexample trace, maps them to absolute flash addresses using the address map, and injects them as `pre_boot_state` writes in a copy of the template profile.

### Address map

Maps CBMC symbolic variable names to flash addresses:

```yaml
# address_map.yaml
meta_bytes: 0x00080000
header: 0x00040000
```

### Dry run

Use `--dry-run` to see the generated profile without writing files:

```bash
python3 scripts/cbmc_to_profile.py \
    --cbmc-output cbmc_output.json \
    --template    template.yaml \
    --address-map address_map.yaml \
    --output      /tmp/out.yaml \
    --dry-run
```

See [`examples/cbmc_bridge/`](../examples/cbmc_bridge/) for a complete worked example with a buggy metadata parser, CBMC harness, pre-generated counterexamples, and address maps.

## Fuzzer integration

Tardigrade bridges the gap between fuzz testing and fault-injection analysis. The pipeline: a fuzzer (libFuzzer, AFL, honggfuzz) finds crash inputs that break your header parser, then `fuzz_crash_to_profile.py` converts each crash into a regression profile that tardigrade runs under full emulation with fault injection.

### Template harness

`harnesses/fuzz_ota_header_template.c` is a generic libFuzzer harness for OTA image header parsers. Adapt it for your bootloader:

1. Replace the header struct and `parse_image_header()` stub with your real parser.
2. Add post-parse invariant checks (size bounds, version constraints, flag consistency).
3. Build and run:

```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/your/include \
    harnesses/fuzz_ota_header_template.c \
    /path/to/your/header_parser.c \
    -o fuzz_ota_header

mkdir -p corpus
./fuzz_ota_header corpus/ -max_len=512
```

Seed the corpus with a known-good header binary for faster coverage.

### Converting crashes to profiles

`scripts/fuzz_crash_to_profile.py` is a standalone CLI tool (usable outside tardigrade) that takes crash inputs and produces regression profiles.

**Single crash:**

```bash
python3 scripts/fuzz_crash_to_profile.py \
    --crash-input crashes/crash-abc123 \
    --base-profile profiles/my_bootloader.yaml \
    --address-map address_map.yaml \
    -o profiles/regression/fuzz_crash_abc123.yaml
```

**Batch mode** (process all crashes in a directory):

```bash
python3 scripts/fuzz_crash_to_profile.py \
    --crash-dir crashes/ \
    --base-profile profiles/my_bootloader.yaml \
    --address-map address_map.yaml \
    --output-dir profiles/regression/
```

The tool auto-detects AFL (`id:NNNNNN`) and libFuzzer (`crash-*`, `oom-*`, `timeout-*`) naming conventions.

#### Injection modes

`--mode pre_boot_state` (default): Crash bytes are mapped to NVM addresses via the address map and injected as `pre_boot_state` writes. Use this for metadata/trailer corruption.

`--mode staging_image`: Crash bytes replace the staging image binary. Use this for malformed firmware image testing -- the bootloader should reject the image and stay on the exec slot.

#### Address map

Describes how to partition sequential crash bytes into flash memory regions:

```yaml
# address_map.yaml
regions:
  - name: metadata
    address: 0x00080000
    size: 16
  - name: header
    address: 0x00040000
    size: 256
```

Without an address map, crash bytes go to sequential addresses starting at the end of the last slot (or `--meta-base` override).

#### Generated profile structure

Each generated profile includes:

- `fuzz_metadata` block with crash SHA-256, file name, size, fuzzer type, and generation timestamp
- `pre_boot_state` writes (pre_boot_state mode) or modified `images.staging` path (staging_image mode)
- `expect.should_find_issues: true` (override with `--no-expect-rejection`)

### fuzz_corpus profile field

Profiles can declare a `fuzz_corpus` directory containing fuzzer inputs to use as staging images in batch mode:

```yaml
fuzz_corpus: corpus/crashes/
```

This is an optional field for documenting the corpus associated with a profile. To run a crash corpus through the audit pipeline, use either:

```bash
python3 scripts/fuzz_corpus.py convert \
  --crash-dir corpus/crashes/ \
  --base-profile profiles/my_bootloader.yaml \
  --output-dir profiles/regression/

python3 scripts/audit_bootloader.py \
  --profile profiles/my_bootloader.yaml \
  --fuzz-crash-dir corpus/crashes/ \
  --output results/fuzz_regression_audit.json
```

### Legacy bridge

`scripts/fuzz_to_profile.py` is the original simpler converter. It still works and is tested, but `fuzz_crash_to_profile.py` is preferred for new workflows -- it adds crash metadata, batch mode, staging-image injection, and auto-detection of fuzzer types.

## Scenarios

`scripts/run_scenario.py` runs multi-step discovery sequences — each step is a profile sweep with optional overrides. Define scenarios in `scenarios/`:

```yaml
# scenarios/mcuboot_upgrade_then_revert.yaml
steps:
  - profile: profiles/mcuboot_head_upgrade.yaml
    description: "Forward upgrade"
  - profile: profiles/mcuboot_head_revert.yaml
    description: "Revert after failed confirmation"
    overrides:
      fault_sweep:
        fault_types: [power_loss, bit_corruption]
```

```bash
python3 scripts/run_scenario.py --scenario scenarios/mcuboot_upgrade_then_revert.yaml
```

## Geometry matrix

`scripts/geometry_matrix.py` generates parametric slot-layout permutations from a base profile to catch geometry-dependent bugs (e.g., different slot sizes, alignments, or offsets):

```bash
python3 scripts/geometry_matrix.py \
    --base-profile profiles/mcuboot_head_upgrade.yaml \
    --output-dir /tmp/geometry_profiles/
```

## Running sweeps

### Parallel workers

`--workers N` distributes fault points across N Renode instances. Points are interleaved (round-robin) for balanced load:

```bash
python3 scripts/audit_bootloader.py \
    --profile profiles/mcuboot_head_upgrade.yaml \
    --workers 4
```

### Docker

If you don't have `renode-test` installed locally, use the Docker backend:

```bash
python3 scripts/audit_bootloader.py \
    --profile profiles/mcuboot_head_upgrade.yaml \
    --renode-test docker://renode-patched:test
```

### Self-test

`scripts/self_test.py` runs the full defect corpus — all profiles with `skip_self_test: false` — and verifies each one matches its `expect` block:

```bash
python3 scripts/self_test.py \
    --renode-test /path/to/renode-test
```

Profiles with `skip_self_test: true` are skipped (typically narrow-window or CI-only profiles that need pre-built assets).

### Calibration caching

Calibration (running the firmware once to count NVM writes and build a trace) can be cached across runs. Pass `--reuse-calibration` with a path to a JSON cache file:

```bash
python3 scripts/audit_bootloader.py \
    --profile profiles/mcuboot_head_upgrade.yaml \
    --reuse-calibration /tmp/cal_cache.json
```

The cache key is derived from the ELF hash, image hashes, fault types, flash backend, and write granularity. If the file exists and the key matches, calibration is loaded from cache (skipping the Renode calibration run entirely). After a fresh calibration, the result is saved to the file for future reuse. This is useful in CI pipelines where the same ELF is swept with different profiles or parameters.

### Quick mode with heuristic points

By default, `--quick` picks 3 representative fault points (first, middle, last). Set `quick_use_heuristic: true` in `fault_sweep` to use heuristic-selected points instead, which gives better coverage of trailer and boundary regions:

```yaml
fault_sweep:
  quick_use_heuristic: true
  max_heuristic_points: 64
```

`max_heuristic_points` caps the total heuristic output (default 2000 for full sweeps). When combined with `quick_use_heuristic: true`, this controls how many points `--quick` mode runs -- typically set to 64 for a fast but meaningful smoke test. Set to `null` to disable the cap entirely.

### Heuristic sharding

For large sweep suites in CI, shard across runners:

```yaml
fault_sweep:
  heuristic_config:
    shard_count: 4
    shard_index: 0 # 0, 1, 2, 3 on separate runners
```

Each shard gets a disjoint subset of heuristic fault points.

## Profile checklist

Before submitting a profile:

1. Does `--quick` pass? (smoke test: 3 fault points)
2. Does the control run (fault_at=0) boot successfully?
3. Is `flash_backend` set to the correct sysbus peripheral name?
4. Are slot addresses and sizes correct for your linker script?
5. Is `write_granularity` correct for your NVM technology?
6. Does `expect.should_find_issues` match your expectation?
7. For differential testing: do you have both broken and fixed ELFs?

## ESP-IDF OTA profiles

ESP-IDF uses a dual-sector otadata partition to track which OTA app slot to boot. Each sector contains a 32-byte `esp_ota_select_entry_t` with a sequence number, OTA state, and CRC-32. The bootloader selects the entry with the highest valid `ota_seq` and maps it to a slot index via `(ota_seq - 1) % num_slots`.

Tardigrade ships a clean-room model of this algorithm (`examples/esp_idf_ota/esp_idf_ota.c`) that compiles to a Cortex-M4 ELF running on the `cortex_m4_flash_fast.repl` platform. This is not ESP-IDF code -- it is a standalone reimplementation of the same algorithm for fault-injection testing.

### otadata layout

The otadata partition is two 4KB sectors, each starting with:

| Offset | Size | Field     | Description              |
| ------ | ---- | --------- | ------------------------ |
| 0      | 4    | ota_seq   | 1-based sequence number  |
| 4      | 20   | seq_label | Unused (0xFF from erase) |
| 24     | 4    | ota_state | State enum (see below)   |
| 28     | 4    | crc       | CRC-32 of ota_seq only   |

OTA state values: `NEW` (0), `PENDING_VERIFY` (1), `VALID` (2), `INVALID` (3), `ABORTED` (4), `UNDEFINED` (0xFFFFFFFF).

### Pre-boot state for ESP-IDF

Set up otadata entries using `pre_boot_state`. Each entry needs three writes (ota_seq, ota_state, crc):

```yaml
pre_boot_state:
  # Entry 0: ota_seq=1, VALID
  - { address: 0x000F8000, u32: 0x00000001 } # ota_seq
  - { address: 0x000F8018, u32: 0x00000002 } # ota_state = VALID
  - { address: 0x000F801C, u32: 0x4743989A } # CRC-32 of ota_seq=1
  # Entry 1: ota_seq=2, NEW
  - { address: 0x000F9000, u32: 0x00000002 } # ota_seq
  - { address: 0x000F9018, u32: 0x00000000 } # ota_state = NEW
  - { address: 0x000F901C, u32: 0x55F63774 } # CRC-32 of ota_seq=2
```

Use `examples/esp_idf_ota/gen_esp_idf_images.py otadata` to compute correct CRC values for arbitrary sequence numbers.

### State probe and invariants

The ESP-IDF target adapter (`targets/esp_idf/`) provides a state probe and four invariants:

```yaml
state_probe:
  script: targets/esp_idf/probe.py

invariant_providers:
  - targets/esp_idf/invariants.py
invariants:
  - esp_idf_otadata_crc_integrity # dual-sector CRC: at least one valid after fault
  - esp_idf_pending_verify_gets_aborted # unconfirmed images get ABORTED on reboot
  - esp_idf_active_entry_maps_to_valid_slot # selected slot matches actual boot
  - esp_idf_seq_not_zero # ota_seq=0 would silently select wrong slot
```

The probe reads both otadata sectors, validates CRC-32, determines the active entry, and exposes `replica0_valid`/`replica1_valid` for the built-in `metadata_single_fault_consistency` invariant.

### Upgrade vs rollback scenarios

**Upgrade** (`esp_idf_ota_upgrade.yaml`): Entry 0 = seq 1/VALID, entry 1 = seq 2/NEW. Bootloader writes PENDING_VERIFY to entry 1 and boots slot 1. Fault during the state transition tests whether the device falls back to slot 0.

**Rollback** (`esp_idf_ota_rollback.yaml`): Entry 0 = seq 1/VALID, entry 1 = seq 2/PENDING_VERIFY. Bootloader ABORTs entry 1 (app never confirmed) and boots slot 0. Fault during the ABORT write tests whether rollback completes.

### Defect variants

The model supports compile-time defect injection via `-DESP_DEFECT=N`. Each defect produces a separate ELF with a known vulnerability:

| Defect | Name             | What it breaks                                   | Profile                               |
| ------ | ---------------- | ------------------------------------------------ | ------------------------------------- |
| 1      | NO_CRC           | Skips CRC validation, accepts corrupt entries    | `esp_idf_fault_no_crc.yaml`           |
| 2      | SINGLE_SECTOR    | Only reads sector 0, no redundancy               | `esp_idf_fault_single_sector.yaml`    |
| 3      | NO_ABORT         | Skips PENDING_VERIFY abort, no rollback          | `esp_idf_fault_no_abort.yaml`         |
| 4      | NO_FALLBACK      | No fallback to other slot if selected is invalid | `esp_idf_fault_no_fallback.yaml`      |
| 5      | CRC_COVERS_STATE | CRC covers seq+state, breaks after state change  | `esp_idf_fault_crc_covers_state.yaml` |

Guard profiles (e.g., `esp_idf_ota_crc_guard.yaml`) test that the correct implementation handles the defect scenario properly.

## Examples to study

| Profile                                          | What it demonstrates                                                    |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| `profiles/fault_no_crc.yaml`                     | Minimal vulnerable-OTA profile                                          |
| `profiles/mcuboot_head_upgrade.yaml`             | MCUboot upgrade with image hash, update trigger, sweep-only hash bypass |
| `profiles/mcuboot_pr2100_broken_discovery.yaml`  | Differential testing (known bug, broken commit)                         |
| `profiles/nuttx_nxboot_128.yaml`                 | State probe, semantic assertions, custom invariants, multi-boot         |
| `profiles/esp_idf_ota_upgrade.yaml`              | ESP-IDF upgrade with state probe and otadata invariants                 |
| `profiles/esp_idf_ota_rollback.yaml`             | ESP-IDF rollback with semantic assertions on otadata state              |
| `profiles/esp_idf_ota_upgrade_confirm_hook.yaml` | Boot-cycle hook for confirm-or-rollback                                 |
