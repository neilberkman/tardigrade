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

## Choosing a platform

Tardigrade ships several platform backends. Pick the one that matches your NVM technology:

| Platform file                             | Backend               | NVM type    | Write granularity |
| ----------------------------------------- | --------------------- | ----------- | ----------------- |
| `platforms/cortex_m4_flash_fast.repl`     | `faultFlash` (NVMC)   | NOR flash   | 4 bytes           |
| `platforms/cortex_m0_nvm.repl`            | `nvm_ctrl` (NVMemory) | Generic NVM | 8 bytes           |
| `platforms/cortex_m0_mram.repl`           | `mram` (MRAMMemory)   | MRAM        | 8 bytes           |
| `platforms/stm32f4.repl`                  | STM32F4 flash         | NOR flash   | 4 bytes           |
| `platforms/nucleo_h753zi_tardigrade.repl` | STM32H7 flash         | NOR flash   | 4 bytes           |
| `platforms/cortex_m0_otp.repl`            | OTPMemory             | OTP fuses   | 4 bytes           |

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

RIOTboot headers are also supported:

```yaml
update_trigger:
  type: riotboot_header
  slot: staging
  version: 2
```

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

Default is `[power_loss]`. Available types (23 total):

| Fault type                 | What it does                            | Backend requirement  |
| -------------------------- | --------------------------------------- | -------------------- |
| `power_loss`               | Truncate write at fault point           | All                  |
| `bit_corruption`           | NOR-physics bit flips (1-to-0)          | All                  |
| `interrupted_erase`        | Partial page erase                      | NVMC, NVMemory       |
| `command_drop`             | Silently dropped NVM controller command | GenericNvmController |
| `silent_write_failure`     | Write accepted but data not stored      | All                  |
| `write_disturb`            | Adjacent cell corruption                | All                  |
| `write_rejection`          | Write rejected (error returned)         | All                  |
| `multi_sector_atomicity`   | Cross-page partial erase                | All                  |
| `wear_leveling_corruption` | Wear-leveling metadata corruption       | All                  |
| `reset_at_time`            | CPU reset at a time offset              | All                  |
| `read_bit_flip`            | Transient read corruption               | NVMemory, MRAM       |
| `instruction_skip`         | Voltage-glitch instruction skip (NOP)   | All                  |
| `nvs_corruption`           | NVS/config region corruption            | All                  |
| `i2c_nack`                 | I2C NACK on secure element transaction  | I2CFaultProxy        |
| `i2c_timeout`              | I2C bus timeout                         | I2CFaultProxy        |
| `i2c_bit_flip`             | I2C data bit flip in transit            | I2CFaultProxy        |
| `i2c_truncated`            | Truncated I2C transaction               | I2CFaultProxy        |
| `i2c_wrong_address`        | I2C response from wrong address         | I2CFaultProxy        |
| `otp_partial_program`      | Partial OTP fuse blow                   | OTPMemory            |
| `otp_stuck_bit`            | OTP bit stuck at 0 or 1                 | OTPMemory            |
| `otp_read_disturb`         | OTP read returns wrong value            | OTPMemory            |
| `otp_overblow`             | OTP fuse blown past threshold           | OTPMemory            |

### Instruction skip (voltage glitch)

The `instruction_skip` fault type models a voltage-glitch attack that causes the CPU to skip one or more instructions. Each fault point is an instruction address rather than an NVM write index. The harness replaces the instruction at the target address with a Thumb NOP (`0xBF00`), boots the firmware, and checks whether the system still recovers.

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
```

Each `target_addresses` entry may be either an explicit `{ start, end }` range or a `{ symbol }` query. `symbol` uses substring matching against `STT_FUNC` names in the bootloader ELF `.symtab`, so `{ symbol: Validate }` matches every function whose name contains `Validate`. Mixed lists are supported.

When a symbol matches multiple functions, tardigrade includes every matching range and logs the resolved addresses at profile-load time. If a query matches nothing, profile loading fails with a clear error that lists the available function symbols. For `STT_FUNC` entries with `st_size: 0`, tardigrade infers the end address from the next function symbol.

`target_addresses` ultimately resolves to address ranges to scan. Every halfword-aligned address in each range becomes a fault point. `start` must be halfword-aligned (Thumb instruction boundary). `skip_count` controls how many consecutive 16-bit halfwords to NOP (default 1). Set it to 2 to model skipping a 32-bit Thumb-2 instruction.

Instruction-skip fault points are always run in execute mode (full CPU boot) -- trace replay is not applicable since the fault is CPU-level, not NVM-level.

To find good target ranges, disassemble your bootloader ELF and identify critical code paths: hash validation, signature checks, version comparisons, or metadata parsing. Narrow ranges produce faster sweeps; whole-function ranges give broader coverage.

### Sweep strategy

Default is `heuristic` — classifies writes by address and samples densely near trailer/metadata regions, sparsely over bulk data. Override with `sweep_strategy: exhaustive` for full coverage (slower).

### Hash bypass

If your bootloader validates image hashes (SHA-256, CRC), the Phase 2 recovery boot spends most of its time in crypto. Bypass it for speed:

```yaml
fault_sweep:
  sweep_hash_bypass_symbols: ["bootutil_img_validate"]
```

Patches the named function to return 0 immediately, but only for faulted sweep runs. Control boots, calibration, and `partial_staging` keep normal validation behavior. Add `--no-hash-bypass` on the CLI to disable the optimization entirely.

### Heuristic tuning

```yaml
fault_sweep:
  heuristic_config:
    tier2_step: 3 # sample every Nth write in boundary regions
    tier3_step: 100 # sample every Nth write in bulk data
    target_points: 500 # cap total points (overrides step calculations)
```

### Reset mode

```yaml
fault_sweep:
  reset_mode: cold # default: warm
```

`warm` does `machine Reset` (CPU reset, NVM persists). `cold` saves NVM state, resets the entire machine, then restores NVM — models a full power cycle where volatile state (SRAM, peripheral registers) is lost.

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
  start: 0x00000000
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

## Interpreting results

### Verdicts

The top-level verdict is `PASS` or `FAIL`. This is what CI gates on.

- **PASS + `should_find_issues: false`**: No bricks, no wrong-image, no invariant violations. The bootloader survived all faults.
- **PASS + `should_find_issues: true`**: Issues were found (expected for known-vulnerable code).
- **FAIL**: Unexpected result — either issues found when none expected, or no issues found when expected.

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

This is an optional field. When set, the audit runner can iterate over all inputs in the directory and run each as a separate staging image, testing whether the bootloader correctly rejects every malformed input.

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

## Examples to study

| Profile                                          | What it demonstrates                                            |
| ------------------------------------------------ | --------------------------------------------------------------- |
| `profiles/fault_no_crc.yaml`                     | Minimal vulnerable-OTA profile                                  |
| `profiles/mcuboot_head_upgrade.yaml`             | MCUboot upgrade with image hash, update trigger, sweep-only hash bypass |
| `profiles/mcuboot_pr2100_broken_discovery.yaml`  | Differential testing (known bug, broken commit)                 |
| `profiles/nuttx_nxboot_128.yaml`                 | State probe, semantic assertions, custom invariants, multi-boot |
| `profiles/esp_idf_ota_upgrade_confirm_hook.yaml` | Boot-cycle hook for confirm-or-rollback                         |
