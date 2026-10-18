# MCUboot Fault-Type Coverage on nRF52840 Swap-Move

Eleven of the 28 fault types in `scripts/fault_types.py` ran against real MCUboot firmware in this session across eight nRF52840 swap-move profiles. One additional fault type, `instruction_skip`, ran against the same MCUboot ELF in existing verification profiles. The remaining 16 fault types in `scripts/fault_types.py` have never run against real firmware and exist only in synthetic `examples/` harnesses or documentation.

Across the eight target profiles run against `results/oss_validation/assets/oss_mcuboot_head_move_nrf52.elf` at MCUboot commit `f84b9d3fd019fb1945e532924bee7a9c03c77373`, all six profiles that bypass `bootutil_img_validate` during post-fault reboots reported zero issue points. The two profiles that remove `bootutil_img_validate` from `sweep_hash_bypass_symbols`, `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` and `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml`, reported seven and four issue points respectively. Six of the seven issue points in `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` and all four issue points in `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` occurred at flash write index `11907` at address `0x0000D860` because `boot_copy_region` in `boot/bootutil/src/loader.c` copies image sectors through `flash_area_write` without read-back verification, finishes the swap, erases the swap status trailer, and leaves corrupted bytes inside the primary slot payload that `bootutil_img_validate` rejects with `BOOT_EBADIMAGE` on reboot. The seventh issue point in `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` occurred under `driver_error` at write index `23814` at address `0x00081FE0` when `boot_write_image_ok` received `-5` from `flash_area_write` while dropping the `image_ok` write and aborted Phase 1 with `FIH_PANIC`.

## Coverage of All 28 Fault Types in `scripts/fault_types.py`

`scripts/fault_types.py` registers 28 fault types in `FAULT_TYPE_INFO`. The table below lists every fault type, its code token, its execution status against real firmware, and the profile or document where it appears.

| Fault type | Code | Status | Profile or documentation reference |
| :--- | :--- | :--- | :--- |
| `power_loss` | `w` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_upgrade_multifault.yaml`, `docs/mcuboot-oss-validation-findings.md` |
| `swap_progress` | `w:sp` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_upgrade_multifault.yaml`, `profiles/mcuboot_head_move_nrf52_upgrade.yaml`, `docs/mcuboot-oss-validation-findings.md` |
| `security_state_erase` | `w:ss` | never run against real firmware | `docs/oss-agent-briefs/04-security-state-erase-domain-analysis.md`, `docs/writing-profiles.md` |
| `interrupted_erase` | `e` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_extended.yaml` |
| `bit_corruption` | `b` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_extended.yaml` |
| `silent_write_failure` | `s` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_long.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml`, `profiles/mcuboot_pr2109_scratch_broken_silent.yaml` |
| `driver_error` | `g` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_stm32f4_revert_driver_error.yaml`, `docs/mcuboot-stm32f4-findings.md` |
| `rc_injection` | `x` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_rc_injection.yaml`, `profiles/mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml`, `profiles/mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml` |
| `write_disturb` | `d` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_long.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` |
| `wear_leveling_corruption` | `l` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_long.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` |
| `multi_sector_atomicity` | `a` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` |
| `write_rejection` | `r` | run against real firmware in this session | `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_long.yaml`, `profiles/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` |
| `read_bit_flip` | `f` | never run against real firmware | `docs/writing-profiles.md` |
| `instruction_skip` | `i` | run elsewhere | `profiles/mcuboot_head_move_nrf52_verify_instruction_skip.yaml`, `profiles/mcuboot_head_move_nrf52_revert_instruction_skip.yaml`, `profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical.yaml`, `profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates.yaml`, `profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full.yaml`, `docs/mcuboot-oss-validation-findings.md` |
| `reset_at_time` | `t` | never run against real firmware | synthetic `examples/esp_idf_ota/esp_idf_ota.elf` in `profiles/esp_idf_ota_upgrade_reset_at_time.yaml` |
| `command_drop` | `k` | never run against real firmware | synthetic `examples/` targets in `profiles/esp_idf_ota_upgrade_hook_fault.yaml`, `profiles/esp_idf_ota_upgrade_confirm_cycle.yaml`, `profiles/nxboot_style_hook_fault.yaml` |
| `otp_partial_program` | `op` | never run against real firmware | synthetic `examples/vulnerable_ota/firmware.elf` in `profiles/security_otp_rollback_counter.yaml`, `profiles/security_otp_security_fuses.yaml`, `docs/otp-backend.md` |
| `otp_stuck_bit` | `os` | never run against real firmware | synthetic `examples/vulnerable_ota/firmware.elf` in `profiles/security_otp_rollback_counter.yaml`, `docs/otp-backend.md` |
| `otp_read_disturb` | `od` | never run against real firmware | synthetic `examples/vulnerable_ota/firmware.elf` in `profiles/security_otp_security_fuses.yaml`, `docs/otp-backend.md` |
| `otp_overblow` | `oo` | never run against real firmware | `docs/otp-backend.md`, `docs/writing-profiles.md` |
| `otp_blow_nop` | `on` | never run against real firmware | synthetic `examples/firmware_otp_harness/harness.elf` and `examples/vulnerable_ota/firmware.elf` in `profiles/firmware_otp_blow_nop_harness.yaml`, `profiles/security_otp_blow_nop.yaml`, `docs/otp-backend.md` |
| `timed_bit_corruption` | `tb` | never run against real firmware | `docs/writing-profiles.md` |
| `nvs_corruption` | `nv` | never run against real firmware | `docs/writing-profiles.md` |
| `i2c_nack` | `in` | never run against real firmware | `docs/i2c-fault-model.md`, `docs/writing-profiles.md` |
| `i2c_timeout` | `it` | never run against real firmware | `docs/i2c-fault-model.md`, `docs/writing-profiles.md` |
| `i2c_bit_flip` | `ib` | never run against real firmware | `docs/i2c-fault-model.md`, `docs/writing-profiles.md` |
| `i2c_truncated` | `ic` | never run against real firmware | `docs/i2c-fault-model.md`, `docs/writing-profiles.md` |
| `i2c_wrong_address` | `iw` | never run against real firmware | `docs/i2c-fault-model.md`, `docs/writing-profiles.md` |

## Exact Commands Run

All eight target profiles were run in the foreground against `docker://tardigrade-oss-validation:latest` with the commands below:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_full_fault_coverage_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/driver_error_after_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_write_faults.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_write_faults_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_write_faults_long.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_write_faults_long_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_write_faults_nohashbypass_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_multifault.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_upgrade_multifault_after_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_rc_injection.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_rc_injection_quick.json

python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_rc_injection_multiboot_quick.json

timeout 1500 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_stm32f4_revert_driver_error.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 2 --no-assert-verdict --output results/coverage/stm32f4_driver_error_before_quick.json

timeout 1500 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_stm32f4_revert_driver_error.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 2 --no-assert-verdict --output results/coverage/stm32f4_driver_error_after_quick.json

timeout 900 python3 scripts/audit_bootloader.py --profile results/coverage/mcuboot_nrf52_driver_error_boot_cycles_3.yaml --renode-test docker://tardigrade-oss-validation:latest --quick --workers 2 --no-assert-verdict --output results/coverage/nrf52_driver_error_boot_cycles_3_quick.json

timeout 3000 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass_full.json

timeout 2400 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 4 --no-assert-verdict --output results/coverage/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass_full.json
```

## Per-Profile Quick Sweep Results

Every profile below ran against `results/oss_validation/assets/oss_mcuboot_head_move_nrf52.elf`. The seven revert profiles calibrated at `23,815` flash writes and `42` sector erases. The upgrade multi-fault profile calibrated at `19,685` flash writes and `38` sector erases.

| Profile | Verdict | `security_aggregate.status` | Points | Issue points | Bricks | Timeouts | Calibration s | Total wall s | Per-type point breakdown |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `mcuboot_head_move_nrf52_revert_full_fault_coverage` | `PASS` | `INCONCLUSIVE` | 30 | 0 | 0 | 0 | 55.7 | 990.6 | `w:3, e:3, a:3, b:3, s:3, g:3, x:3, d:3, l:3, r:3` |
| `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass` | `PASS` with `should_find_issues: true` | `FINDINGS` | 30 | 7 | 7 | 0 | 58.1 | 1150.9 | `w:3, e:3, a:3, b:3, s:3, g:3, x:3, d:3, l:3, r:3` |
| `mcuboot_head_move_nrf52_revert_write_faults` | `PASS` | `INCONCLUSIVE` | 12 | 0 | 0 | 0 | 64.5 | 575.7 | `r:3, s:3, d:3, l:3` |
| `mcuboot_head_move_nrf52_revert_write_faults_long` | `PASS` | `INCONCLUSIVE` | 12 | 0 | 0 | 0 | 90.0 | 667.6 | `r:3, s:3, d:3, l:3` |
| `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass` | `PASS` with `should_find_issues: true` | `FINDINGS` | 12 | 4 | 4 | 0 | 59.1 | 563.7 | `r:3, s:3, d:3, l:3` |
| `mcuboot_head_move_nrf52_upgrade_multifault` with `--workers 4` | `PASS` | `INCONCLUSIVE` | 6 single-fault, 5 multi-fault | 0 | 0 | 0 | 137.4 | 430.6 | `w:3, w:sp:3` plus `mf:5` with 5 completed and 0 `infra_error` |
| `mcuboot_head_move_nrf52_revert_rc_injection` | `PASS` | `INCONCLUSIVE` | 3 | 0 | 0 | 0 | 148.4 | 487.8 | `x:3` |
| `mcuboot_head_move_nrf52_revert_rc_injection_multiboot` | `PASS` | `INCONCLUSIVE` | 3 | 0 | 0 | 0 | 168.6 | 437.4 | `x:3` |

In the six zero-issue profiles, `security_aggregate.status` is `INCONCLUSIVE` because `whole_device_layout_assessed` is `false` on profiles that do not declare a full-flash `memory_map` covering bootloader and hardware configuration regions. Both `_nohashbypass` profiles set `expect.should_find_issues: true` and report `security_aggregate.status: FINDINGS`.

For `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, the 7 issue points and 7 bricks break down by fault type as follows:
- `bit_corruption`: 3 points at `0`, `11907`, `23814`; 1 issue point and 1 brick at `11907` at address `0x0000D860`.
- `silent_write_failure`: 3 points at `0`, `11907`, `23814`; 1 issue point and 1 brick at `11907` at address `0x0000D860`.
- `driver_error`: 3 points at `0`, `11907`, `23814`; 2 issue points and 2 bricks at `11907` at address `0x0000D860` and `23814` at address `0x00081FE0`.
- `write_disturb`: 3 points at `0`, `11907`, `23814`; 1 issue point and 1 brick at `11907` at address `0x0000D860`.
- `wear_leveling_corruption`: 3 points at `0`, `11907`, `23814`; 1 issue point and 1 brick at `11907` at address `0x0000D860`.
- `write_rejection`: 3 points at `0`, `11907`, `23814`; 1 issue point and 1 brick at `11907` at address `0x0000D860`.
- `rc_injection`: 3 points at `0`, `11907`, `23814`; 0 issue points and 0 bricks after `classify_security_issue` dismissed `no_boot` outcomes at `11907` and `23814` as `dos_only`.
- `power_loss`: 3 points at `0`, `11907`, `23814`; 0 issue points and 0 bricks.
- `interrupted_erase`: 3 points at `0`, `21`, `41`; 0 issue points and 0 bricks.
- `multi_sector_atomicity`: 3 points at `0`, `21`, `41`; 0 issue points and 0 bricks.

For `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml`, the 4 issue points and 4 bricks occur at the exact same midpoint `11907` at address `0x0000D860`, with 1 issue point and 1 brick each for `write_rejection`, `silent_write_failure`, `write_disturb`, and `wear_leveling_corruption`.

## Per-Fault-Type Findings and MCUboot Source Analysis

Inspection of MCUboot commit `f84b9d3fd019fb1945e532924bee7a9c03c77373` in `boot/bootutil/src/loader.c` and `boot/zephyr/main.c` explains the behaviour of all 11 fault types exercised in this session.

### Non-Halting Physical Write Faults: `bit_corruption`, `silent_write_failure`, `write_disturb`, `wear_leveling_corruption`, `write_rejection`

Five fault types mutate or suppress an NVMC flash write in `NRF52NVMC` without halting the CPU and without altering the return value of `flash_area_write`:
- `bit_corruption` flips one bit in the written word at the target write index.
- `silent_write_failure` drops the write at the target write index while leaving destination flash bytes unchanged.
- `write_disturb` flips a bit in an adjacent word in the same flash page.
- `wear_leveling_corruption` corrupts bits at the target write to simulate degraded endurance.
- `write_rejection` rejects the write while the controller reports completion.

At `fault_at: 0` at address `0x000F7FE8`, the fault hits the first trailer write in `boot_write_magic` at `boot/bootutil/src/loader.c:563`. Even when the trailer word is corrupted or dropped, the uninterrupted Phase-1 execution continues the revert swap, rewrites the primary trailer, and boots `0x0000C200`. At `fault_at: 23814` at address `0x00081FE0`, the fault hits the final `boot_write_image_ok` write at `boot/bootutil/src/loader.c:663` after all image sectors have already been swapped into the primary slot. On the post-fault reboot, `context_boot_go` validates the intact primary slot image and boots `0x0000C200` regardless of whether `bootutil_img_validate` is bypassed.

At `fault_at: 11907` at address `0x0000D860`, the fault hits `boot_copy_region` at `boot/bootutil/src/loader.c:1671-1695` while MCUboot copies image payload bytes into the primary slot at `0x0000D860`, which lies `0x1860` bytes inside the primary slot starting at `0x0000C000`. In `boot_copy_region`, MCUboot calls `flash_area_read` and `flash_area_write` in chunks without reading back the written destination bytes:

```c
rc = flash_area_read(fap_src, off_src + bytes_copied, buf, chunk_sz);
if (rc != 0) {
    return BOOT_EFLASH;
}
rc = flash_area_write(fap_dst, off_dst + bytes_copied, buf, chunk_sz);
if (rc != 0) {
    return BOOT_EFLASH;
}
```

Because `flash_area_write` returns `0` under all five physical write faults, `boot_swap_sectors` completes the entire swap, writes `image_ok`, and erases the swap status trailer. What happens on the post-fault reboot depends entirely on `sweep_hash_bypass_symbols`:
- When `sweep_hash_bypass_symbols` contains `bootutil_img_validate`, the runtime hook forces `bootutil_img_validate` at `boot/bootutil/src/loader.c:1272` to return `0`. `boot_validate_slot` at `boot/bootutil/src/loader.c:1337` accepts the corrupted primary slot, and the target firmware boots at `0x0000C200` because the corrupted word at `0x0000D860` does not lie on the reset-to-marker execution path.
- When `sweep_hash_bypass_symbols` is empty in the `_nohashbypass` profiles, `context_boot_go` calls `boot_validate_slot` at `boot/bootutil/src/loader.c:3640`, which runs `bootutil_img_validate` over the full image payload. The SHA-256 digest mismatches because of the corrupted word at `0x0000D860`, `boot_validate_slot` returns `BOOT_EBADIMAGE`, `context_boot_go` returns `BOOT_EBADIMAGE` at `boot/bootutil/src/loader.c:3649`, and `main` in `boot/zephyr/main.c:411` executes `FIH_PANIC`, leaving the CPU spinning at `0x0000113E` with `boot_outcome: hard_fault`. Because the swap completed and erased the swap status trailer during Phase 1, subsequent reboots cannot recover the image.

Maintainer assessment: this `hard_fault` panic under `nohashbypass` is expected fail-closed image authentication when an unverified physical flash write corrupts image payload bytes during swap, not a logic bug in MCUboot's swap state machine. An MCUboot maintainer would only act on this if adding optional read-back verification in `boot_copy_region` to detect silent flash write corruption before erasing the source slot.

### `driver_error` on nRF52840 and STM32F4

On nRF52840, `flash_area_write` at `0x00004638` tail-calls `flash_nrf_write` at `0x00002534`, which loops over `nrfx_nvmc_word_write` at `0x00003f64`, polls only `NVMC.READY` at offset `0x400`, and unconditionally returns `0` without reading `NRF52NVMC`'s synthetic `ERRORSTATUS` register at offset `0x410`. `NRF52NVMC` now exposes `DriverErrorRequiresReturnHook => true`, and `scripts/run_runtime_fault_sweep.py` reuses the `rc_injection` entry and return hooks on `flash_area_write` whenever `fault_type == 'g'` runs against a backend with `driver_error_requires_return_hook`. At the target write index, `NRF52NVMC` drops the physical word write and sets `DriverErrorFired = true`, while `_rc_injection_return_hook` overwrites `r0` with `0xFFFFFFFB` on return from `flash_area_write` and records `driver_error_model: software_return_code`.

Comparing the three `driver_error` points in `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` before and after wiring the `flash_area_write` return-value hook shows:
- At `fault_at: 0` at address `0x000F7FE8`: before the change, `driver_error_model` was `peripheral_status_flag`, `rc_injection_applied` was `None`, and the point completed as `recoverable` with `boot_outcome: success`. After the change, `driver_error_model` is `software_return_code`, `rc_injection_applied` is `true` at return address `0x000054C8` with `r0 = 0xFFFFFFFB`, and the point remains `recoverable` with `boot_outcome: success` because aborting the initial trailer write leaves the primary slot valid.
- At `fault_at: 11907` at address `0x0000D860`: before the change, `flash_area_write` returned `0` while dropping the word at `0x0000D860`, and the point completed as `unrecoverable` with `boot_outcome: hard_fault` when `bootutil_img_validate` rejected the primary slot. After the change, `rc_injection_applied` is `true` at return address `0x00000F88` with `r0 = 0xFFFFFFFB` alongside the dropped write at `0x0000D860`; `boot_swap_sectors` at `boot/bootutil/src/loader.c:2367-2373` logs `Failed to copy sectors` and skips `boot_write_swap_idx` for that sector but continues the remaining sector loop and erases the swap status trailer, so the point remains `unrecoverable` with `boot_outcome: hard_fault`.
- At `fault_at: 23814` at address `0x00081FE0`: before the change, `InjectDriverErrorAt` dropped the `image_ok` write at `0x00081FE0` while `flash_area_write` returned `0`, so `boot_write_image_ok` returned `0` and the point completed as `recoverable` with `boot_outcome: success`. After the change, `rc_injection_applied` is `true` at return address `0x000054C8` with `r0 = 0xFFFFFFFB` while dropping the write at `0x00081FE0`; `boot_write_image_ok` at `boot/bootutil/src/loader.c:663` propagates `-5` to `boot_perform_update`, which aborts Phase 1 into `FIH_PANIC` at `0x0000113E` with `no_progress_stall`, changing the point from `recoverable` / `success` to `unrecoverable` / `hard_fault` and increasing `driver_error` issue points from `1` to `2`.

On STM32F4, the runtime return-address hook is used for `STM32F4FastFlash` rather than latching `PROGRAM_ERROR_BIT` in `FLASH_SR` at offset `0x0C` because PG-deactivation write tracking fires after the driver has already polled `FLASH_SR` for that write. In `results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf`, `flash_stm32_write_range` at `0x08004856` calls `flash_stm32_wait_flash_idle` at `0x08004882` before setting `FLASH_CR.PG` at `0x080048ac`, writes one byte to mapped flash at `0x080048b0`, calls `flash_stm32_wait_flash_idle` again at `0x080048ba` while `PG` is still `1`, and only clears `PG` at `0x080048c4`. Because `STM32F4FastFlash` detects the write in `HandlePgDeactivation` on the `PG 1 -> 0` transition at `0x080048c4`, latching `0x80` in `FLASH_SR` at that point misses the post-write poll at `0x080048ba`: on a single-byte write such as `boot_write_image_ok` or on the final byte of any `flash_area_write` call, `flash_stm32_write_range` exits the loop at `0x0800486e` and returns `0` to the caller, leaving the latched `FLASH_SR` error bit to fail the pre-write `flash_stm32_wait_flash_idle` check at `0x08004882` of the next `flash_area_write` call or to go unobserved if no further write occurs. By contrast, setting `DriverErrorRequiresReturnHook => true` on `STM32F4FastFlash` and enabling `driver_error_requires_return_hook` for `STM32F4FastFlash` in `resolve_backend` in `scripts/run_runtime_fault_sweep.py` delivers `r0 = 0xFFFFFFFB` on return from the exact `flash_area_write` call that suffered the dropped write, matching nRF52840 across single-byte and multi-byte writes. `STM32F4FastFlash.HandlePgDeactivation` also now sets `DriverErrorFired = true` when `WriteFaultMode == 6` on `0xFF`-over-`0xFF` byte writes where the pre-write and post-write flash snapshots do not differ.

In `peripherals/STM32F4FlashController.cs`, `ReadDoubleWord` at offset `0x40C` already returns `PROGRAM_ERROR_BIT` with value `0x80` when `DriverErrorFired` is true, and `WriteDoubleWord` at offset `0x40C` clears `DriverErrorFired` when bit 7 is written. However, when `STM32F4FlashInterceptor` is not wired in `platforms/stm32f4.repl`, `STM32F4FlashController` also detects writes only inside `HandlePgDeactivation` on `PG 1 -> 0` at `0x080048c4`, after `flash_stm32_wait_flash_idle` at `0x080048ba` has already polled `FLASH_SR`. To close that gap in `peripherals/STM32F4FlashController.cs` without wiring `STM32F4FlashInterceptor`, `STM32F4FlashController` would need to expose `public bool DriverErrorRequiresReturnHook => true;` and preserve `DriverErrorFired = true` across `WriteDoubleWord` at `0x40C` or let `resolve_backend` include `STM32F4FlashController` in `driver_error_requires_return_hook`, or `platforms/stm32f4.repl` would need to wire `STM32F4FlashInterceptor` so `HandleDirectWrite` sets `DriverErrorFired = true` during the `strb` at `0x080048b0` before `flash_stm32_wait_flash_idle` polls `FLASH_SR` at `0x080048ba`.

Running `profiles/mcuboot_head_move_stm32f4_revert_driver_error.yaml` with `--quick --workers 2 --no-assert-verdict` before and after the change calibrated at `200,000` writes, capped by `max_writes_cap: 200000` out of `393,263` Phase-1 byte writes, and `6` sector erases, completing in `292.4s` before and `424.7s` after:

| `fault_at` | `fault_address` | Caller symbol and return PC | Before `delivery_mode` | Before return code reached caller | Before Phase 2 outcome | After `delivery_mode` | After return code reached caller | After Phase 2 outcome |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `0` | `0x080DFFE8` | `boot_write_trailer` at `0x08004E86` | `peripheral_status_flag` with `driver_error_flag_set: true` | `false`, `rc_injection_applied: None`, `flash_area_write` returned `0` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` | `software_return_code` with `driver_error_flag_set: true` | `true`, `rc_injection_applied: true`, `r0 = 0xFFFFFFFB` at `0x08004E86` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` |
| `100000` | `0x00000000` | `boot_copy_region` at `0x08000E94` | `peripheral_status_flag` with `driver_error_flag_set: false` | `false`, `rc_injection_applied: None`, `flash_area_write` returned `0` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` | `software_return_code` with `driver_error_flag_set: true` | `true`, `rc_injection_applied: true`, `r0 = 0xFFFFFFFB` at `0x08000E94` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` |
| `199999` | `0x00000000` | `boot_copy_region` at `0x08000E94` | `peripheral_status_flag` with `driver_error_flag_set: false` | `false`, `rc_injection_applied: None`, `flash_area_write` returned `0` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` | `software_return_code` with `driver_error_flag_set: true` | `true`, `rc_injection_applied: true`, `r0 = 0xFFFFFFFB` at `0x08000E94` | `recoverable`, `boot_outcome: success`, `boot_slot: exec`, `vtor: 0x08020200` |

At `fault_at: 100000` and `fault_at: 199999`, `boot_copy_region` copies `0xFF` padding bytes within a 128 KB STM32F4 sector over already-erased `0xFF` destination bytes, so `fault_address` is `0x00000000` and the physical flash contents match the expected image; even when `boot_copy_region` returns `BOOT_EFLASH` at `0x08000E94`, `boot_swap_sectors` logs `Failed to copy sectors`, skips `boot_write_swap_idx` for that sector, finishes the remaining sectors in the same boot, and boots `exec` at `0x08020200`.

#### Power-Cycle Recovery and Classification of `driver_error` at `fault_at: 23814`

The `driver_error` failure at write index `23814` at address `0x00081FE0` on nRF52840 is a denial-of-service exposure to transient driver faults caused by fail-closed error handling in `boot_perform_update` and `context_boot_go`, not a permanent brick across power cycles and not a modeling artefact. A device in the field that hits a transient write error during `boot_write_image_ok` hangs in `FIH_PANIC` for the remainder of the current boot cycle until a watchdog or external power cycle resets the MCU, and then self-heals and boots the primary slot on the very first reboot.

No STM32F4 counterpart appeared in `profiles/mcuboot_head_move_stm32f4_revert_driver_error.yaml` because a full Phase-1 revert swap on STM32F4 performs `393,263` single-byte writes, placing `boot_write_image_ok` at write index `393,261` at address `0x0807FFE0` and `boot_write_copy_done` at write index `393,262` at address `0x0807FFD8`, whereas `max_writes_cap: 200000` caps the quick sweep's final point at write index `199,999` inside `boot_copy_region`. In `results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf`, the compiled `boot_perform_update` and `context_boot_go` sequence at `0x0800100C..0x08001052` is instruction-for-instruction identical to the nRF52840 sequence at `0x00001100..0x00001146`.

At MCUboot commit `f84b9d3fd019fb1945e532924bee7a9c03c77373`, the call chain and flash state at write index `23814` are as follows:
1. `context_boot_go` at `boot/bootutil/src/loader.c:1853`, inlined at `0x00001100` on nRF52840 and `0x0800100C` on STM32F4, calls `boot_perform_update` at `boot/bootutil/src/loader.c:1251`.
2. `boot_perform_update` calls `boot_swap_image` at `boot/bootutil/src/loader.c:1274`, which calls `swap_run` at `boot/bootutil/src/swap_move.c:489`. During a revert swap, `fixup_revert` at `boot/bootutil/src/swap_move.c:450` initializes the secondary trailer, `boot_move_sector_up` at `boot/bootutil/src/swap_move.c:353` initializes the primary trailer, erases the secondary trailer at `boot/bootutil/src/swap_move.c:383`, and shifts primary sectors up by one sector, and `boot_swap_sectors` at `boot/bootutil/src/swap_move.c:400` swaps every sector between secondary and primary slots while logging sector progress in the primary trailer `swap_status` area.
3. When `boot_swap_image` returns `0` at `boot/bootutil/src/loader.c:1276`, all image sectors have already been swapped into their final positions in the primary slot at `0x0000C000..0x00081FC0` and the secondary slot at `0x00082000..0x000F7FC0`.
4. At `boot/bootutil/src/loader.c:1283-1289`, because `swap_type == BOOT_SWAP_TYPE_REVERT`, `boot_perform_update` calls `swap_set_image_ok` at `boot/bootutil/src/swap_misc.c:225` and `0x00001114`, which calls `boot_write_image_ok` at `boot/bootutil/src/bootutil_misc.c:186` and `0x000054EE`, `boot_write_trailer_flag` at `boot/bootutil/src/bootutil_misc.c:167` and `0x000054DA`, and `boot_write_trailer` at `boot/bootutil/src/bootutil_misc.c:132` and `0x00005482`:

```c
if (swap_type == BOOT_SWAP_TYPE_REVERT ||
    swap_type == BOOT_SWAP_TYPE_PERM) {
    rc = swap_set_image_ok(BOOT_CURR_IMG(state));
    if (rc != 0) {
        BOOT_SWAP_TYPE(state) = swap_type = BOOT_SWAP_TYPE_PANIC;
    }
}
```

5. `boot_write_trailer` calls `flash_area_write` at `0x00004638` with return address `0x000054C8` to write `BOOT_FLAG_SET` with value `0x01` to the primary slot trailer `image_ok` field at `0x00081FE0`. Under `driver_error` at write index `23814`, `NRF52NVMC` drops the physical word write so `0x00081FE0` remains `0xFFFFFFFF`, and the return hook sets `r0 = 0xFFFFFFFB` on return to `0x000054C8`. `boot_write_trailer` returns `BOOT_EFLASH` with value `1`, which propagates through `boot_write_image_ok` and `swap_set_image_ok` to `boot_perform_update` at `0x00001118`.
6. Because `rc != 0`, `boot_perform_update` sets `BOOT_SWAP_TYPE(state) = swap_type = BOOT_SWAP_TYPE_PANIC` with value `0xFF` at `0x00001122..0x00001124`. At `boot/bootutil/src/loader.c:1310`, `BOOT_IS_UPGRADE(swap_type)` evaluates false when `swap_type` is `0xFF`, so `swap_set_copy_done` at `0x0000111C`, which would otherwise perform write index `23815` at `0x00081FD8`, is skipped.
7. Control returns to `context_boot_go` at `boot/bootutil/src/loader.c:1876-1882` and `0x0000112E..0x0000113E`:

```c
if (BOOT_SWAP_TYPE(state) == BOOT_SWAP_TYPE_PANIC) {
    BOOT_LOG_ERR("panic!");
    FIH_PANIC;
}
```

`context_boot_go` logs `panic!` at `0x0000113A` and spins in an infinite self-branch `b.n 0x113e` at `0x0000113E` on nRF52840, or `0x0800104A` on STM32F4.

When `FIH_PANIC` spins at `0x0000113E`, the flash device state is:
- The primary slot payload at `0x0000C000..0x00081FC0` contains the complete, intact reverted firmware image with SHA-256 `b13287b23c252c7432c5079918b764f6b9b8b09461fd5d395da8b07989074f9d`.
- The secondary slot trailer at `0x000F7FD8..0x000F7FFF` is erased to `0xFF`.
- The primary slot trailer at `0x0007EFD0..0x00081FFF` holds `magic = BOOT_MAGIC_GOOD` at `0x00081FF0..0x00081FFF`, `swap_size` at `0x00081FE8`, `swap_info` at `0x00081FE4`, `image_ok = 0xFF` at `0x00081FE0`, `copy_done = 0xFF` at `0x00081FD8`, and all completed sector swap status bytes `0x01` and `0x02` through `last_idx` at `0x0007EFD0..0x00080018`.

On the next boot after a power cycle, `boot_prepare_image_for_update` at `boot/bootutil/src/loader.c:1479` calls `swap_read_status`, which calls `swap_status_source` at `boot/bootutil/src/swap_move.c:312`. Because the primary slot trailer has `magic == BOOT_MAGIC_GOOD` and `copy_done == BOOT_FLAG_UNSET` while the secondary slot trailer has `magic == BOOT_MAGIC_UNSET`, `swap_status_source` returns `BOOT_STATUS_SOURCE_PRIMARY_SLOT`. `swap_read_status` scans the primary trailer `swap_status` bytes and reconstructs `bs.op = BOOT_STATUS_OP_SWAP`, `bs.idx = last_idx`, and `bs.state = BOOT_STATUS_STATE_2`. Because `!boot_status_is_reset(&bs)` is true at `boot/bootutil/src/loader.c:1513`, MCUboot calls `boot_complete_partial_swap` at `boot/bootutil/src/loader.c:1330`, inlined at `0x0000104E..0x0000109C` on nRF52840 and `0x08000F5A..0x08000FA8` on STM32F4. Inside `boot_complete_partial_swap`, `boot_swap_image` sees that every sector has already reached `state == 2` at `last_idx` and returns `0` without erasing or copying any flash sector; `boot_complete_partial_swap` then calls `swap_set_image_ok` at `0x00001066` to write `0x01` to `0x00081FE0` and `swap_set_copy_done` at `0x0000107E` to write `0x01` to `0x00081FD8`, reloads image headers, validates the primary slot with `bootutil_img_validate`, and boots the primary slot at `0x0000C200`.

Running the point with `fault_sweep.boot_cycles: 3` under `timeout 900` into `results/coverage/nrf52_driver_error_boot_cycles_3_quick.json` completed in `334.1s` and confirmed this exact three-cycle trace at `fault_at: 23814`:
- Cycle 0, the faulted boot: `rc_injection_applied` is `true` on `flash_area_write` at return address `0x000054C8` with `r0 = 0xFFFFFFFB`, `phase1_ops_total` is `23815`, `fault_snapshot_word` at `0x00081FE0` is `0xFFFFFFFF`, `pc` halts at `0x0000113E` with `phase1_stop_reason: no_progress_stall(20.02s_emulated)`, `vtor` is `0x00000000`, and `initial_boot_outcome` is `hard_fault` with `initial_boot_slot: null`.
- Cycle 1, the first power-cycle reboot: `boot_complete_partial_swap` writes `image_ok = 0x01` at `0x00081FE0`, changing the word at `0x00081FE0` from `0xFFFFFFFF` to `0xFFFFFF01` with `fault_word_changed_post_boot: true`, writes `copy_done = 0x01` at `0x00081FD8`, and boots `exec` at `vtor = 0x0000C200` with `marker_actual = 0x00000001` and `outcomes_observed[1] = success`.
- Cycle 2, the second power-cycle reboot: MCUboot sees `copy_done = 0x01` and `image_ok = 0x01` in the primary trailer and boots `exec` directly with `outcomes_observed[2] = success`, `multi_boot_analysis.status = converged`, `converged_at_cycle = 1`, `final_boot_outcome = success`, `final_boot_slot = exec`, and `finding_validation.disposition = self_healed`.

MCUboot could tolerate a transient driver error at `boot_write_image_ok` without entering `FIH_PANIC` in two ways:
1. `boot_write_trailer` or `swap_set_image_ok` could retry `flash_area_write` a bounded number of times when `flash_area_write` returns `BOOT_EFLASH` on a transient controller error.
2. In `boot_perform_update` at `boot/bootutil/src/loader.c:1284-1318`, all image sectors are already swapped into the primary slot before `swap_set_image_ok` runs. If `swap_set_image_ok` fails transiently on a revert, MCUboot could still validate and boot the already-swapped primary slot image in the current boot cycle: leaving `copy_done` and `image_ok` unset at `0xFF` causes the next reboot to enter `boot_complete_partial_swap` and rewrite both trailer flags without repeating any sector copies, whereas setting `BOOT_SWAP_TYPE_PANIC` halts a device that lacks a hardware watchdog even though a valid, authenticated image is already in place in the primary slot.

### `rc_injection`

`rc_injection` with code `x` hooks `flash_area_write` at `0x00004638` and its return address in `scripts/run_runtime_fault_sweep.py`. At the target write index, the underlying NVMC write executes normally and the return hook overwrites `r0` with `0xFFFFFFFB`, which equals `-5` or `BOOT_EFLASH`.

Across the four profiles that run `rc_injection`, the three sampled write indices behave as follows:
- At `fault_at: 0` at address `0x000F7FE8`, `boot_write_magic` at `boot/bootutil/src/loader.c:563` receives `-5` and returns `BOOT_EFLASH`. On the post-fault reboot, MCUboot resumes from the trailer state and boots `0x0000C200`.
- At `fault_at: 11907` at address `0x0000D860`, `boot_copy_region` at `boot/bootutil/src/loader.c:1689` receives `-5` and returns `BOOT_EFLASH` to `swap_scramble_region` at `boot/bootutil/src/loader.c:1770`, which returns `BOOT_EFLASH` to `boot_swap_sectors` at `boot/bootutil/src/loader.c:2367`:

```c
rc = swap_scramble_region(fap_pri, fap_pri,
                          last_sector_offset,
                          swap_offset,
                          sz, true);
if (rc == 0) {
    boot_write_swap_idx(fap_pri, swap_state_pri->swap_idx);
} else {
    BOOT_LOG_ERR("Failed to copy sectors; %d", rc);
}
```

When `swap_scramble_region` returns non-zero in the revert loop of `boot_swap_sectors`, MCUboot logs `Failed to copy sectors` and skips `boot_write_swap_idx`, but does not break out of the `while` loop at `boot/bootutil/src/loader.c:2393`. Instead, the loop advances `erase_idx` and `swap_idx` in memory and continues copying remaining sectors. In `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, this causes the post-fault reboot to fail `bootutil_img_validate` with `hard_fault`, which `classify_security_issue` in `scripts/sweep.py` classifies as `dos_only` and dismisses from `issue_points`.
- At `fault_at: 23814` at address `0x00081FE0`, the fault fires on the final `flash_area_write` inside `boot_write_image_ok` at `boot/bootutil/src/loader.c:663`. Because `rc_injection` hooks the return of `flash_area_write` after the byte `0x01` has already been written to `0x00081FE0`, flash now contains `image_ok = 0x01`, while `boot_write_image_ok` returns `BOOT_EFLASH` with value `-5`. `boot_swap_image` propagates the non-zero return to `context_boot_go` at `boot/bootutil/src/loader.c:3625`, which aborts the Phase-1 boot with `FIH_PANIC`. In single-reboot profiles `full_fault_coverage`, `full_fault_coverage_nohashbypass`, and `rc_injection`, the first post-fault reboot enters `swap_status_source`, starts a new swap cycle that does not finish within the single post-fault window, and records `boot_outcome: hard_fault`, dismissed as `dos_only`. In `mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml`, which sets `boot_recovery_cycles: 3`, boot cycle 1 runs the recovery swap and boot cycle 2 boots `0x0000C200` with `self_healed: true`.

Maintainer assessment: `boot_swap_sectors` continuing the sector loop after `swap_scramble_region` fails at `boot/bootutil/src/loader.c:2367-2373` instead of returning immediately is real MCUboot code behaviour that a maintainer could tighten by breaking on error, though under transient driver errors the device either self-heals across reboots or fails closed.

### Halting and Erase Faults: `power_loss`, `swap_progress`, `interrupted_erase`, `multi_sector_atomicity`

All four halting and erase fault types produced zero issue points, zero bricks, and zero timeouts across `mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml`, `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, and `mcuboot_head_move_nrf52_upgrade_multifault.yaml`:
- `power_loss` with code `w` at write indices `0`, `11907`, and `23814` on revert and `0`, `9842`, and `19684` on upgrade booted `0x0000C200` on the post-fault reboot by resuming the swap from the sector trailer state in `swap_status_source` at `boot/bootutil/src/loader.c:1049`.
- `swap_progress` with code `w:sp` at write indices `6`, `12366`, and `19684` in `mcuboot_head_move_nrf52_upgrade_multifault.yaml` booted `0x0000C200` on the post-fault reboot.
- `interrupted_erase` with code `e` at erase indices `0`, `21`, and `41` filled the target 4 KB page with deterministic pseudo-random partial-erase garbage and halted the CPU; on the post-fault reboot, MCUboot re-erased the page and completed the revert swap to `0x0000C200`.
- `multi_sector_atomicity` with code `a` at erase indices `0`, `21`, and `41` reverted the second half of the erase span and halted the CPU; on the post-fault reboot, MCUboot re-erased the affected sector and booted `0x0000C200`.

## Resolution of `mcuboot_head_move_nrf52_upgrade_multifault.yaml`

Before fixing the runner and multi-fault stage scheduler, running `mcuboot_head_move_nrf52_upgrade_multifault.yaml` with `--quick --workers 4` produced `FAIL, multi-fault campaign incomplete: 3 infrastructure errors` across the 5 planned `boundary_pairs` sequences `mf:0:6`, `mf:6:9842`, `mf:9842:12366`, `mf:12366:19684`, and `mf:0:19684`:
1. In `run_multi_fault_phase` in `scripts/sweep.py`, `run_runtime_sweep` runs in `work_dir / "multi_fault"` with `include_control=False`, so no single-point control run pre-populated `work_dir / "multi_fault" / ".dotnet_bundle"` before the 4 worker processes started. `_run_batch_worker` passed `shared_bundle_dir = work_dir / ".dotnet_bundle"` to `_run_batches_chunked` in `scripts/renode_runner.py`, causing all 4 concurrent Renode containers to extract `libtftp.dll` into the same `DOTNET_BUNDLE_EXTRACT_BASE_DIR` directory simultaneously. Workers 1, 2, and 3 exited with return code `160` and `runner_error` on `mf:6:9842`, `mf:9842:12366`, and `mf:12366:19684`.
2. In `run_multi_fault_sequence` in `scripts/run_runtime_fault_sweep.py`, stages after stage 1 used a hardcoded 60 s wall timeout instead of `phase1_wall_timeout`, did not reset the VTOR watchpoint before each stage, and returned `stage2_fault_index_beyond_writes` whenever stage 2 completed recovery in fewer writes than the full-trace second fault index. For `mf:12366:19684`, stage 1 faulted at `swap_progress` point `12366`, which had `fault_type: "w:sp"` in `sweep_results` rather than `"w"`, so `_validated_prior_stage_result` in `scripts/sweep.py` did not retarget it.

Isolating `shared_bundle_dir` to `work_dir / ".dotnet_bundle"` per parallel worker in `_run_batches_chunked` in `scripts/renode_runner.py` and retargeting overlong later stages in-place from `stage_input_flash` in `run_multi_fault_sequence` in `scripts/run_runtime_fault_sweep.py` resolved all 3 errors. Rerunning `mcuboot_head_move_nrf52_upgrade_multifault.yaml` with `--quick --workers 4` completed all 6 single-fault points and all 5 multi-fault sequences with `0` infrastructure errors, `0` incomplete points, and `verdict: PASS`:
- `mf:0:6`: stage 1 faulted at write `0`, stage 2 faulted at write `6`, and recovery booted `exec` at `0x0000C200` as `recoverable`.
- `mf:6:9842`: stage 1 faulted at write `6`, stage 2 faulted at write `9842`, and recovery booted `exec` at `0x0000C200` as `recoverable`.
- `mf:9842:12366`: stage 1 faulted at write `9842`, stage 2 observed `10,394` writes to `vtor_captured` and retargeted in-place from `12366` to `10393`, and recovery booted `exec` at `0x0000C200` as `recoverable`.
- `mf:12366:19684`: stage 1 faulted at write `12366`, stage 2 observed `7,319` writes to `vtor_captured` and retargeted in-place from `19684` to `7318`, and recovery booted `exec` at `0x0000C200` as `recoverable`.
- `mf:0:19684`: stage 1 faulted at write `0`, stage 2 faulted at write `19684`, and recovery booted `exec` at `0x0000C200` as `recoverable`.

## Non-Quick Sweep of `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`

### Cause of Single-Point Batching Before the Fix

Before the multi-type batching fix, `_auto_execute_batch_points` in `scripts/sweep.py:523-529` and `scripts/sweep.py:603-607` evaluated the entire 3,300-point mixed-type plan in a single call from `run_runtime_sweep` at `scripts/sweep.py:1316-1324`, where any non-`w` fault type set `has_full_execute_only_points = True` to disable trace-replay batching for the `402` `power_loss` points and `max_point_cost_s` at `scripts/sweep.py:603` used the global maximum write index `fp = 23814` with `287.8s` estimated cost against the `180s` batch budget to clamp `max_batch_points` to `1` across all 3,300 points, including `power_loss`, `interrupted_erase`, and `multi_sector_atomicity`.

### Multi-Type Batching Fix and Deliberate Limit on Non-Replay Write Faults

`build_fault_plan` in `scripts/fault_plan.py:766-1025` appends each fault type as a contiguous run in `combined`: `402` `w` points at global indices `0..401`, `42` `e` points at `402..443`, `42` `a` points at `444..485`, and `402` points each for `b`, `s`, `g`, `x`, `d`, `l`, and `r` at `486..3299`. To make multi-type sweeps batch each fault type the same way single-type sweeps do:
1. `_group_fault_plan_by_type`, `_split_batch_plan`, and `_run_batches_chunked` in `scripts/renode_runner.py:1374-1444` and `scripts/renode_runner.py:1585-1636` split `(fault_points, fault_types_list)` at contiguous base fault-type boundaries and slice each contiguous run using `max_batch_points_by_type[base_code]`, ensuring a chunk never mixes fault types and never inherits a smaller batch limit from another fault type.
2. `_auto_execute_batch_points_by_type`, `_run_batch_worker`, and `run_runtime_sweep` in `scripts/sweep.py:644-674`, `scripts/sweep.py:792-915`, and `scripts/sweep.py:1365-1458` compute `_auto_execute_batch_points` independently for each contiguous fault-type run and pass `max_batch_points_by_type` into `_run_batches_chunked`.
3. In `_auto_execute_batch_points` in `scripts/sweep.py:555-563`, trace-replay batches with `fault_sweep.run_duration > 5.0` scale `point_cost_s = max(point_cost_s, 2.75 + run_duration_s * 0.1375)` so profiles with `run_duration: "60.0"` and unbypassed SHA-256 verification choose `16` points per batch instead of `128` points per batch, keeping each 16-point container around `402s` wall time and well below the `1,800s` Robot `TEST_TIMEOUT`.

With this fix, `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` batches `power_loss` at `16` points per chunk, `interrupted_erase` at `42` points per chunk, or `10` to `11` points per worker chunk across 4 workers, and `multi_sector_atomicity` at `42` points per chunk, or `10` to `11` points per worker chunk across 4 workers. Across the first `486` points of the plan covering all `w`, `e`, and `a` points, each worker now runs `9` chunks instead of `122` single-point chunks, and total chunks per worker drop from `825` to `712` on workers 0 and 1 and `713` on workers 2 and 3.

The remaining `1` point per batch limit for the seven non-halting write fault types `bit_corruption`, `silent_write_failure`, `driver_error`, `rc_injection`, `write_disturb`, `wear_leveling_corruption`, and `write_rejection` when `max_fp = 23814` is deliberate in `_auto_execute_batch_points` at `scripts/sweep.py:611-629` and enforced by `test_large_execute_write_indices_use_safe_small_batches` in `tests/test_sweep_execute_batch_points.py:50-59`. Because non-halting write faults mutate or drop one flash write and then continue executing Phase 1 through all `23,815` writes, they cannot use persisted-flash trace replay in `scripts/fault_types.py:42-55` where `TRACE_REPLAY_WIRE_CODES = frozenset({"w"})`. Each point emulates all `23,815` writes with `SkipShadowScan = False` on `NRF52NVMC` in `77s` to `117s` plus full-flash snapshot comparisons and Phase-2 validation, so `max_point_cost_s = 2.0 + 23814 * 0.012 = 287.8s` exceeds the `180s` batch budget whenever `max_fp >= 7334`. Clamping `max_batch_points` to `1` for those high-index execute-only write faults protects against exceeding the `180s` per-batch budget, hitting the `1,800s` Robot `TEST_TIMEOUT`, and accumulating Mono/Renode managed heap across multiple full-emulation runs in one container. The limit can be relaxed in a profile by setting `fault_sweep.max_writes` below `7,334`, as in the `*_selftest.yaml` profiles that set `max_writes: 256` and batch at `35` points per chunk, or on the command line via `--max-batch-points N` or `--fault-end N`.

### Comparison of Non-Quick Sweep Runs Before and After the Fix

Running `profiles/mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` without `--quick` under `timeout 2400` with `--workers 4` after the batching fix calibrated at `23,815` flash writes and `42` sector erases in `150s`, planned `3,300` total fault points, and sub-batched the 4 workers into `712`, `712`, `713`, and `713` chunks. Before `timeout 2400` exited with code `124` at `2,400s`, all 4 workers completed chunks `1` through `5` of `16` `power_loss` points each, totaling `320` completed points across write indices `0` through `19571` in `395.9s` to `419.7s` per 16-point chunk and `22.9s` average inside Renode per point, while chunk `6` on each worker was in flight across write indices `19596` through `23621`. All `320` completed points finished as `recoverable` with `boot_outcome: success`, `0` issue points, `0` bricks, and `0` timeouts.

| Metric | Previous session before fix under `timeout 3000` | Current session after fix under `timeout 2400` |
| :--- | :--- | :--- |
| Wall-clock timeout s | 3000 | 2400 |
| Points planned | 3300 | 3300 |
| Chunks per worker | `825` across all 4 workers at `1` pt/chunk | `712` on workers 0 and 1, `713` on workers 2 and 3 at `16` pts/chunk for `w`, `10..11` pts/chunk for `e` and `a`, `1` pt/chunk for `b..r` |
| Points completed | 96 at write indices `0..5114` | 320 at write indices `0..19571` |
| Points in flight at cutoff | 4 at write indices `5216..5219` | 64 across chunk 6 on all 4 workers at write indices `19596..23621` |
| Points per hour over full wall window | 115.2 | 480.0 |
| Points per hour over post-calibration worker phase | 123.2 over 2806 s | 516.6 over 2230 s |
| Issue points observed | 0 | 0 |
| Bricks observed | 0 | 0 |
| Timeouts observed | 0 | 0 |

| Fault type | Code | Global plan indices | Batch size pts/chunk | Points planned | Points completed in 3000 s before fix | Points completed in 2400 s after fix | In-flight at 2400 s cutoff | Issue points observed | Bricks observed | Timeouts observed |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `power_loss` | `w` | `0..401` | 16 | 402 | 96 at write indices `0..5114` | 320 at write indices `0..19571` | 64 at write indices `19596..23621` | 0 | 0 | 0 |
| `interrupted_erase` | `e` | `402..443` | 42 global, 10..11 per worker | 42 | 0 | 0 | 0 | 0 | 0 | 0 |
| `multi_sector_atomicity` | `a` | `444..485` | 42 global, 10..11 per worker | 42 | 0 | 0 | 0 | 0 | 0 | 0 |
| `bit_corruption` | `b` | `486..887` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `silent_write_failure` | `s` | `888..1289` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `driver_error` | `g` | `1290..1691` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `rc_injection` | `x` | `1692..2093` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `write_disturb` | `d` | `2094..2495` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `wear_leveling_corruption` | `l` | `2496..2897` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| `write_rejection` | `r` | `2898..3299` | 1 | 402 | 0 | 0 | 0 | 0 | 0 | 0 |
| Total | all 10 | `0..3299` | 16 / 42 / 1 | 3300 | 96 | 320 | 64 | 0 | 0 | 0 |

## Remaining Operational Constraints

1. Full non-`--quick` sweeps on the seven revert profiles cannot finish within either the 300 s self-test budget or a 3600 s single-run timeout on this host:
   - `scripts/fault_types.py` places `bit_corruption`, `silent_write_failure`, `driver_error`, `rc_injection`, `write_disturb`, `wear_leveling_corruption`, `write_rejection`, `interrupted_erase`, and `multi_sector_atomicity` in `EXECUTE_ONLY_FAULT_TYPES`. Each execute-only point runs full Phase-1 CPU emulation with `SkipShadowScan = False` on `NRF52NVMC`, which diffs 1 MB of flash on every `WEN` transition across `23,815` writes.
   - Because `max_fp` is `23,814` for the seven non-replay write fault types, `max_point_cost_s` is `287.8s` against the `180s` budget in `_auto_execute_batch_points` in `scripts/sweep.py`, so each non-replay write-fault batch runs `1` point unless `fault_sweep.max_writes`, `--fault-end`, or `--max-batch-points` relaxes the limit.
   - In `mcuboot_head_move_nrf52_revert_write_faults.yaml`, `mcuboot_head_move_nrf52_revert_write_faults_long.yaml`, `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml`, `mcuboot_head_move_nrf52_revert_rc_injection.yaml`, and `mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml`, no fault type belongs to `TRACE_COVERAGE_FAULT_TYPES` and `sweep_strategy` is not explicitly set in the YAML. As a result, `scripts/sweep.py` sets `CALIBRATION_TRACE_REQUIRED:false` and `HEURISTIC_TRACE_REQUIRED:false`, skips Phase-2 fine trace capture during calibration, and falls back to exhaustive point generation in `build_fault_plan`: `95,260` execute-only points for each `write_faults*` profile across 4 types and `23,815` execute-only points for each `rc_injection*` profile.
   - In `mcuboot_head_move_nrf52_revert_full_fault_coverage.yaml` and `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml`, per-type batching runs the `402` `power_loss` points in `28` chunks across 4 workers and the `84` `interrupted_erase` and `multi_sector_atomicity` points in `8` chunks across 4 workers, leaving `2,814` single-point chunks for the 7 non-replay write fault types and `2,850` total chunks across the 4 workers.
2. Both `mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml` and `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` now set `expect.should_find_issues: true`, and `mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml` has been removed from `negative_controls` in `tests/test_self_test_profiles.py`.
3. All eight target profiles exceed 300 s wall time on this host even under `--quick`, ranging from `430.6s` to `1150.9s`, and take hours without `--quick`, so all eight profiles keep `skip_self_test: true`.

