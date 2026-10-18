# MCUboot STM32F4 swap-scratch writeback triage

The mid-swap failure flagged by `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` at write index `45156`, sequence `45163`, is a real writeback durability bug in MCUboot's swap-scratch algorithm when running over a buffered flash stack without flush barriers between swap states. In `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c`, MCUboot copies the staged `v1.1.0` image from the secondary slot into scratch across writes `43..37020` and writes the `BOOT_STATUS_STATE_0` completion byte to the primary slot trailer at write `37021`, then immediately erases the secondary slot at the start of `BOOT_STATUS_STATE_1` without flushing scratch or the primary trailer. When power fails at write index `45156` at flash offset `0x10A00C`, the 16,384-entry writeback buffer still holds the last `8,248` writes to scratch, the `BOOT_STATUS_STATE_0` status byte write at `0x0803F3D0`, and the first `8,135` writes copying the `v1.0.0` primary image into the secondary slot. Discarding those uncommitted writes after the secondary slot erase leaves all primary status bytes equal to `0xFF` while the secondary slot is erased, so on recovery boot `swap_read_status_bytes` reports no partial swap in progress, `boot_prepare_image_for_update` fails secondary slot validation, and MCUboot boots the old `v1.0.0` image in the primary slot.

## Commits and commands

The triage used the following revisions:

- Tardigrade commit: `085a438851f89de1c1b70daa48cb33214f6a4314`
- MCUboot commit in `results/oss_validation/assets/mcuboot_head_commit.txt`: `f84b9d3fd019fb1945e532924bee7a9c03c77373`
- Zephyr commit in `results/oss_validation/assets/zephyr_head_commit.txt`: `36940db938a8f4a1e919496793ed439850a221c2`

Commands executed to rebuild the current-head matrix assets and run the writeback and write-through sweeps:

```bash
GNUARMEMB_TOOLCHAIN_PATH=/opt/homebrew MCUBOOT_BOOTSTRAP_SCOPE=head \
  ./scripts/bootstrap_mcuboot_matrix_assets.sh
GNUARMEMB_TOOLCHAIN_PATH=/opt/homebrew ./scripts/build_mcuboot_head_matrix.sh

python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_stm32f4_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 4 \
  --quick \
  --no-assert-verdict \
  --output results/writeback_quick.json

timeout 3600 python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_stm32f4_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 4 \
  --no-assert-verdict \
  --keep-run-artifacts \
  --output results/writeback_full.json

python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_stm32f4_writethrough_tmp.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 4 \
  --fault-start 45156 \
  --fault-end 45157 \
  --no-assert-verdict \
  --output results/writethrough_45156.json
```

In the quick sweep, `audit_bootloader.py` tested fault points `0`, `45156`, and `90312` out of `90,313` calibrated writes and `10` erases. Fault points `0` and `90312` recovered to `v1.1.0` with `boot_outcome: "success"` and `marker_actual: "0x00000101"`. Fault point `45156` failed with `boot_outcome: "wrong_image"` and `marker_actual: "0x00000001"`, producing top-level verdict `FAIL` with `1` issue point.

With the host Arm GNU toolchain 16.2.0 against Zephyr `36940db938a8f4a1e919496793ed439850a221c2`, calibration records `90,313` writes and `10` erases, placing the quick midpoint at `fault_at: 45156` and `fault_window.before.sequence: 45163`. With the container xPack GCC 13.2.1 build of the same commits, `zephyr_head_scratch_stm32f4_mirrored_slot0.bin` is `4` bytes longer, calibration records `90,327` writes, and the midpoint lands at `45163`. Against newer Zephyr `main` where STM32 applications link with `CONFIG_ROM_START_OFFSET=0x400`, calibration records `92,662` writes and the midpoint lands at `46331`. All three midpoint indices cut power halfway through `BOOT_STATUS_STATE_1`.

In the non-quick run under `timeout 3600`, `audit_bootloader.py` selected `67,611` heuristic fault points across `4` workers at `1` point per batch and completed `80` points in the range `0..97` before reaching the 3600-second timeout with exit code `124`. Seven of those `80` points hit the 30-second per-point wall-clock limit at `0.95` emulated seconds under four-worker CPU contention, and all `73` points that completed Phase 2 execution in `0..97` succeeded with `vtor: "0x08008200"` and `marker_actual: "0x00000101"`.

## Flagged point data from `results/writeback_quick.json`

- Fault request: `fault_at = 45156`, `fault_requested = 45156`, `fault_type = "w"`, `fault_address = "0x0810A00C"`
- Fault window:
  - `before`: `kind = "write"`, `write_index = 45156`, `sequence = 45163`, `flash_offset = 1089548` or `0x10A00C`, `address = "0x0810A00C"`, `value = "0xFFFFFF58"`, `width = 4`
  - `at`: `kind = "write"`, `write_index = 45157`, `sequence = 45164`, `flash_offset = 1089548` or `0x10A00C`, `address = "0x0810A00C"`, `value = "0xFFFF0358"`, `width = 4`
  - `after`: `kind = "write"`, `write_index = 45158`, `sequence = 45165`, `flash_offset = 1089548` or `0x10A00C`, `address = "0x0810A00C"`, `value = "0xFF000358"`, `width = 4`
- Writeback and durability annotations:
  - `durability_model`: `"writeback"`
  - `writeback_capacity`: `16384`
  - `writeback_diagnostics.writeback_buffer_loss`: `true`
  - `writeback_diagnostics.writeback_stats`: `commit_ratio = 0.6372`, `writes_issued = 45157`, `writes_committed = 28773`, `write_differential = 16384`
  - `writeback_diagnostics.dirty_domains_at_fault`:
    - `unknown`, which covers the scratch partition at `0x08040000..0x08060000`: `pending = 8248`, `oldest_wi = 28773`, `newest_wi = 37020`
    - `exec`, which covers `0x08008000..0x08040000`: `pending = 1`, `oldest_wi = 37021`, `newest_wi = 37021`
    - `staging`, which covers `0x08108000..0x08140000`: `pending = 8135`, `oldest_wi = 37022`, `newest_wi = 45156`
  - `calibration.barrier_audit`: `verdict = "ok"`, `missing_barriers = 0`, `total_barrier_events = 73907`, `total_phases = 3`
    - Phase 1: `domain = "exec"`, `start_write = 22`, `end_write = 37021`, `write_count = 22`, `barrier_at_end = true`
    - Phase 2: `domain = "staging"`, `start_write = 37022`, `end_write = 53332`, `write_count = 16311`, `barrier_at_end = true`
    - Phase 3: `domain = "exec"`, `start_write = 53333`, `end_write = 90313`, `write_count = 36981`, `barrier_at_end = true`
    - Note on `barrier_audit`: `writeback_simulate_buffer` in `scripts/run_runtime_fault_sweep.py` records each capacity eviction in `_ba_events` and `writeback_domain_for_address` maps only `memory.slots` entries, returning `None` for scratch writes `43..37020`. Capacity evictions during the `36,978` scratch writes therefore satisfy the phase-boundary check between `exec` write `22` and `staging` write `37022`, even though no explicit barrier flushed the last `16,384` writes before MCUboot erased `staging`.
- Phase 2 boot outcome:
  - `boot_outcome`: `"wrong_image"`, `initial_boot_outcome`: `"wrong_image"`, `final_boot_outcome`: `"wrong_image"`
  - `boot_slot`: `"exec"`, `actual_writes`: `28751`
  - `signals.vtor`: `"0x08008200"`, `signals.pc`: `"0x0800ADF2"`, `signals.phase2_stop_reason`: `"vtor_captured"`
  - `signals.marker_actual`: `"0x00000001"`, `signals.marker_ok`: `false`, `signals.content_mismatch`: `true`
- Slot state and postmortem fields:
  - `contracts.state_probe` is `null` in `mcuboot_head_scratch_stm32f4_writeback.yaml`, so `semantic_state` is `null` in the report JSON. `pre_state` records `slot_a_valid = true`, `slot_b_valid = false`, and `fault_snapshot` records that `exec` at `0x08008000` has SHA-256 `b4d7b44266232ae1fdd595405035a73fc5ae58fa9729fb0a688c1d12dd44ec43` with `differing_bytes = 0` against `zephyr_head_scratch_stm32f4_mirrored_slot0.bin`.
  - Direct inspection of the reconstructed 2 MiB flash image at `fault_at = 45156` shows:
    - `exec` at `0x08008000..0x08040000`: header magic `0x96F3B83D`, version `1.0.0`, `img_sz = 15688`, trailer magic `77c295f360d2ef7f3552500f2cb67980`, `swap_info = 0x02`, `swap_size = 37200`, `copy_done = 0xFF`, `image_ok = 0xFF`, and status byte 0 at `0x0803F3D0` equal to `0xFF`.
    - `staging` at `0x08108000..0x08140000`: completely erased to `0xFF`, header magic `0xFFFFFFFF`, trailer magic `ffffffffffffffffffffffffffffffff`.
    - `scratch` at `0x08040000..0x08060000`: header magic `0x96F3B83D`, version `1.1.0`, `img_sz = 36352`, with bytes `0x080470F8..0x08049150` still `0xFF` because writes `28773..37020` were lost from the writeback buffer, and trailer magic `ffffffffffffffffffffffffffffffff`.
  - Per-point postmortem is absent because `run_runtime_fault_sweep.py` emits `partition_postmortem` only for `no_boot` outcomes, whereas Phase 2 hands off to the `v1.0.0` image in `exec`.

## Writeback versus write-through comparison at `fault_at = 45156`

| Field | Writeback with `durability_model: writeback` | Write-through with `durability_model: direct` |
| --- | --- | --- |
| `fault_at` | `45156` | `45156` |
| `fault_address` | `0x0810A00C` | `0x0810A00C` |
| `actual_writes` | `28751` | `45156` |
| `writes_committed` | `28773` of `45157`, `commit_ratio = 0.6372` | `45157` of `45157` |
| `exec` header before Phase 2 | `v1.0.0`, `img_sz = 15688` | `v1.0.0`, `img_sz = 15688` |
| `exec` status byte 0 at `0x0803F3D0` | `0xFF` because write `37021` was buffered | `0x01` because write `37021` was durable |
| `scratch` payload before Phase 2 | Truncated: writes `28773..37020` lost | Complete `37,200`-byte `v1.1.0` image |
| `staging` slot before Phase 2 | All `0xFF` after erases `4..7` at `writes_at = 37021` | Partial `v1.0.0` image from writes `37022..45156` |
| Phase 2 `boot_outcome` | `wrong_image` | `success` |
| Phase 2 `signals.vtor` | `0x08008200` | `0x08008200` |
| Phase 2 `signals.marker_actual` | `0x00000001`, `marker_ok = false` | `0x00000101`, `marker_ok = true` |
| Report `verdict` | `FAIL`, `1` issue point | `PASS`, `0` issue points |

## Trace analysis and decision

Calibration records the following 10 erase operations and 90,313 write operations during `swap_run` and `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c`:

1. In `BOOT_STATUS_STATE_0` at lines 411 through 450 of `boot/bootutil/src/swap_scratch.c`:
   - Erase 1 at `writes_at = 0` erases `scratch` at `0x08040000..0x08060000`.
   - Writes `1..21` at `0x0805FFD8..0x0805FFFC` execute `swap_status_init(state, fap_scratch, bs)`.
   - Erase 2 at `writes_at = 21` erases the primary trailer sector at `0x08020000..0x08040000`.
   - Writes `22..42` at `0x0803FFD0..0x0803FFFC` execute `swap_status_init(state, fap_primary_slot, bs)`, persisting `swap_size = 37200`, `swap_info = 0x02`, and `BOOT_MAGIC_GOOD` in the primary trailer.
   - Erase 3 at `writes_at = 42` erases `scratch` at `0x08040000..0x08060000`.
   - Writes `43..37020` at `0x08040000..0x0804914C` execute `boot_copy_region(state, fap_secondary_slot, fap_scratch, img_off, 0, copy_sz)` at lines 443 and 444, copying the `37,200`-byte `v1.1.0` image from `staging` into `scratch`.
   - Write `37021` at `0x0803F3D0` executes `boot_write_status(state, bs)` at line 447, writing status byte `0x01` to the primary slot trailer and setting `bs->state = BOOT_STATUS_STATE_1` in RAM.
2. In `BOOT_STATUS_STATE_1` at lines 452 through 471 of `boot/bootutil/src/swap_scratch.c`:
   - Erases `4..7` at `writes_at = 37021` execute `boot_erase_region(fap_secondary_slot, img_off, sz)` at line 453 and `swap_erase_trailer_sectors(state, fap_secondary_slot)` at line 464, erasing the secondary slot at `0x08108000..0x08140000` where the `v1.1.0` image was stored.
   - Writes `37022..53332` at `0x08108000..0x0810C094` execute `boot_copy_region(state, fap_primary_slot, fap_secondary_slot, img_off, img_off, copy_sz)` at lines 456 and 457, copying the `16,536`-byte `v1.0.0` image from `exec` into `staging`.
   - Write `53333` at `0x0803F3D0` executes `boot_write_status(state, bs)` at line 468, writing status byte `0x02` to the primary slot trailer.
3. In `BOOT_STATUS_STATE_2` at lines 473 through 524 of `boot/bootutil/src/swap_scratch.c`:
   - Erases `8..10` at `writes_at = 53333` erase the primary slot image sectors at `0x08008000..0x08020000`.
   - Writes `53334..90311` at `0x08008000..0x0801114C` copy the `v1.1.0` image from `scratch` into `exec`.
   - Write `90312` at `0x0803F3D0` writes status byte `0x03`, and write `90313` at `0x0803FFE0` sets `copy_done = 0x01`.

At `fault_at = 45156`, MCUboot has issued `8,135` writes in `BOOT_STATUS_STATE_1` after write `37021`. Because MCUboot issues no flush barrier at the end of `BOOT_STATUS_STATE_0` and `flash_area_close` is not called until lines 526 through 528 after `BOOT_STATUS_STATE_2`, a 16,384-write buffer still holds writes `28773..37020` to `scratch` and write `37021` to the `exec` trailer when `boot_erase_region(fap_secondary_slot, img_off, sz)` erases `staging`. Even on a storage controller where erasing a partition flushes pending writes to that same partition, erasing `fap_secondary_slot` does not flush `fap_scratch` or `fap_primary_slot`.

On Phase 2 recovery boot, `boot_prepare_image_for_update` in `boot/bootutil/src/loader.c` calls `swap_read_status` at line 1877, which calls `swap_read_status_bytes` at lines 82 through 151 of `boot/bootutil/src/swap_scratch.c`. Because write `37021` at `0x0803F3D0` was lost from the writeback buffer, `swap_read_status_bytes` sees `found == 0` and leaves `bs->idx = BOOT_STATUS_IDX_0` and `bs->state = BOOT_STATUS_STATE_0`. At line 1906 of `boot/bootutil/src/loader.c`, `boot_status_is_reset(bs)` returns `true`, so MCUboot skips `boot_complete_partial_swap`, enters the fresh-boot branch at line 1926, calls `boot_validate_slot(state, BOOT_SECONDARY_SLOT, bs)` on the erased secondary slot, sets `BOOT_SWAP_TYPE(state) = BOOT_SWAP_TYPE_FAIL`, and boots the old `v1.0.0` image in `exec` while the `v1.1.0` update image is lost from both `staging` and `scratch`.

## Required bootloader change

To make `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c` resilient on a writeback storage stack, a bootloader author must add an explicit storage flush barrier before every state transition that erases a source slot or advances `bs->state`:

1. At the end of `BOOT_STATUS_STATE_0`, before entering `BOOT_STATUS_STATE_1` and calling `boot_erase_region(fap_secondary_slot, img_off, sz)`, flush `fap_scratch` after `boot_copy_region(state, fap_secondary_slot, fap_scratch, img_off, 0, copy_sz)` so the entire scratch copy is durable, and then flush the status partition, which is `fap_primary_slot` or `fap_scratch` when `bs->use_scratch` is active, after `boot_write_status(state, bs)` so the `BOOT_STATUS_STATE_0` status byte is durable on flash before the secondary slot is erased.
2. At the end of `BOOT_STATUS_STATE_1`, before entering `BOOT_STATUS_STATE_2` and calling `boot_erase_region(fap_primary_slot, img_off, sz)`, flush `fap_secondary_slot` after `boot_copy_region(state, fap_primary_slot, fap_secondary_slot, img_off, img_off, copy_sz)` and flush the status partition after `boot_write_status(state, bs)` so the secondary backup copy and `BOOT_STATUS_STATE_1` status byte are durable before the primary slot is erased.
3. In `BOOT_STATUS_STATE_2`, flush `fap_primary_slot` after copying from `fap_scratch` and writing the rebuilt primary trailer and `boot_write_status(state, bs)` before calling `boot_erase_region(fap_scratch, 0, flash_area_get_size(fap_scratch))` and before `swap_set_copy_done` marks the swap complete.

## Generalization

Both MCUboot swap algorithms, `swap-scratch` in `boot/bootutil/src/swap_scratch.c` and `swap-move` in `boot/bootutil/src/swap_move.c`, have the same shape of writeback durability gap across both STM32F4 and nRF52840. Every sector swap state writes image payload words and a trailing `boot_write_status` byte and then immediately calls `boot_erase_region` on the source slot without a storage flush barrier. Whether the three-point `--quick` smoke probe at `[0, N // 2, N - 1]` lands inside an unbuffered post-erase window depends on the ratio of the writeback FIFO capacity to the total write count `N`.

### Writeback durability model mechanics

In `docs/writing-profiles.md` and `scripts/run_runtime_fault_sweep.py` at lines 3104 through 3450, `durability_model: writeback` interposes a single FIFO `buffer` of capacity `cap = writeback_capacity()` in front of flash during Phase 1 trace replay up to `fault_at`. With `buffer_capacity: auto`, `writeback_capacity()` divides the flash controller `PageSize` by `WRITE_GRANULARITY`:

- On STM32F4, `STM32F4FlashController.cs` reports `PageSize = 65536` and `WRITE_GRANULARITY = 4`, giving `cap = 16,384` writes.
- On nRF52840, `NRF52NVMC.cs` reports `PageSize = 4096` and `WRITE_GRANULARITY = 8`, giving `cap = 512` writes.

As Phase 1 replays the chronological event stream up to write index `fault_at`, each write event is appended to `buffer` instead of reaching the flash image immediately. Buffered writes commit to flash only when one of three events occurs before `fault_at`:

1. FIFO capacity eviction: when `len(buffer) > cap`, `buffer.pop(0)` commits the oldest buffered write to flash.
2. Explicit barrier write: when a write targets an address listed in `_writeback_barriers` from `writeback.flush_trigger`, the runner commits every entry in `buffer` and clears it. None of the four MCUboot writeback profiles declare a `flush_trigger`.
3. Erase with domain flush enabled: when `erase_flushes_domain: true`, an erase commits all entries in `buffer` before erasing `[e_off, e_off + e_sz)`. All four MCUboot writeback profiles set `erase_flushes_domain: false`, so an erase at `[e_off, e_off + e_sz)` drops any buffered writes overlapping that erased range and leaves buffered writes to all other addresses uncommitted in `buffer`.

When power fails at `fault_at`, all remaining entries in `buffer`, up to the last `cap` writes before `fault_at`, are discarded.

### Generalization table

| Algorithm | Platform | Profile | Calibrated writes and erases | Buffer capacity | Flagged points under `--quick` | Targeted erase-boundary point | MCUboot step and source lines | Outcome under write-through `durability_model: direct` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `swap-scratch` | STM32F4 | `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` | `90,313` writes, `10` erases | `16,384` writes | `fault_at = 45156` out of `0, 45156, 90312`: `boot_outcome = "wrong_image"`, `vtor = 0x08008200`, `marker_actual = 0x00000001` | `fault_at = 37021..53404` window; `fault_at = 45156` already in `--quick` | `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c` lines 443 through 468: `BOOT_STATUS_STATE_0` copies `staging` to `scratch` at writes `43..37020` and writes status byte `0x01` at write `37021`, then `BOOT_STATUS_STATE_1` erases `staging` at erases `4..7` at `writes_at = 37021` without flushing `scratch` or the `exec` trailer | `boot_outcome = "success"`, `vtor = 0x08008200`, `marker_actual = 0x00000101` at `fault_at = 45156` |
| `swap-scratch` | nRF52840 | `profiles/mcuboot_head_scratch_nrf52_writeback.yaml` | `23,787` writes, `60` erases | `512` writes | None at `0, 11893, 23786` because `11893` is `2,071` writes past the `9311..9822` buffer window | `fault_at = 9311`: `boot_outcome = "wrong_image"`, `vtor = 0x0000C200`, `marker_actual = 0x00000001`, `copy_done = 0xFF` | `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c` lines 443 through 468: `BOOT_STATUS_STATE_0` copies `staging` to `scratch` at writes `13..9310` and writes status word `0xFFFFFF01` at write `9311`, then `BOOT_STATUS_STATE_1` erases `staging` at erases `21..50` at `writes_at = 9311` while writes `8800..9311` are still buffered | `boot_outcome = "success"`, `vtor = 0x0000C200`, `marker_actual = 0x00000101`, `copy_done = 0x01` at `fault_at = 9311` |
| `swap-move` | nRF52840 | `profiles/mcuboot_head_move_nrf52_writeback.yaml` | `19,685` writes, `38` erases | `512` writes | None at `0, 9842, 19684` because `9842` is `40` writes past the `9290..9801` buffer window and `sweep_hash_bypass_symbols` masks the `511` lost tail writes at `19684` | `fault_at = 6216`: `boot_outcome = "timeout"` at `instruction_limit = 200000000`, `vtor = 0x00000000`, `pc = 0x0000D224`, `copy_done = 0xFF` | `boot_swap_sectors` in `boot/bootutil/src/swap_move.c` lines 423 through 446: for sector `idx = 1`, `BOOT_STATUS_STATE_0` copies `staging` sector 0 to `exec` sector 0 at writes `5191..6215` and writes status word `0xFFFFFF01` at write `6216`, then `BOOT_STATUS_STATE_1` erases `staging` sector 0 at erase `20` at `writes_at = 6216` while writes `5705..6216` are still buffered | `boot_outcome = "success"`, `vtor = 0x0000C200`, `marker_actual = 0x00000101`, `copy_done = 0x01` at `fault_at = 6216` |
| `swap-move` | STM32F4 | `profiles/mcuboot_head_move_stm32f4_writeback.yaml` | `69,646` writes, `5` erases | `16,384` writes | `fault_at = 0` hit `wall_timeout` at `31s` and `1.05s` emulated under the default 30s Phase 2 wall limit; `0` flagged points at `0, 34823, 69645` with `phase2_wall_timeout_s: 90` because `34823` is between the `16343..32726` and `53323..69645` windows and `sweep_hash_bypass_symbols` masks the aborted swap at `69645` | `fault_at = 53323` and `fault_at = 69645`: partial swap aborts in `boot_read_image_headers` with `copy_done = 0xFF` and `20,927` or `16,382` differing bytes in `exec` | `boot_swap_sectors` in `boot/bootutil/src/swap_move.c` lines 423 through 446: `BOOT_STATUS_STATE_0` copies `staging` to `exec` at writes `16344..53322` and writes status byte `0x01` at write `53323`, then `BOOT_STATUS_STATE_1` erases `staging` at erase `5` at `writes_at = 53323` while writes `36940..53323` are still buffered | `boot_outcome = "success"`, `vtor = 0x08020200`, `marker_actual = 0x00000101`, `copy_done = 0x01` at `fault_at = 0`, `53323`, and `69645` |

### Per-point extraction across the three new profiles

1. `profiles/mcuboot_head_scratch_nrf52_writeback.yaml`:
   - Quick sweep command and result: `timeout 1500 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_scratch_nrf52_writeback.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/writeback_gen/mcuboot_head_scratch_nrf52_writeback_quick.json` completed in `153.2s` over `23,787` calibrated writes and `60` erases. Points `0`, `11893`, and `23786` all returned `boot_outcome: "success"`, `vtor: "0x0000C200"`, `marker_actual: "0x00000101"`, and `semantic_state.slots.exec.copy_done.state: "set"`.
   - Why `--quick` missed the window: in `boot_swap_sectors` in `boot/bootutil/src/swap_scratch.c` at lines 443 through 468, `BOOT_STATUS_STATE_0` copies `v1.1.0` from `staging` at `0x0006E000` into `scratch` at `0x000CE000` across writes `13..9310` and writes the `BOOT_STATUS_STATE_0` status word at write `9311`, then `BOOT_STATUS_STATE_1` erases `staging` across erases `21..50` at `writes_at = 9311`. Because the nRF52840 writeback buffer holds `512` writes, the unbuffered window where `staging` is erased while write `9311` is still uncommitted spans `fault_at = 9311..9822`. The `--quick` midpoint `11893` lands `2,071` writes after capacity eviction has already committed writes `13..9311`.
   - Targeted erase-boundary point `fault_at = 9311` in `results/writeback_gen/mcuboot_head_scratch_nrf52_writeback_9311.json`:
     - Write index and flash offset: `fault_at = 9311`, `fault_window.at.write_index = 9312` at address `0x0006E000` and `flash_offset = 450560` or `0x6E000`.
     - Buffered writes discarded: `512` writes from `write_index = 8800` to `9311`, with `writes_issued = 9312` and `writes_committed = 8800`, consisting of `511` writes to `scratch` in `dirty_domains_at_fault.unknown` at `8800..9310` and `1` status write to the `exec` trailer in `dirty_domains_at_fault.exec` at `9311`.
     - Erase that should have been preceded by a flush: `boot_erase_region(fap_secondary_slot, img_off, sz)` at line 453 of `boot/bootutil/src/swap_scratch.c`, recorded as `erase_index = 21..50` ending at `address = "0x00077000"`, `flash_offset = 487424`, `writes_at_this_point = 9311`.
     - Phase 2 outcome and `semantic_state`: `boot_outcome = "wrong_image"`, `vtor = "0x0000C200"`, `marker_actual = "0x00000001"`, `semantic_state.slots.exec = {"magic_state": "good", "image_ok": {"raw": "0x01", "state": "set"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`, `semantic_state.slots.staging = {"magic_state": "unset", "image_ok": {"raw": "0xFF", "state": "unset"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`.
     - Write-through confirmation in `results/writeback_gen/mcuboot_head_scratch_nrf52_direct_9311.json`: `fault_at = 9311` with `durability_model: direct` recovers with `boot_outcome = "success"`, `vtor = "0x0000C200"`, `marker_actual = "0x00000101"`, and `semantic_state.slots.exec.copy_done = {"raw": "0x01", "state": "set"}`.

2. `profiles/mcuboot_head_move_nrf52_writeback.yaml`:
   - Quick sweep command and result: `timeout 1500 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_writeback.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/writeback_gen/mcuboot_head_move_nrf52_writeback_quick.json` completed in `118.7s` over `19,685` calibrated writes and `38` erases. Points `0`, `9842`, and `19684` all returned `boot_outcome: "success"`, `vtor: "0x0000C200"`, `marker_actual: "0x00000101"`, and `semantic_state.slots.exec.copy_done.state: "set"`.
   - Why `--quick` missed the window: in `swap_run` in `boot/bootutil/src/swap_move.c`, `boot_move_sector_up` at lines 367 through 407 shifts six 4 KB sectors of `v1.0.0` up by one sector inside `exec` across writes `1..6216`, and `boot_swap_sectors` at lines 410 through 447 then swaps 4 KB sectors between `staging` and `exec`. Each 4 KB sector copy issues `1,024` four-byte writes plus `1` status write, which exceeds the `512`-write nRF52840 buffer capacity, so each unbuffered window after a sector erase is `512` writes wide. The `--quick` midpoint `9842` falls `552` writes into Phase 5 at writes `9291..10316`, which is `40` writes after capacity eviction has already committed the preceding `staging` copy at writes `8267..9290` and its status write at `9291`.
   - Targeted erase-boundary point `fault_at = 6216` in `results/writeback_gen/mcuboot_head_move_nrf52_writeback_boundaries.json`:
     - Write index and flash offset: `fault_at = 6216`, `fault_window.at.write_index = 6217` at address `0x00076000` and `flash_offset = 483328` or `0x76000`.
     - Buffered writes discarded: `512` writes to `exec` from `write_index = 5705` to `6216`, with `writes_issued = 6217` and `writes_committed = 5705`, consisting of the second half of `v1.1.0` sector 0 at `0x0000C800..0x0000CFFC` across writes `5705..6215` and the `BOOT_STATUS_STATE_0` status write in the `exec` trailer at write `6216`.
     - Erase that should have been preceded by a flush: `boot_erase_region(fap_sec, sec_off, sz)` at line 436 of `boot/bootutil/src/swap_move.c`, recorded as `erase_index = 20`, `address = "0x00076000"`, `flash_offset = 483328`, `writes_at_this_point = 6216`.
     - Phase 2 outcome and `semantic_state`: because write `6216` was discarded and `staging` sector 0 at `0x00076000` was already erased, `swap_read_status` falls back to the `BOOT_STATUS_OP_MOVE` status bytes, `boot_read_image_headers` fails on the erased `staging` header at `0x00076000` and aborts the partial swap, and MCUboot jumps into `exec` at `0x0000C000` where bytes `0x0000C800..0x0000CFFC` are still `0xFF`. Phase 2 stalls in the corrupted image until `instruction_limit(200000000)` at `pc = "0x0000D224"` with `boot_outcome = "timeout"`, `vtor = "0x00000000"`, `semantic_state.slots.exec = {"magic_state": "good", "image_ok": {"raw": "0xFF", "state": "unset"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`, and `semantic_state.slots.staging = {"magic_state": "unset", "image_ok": {"raw": "0xFF", "state": "unset"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`.
     - Write-through confirmation in `results/writeback_gen/mcuboot_head_move_nrf52_direct_6216.json`: `fault_at = 6216` with `durability_model: direct` recovers with `boot_outcome = "success"`, `vtor = "0x0000C200"`, `marker_actual = "0x00000101"`, and `semantic_state.slots.exec.copy_done = {"raw": "0x01", "state": "set"}`.

3. `profiles/mcuboot_head_move_stm32f4_writeback.yaml`:
   - Quick sweep command and result: `timeout 1500 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_stm32f4_writeback.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/writeback_gen/mcuboot_head_move_stm32f4_writeback_quick.json` calibrated `69,646` writes and `5` erases in `1.28s` emulated time and `36.0s` wall time. Under the default 30-second `phase2_wall_timeout_s`, point `0` hit `wall_timeout(31s)` at `phase2_emulated_s = 1.05` with `boot_outcome: "hard_fault"` and `vtor: "0x08000000"` because a full unstarted swap-move in Phase 2 takes `1.28` emulated seconds and `31.1s` wall time. Setting `phase2_wall_timeout_s: 90` in `profiles/mcuboot_head_move_stm32f4_writeback.yaml` allows point `0` to complete Phase 2 in `31.1s` with `boot_outcome: "success"`, `vtor: "0x08020200"`, `marker_actual: "0x00000101"`, and `copy_done: "0x01"`.
   - Trace structure and unbuffered windows on STM32F4 `swap-move`:
     - `Erase 1` at `writes_at = 0` at `0x08060000`, writes `1..21` at `0x0807FFD8..0x0807FFFC` in `swap_status_init`, `Erase 2` at `writes_at = 21` at `0x080C0000`, and `Erase 3` at `writes_at = 21` at `0x08040000` prepare `boot_move_sector_up` in `boot/bootutil/src/swap_move.c` at lines 384 through 398.
     - Writes `22..16342`, totaling `16,321` writes at `0x08040000..0x08044098`, copy `v1.0.0` from `exec` sector 0 at `0x08020000` up to `exec` sector 1 at `0x08040000`, and write `16343` at `0x0807F3D0` writes the `BOOT_STATUS_OP_MOVE` status byte `0x01`.
     - `Erase 4` at `writes_at = 16343` at `0x08020000` executes `boot_erase_region(fap_pri, pri_off, sz)` at line 424 of `boot/bootutil/src/swap_move.c` while all `16,343` prior writes are still in the `16,384`-entry writeback buffer across the `16343..32726` window.
     - Writes `16344..53322`, totaling `36,979` writes at `0x08020000..0x0802914C`, copy `v1.1.0` from `staging` at `0x08080000` to `exec` at `0x08020000`, and write `53323` at `0x0807F7D0` writes the `BOOT_STATUS_OP_SWAP` `BOOT_STATUS_STATE_0` status byte `0x01`.
     - `Erase 5` at `writes_at = 53323` at `0x08080000` executes `boot_erase_region(fap_sec, sec_off, sz)` at line 436 of `boot/bootutil/src/swap_move.c`, erasing `staging` while writes `36940..53323` are still uncommitted in the `16,384`-entry buffer.
     - Writes `53324..69644`, totaling `16,321` writes at `0x08080000..0x08084098`, copy `v1.0.0` from `0x08040000` to `staging`, write `69645` at `0x0807F7D0` writes the `BOOT_STATUS_STATE_1` status byte `0x02`, and write `69646` at `0x0807FFE0` writes `copy_done = 0x01`.
   - Why `calibration.barrier_audit` reports `verdict: "missing_barriers"` with `missing_barriers: 1` on STM32F4 `swap-move`: Phase 2 of `barrier_audit` in `domain: "staging"` spans writes `53324..69644` for `16,321` writes, which is shorter than the `16,384`-write buffer capacity, so when MCUboot switches back to `domain: "exec"` at write `69645` at `0x0807F7D0`, all `16,321` `staging` writes and `62` prior `exec` writes at `53262..53323` are still uncommitted in the buffer.
   - Extraction at `fault_at = 53323` in `results/writeback_gen/mcuboot_head_move_stm32f4_writeback_53323.json` and `fault_at = 69645` in `results/writeback_gen/mcuboot_head_move_stm32f4_writeback_quick.json`:
     - At `fault_at = 53323`, `fault_window.at.write_index = 53324` at `address = "0x08080000"` and `flash_offset = 524288`, `writes_committed = 36940`, and the buffer discards `16,383` writes to `exec` across writes `36940..53322` at `0x080250DE..0x0802914F` plus write `53323` at `0x0807F7D0`. At `fault_at = 69645`, `fault_window.at.write_index = 69646` at `address = "0x0807FFE0"` and `flash_offset = 524256`, `writes_committed = 53262`, and the buffer discards the last `60` writes of `v1.1.0` in `exec` across writes `53262..53322` at `0x08029113..0x0802914F` containing the trailing SHA-256 and ECDSA TLV, write `53323` at `0x0807F7D0`, all `16,321` `staging` writes across `53324..69644`, and write `69645` at `0x0807F7D0`.
     - In both cases, `Erase 5` from `boot_erase_region(fap_sec, sec_off, sz)` at line 436 of `boot/bootutil/src/swap_move.c` at `address = "0x08080000"`, `flash_offset = 524288`, and `writes_at_this_point = 53323` has already erased `staging`. On Phase 2 recovery boot, `swap_read_status` sees only write `16343` at `0x0807F3D0` with `bs->op = BOOT_STATUS_OP_MOVE` and `bs->idx = 2`, so `boot_read_image_headers(state, true, &bs)` reads `0xFFFFFFFF` from `staging` at `0x08080000` and returns `-1`, aborting partial swap recovery at `phase2_emulated_s = 0.05` with `semantic_state.slots.exec = {"magic_state": "good", "image_ok": {"raw": "0xFF", "state": "unset"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`, `semantic_state.slots.staging = {"magic_state": "unset", "image_ok": {"raw": "0xFF", "state": "unset"}, "copy_done": {"raw": "0xFF", "state": "unset"}}`, and `fault_snapshot_differing_bytes` equal to `20927` at `53323` and `16382` at `69645`. Phase 2 reaches `vtor = "0x08020200"` with `boot_outcome = "success"` only because the first `16 KB` of `v1.1.0` containing `.text` across writes `16344..32664` was already evicted before write `36940` and `sweep_hash_bypass_symbols: ["bootutil_img_validate"]` skips TLV hash and signature verification on the truncated `exec` image.
     - Write-through confirmation in `results/writeback_gen/mcuboot_head_move_stm32f4_direct_0_53323.json`: under `durability_model: direct`, both `fault_at = 0` at `phase2_emulated_s = 1.25` and `fault_at = 53323` at `phase2_emulated_s = 0.45` complete the swap and set `semantic_state.slots.exec.copy_done = {"raw": "0x01", "state": "set"}` with `boot_outcome = "success"`.

## Draft upstream report

### Summary and durability assumption

MCUboot's `swap-scratch` and `swap-move` state machines assume that every byte written by `flash_area_write` during `BOOT_STATUS_STATE_0` is durable on non-volatile media before `boot_erase_region` calls `flash_area_erase` on the source slot in `BOOT_STATUS_STATE_1`. Neither swap algorithm invokes a flush, sync, or read-back barrier on the destination flash area or status trailer flash area before erasing the source sector. When `flash_area_write` is backed by a write-buffered storage layer where `flash_area_erase` on one region does not implicitly flush pending writes to other regions or sectors, a power loss during or after the source-slot erase discards buffered destination payload and swap-status writes while leaving the source slot erased on the medium.

### Pinned commit and source locations

At MCUboot commit `f84b9d3fd019fb1945e532924bee7a9c03c77373`, the unbarriered write-then-erase transitions occur at three locations:

1. `boot/bootutil/src/swap_scratch.c` lines 443 through 468 in `boot_swap_sectors`:
   - Under `if (bs->state == BOOT_STATUS_STATE_0)` at lines 443 through 451, `boot_erase_region(fap_scratch, 0, fap_scratch->fa_size)` erases `scratch`, `boot_copy_region(state, fap_secondary_slot, fap_scratch, img_off, 0, sz)` copies `sz` bytes from the secondary slot into `scratch` via `flash_area_write`, `bs->state = BOOT_STATUS_STATE_1` advances the in-memory state, and `boot_write_status(state, bs)` calls `flash_area_write` on the status trailer in `fap_primary_slot` or `fap_scratch`.
   - Under `if (bs->state == BOOT_STATUS_STATE_1)` at lines 452 through 468, `boot_erase_region(fap_secondary_slot, img_off, sz)` at line 453 immediately calls `flash_area_erase` on the secondary slot without flushing `fap_scratch` or `fap_primary_slot`.
2. `boot/bootutil/src/swap_move.c` lines 383 through 407 in `boot_move_sector_up`:
   - Under `if (bs->state == BOOT_STATUS_STATE_0)` at lines 383 through 395, `boot_erase_region(fap, dst_off, sz)` erases the upper primary sector, `boot_copy_region(state, fap, fap, src_off, dst_off, sz)` copies the lower primary sector up by one sector via `flash_area_write`, and `boot_write_status(state, bs)` writes the status entry to the primary trailer.
   - Next, `boot_swap_sectors` at line 424 erases `src_off` in `fap_pri` without an intervening flush on the destination sector or trailer.
3. `boot/bootutil/src/swap_move.c` lines 423 through 446 in `boot_swap_sectors`:
   - Under `if (bs->state == BOOT_STATUS_STATE_0)` at lines 423 through 434, `boot_erase_region(fap_pri, pri_off, sz)` erases the primary sector, `boot_copy_region(state, fap_sec, fap_pri, sec_off, pri_off, sz)` copies the secondary sector into the primary slot via `flash_area_write`, and `boot_write_status(state, bs)` writes the `BOOT_STATUS_STATE_0` status entry to the primary trailer.
   - Under `if (bs->state == BOOT_STATUS_STATE_1)` at lines 435 through 446, `boot_erase_region(fap_sec, sec_off, sz)` at line 436 immediately calls `flash_area_erase` on the secondary sector without flushing `fap_pri`.

### Affected and unaffected flash stacks

- **Unaffected flash stacks**: Raw internal MCU NOR flash controllers driven by polling programming registers until completion on every call, including Zephyr's `soc_flash_stm32.c` on STM32F4 where `FLASH_SR.BSY` is polled per byte or word and `nrf_nvmc` on nRF52840 where `NVMC->READY` is polled per 32-bit word, commit each `flash_area_write` directly to the flash array before returning.
- **Affected flash stacks**:
  - RTOS block-to-MTD translation layers with write buffering such as Apache NuttX `drivers/mtd/ftl.c` configured with `CONFIG_FTL_WRITEBUFFER=y` and `drivers/misc/rwbuffer.c`, where `flash_area_write` appends to a RAM writebuffer and an erase ioctl on another sector does not flush unrelated buffered blocks.
  - External QSPI or OSPI NOR drivers and XIP controllers configured with page-program write-combining caches or asynchronous DMA staging buffers that defer commit until a page boundary or explicit sync call.
  - Flash Translation Layers on managed NAND, eMMC, or SD cards where `flash_area_write` targets logical blocks cached in controller SRAM and `flash_area_erase` issues trim or discard on a separate logical block range without forcing a cache flush.
  - Filesystem-backed or POSIX-emulated `flash_area` backends where `flash_area_write` writes to page cache without `fsync` before erasing another partition file or region.

### Medium state after power loss and next-boot behavior

1. **`swap-scratch` silent downgrade to the old primary image**:
   - When power fails during `BOOT_STATUS_STATE_1` after `boot_erase_region(fap_secondary_slot, img_off, sz)` has erased the secondary slot in `boot/bootutil/src/swap_scratch.c` line 453 but before the buffered writes from `BOOT_STATUS_STATE_0` are flushed, the medium retains the old `v1.0.0` image in `fap_primary_slot`, an erased `0xFF` header and payload in `fap_secondary_slot`, a truncated `v1.1.0` copy in `fap_scratch`, and an all-`0xFF` status area in the `fap_primary_slot` trailer because the `boot_write_status` write for `BOOT_STATUS_STATE_0` was still in the writeback buffer.
   - On the next boot, `swap_read_status_bytes` in `boot/bootutil/src/swap_misc.c` lines 253 through 289 scans the primary trailer, finds only `0xFF`, and sets `bs->idx = BOOT_STATUS_IDX_0` and `bs->state = BOOT_STATUS_STATE_0`. `boot_validated_swap_type` sees `BOOT_SWAP_TYPE_NONE` because the secondary slot magic was erased with `fap_secondary_slot`. `boot_prepare_image_for_update` does not resume the swap, and `context_boot_go` validates and boots the old `v1.0.0` primary image while the staged `v1.1.0` update is permanently lost.
2. **`swap-move` mid-swap corruption or unbootable primary slot**:
   - When power fails during `BOOT_STATUS_STATE_1` after `boot_erase_region(fap_sec, sec_off, sz)` in `boot/bootutil/src/swap_move.c` line 436 has erased sector 0 of `fap_sec` while the trailing portion of the `v1.1.0` sector-0 copy into `fap_pri` and its `BOOT_STATUS_STATE_0` status write are still buffered, the medium retains only the earlier `BOOT_STATUS_OP_MOVE` status entries in the `fap_pri` trailer, a partially written sector 0 in `fap_pri`, and an erased sector 0 in `fap_sec`.
   - On the next boot, `swap_read_status` reconstructs `bs->op = BOOT_STATUS_OP_MOVE`, enters the partial-swap recovery path in `boot_prepare_image_for_update`, and calls `boot_read_image_headers(state, true, &bs)`. Because `fap_sec` sector 0 was already erased and `bs->op` does not reflect the lost `BOOT_STATUS_OP_SWAP` status write, `boot_read_image_headers` reads `0xFFFFFFFF` as the secondary image magic and returns `-1`. `boot_prepare_image_for_update` aborts swap recovery without completing `copy_done`, leaving `fap_pri` half-written; on nRF52840 at `fault_at = 6216` where sector 0 `.text` at `0x0000C800..0x0000CFFC` was lost in the buffer, execution faults or stalls when jumping into the corrupted primary slot.

### Minimal reproduction commands

Using this repository with the `tardigrade-oss-validation:latest` Docker image:

```sh
# 1. swap-scratch on STM32F4: reproduces wrong_image at fault_at = 45156
python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_stm32f4_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 --quick --no-assert-verdict \
  --output results/repro_scratch_stm32f4.json

# 2. swap-scratch on nRF52840: reproduces wrong_image at erase boundary fault_at = 9311
python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_nrf52_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --fault-start 9311 --fault-end 9311 --no-assert-verdict \
  --output results/repro_scratch_nrf52_9311.json

# 3. swap-move on nRF52840: reproduces corrupted primary slot and boot timeout at fault_at = 6216
python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_move_nrf52_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --fault-start 6216 --fault-end 6216 --no-assert-verdict \
  --output results/repro_move_nrf52_6216.json
```

### Mitigation for bootloader and flash-backend authors

1. **Add an explicit flash durability barrier before every source-slot erase in the swap state machine**:
   - Introduce a `flash_area_flush(const struct flash_area *fa)` or `flash_area_sync(const struct flash_area *fa)` API in MCUboot's porting layer, defaulting to a no-op on synchronous internal NOR drivers and mapped to the underlying MTD/FTL flush ioctl or cache sync on buffered drivers.
   - In `boot/bootutil/src/swap_scratch.c` `boot_swap_sectors`, flush `fap_scratch` and the status trailer flash area after `boot_write_status(state, bs)` at line 450 and before `boot_erase_region(fap_secondary_slot, img_off, sz)` at line 453, and flush `fap_primary_slot` and the status trailer after `boot_write_status(state, bs)` at line 467 and before `boot_erase_region(fap_scratch, 0, fap_scratch->fa_size)`.
   - In `boot/bootutil/src/swap_move.c`, flush `fap` after `boot_write_status(state, bs)` at line 394 of `boot_move_sector_up` before `boot_swap_sectors` erases `fap_pri` at line 424, and flush `fap_pri` after `boot_write_status(state, bs)` at line 433 before `boot_erase_region(fap_sec, sec_off, sz)` at line 436.
2. **Enforce cross-region flush on erase or read-back verification in the platform `flash_area` implementation**:
   - On platforms where the MCUboot state machine cannot be modified, `flash_area_erase` must flush all pending buffered writes across every MCUboot flash area before issuing the erase, or `boot_write_status` and `boot_copy_region` must perform an uncached read-back verification from the physical medium before returning `0`.

## Tractability of `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml`

### Root cause of the 67,611-point heuristic plan

The default heuristic planner emits `67,611` cutpoints out of `90,313` calibrated writes, or `74.86%` of the trace, because STM32F4 byte-wide flash programming interacts with consecutive-offset overwrite detection in `scripts/write_trace_heuristic.py`:

1. **Byte-granularity programming recorded as 4-byte aligned word writes**: Zephyr's STM32F4 flash driver `soc_flash_stm32.c` programs internal flash with `FLASH_CR_PSIZE = 0`, issuing 1-byte writes during `boot_copy_region`. In `peripherals/STM32F4FlashController.cs`, `RecordTraceWrite` aligns every byte write to its 32-bit word offset via `changedOffset & ~3` with `width = 4`. Each 4-byte word in a bulk image copy therefore generates four consecutive trace entries with the identical `flash_off`.
2. **Promotion of 3 out of 4 bulk-copy byte writes into `tier1`**: In `scripts/write_trace_heuristic.py` at line 325, `classify_trace` checks `if i > 0 and flash_off == trace[i - 1][1]: overwrite_indices.add(i)`. Across the `90,313`-write `swap-scratch` trace on STM32F4, `67,565` writes are consecutive byte writes to the same 4-byte aligned word offset and are added to `overwrite_indices`. Lines 349 through 353 promote all `overwrite_indices` into `tier1`.
3. **Unbounded retention when `preserve_critical_tiers` is enabled**: In `HeuristicConfig` in `scripts/write_trace_heuristic.py` at line 42, `preserve_critical_tiers` defaults to `True`. At line 427 of `scripts/write_trace_heuristic.py`, `classify_trace` returns `sorted(critical)` without subsampling whenever `len(critical) >= target` and `preserve_critical_tiers` is `True`, bypassing `max_heuristic_points = 2000` in `scripts/sweep.py` line 623.
4. **Per-point container and CLR replay overhead under writeback mode**: In `scripts/sweep.py` at line 606, `durability_model == "writeback"` forces `max_batch_points = 1`, spawning a fresh Docker container per fault point. Inside each container, `writeback_apply_to_trace_snapshot` in `scripts/run_runtime_fault_sweep.py` at lines 3451 through 3483 allocates a CLR `System.Byte` array per committed write and iterates byte-by-byte across `131,072`-byte STM32F4 sectors on every erase, taking `60s` to `150s` per point.
5. **YAML schema mismatch between `docs/writing-profiles.md` and `scripts/profile_loader.py`**: Although `docs/writing-profiles.md` at line 982 documents the YAML key under `fault_sweep` as `heuristic_config`, `scripts/profile_loader.py` at lines 4150 and 6982 validates and parses `heuristic`. Setting `heuristic` in `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` with `preserve_critical_tiers: false`, `target_points: 25`, and `critical_regions` covering the primary and scratch status trailers at `0x0803F3D0..0x08040004` and `0x0805FFD0..0x08060000` plus the slot headers at `0x08008000..0x08008004` and `0x08108000..0x08108004` reduces the planned heuristic set from `67,611` points to `25` points while preserving `tier0` status-byte transitions, erase boundaries, and phase transitions.

### Flagged window across the `BOOT_STATUS_STATE_0 -> BOOT_STATUS_STATE_1` transition

In `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` with `90,313` calibrated writes and `writeback_capacity = 16,384`:

- **First failing `fault_at`**: `fault_at = 37021`. Write `37021` at `0x0803FFD0` with `flash_offset = 0x3FFD0` is the 1-byte `boot_write_status` call at the end of `BOOT_STATUS_STATE_0` in `boot/bootutil/src/swap_scratch.c` line 450 after `boot_copy_region` copies `v1.1.0` from `staging` to `scratch` across writes `43..37020`. Immediately after write `37021`, `BOOT_STATUS_STATE_1` at line 453 executes `boot_erase_region(fap_secondary_slot, img_off, sz)`, recorded as `Erase 4..7` at `writes_at_this_point = 37021` across `0x08060000..0x080C0000`. A power cut at `fault_at = 37021` leaves `staging` erased on flash while discarding buffered writes `20638..37021`, including write `37021` to the `exec` trailer. Phase 2 boots `v1.0.0` with `boot_outcome = "wrong_image"`.
- **Midpoint verification**: `fault_at = 45156` in `results/writeback_scratch_stm32f4_quick.json` falls `8,135` writes into `BOOT_STATUS_STATE_1` while `boot_copy_region(state, fap_primary_slot, fap_secondary_slot, ...)` is copying `v1.0.0` from `exec` into `staging` across writes `37022..53342`. Because `45156 - 37021 = 8,135 < 16,384`, write `37021` and `scratch` writes `28773..37020` remain uncommitted in the `16,384`-entry FIFO buffer and are lost on power loss, producing `boot_outcome = "wrong_image"`, `vtor = "0x08008200"`, and `marker_actual = "0x00000001"`.
- **Last failing `fault_at`**: `fault_at = 53404`. Write `37021` remains in the `16,384`-entry FIFO buffer until `16,384` subsequent writes across `37022..53405` have entered the buffer and evicted it via capacity overflow. At `fault_at = 53404`, `writes_committed = 37020`, so write `37021` is the oldest uncommitted entry in `buffer` and is discarded on power loss. At `fault_at = 53405`, `62` writes into `BOOT_STATUS_STATE_2` while copying `scratch` to `exec` across writes `53344..90311`, capacity eviction commits write `37021` at `0x0803FFD0` and all `scratch` writes `43..37020` to flash, allowing Phase 2 recovery to resume from `scratch` and complete the upgrade to `v1.1.0`.

## Vector table offset resolution for `mcuboot_head_scratch_stm32f4_writeback.yaml`

The vector table offset for `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` and its base profile `profiles/mcuboot_head_scratch_stm32f4_upgrade.yaml` is `0x200`, matching the tracked `zephyr_head_scratch_stm32f4_mirrored_slot0.bin` and `zephyr_head_scratch_stm32f4_mirrored_slot1.bin` images. Setting `success_criteria.vector_table_offset` to `0x400` in the profile was wrong for those pinned Zephyr 3.7 images.

1. Image bytes in `zephyr_head_scratch_stm32f4_mirrored_slot0.bin` at `16,540` bytes and `zephyr_head_scratch_stm32f4_mirrored_slot1.bin` at `37,200` bytes:
   - Both headers store `ih_magic = 0x96F3B83D` at offset `0x00` and `ih_hdr_size = 0x0200` at offset `0x08`, with version words `0x00000001` and `0x00000101` at offset `0x14`.
   - At offset `0x200`, corresponding to `0x08008200` in `exec` and `0x08108200` in `staging`, both images place the Cortex-M vector table: word `0` is initial stack pointer `0x200007C0` in SRAM `0x20000000..0x20040000` and word `1` is Thumb reset vector `0x08009131` inside `exec` `0x08008000..0x08040000`.
   - At offset `0x400`, word `0` is `0xF707FA20` and word `1` is `0xEA474095`, which are Thumb-2 `.text` instructions rather than a vector table.
   - In the application reset entry at `0x08009130`, `bl 0x08009344` at `0x08009170` loads `_vector_start = 0x08008200` from literal pool address `0x08009374` and writes `0x08008200` to `SCB->VTOR` at `0xE000ED08` at instruction `0x0800934e`.
2. Bootloader handoff in `results/oss_validation/assets/oss_mcuboot_head_scratch_stm32f4.elf`:
   - In `main` at `0x0800050c..0x08000544`, MCUboot does not use a fixed `0x400` offset. Instruction `0x08000518` executes `ldrh r2, [r2, #8]` to read `br_hdr->ih_hdr_size = 0x200`, adds `flash_base + br_image_off = 0x08008000` to form vector table pointer `vt = 0x08008200` in `0x20020240`, loads `MSP = 0x200007C0` from `0x08008200` at `0x0800052c`, loads `reset = 0x08009131` from `0x08008204` at `0x08000542`, and branches via `blx r3` at `0x08000544`.
3. Runtime success evaluation in `scripts/run_runtime_fault_sweep.py`:
   - When `vtor_in_slot: exec` is active, `evaluate_boot_outcome` at lines `7209`, `7219..7222`, and `7239..7240` checks only `actual_vtor % 128 == 0` and `s_lo <= actual_vtor < s_hi` across `0x08008000..0x08040000`; `evaluate_boot_outcome` never compares `actual_vtor` against `s_lo + success_vector_offset`.
   - When the earlier profile override set `vtor_in_slot: null`, `pc_in_slot: exec`, and `vector_table_offset: 0x400`, `run_until_done` at lines `8003..8049` read `0x08008000 + 0x400 = 0x08008400`, saw `reset_vector = 0xEA474095` outside `0x08008000..0x08040000`, and installed no reset-handler hook in `pc_handoff_hook_addresses`. Even so, MCUboot jumped through `ih_hdr_size = 0x200` to `0x08009131`, and per-slice polling at line `8081` called `capture_sticky_pc` at lines `2002..2009`, which tests `s_lo <= pc < s_hi` without `vector_table_offset` and captured `pc = 0x0800ADF2` in `exec`.
   - Setting `success_criteria.vector_table_offset: 0x200` in `profiles/mcuboot_head_scratch_stm32f4_upgrade.yaml` and `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` aligns `pc_handoff_vector_offset` and postmortem `evaluate_slot_header` checks at lines `5118..5142` and `5289..5304` with the `0x200` image header.
4. Verification run with `vector_table_offset: 0x200`:

```bash
timeout 1200 python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_head_scratch_stm32f4_writeback.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --quick \
  --workers 2 \
  --output results/writeback_vector_offset_check.json
```

The command exited `0` in `225.7s` wall time with `effective_success_criteria.vector_table_offset = 512` or `0x200`. The clean control passed after `90,313` writes and `10` erases with `vtor = "0x08008200"`, `pc = "0x0800ADF2"`, `marker_actual = "0x00000101"`, and `marker_ok = true`. Fault points `0` and `90312` recovered to `v1.1.0` with `boot_outcome = "success"`, and midpoint `fault_at = 45156` at `0x0810A00C` reproduced `boot_outcome = "wrong_image"` with `vtor = "0x08008200"` and `marker_actual = "0x00000001"`, yielding top-level verdict `PASS` for `expect.should_find_issues: true` with `1` issue point and `0` bricks out of `3` points.

### Runtime enforcement of `vector_table_offset` across all declaring profiles

All 15 profiles in `profiles/` that declare `success_criteria.vector_table_offset` set `0x200`, matching the `0x200` header size and vector table offset in their `images.exec` binaries. In `scripts/run_runtime_fault_sweep.py`, `evaluate_boot_outcome` now requires the captured VTOR register to equal `slot_base + vector_table_offset` when `vtor_in_slot` is set with a non-zero `vector_table_offset`, and requires the captured sticky PC to fall at or above `slot_base + vector_table_offset` and below `slot_end` when `pc_in_slot` is set with a non-zero `vector_table_offset`. When either check fails, `evaluate_boot_outcome` records the expected and actual addresses in `signals.failure_reason`, `signals.vtor_failure_reason`, and `signals.pc_failure_reason`. Profiles that omit `vector_table_offset` retain the full in-slot range check from `slot_base` to `slot_end`.

| **Profile** | **Slot `exec` base and size** | **Declared `vector_table_offset`** | **Image `images.exec` and actual vector table offset in bytes** | **Before enforcement** | **After enforcement** |
| --- | --- | --- | --- | --- | --- |
| `profiles/mcuboot_head_scratch_stm32f4_upgrade.yaml` | `0x08008000`, size `0x38000` | `0x200` | `results/oss_validation/assets/zephyr_head_scratch_stm32f4_mirrored_slot0.bin`: `ih_magic = 0x96F3B83D`, `ih_hdr_size = 0x200`, vector table at `0x200` with SP `0x200007C0` and reset `0x08009131` | Control and all 6 quick points passed with `vtor = 0x08008200`; `evaluate_boot_outcome` checked only `0x08008000 <= vtor < 0x08040000` | Control and all 6 quick points pass in `539.8s` with `vtor = 0x08008200`, matching `vtor_expected = 0x08008200` |
| `profiles/mcuboot_head_scratch_stm32f4_writeback.yaml` | `0x08008000`, size `0x38000` | `0x200` | `results/oss_validation/assets/zephyr_head_scratch_stm32f4_mirrored_slot0.bin`: `ih_magic = 0x96F3B83D`, `ih_hdr_size = 0x200`, vector table at `0x200` with SP `0x200007C0` and reset `0x08009131` | Control passed with `vtor = 0x08008200` even when `vector_table_offset` was set to `0x400`, because `evaluate_boot_outcome` checked only slot bounds | Control passes in `638.6s` with `vtor = 0x08008200` matching `vtor_expected = 0x08008200`; points `0` and `90312` recover and point `45156` reports `wrong_image` |
| `profiles/nxboot_style_hook_fault.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed with `vector_base = 0x10002200` and `vector_valid = true`; 3 power-loss points flagged and 9 hook points skipped on `nvm_ctrl` | Control passes in `114.3s` with `vector_base = 0x10002200` and `vector_valid = true`; 3 power-loss points flagged and 9 hook points skipped on `nvm_ctrl` |
| `profiles/nxboot_style_partial_staging.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed with `vector_base = 0x10002200` and `vector_valid = true`; 3 quick points flagged `hard_fault` with verdict `PASS` | Control passes in `79.5s` with `vector_base = 0x10002200` and `vector_valid = true`; 3 quick points flagged `hard_fault` with verdict `PASS` |
| `profiles/nxboot_style_instruction_skip.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000`, reset `0x10002241`, and hardfault `0x10002241` | Execute-mode control captured `vtor = 0x10002200` with `vtor_ok = true`, then aborted with `boot_outcome = "hard_fault"` because `gen_nxboot_images.py` sets `hardfault_vector` at `0x1000220C` equal to `reset_vector` at `0x10002241` | Execute-mode control captures `vtor = 0x10002200` matching `vtor_expected = 0x10002200` with `vtor_ok = true`, and aborts on the same shared `reset_vector` and `hardfault_vector` address `0x10002241` in `nxboot_primary.bin` |
| `profiles/nxboot_style_instruction_skip_bad_image.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000`, reset `0x10002241`, and hardfault `0x10002241` | Execute-mode control captured `vtor = 0x10002200` with `vtor_ok = true`, then aborted with `boot_outcome = "hard_fault"` because `hardfault_vector` equals `reset_vector` at `0x10002241` | Execute-mode control captures `vtor = 0x10002200` matching `vtor_expected = 0x10002200` with `vtor_ok = true`, and aborts on the same shared `reset_vector` and `hardfault_vector` address `0x10002241` |
| `profiles/nxboot_style_instruction_skip_boot_logic.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000`, reset `0x10002241`, and hardfault `0x10002241` | Execute-mode control captured `vtor = 0x10002200` with `vtor_ok = true`, then aborted with `boot_outcome = "hard_fault"` because `hardfault_vector` equals `reset_vector` at `0x10002241` | Execute-mode control captures `vtor = 0x10002200` matching `vtor_expected = 0x10002200` with `vtor_ok = true`, and aborts on the same shared `reset_vector` and `hardfault_vector` address `0x10002241` |
| `profiles/nxboot_style_instruction_skip_probe.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000`, reset `0x10002241`, and hardfault `0x10002241` | Execute-mode control captured `vtor = 0x10002200` with `vtor_ok = true`, then aborted with `boot_outcome = "hard_fault"` because `hardfault_vector` equals `reset_vector` at `0x10002241` | Execute-mode control captures `vtor = 0x10002200` matching `vtor_expected = 0x10002200` with `vtor_ok = true`, and aborts on the same shared `reset_vector` and `hardfault_vector` address `0x10002241` |
| `profiles/nxboot_style_no_crc.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` because `run_state_fault` does not emit `image_hash_match` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_no_recovery.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_no_revert.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_update.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_update_erase_fault.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_update_multifault.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |
| `profiles/nxboot_style_update_phase2fault.yaml` | `0x10002000`, size `0x23000` | `0x200` | `examples/nxboot_style/nxboot_primary.bin`: `magic = 0x534F584E`, `header_size = 0x200`, vector table at `0x200` with SP `0x20020000` and reset `0x10002241` | State-mode control passed `vector_valid = true` at `0x10002200`, then `_validate_runtime_control_result` aborted with `configured image_hash was not confirmed` | State-mode control passes `vector_valid = true` at `0x10002200`, and `_validate_runtime_control_result` aborts on the same missing `image_hash_match` signal in state mode |

