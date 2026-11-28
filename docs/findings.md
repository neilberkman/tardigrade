# Findings and validation history

What tardigrade has found in real upstream code, and the known bugs it is checked against. Only the NuttX nxboot failure was found by tardigrade. The MCUboot and Zephyr bugs were reported and fixed upstream by other people and are reproduced here. The [README](../README.md) has the short version.

## NuttX nxboot -- original discovery

A historical Tardigrade campaign against the upstream [NuttX nxboot bootloader](https://github.com/apache/nuttx-apps/tree/45d4c7098bb3a7a6d9b5642efc47df5998c048d5/boot/nxboot) found a power-loss recovery vulnerability: 92 of 94 tested fault points resulted in the bootloader jumping to partially-written firmware. Three fixes were submitted:

| Fix                                                                                         | PR                                                                       |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| FTL layer ignores `O_DIRECT` flag -- writes buffered in RAM despite explicit bypass request | [apache/nuttx#18552](https://github.com/apache/nuttx/pull/18552)         |
| Missing flush barriers between critical partition writes in nxboot                          | [apache/nuttx-apps#3428](https://github.com/apache/nuttx-apps/pull/3428) |
| Boot decision validates header only, not image CRC                                          | [apache/nuttx-apps#3428](https://github.com/apache/nuttx-apps/pull/3428) |

The FTL `O_DIRECT` bug affects all NuttX applications that write to MTD partitions expecting direct access, not just nxboot.

## MCUboot retroactive validation

Five MCUboot historical differential pairs separate broken from fixed firmware on their current profiles:

| PR                                                      | Bug                                                                 | Broken revision result | Fixed revision result |
| ------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------- | --------------------- |
| [#2100](https://github.com/mcu-tools/mcuboot/pull/2100) | Revert magic left in bad state in swap-move                         | 3 `wrong_image` issues across 277 heuristic points, 1.1%; 3 bricks across 31 points, 9.7% | 0 issues              |
| [#2109](https://github.com/mcu-tools/mcuboot/pull/2109) | Header reload from wrong slot after interrupted swap in swap-scratch | 3 bricks across 6 quick points, 50.0%; 19 bricks across 57 points, 33.3%      | 0 bricks              |
| [#2199](https://github.com/mcu-tools/mcuboot/pull/2199) | Stuck revert where primary trailer is never cleared in swap-move    | Control boot only, see note | 0 issues         |
| [#2206](https://github.com/mcu-tools/mcuboot/pull/2206) | Multi-sector align-32 trailer erase omitted in swap-scratch         | 1 `wrong_image` (`boot_outcome`) issue across 5 quick points (20.0%) and 854 heuristic points (0.1%) | 0 issues              |
| [#2214](https://github.com/mcu-tools/mcuboot/pull/2214) | Off-by-one sector index in `find_last_idx` in swap-offset           | Control boot refuses upgrade | Swaps and boots staging |

PR #2199 note: no fault point detects this bug. `profiles/mcuboot_pr2199_move_broken.yaml` sets `expect.allow_control_only_issues: true`, and the stuck revert reproduces on the clean control boot with no injected fault. Detection comes from the MCUboot semantic state probe on that control boot: the primary trailer still holds GOOD magic with `copy_done` set and `image_ok` unset, which is the REVERT state that the fixed build clears.

PR #2206 note: `profiles/mcuboot_pr2206_scratch_geom_broken.yaml` (commit `66d41e73`, immediately before PR #2206's multi-sector trailer erase fix `d1a3b953`) and `profiles/mcuboot_pr2206_scratch_geom_fixed.yaml` (PR #2206 head `d00b11dc`) run in the default self-test corpus on mirrored-bank STM32F429 slots (`0x18000` across 16 KiB + 16 KiB + 64 KiB, `write-block-size = 4`, `MCUBOOT_BOOT_MAX_ALIGN = 32`, `CONFIG_BOOT_MAX_IMG_SECTORS = 5450`, `boot_trailer_sz(4) = 0x10018`). During revert of an unconfirmed `0x7D50` image extending into sector 1, broken `66d41e73` omits `swap_erase_trailer_sectors` and leaves stale `copy_done = 1` at `0x0801FFA0`; power loss at the final `image_ok` write (`w=16291`, `0x0801FFC0`) causes Phase 2 to trigger a second revert and boot the rejected `v2.0.0` image (`wrong_image`, `required_issue_reasons: [boot_outcome]`), while fixed `d00b11dc` erases primary sector 2 and recovers with 0 issues.

PR #2214 note: `profiles/mcuboot_pr2214_offset_broken.yaml` and `profiles/mcuboot_pr2214_offset_fixed.yaml` separate on the unfaulted control boot on an nRF52840 swap-offset layout where the secondary slot is one 4 KiB sector larger than the primary and the staged image has swap size `0x74000`. Broken commit `429e2fea` aborts with insufficient space and stays on the old image, while fixed commit `90fd59d2` completes the swap and boots the staged image. The STM32F429 mirrored-bank geometry pair `mcuboot_pr2214_offset_geom_broken.yaml` and `mcuboot_pr2214_offset_geom_fixed.yaml` also separates on the unfaulted control boot on a `0x18000` primary and `0x38000` secondary layout with swap size `0x8000`. All four PR #2214 profiles run as strict regression profiles in `scripts/self_test.py` via `scripts/self_test_runtime_manifest.json`.

Candidate pairs for PRs [#1597](https://github.com/mcu-tools/mcuboot/pull/1597) and [#2205](https://github.com/mcu-tools/mcuboot/pull/2205) were removed after trace analysis showed that PR #1597's 1-sector staged image never enters the broken `g_last_idx` swap branch while its transplanted fixed `swap_move.c` passes `0` as `NULL` to `boot_read_swap_size`, and PR #2205 only adds an extra swap iteration on the erased upper 128 KiB sector while completing the upgrade and recovering on all 6 quick fault points across five STM32F4 layouts. An earlier PR #2206 boundary-validation candidate (`e35461d2` vs `08985c96`) whose cycle-0 `wrong_image` came from `compute_slot_hash` hashing across normal primary-slot swap-status bytes was superseded by the `66d41e73`/`d00b11dc` multi-sector trailer erase pair above.

See [`docs/mcuboot-differentials.md`](mcuboot-differentials.md) for the status table, `--quick` differential gate, and trace analysis across the five retained MCUboot PR differential pairs and the two removed pairs.
See [`docs/mcuboot-pr2214-swap-offset.md`](mcuboot-pr2214-swap-offset.md) for the PR #2214 swap-offset sector-count derivation and STM32F4 geometry root cause.

## MCUboot upstream

Tardigrade's torn-write power-loss model is part of MCUboot's simulator: it was proposed in [mcu-tools/mcuboot#2648](https://github.com/mcu-tools/mcuboot/pull/2648) in July 2026 and merged with [mcu-tools/mcuboot#3011](https://github.com/mcu-tools/mcuboot/pull/3011) in November 2026. #3011 fixes two revert bugs reported in [#3009](https://github.com/mcu-tools/mcuboot/issues/3009) (swap-move: the revert is lost and the unconfirmed image keeps booting) and [#3010](https://github.com/mcu-tools/mcuboot/issues/3010) (swap-using-offset: the device asserts on every boot), and its two-power-loss sweep reproduces both. Tardigrade reproduces both on an emulated nRF52840 with broken and fixed builds ([MCUboot differentials](mcuboot-differentials.md)), and its recovery-state search finds #3009 without hand-picked cut pairs.
