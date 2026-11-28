# Supported targets

The upstream projects tardigrade runs against, how their test assets are built, and the reference examples used for self-testing.

## Real upstream integrations

**MCUboot** covers narrow canary profiles against MCUboot HEAD, retroactive broken and fixed differential profiles for 5 known bugs, geometry-variant profiles, and multi-step exploratory scenarios with semantic probes and invariant checking on nRF52840 NVMC and STM32F4. The five retained historical PR differentials separate broken from fixed firmware: `#2100` for revert-magic corruption, `#2109` for header reload after resume, `#2199` for a stuck revert trailer on the control boot, `#2206` for omitted multi-sector align-32 trailer erasure in swap-scratch, and `#2214` for swap-offset sector-index calculation, while the candidate pairs for `#1597` and `#2205` were removed as documented in [`docs/mcuboot-differentials.md`](mcuboot-differentials.md). Each validated bug class was also checked against the other swap algorithms to test for cross-algorithm variants. See `profiles/mcuboot_*.yaml` and [`targets/mcuboot/`](../targets/mcuboot/).

The current-head STM32F4 swap-scratch profiles use dedicated mirrored-bank STM32F429 assets. Their 2 MiB STM32F429 layout places 224 KiB slots at `0x08008000` and `0x08108000`, with a 128 KiB scratch sector at flash offset `0x40000`; the slots each span the final two of a bank's four 16 KiB sectors, its 64 KiB sector, and one 128 KiB sector.

To rebuild the MCUboot matrix assets, make an Arm GNU toolchain available,
bootstrap the pinned Zephyr and MCUboot workspace, and then run the matrix
builder:

```bash
export GNUARMEMB_TOOLCHAIN_PATH=/path/to/arm-gnu-toolchain
./scripts/bootstrap_mcuboot_matrix_assets.sh
./scripts/build_mcuboot_head_matrix.sh
```

`scripts/bootstrap_mcuboot_matrix_assets.sh` also accepts `MCUBOOT_BOOTSTRAP_SCOPE=full|head|pr2206_geom|pr2214|pr2214_geom|swaptable|stm32f4` for targeted rebuilds. The build scripts write the generated ELFs and signed slot images under `results/oss_validation/assets/`. [`scripts/check_mcuboot_swap_tables.py`](../scripts/check_mcuboot_swap_tables.py) verifies the compiled `boot_flash_map` and `flash_map` tables across all 28 tracked MCUboot ELFs, and [`scripts/check_mcuboot_images.py`](../scripts/check_mcuboot_images.py) verifies the MCUboot headers, reset vectors, and profile slot alignment across all 35 tracked `.bin` payloads and 96 MCUboot profiles. The normal and fast STM32F4 profiles share the current-head bootloader and mirrored slot images; the fast profile changes the Renode backend for execute-mode performance. The dedicated [`mcuboot_head_scratch_stm32f4_writeback.yaml`](../profiles/mcuboot_head_scratch_stm32f4_writeback.yaml), [`mcuboot_head_scratch_nrf52_writeback.yaml`](../profiles/mcuboot_head_scratch_nrf52_writeback.yaml), [`mcuboot_head_move_nrf52_writeback.yaml`](../profiles/mcuboot_head_move_nrf52_writeback.yaml), and [`mcuboot_head_move_stm32f4_writeback.yaml`](../profiles/mcuboot_head_move_stm32f4_writeback.yaml) profiles apply the writeback durability model across swap-scratch and swap-move on STM32F4 and nRF52840.
See [`docs/mcuboot-asset-provenance.md`](mcuboot-asset-provenance.md) for the MCUboot ELF flash-map and slot-image provenance audit and rebuild inventory.

**NuttX nxboot** runs real upstream NuttX firmware built from source with upstream board configs from [apache/nuttx#18509](https://github.com/apache/nuttx/pull/18509). Tardigrade found a power-loss recovery vulnerability with 92 bricks out of 94 fault points that led to fixes in both the NuttX kernel in [#18552](https://github.com/apache/nuttx/pull/18552) and nxboot in [nuttx-apps#3428](https://github.com/apache/nuttx-apps/pull/3428). The target adapter in [`targets/nuttx_nxboot/`](../targets/nuttx_nxboot/) includes a build script, runtime profile generator, and state probe. All four generated canary presets `baseline`, `sector_boundary_resume`, `metadata_erase_resume`, and `sector_boundary_writeback` have 12 completed verification reports under `results/nuttx_canary_verification/`, including all four CI-mode asserting runs with 0 issues, 0 bricks, and 0 timeouts.
See [`docs/nuttx-canary-verification.md`](nuttx-canary-verification.md) for the 12-run verification matrix across all four NuttX nxboot canary profiles.

**rustBoot** -- an independent state probe and invariant package for the public
MIT-licensed rustBoot partition/trailer protocol. No rustBoot prebuilt firmware
is distributed. See [`targets/rustboot/`](../targets/rustboot/) and
[`docs/rustboot-target.md`](rustboot-target.md) for the adapter reference.

**Trusted Firmware-M BL2** provides a four-slot probe, multi-image acceptance invariants, persisted-snapshot evaluator, source build script [`targets/tf_m_bl2/build_public_target.sh`](../targets/tf_m_bl2/build_public_target.sh), and runtime profile generator [`targets/tf_m_bl2/generate_runtime_profile.py`](../targets/tf_m_bl2/generate_runtime_profile.py) for dual-image TF-M `TF-Mv2.3.1` with MCUboot `v2.4.0` on MPS2 AN521. No TF-M firmware binary is distributed. Under `SWAP_USING_MOVE`, unconfirmed upgrades fail 33 of 33 fault points because interrupted swaps revert to the initial image while the clean control boots the staged image without confirming it, whereas confirmed upgrades with `image_ok=1` in the staged trailer and `OVERWRITE_ONLY` upgrades pass 33 of 33 and 3 of 3 fault points with 0 bricks. The AN521 platform provides update-state observation, fault instrumentation, and register-driver compatibility; it does not validate live SAU or MPC memory isolation. See [`targets/tf_m_bl2/`](../targets/tf_m_bl2/).
See [`docs/tfm-bl2-an521.md`](tfm-bl2-an521.md) for the TF-M v2.3.1 BL2 AN521 build reproduction and swap-move fault-sweep findings.

## Other targets

- **wolfBoot** on STM32F4: a fetch-and-build script and recovery profiles. The repository does not include wolfBoot source or binaries. See [`docs/wolfboot-target.md`](wolfboot-target.md).
- **MCUboot on STM32F103 and STM32L476**: Zephyr-built targets on the STM32F1 and STM32L4 flash models, under [`examples/stm32_mcuboot/`](../examples/stm32_mcuboot/) with `profiles/mcuboot_stm32f103_*.yaml` and `profiles/mcuboot_stm32l476_*.yaml`.
- **Zephyr storage on external memory**: NVS on SPI NOR, storage on an I2C EEPROM, and MCUboot with its secondary slot on SPI NOR, under [`targets/zephyr_external_nvm/`](../targets/zephyr_external_nvm/) with `profiles/zephyr_*.yaml` and `profiles/mcuboot_zephyr_spi_nor_*.yaml`. The NVS pair `zephyr_spi_nor_nvs_broken.yaml` / `_fixed.yaml` is pinned on either side of Zephyr commit `c200ff1e`.

## Reference examples

The `examples/` directory contains standalone firmware plus declarative models
and trace fixtures for engine validation and self-testing:

| Example                  | Purpose                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `authorization_review`   | Reviewed-versus-signed declarative model and trace fixtures         |
| `authenticated_equivalence` | Grammar-aware authenticated-content equivalence fixtures         |
| `freshness_oracle`       | Authenticated-metadata expiry and split-channel regression fixtures |
| `preauth_bounds_oracle` | Synthetic nested-header pre-authentication bounds fixtures        |
| `naive_copy`             | Worst-case baseline; proves the engine catches obvious brick paths |
| `vulnerable_ota`         | Copy-in-place OTA with frequent boot-visible failures              |
| `nxboot_style`           | Modeled nxboot family for adapter/probe/invariant development      |
| `esp_idf_ota`            | Standalone model of ESP-IDF OTA slot-selection behavior            |
| `bootloader_self_update` | Bootloader-region integrity and self-update fault modeling         |
| `nvs_config_migration`   | Config/NVS-region corruption and migration validation              |
| `firmware_otp_harness`   | OTP programming and fuse-fault validation                          |
| `cbmc_bridge`            | Formal-counterexample and crash-input conversion fixtures          |
| `fuzzer_harness`         | End-to-end parser fuzzing and regression-profile example           |
| `persistent_state_fail_closed` | Failed persistent-state read/write outcome fixtures          |
| `runtime_self_update`    | Reset-gated in-place self-update fixture and negative variants     |
| `runtime_self_update_delayed` | Direct-reset self-update fixture with delayed post-reset liveness |
| `deliberate_crash_report` | Deliberate post-success crash-dump fixture (`allow_fault_after_success`) and negative/follow-up variants |
| `mram_ecc_record_recovery` | MRAM ECC `uncorrectable` torn-word handled and unhandled recovery fixtures |
