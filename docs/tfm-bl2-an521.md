# TF-M BL2 AN521 Bring-Up and Power-Loss Sweep

TF-M BL2 at tag `TF-Mv2.3.1` with MCUboot `v2.4.0`, `MCUBOOT_IMAGE_NUMBER=2`, and `MCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE` builds in `tardigrade-oss-validation:latest` and boots through `bl2.axf`, `tfm_s`, and `tfm_ns` on `platforms/mps2_an521.repl` under Renode. The unfaulted control boot completes the dual-slot upgrade from `2.3.1+0` to `2.4.0+0` in `110,198` flash word writes and reaches the Non-Secure idle loop in the `tertiary` slot at `PC = 0x00101E2E`. The 3-point quick sweep finishes in `121.1` seconds with verdict `FAIL`, `security_aggregate.status` `FINDINGS`, `0` bricks, `0` timeouts, and `1` invariant issue point at `fault_at = 55099` and flash offset `0x00080E28`. That issue point triggers `tfm_multi_image_consistency` at `semantic_state_stage: fault_snapshot` because `bl2_main.c` calls `boot_go_for_image_id` in a reverse loop that finishes swapping Non-Secure `image_id = 1` before starting Secure `image_id = 0`, and on the Phase 2 recovery boot BL2 reverts Non-Secure `ns_exec` to `2.3.1+0` while completing the interrupted forward swap of Secure `secure_exec` to `2.4.0+0`.

## Pinned Revisions

All eight upstream repositories are checked out under `third_party/` at the commits below.

| Repository | Remote URL | Tag or Describe | Commit SHA |
| --- | --- | --- | --- |
| `third_party/trusted-firmware-m` | `https://github.com/TrustedFirmware-M/trusted-firmware-m.git` | `TF-Mv2.3.1` | `0b40d7806136baadf489febf8e2f91bf87aca63d` |
| `third_party/tf-m-tests` | `https://github.com/TrustedFirmware-M/tf-m-tests.git` | `TF-Mv2.3.1` | `465acb8405fb35b12a624a27062e361afe0025e4` |
| `third_party/mcuboot` | `https://github.com/mcu-tools/mcuboot.git` | `v2.4.0` | `6d3b3d2c38ab20c242e5b9abb04d050086383eb2` |
| `third_party/tf-psa-crypto` | `https://github.com/Mbed-TLS/TF-PSA-Crypto.git` | `tf-psa-crypto-1.1.1` | `a0632be94d883daa0295ac1eabf70359ad94f91b` |
| `third_party/cmsis` | `https://github.com/ARM-software/CMSIS_6.git` | `v6.2.0` | `6f0a58d01aa9bd2feba212097f9afe7acd991d52` |
| `third_party/qcbor` | `https://github.com/laurencelundblade/QCBOR.git` | `v1.2` | `92d3f89030baff4af7be8396c563e6c8ef263622` |
| `third_party/t_cose` | `https://github.com/laurencelundblade/t_cose.git` | `v2.0-alpha-2` | `3076010eeb6383f0827bd992c75b68af9311cf1d` |
| `third_party/tf-m-extras` | `https://git.trustedfirmware.org/TF-M/tf-m-extras.git` | `TF-Mv2.2.2-70-g2ac90af` | `2ac90aff6da35cde4a67f2d34076b1adf6ca9161` |

## Build, Sign, and Run Commands

### Automated Build and Reproduction Check

Run `targets/tf_m_bl2/build_public_target.sh` to verify the pinned `third_party/` commits, apply the required TF-M patches idempotently, build SPE, BL2, and NSPE inside `tardigrade-oss-validation:latest`, sign the primary `2.3.1` and staging `2.4.0` images, and render `tf_m_bl2_an521_native.yaml`:

```bash
./targets/tf_m_bl2/build_public_target.sh --output-dir results/tfm_an521
```

Running `./targets/tf_m_bl2/build_public_target.sh --output-dir results/tfm_an521_repro` into a clean directory produces a `bl2.axf` whose `.text` and `.data` sections match `results/tfm_an521/bl2.axf` byte-for-byte:

- `.text` size `0x007DB4`, SHA-256 `ff416945abe5bf8cdc7b13b556a1d7a866d47db4ebe624b96d3263d3845d4c98` in both `results/tfm_an521/bl2.axf` and `results/tfm_an521_repro/bl2.axf`.
- `.data` size `0x000028`, SHA-256 `5ab1638e6e3139a5b8beceefa85159373cc4b3f82912622dafbcf4fbed96e5bd` in both `results/tfm_an521/bl2.axf` and `results/tfm_an521_repro/bl2.axf`.
- The four signed `.bin` images differ between runs because ECDSA-P256 signing in `imgtool` uses a randomized nonce per invocation.

### Exact Container Build and Sign Commands

Inside `docker run --rm --platform linux/amd64 -v "$PWD:/workspace" -w /workspace tardigrade-oss-validation:latest bash -lc '...'`, the build script executes:

```bash
OUT_DIR="/workspace/results/tfm_an521"
TP_DIR="/workspace/third_party"
BUILD_ROOT="$OUT_DIR/build_test"

export PATH="$BUILD_ROOT/host-bin:/opt/tardigrade-venv/bin:/opt/xpack-arm-none-eabi-gcc-13.2.1-1.1/bin:$PATH"
export PYTHONPATH="$BUILD_ROOT/pypkgs:$TP_DIR/mcuboot/scripts:${PYTHONPATH:-}"

cmake -S "$TP_DIR/trusted-firmware-m" -B "$BUILD_ROOT/spe" -G Ninja \
  -DTFM_PLATFORM=arm/mps2/an521 \
  -DTFM_TOOLCHAIN_FILE="$TP_DIR/trusted-firmware-m/toolchain_GNUARM.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBL2=ON \
  -DMCUBOOT_IMAGE_NUMBER=2 \
  -DMCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE \
  -DMCUBOOT_IMAGE_VERSION_S=2.3.1 \
  -DMCUBOOT_IMAGE_VERSION_NS=2.3.1 \
  -DTFM_MERGE_HEX_FILES=OFF \
  -DTFM_TEST_REPO_PATH="$TP_DIR/tf-m-tests" \
  -DMCUBOOT_PATH="$TP_DIR/mcuboot" \
  -DTF_PSA_CRYPTO_PATH="$TP_DIR/tf-psa-crypto" \
  -DCMSIS_PATH="$TP_DIR/cmsis" \
  -DQCBOR_PATH="$TP_DIR/qcbor" \
  -DT_COSE_PATH="$TP_DIR/t_cose" \
  -DTFM_EXTRAS_REPO_PATH="$TP_DIR/tf-m-extras"
cmake --build "$BUILD_ROOT/spe" -- install -j4

cmake -S "$TP_DIR/tf-m-tests/tests_reg" -B "$BUILD_ROOT/nspe" -G Ninja \
  -DCONFIG_SPE_PATH="$BUILD_ROOT/spe/api_ns" \
  -DTFM_TOOLCHAIN_FILE="$BUILD_ROOT/spe/api_ns/cmake/toolchain_ns_GNUARM.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DQCBOR_PATH="$TP_DIR/qcbor" \
  -DT_COSE_PATH="$TP_DIR/t_cose"
cmake --build "$BUILD_ROOT/nspe" -j4

cp "$BUILD_ROOT/spe/api_ns/bin/bl2.axf" "$OUT_DIR/bl2.axf"

mcuboot_imagesign_wrapper \
  --version 2.3.1 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_s.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_s_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(1, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451243 \
  "$BUILD_ROOT/spe/api_ns/bin/tfm_s.bin" \
  "$OUT_DIR/tfm_s_signed.bin"

mcuboot_imagesign_wrapper \
  --version 2.3.1 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_ns.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_ns_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(0, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451244 \
  "$BUILD_ROOT/nspe/bin/tfm_ns.bin" \
  "$OUT_DIR/tfm_ns_signed.bin"

mcuboot_imagesign_wrapper \
  --version 2.4.0 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_s.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_s_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(1, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451243 \
  "$BUILD_ROOT/spe/api_ns/bin/tfm_s.bin" \
  "$OUT_DIR/tfm_s_staging_signed.bin"

mcuboot_imagesign_wrapper \
  --version 2.4.0 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_ns.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_ns_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(0, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451244 \
  "$BUILD_ROOT/nspe/bin/tfm_ns.bin" \
  "$OUT_DIR/tfm_ns_staging_signed.bin"
```

### Profile Generation and Audit Commands

Generate the runtime profile from the build directory:

```bash
python3 targets/tf_m_bl2/generate_runtime_profile.py --build-dir results/tfm_an521
```

Run the 3-point quick sweep:

```bash
timeout 600 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --quick \
  --no-assert-verdict \
  --output results/tfm_an521/quick.json
```

Rerun the single issue point at `fault_at = 55099`:

```bash
timeout 600 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 55099 \
  --fault-end 55100 \
  --no-assert-verdict \
  --output results/tfm_an521/fp55099_rerun.json
```

Run the full 64-point heuristic sweep:

```bash
timeout 3000 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --no-assert-verdict \
  --output results/tfm_an521/power_loss_full.json
```

## Generated Runtime Profile

`targets/tf_m_bl2/generate_runtime_profile.py` renders `results/tfm_an521/tf_m_bl2_an521_native.yaml` from `profiles/tf_m_bl2_an521_native.template.yaml.in`, `third_party/trusted-firmware-m/platform/ext/target/arm/mps2/an521/partition/flash_layout.h`, `region_defs.h`, and `results/tfm_an521/bl2.axf`:

```yaml
schema_version: 1
name: tf_m_bl2_an521_native
description: >
  Native AN521 TF-M multi-image runner profile. This is an interface template
  for a locally built BL2 and signed S/NS images.

platform: platforms/mps2_an521.repl
flash_backend: faultFlash
bootloader:
  elf: results/tfm_an521/bl2.axf
  entry: 0x10000000
memory:
  sram: { start: 0x38000000, end: 0x38040000 }
  write_granularity: 4
  trace_address_map:
    - { offset_start: 0x00080000, offset_end: 0x00100000, address_addend: 0x10000000 }
    - { offset_start: 0x00100000, offset_end: 0x00180000, address_addend: 0x00000000 }
    - { offset_start: 0x00180000, offset_end: 0x00200000, address_addend: 0x10000000 }
    - { offset_start: 0x00200000, offset_end: 0x00280000, address_addend: 0x00000000 }
  slots:
    exec: { base: 0x10080000, size: 0x00080000 }
    staging: { base: 0x10180000, size: 0x00080000 }
    tertiary: { base: 0x00100000, size: 0x00080000 }
    recovery: { base: 0x00200000, size: 0x00080000 }
images:
  exec: results/tfm_an521/tfm_s_signed.bin
  staging: results/tfm_an521/tfm_s_staging_signed.bin
  tertiary: results/tfm_an521/tfm_ns_signed.bin
  recovery: results/tfm_an521/tfm_ns_staging_signed.bin
success_criteria:
  pc_in_slot: tertiary
fault_sweep:
  mode: runtime
  evaluation_mode: execute
  fault_types: [power_loss]
  run_duration: "3.0"
  vtor_settle_iters: 10
  tracking_start_address: 0x0
  max_writes: auto
  max_writes_cap: 200000
  boot_cycles: 1
  max_heuristic_points: 64
  heuristic:
    preserve_critical_tiers: false
state_probe:
  script: targets/tf_m_bl2/probe.py
  format: python
  contract_version: 1
invariants:
  - tfm_multi_image_consistency
  - tfm_multi_image_acceptance_consistency
  - tfm_no_partial_magic
  - tfm_secure_slot_not_empty
invariant_providers:
  - targets/tf_m_bl2/invariants.py
invariant_config:
  tfm_joint_acceptance: true
  tfm_joint_version_policy: compatible
  semantic_state_stage: final
expect:
  should_find_issues: true
```

## Setup Failures Encountered and Changes Made

1. CMake `FetchContent` attempted network clones and bypassed TF-M patches when local paths were supplied. Passing `-DTFM_TEST_REPO_PATH`, `-DMCUBOOT_PATH`, `-DTF_PSA_CRYPTO_PATH`, `-DCMSIS_PATH`, `-DQCBOR_PATH`, `-DT_COSE_PATH`, and `-DTFM_EXTRAS_REPO_PATH` disabled network fetches, and applying every patch in `third_party/trusted-firmware-m/lib/ext/<repo>/*.patch` via `git apply` restored the TF-M integrations for `cmsis`, `mcuboot`, `qcbor`, `t_cose`, and `tf-psa-crypto`.
2. TF-M build rules invoke console scripts `mcuboot_imagesign_wrapper`, `mcuboot_imagesign_assemble`, `c_include`, `c_macro`, `c_struct`, and `hex_generation`, which were not installed in `/opt/tardigrade-venv/bin`. Creating module symlinks under `build_test/pypkgs/` and executable wrappers under `build_test/host-bin/`, plus setting `-DTFM_MERGE_HEX_FILES=OFF` and implementing `hex_generation` via `arm-none-eabi-objcopy -I binary -O ihex`, allowed the SPE and NSPE Ninja builds to succeed offline.
3. The default AN521 TF-M configuration uses `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY` and signs images with `--overwrite-only`. Under `OVERWRITE_ONLY`, `mcuboot_imagesign_wrapper` omits the swap trailer magic from the padded image tail and BL2 overwrites the primary slots without writing `copy_done = 0x01`, leaving `copy_done` unset and failing `probe.py` swap-completion expectations. Rebuilding SPE with `-DMCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE` and signing without `--overwrite-only` enabled full two-slot swap trailers.
4. Initial manual `mcuboot_imagesign_wrapper` commands used `--public-key-format full` and omitted `--measured-boot-record` and `-L 128`, which caused BL2 key-hash validation to reject the images because AN521 BL2 embeds the SHA-256 key hash in OTP via `MCUBOOT_BUILTIN_KEY=ON` and `--public-key-format hash`. Switching to `--public-key-format hash --align 1 --pad --pad-header -H 0x400 -s 1 -L 128 --measured-boot-record --psa-key-ids 2147451243` for Secure and `2147451244` for Non-Secure matched the TF-M Ninja signing rules.
5. After BL2 verified and booted `tfm_s`, the transition from `tfm_s` to `tfm_ns` via `bxns r0` in `ns_agent_tz_main` crashed immediately at `tfm_ns` `Reset_Handler` at `0x00103440`. `tfm_s` switches to Thread mode on `PSP_S` with `CONTROL.SPSEL = 1` before entering `ns_agent_tz_main`, while `tfm_hal_set_up_static_boundaries` only initializes `MSP_NS` to `0x281026e0` and leaves `PSP_NS = 0x00000000`. In the Renode Cortex-M33 model, `CONTROL.SPSEL` remained `1` across `bxns`, so `tfm_ns` executed `Reset_Handler` with `SP = 0x00000000` and faulted on its first stack push. Clearing `CONTROL.SPSEL` via `mrs r2, control; bic r2, r2, #2; msr control, r2; isb` immediately before `bxns r0` in `secure_fw/partitions/ns_agent_tz/ns_agent_tz_v80m.c` and `ns_agent_tz.c` caused `tfm_ns` to enter `Reset_Handler` on `MSP_NS = 0x281026e0` and reach the Non-Secure RTOS idle loop at `0x00101E2E`.
6. The clean boot emits `110,198` word writes, consisting of `81,834` writes inside BL2 during the two-image swap plus `28,364` writes in `tfm_s` when initializing Internal Trusted Storage and Protected Storage in flash at `0x00300000..0x0030AFFC`, exceeding the initial `max_writes_cap = 100000`. Raising default `max_writes_cap` to `200000` in `targets/tf_m_bl2/generate_runtime_profile.py` captured the unclipped calibration trace.
7. Replaying the trace and reading the `4,194,304`-byte `ssram1` flash snapshot in IronPython took ~150 seconds per fault point because `platforms/mps2_an521.repl` lacked `Memory.TraceReplayEngine` and `to_py_bytes` in `scripts/run_runtime_fault_sweep.py` iterated byte-by-byte over the 4 MB CLR `Byte[]` array. Adding `trace_replay: Memory.TraceReplayEngine @ sysbus 0x5800A000` targeting `ssram1` in `platforms/mps2_an521.repl` and converting non-string buffers via `bytearray` in `to_py_bytes` reduced Phase 1 trace replay time to `133` ms average.
8. Trace-replay fault points initially failed with `semantic_observation_points` errors because `run_trace_replay_fault_native` and `run_trace_replay_fault` in `scripts/run_runtime_fault_sweep.py` did not collect `fault_semantic_state` after `restore_flash_and_boot`, whereas `tf_m_bl2_an521_native.yaml` configures `invariant_config.semantic_state_stage: fault_snapshot`. Adding `fault_semantic_state` collection at `stage: fault_snapshot` in both trace-replay functions resolved the observation errors.
9. Because `An521NvmInterceptor` backs flash with `ssram1`, the TF-M CMSIS flash driver erases each 4 KB sector by writing `1,024` words of `0xFFFFFFFF`. Across the Secure and Non-Secure primary and secondary trailer sectors, calibration recorded `4,134` Tier 1 trailer writes, which under `preserve_critical_tiers: true` would schedule over `4,000` Renode boots. Setting `max_heuristic_points: 64` and `heuristic.preserve_critical_tiers: false` in `targets/tf_m_bl2/generate_runtime_profile.py` bounded the full heuristic sweep to `64` points.

## Control Result and Primary Trailer Offset Evidence

In `results/tfm_an521/quick.json`, the unfaulted control point with `fault_at = -1` and `is_control = true` succeeded with:

- `boot_outcome = "success"`, `boot_slot = "tertiary"`, `pc = "0x00101E2E"`, `phase1_stop_reason = "pc_captured"`, `phase1_emulated_s = 1.9`, `phase1_ms = 8376`.
- `actual_writes = 110198`, decomposed in `calibration.coverage` as `slot_data_writes = 49152`, `slot_trailer_writes = 4134`, and `outside_slot_writes = 56912`.
- Both primary trailer regions appeared in the trace with `2,093` writes in `0x000FF000..0x000FFFFC` for the Secure primary trailer mapped to `0x100FF000..0x100FFFFC` and `2,093` writes in `0x0017F000..0x0017FFFC` for the Non-Secure primary trailer, ending at the `copy_done` and `magic` offsets `0x000FFFE0..0x000FFFFC` and `0x0017FFE0..0x0017FFFC`.
- Post-boot `semantic_state.slots` on the control point:
  - `secure_exec` at `0x10080000`: `version = 2.4.0+0`, `magic_state = good`, `copy_done = set` with raw byte `0x01`, `image_ok = unset` with raw byte `0xFF`.
  - `secure_staging` at `0x10180000`: `version = 2.3.1+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.
  - `ns_exec` at `0x00100000`: `version = 2.4.0+0`, `magic_state = good`, `copy_done = set` with raw byte `0x01`, `image_ok = unset` with raw byte `0xFF`.
  - `ns_staging` at `0x00200000`: `version = 2.3.1+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.

## Quick and Full Sweep Results

### Quick Sweep in `results/tfm_an521/quick.json`

- Verdict: `FAIL` with `1` issue point, `0` boot mismatches, `0` semantic failures, and `1` invariant failure.
- `security_aggregate.status`: `FINDINGS`.
- Points tested: `3` fault points at `fault_at = 0` at `0x00309000`, `fault_at = 55099` at `0x00080E28`, and `fault_at = 110197` at `0x0030AFFC`, plus `1` control point at `fault_at = -1`.
- Issue points: `1`, at `fault_at = 55099`.
- Bricks: `0`.
- Timeouts: `0`.
- Invariant results:
  - `tfm_multi_image_consistency`: `1` violation at `fault_at = 55099`, `2` passed at `fault_at = 0` and `110197`.
  - `tfm_multi_image_acceptance_consistency`: `0` violations, `3` passed.
  - `tfm_no_partial_magic`: `0` violations, `3` passed.
  - `tfm_secure_slot_not_empty`: `0` violations, `3` passed.
- Wall time: `121.1` seconds, with `replay_ms` average `133` ms, `emulation_ms` average `17,772` ms, and `total_ms` average `19,810` ms per point.

### Single-Point Rerun in `results/tfm_an521/fp55099_rerun.json`

- Running `--fault-start 55099 --fault-end 55100` reproduced the exact outcome in `116.9` seconds wall time with `total_ms = 13,107` ms and `replay_ms = 113` ms: `fault_at = 55099`, `fault_address = 0x00080E28`, `snapshot_sha256 = 9f17853a791a699362d7d6181121751cb4fea4b6f531f344aa01b2b941f746e3`, Phase 2 `boot_outcome = success` in `tertiary`, and the identical `tfm_multi_image_consistency` violation at `fault_snapshot`.

### Full Sweep Runs Across `64` Heuristic Points

1. Unbatched default command `timeout 3000 python3 scripts/audit_bootloader.py --profile results/tfm_an521/tf_m_bl2_an521_native.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --no-assert-verdict --output results/tfm_an521/power_loss_full.json`:
   - Timed out at the `3,000`-second outer wrapper with exit code `124`. Because `audit_bootloader.py` defaults to `--max-batch-points 0` and estimates `~0.9` seconds per trace-replay point, it grouped `32` points per worker into a single Robot Framework test whose `180`-second suite timeout fired at depths `0` for `32` points, `1` for `16` points, `2` for `8` points, and `3` for `4` points, spending most of the `3,000` seconds bisecting batches before executing `2`-point and `1`-point fallback batches.
   - Completed before timeout: `1` control point with `fault_at = -1`, `boot_outcome = success`, and `boot_slot = tertiary`, plus `40` of `64` fault points from `fault_at = 0` through `44521`.
   - Bricks: `0`.
   - Point-level timeouts: `0`.
   - Invariant results across the `40` completed fault points:
     - `32` points at `fault_at = 0, 2047, 17332..19300, 23455, 43938`, all prior to `ns_exec` writing `copy_done = 0x01`, passed all four invariants and recovered to `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` in `tertiary`.
     - `8` points at `fault_at = 44011, 44084, 44157, 44230, 44303, 44375, 44448, 44521`, all inside the `image_id = 0` Secure swap after `ns_exec.copy_done` was set, failed `tfm_multi_image_consistency` at `fault_snapshot` and booted into `tertiary` in Phase 2 with `secure_exec = 2.4.0+0` and `image_ok = unset`, and `ns_exec = 2.3.1+0` and `image_ok = set`.
2. Sub-batched run with `--max-batch-points 4` over `1,800` seconds:
   - Completed `52` of `64` fault points plus the control point with `0` bricks and `0` point-level timeouts:
     - `33` points at `0..43938` before `ns_exec.copy_done` is written, plus `108150` at `0x00309FE8` after both S and NS swaps have completed and `tfm_s` is initializing ITS and PS storage, passed all four invariants with both `secure_exec` and `ns_exec` at `2.4.0+0`.
     - `19` points at `44011..45906` and `60339`, all during the `image_id = 0` Secure swap while `ns_exec.copy_done = set` and `secure_exec.copy_done = unset`, triggered `tfm_multi_image_consistency` at `fault_snapshot` and booted in Phase 2 with `secure_exec = 2.4.0+0` and `image_ok = unset`, and `ns_exec = 2.3.1+0` and `image_ok = set`.

## Issue-Point Analysis for `fault_at = 55099`

### Extracted Evidence from `quick.json`

- Fault index: `55099`.
- Flash offset: `0x00080E28` in `ssram1` backing storage, mapped by `trace_address_map` to Secure alias `0x10080E28` inside `secure_exec` spanning `0x10080000..0x10100000`.
- Failed invariant: `tfm_multi_image_consistency` in `targets/tf_m_bl2/invariants.py`, evaluated at `semantic_state_stage: fault_snapshot` with details `ns_exec_copy_done = set`, `ns_exec_magic = good`, `secure_exec_copy_done = unset`, `secure_exec_magic = good`.
- Phase 2 boot outcome: `boot_outcome = success`, `boot_slot = tertiary`, `pc = 0x0010137C`, `phase2_stop_reason = pc_captured`.
- Semantic state at `fault_snapshot` at the pre-recovery power-loss boundary:
  - `secure_exec` at `0x10080000`: `version.state = erased`, `magic_state = good`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.
  - `secure_staging` at `0x10180000`: `version = 2.4.0+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.
  - `ns_exec` at `0x00100000`: `version = 2.4.0+0`, `magic_state = good`, `copy_done = set` with raw byte `0x01`, `image_ok = unset` with raw byte `0xFF`.
  - `ns_staging` at `0x00200000`: `version = 2.3.1+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.
- Semantic state at `post_boot` after Phase 2 recovery boot completes:
  - `secure_exec` at `0x10080000`: `version = 2.4.0+0`, `magic_state = good`, `copy_done = set` with raw byte `0x01`, `image_ok = unset` with raw byte `0xFF`.
  - `secure_staging` at `0x10180000`: `version = 2.3.1+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.
  - `ns_exec` at `0x00100000`: `version = 2.3.1+0`, `magic_state = good`, `copy_done = set` with raw byte `0x01`, `image_ok = set` with raw byte `0x01`.
  - `ns_staging` at `0x00200000`: `version = 2.4.0+0`, `magic_state = unset`, `copy_done = unset` with raw byte `0xFF`, `image_ok = unset` with raw byte `0xFF`.

### Code-Path Classification

1. Not a trailer-offset error in the generated profile: `tf_m_bl2_an521_native.yaml` places `secure_exec` at `0x10080000` with size `0x00080000` and `ns_exec` at `0x00100000` with size `0x00080000`, matching `FLASH_AREA_0_OFFSET = 0x80000` and `FLASH_AREA_1_OFFSET = 0x100000` in `flash_layout.h`. `probe.py` reads `magic` at `slot_end - 16`, `image_ok` at `slot_end - 24`, and `copy_done` at `slot_end - 32` under `mcuboot_trailer_align = 8`, which match the exact addresses written by BL2 at `0x100FFFE0..0x100FFFFC` and `0x0017FFE0..0x0017FFFC`.
2. Invariant stage modeling gap for the `fault_snapshot` violation: `profiles/tf_m_bl2_an521_native.template.yaml.in` sets `invariant_config.semantic_state_stage: fault_snapshot`. That setting is intended for runtime `psa_fwu_accept` campaigns where `tracking_start_address` gates fault injection to `fwu_bootloader_mark_image_accepted`. When `tracking_start_address` is `0x0` across the entire BL2 swap, evaluating `check_tfm_multi_image_consistency` at `fault_snapshot` checks flash at the instant power is lost, before Phase 2 recovery executes. Because `third_party/trusted-firmware-m/bl2/ext/mcuboot/bl2_main.c` lines 203-238 loop from `image_id = MCUBOOT_IMAGE_NUMBER - 1` down to `0` and swap `image_id = 1` to completion before starting `image_id = 0`, every power loss during the `image_id = 0` swap across `fault_at` `44011` through `81741` has `ns_exec.copy_done = set` and `secure_exec.copy_done = unset` prior to recovery.
3. BL2 Phase 2 recovery behavior under `boot_go_for_image_id`: In `bl2_main.c:221`, BL2 invokes `boot_go_for_image_id` in `third_party/mcuboot/boot/bootutil/src/loader.c:2503`, which sets `boot_data.img_mask` to mask out all images except `image_id` rather than calling MCUboot's coordinated multi-image `boot_go`. When Phase 2 boots after the power loss at `fault_at = 55099`:
   - For Non-Secure `image_id = 1`, `ns_exec` already finished its test swap in Phase 1 with `copy_done = set` and `image_ok = unset`, so `boot_prepare_image_for_update` classifies it as an unconfirmed test boot with `BOOT_SWAP_TYPE_REVERT` and reverts `ns_exec` back to `2.3.1+0` with `image_ok = set`.
   - For Secure `image_id = 0`, `secure_exec` has an active swap status table in flash with `BOOT_STATUS_SOURCE_PRIMARY_SLOT`, so `boot_prepare_image_for_update` resumes and completes the interrupted forward swap of `secure_exec` to `2.4.0+0` with `image_ok = unset`.
   - Because `boot_go_for_image_id` masks out the peer image in `boot_verify_dependencies` and both staging images were signed with default minimum dependencies `0.0.0+0`, Phase 2 boots with `secure_exec` at `2.4.0+0` and `image_ok = unset` alongside `ns_exec` at `2.3.1+0` and `image_ok = set`. Evaluating invariants at `semantic_state_stage: post_boot` passes `tfm_multi_image_consistency` under `tfm_joint_version_policy: compatible` because both have major version `2` and `copy_done = set`, fails `tfm_multi_image_consistency` under `tfm_joint_version_policy: equal` because `2.4.0+0` does not equal `2.3.1+0`, and fails `tfm_multi_image_acceptance_consistency` because `secure_exec.image_ok = unset` while `ns_exec.image_ok = set`.

## What Did Not Work and Why

- Host macOS native build of TF-M: The host environment lacks `arm-none-eabi-gcc` on default `PATH` and TF-M's GNUARM toolchain requires the Linux container toolchain at `/opt/xpack-arm-none-eabi-gcc-13.2.1-1.1/bin` inside `tardigrade-oss-validation:latest`.
- CMake `FetchContent` inside the Docker container: GitHub and `git.trustedfirmware.org` clones inside CMake configure either timed out or skipped local patches when `*_PATH` overrides were supplied without manually applying `third_party/trusted-firmware-m/lib/ext/<repo>/*.patch`.
- `pip install -e` of TF-M and MCUboot scripts inside ephemeral containers: Container builds are stateless across invocations and lacked network build isolation dependencies; symlinking `bl2`, `tfm_tools`, and `imgtool` into `build_test/pypkgs/` with thin wrappers in `build_test/host-bin/` avoided `pip` during builds.
- Default `TFM_MERGE_HEX_FILES=ON`: TF-M's `hex_generation` tool requires `clang` preprocessor output and `bintools` to parse C macro headers into Intel HEX offsets; setting `-DTFM_MERGE_HEX_FILES=OFF` with an `arm-none-eabi-objcopy` wrapper bypassed unused `.hex` merging.
- Default `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY`: Overwrite-only mode erases and overwrites the primary slots without writing `copy_done = 0x01` or preserving secondary images, so `probe.py` never observes `copy_done = set`.
- `mcuboot_imagesign_wrapper` with `--public-key-format full` or hex `--psa-key-ids 0x7fff816b`: AN521 BL2 uses built-in key hashes via `--public-key-format hash`, and `imgtool` parses `--psa-key-ids` with base-10 `int`, requiring decimal `2147451243` and `2147451244`.
- Unpatched `ns_agent_tz_main` Non-Secure entry in Renode: Renode's Cortex-M33 model leaves `CONTROL.SPSEL = 1` across `bxns r0`, causing `tfm_ns` `Reset_Handler` to run on `PSP_NS = 0x00000000` instead of `MSP_NS = 0x281026e0` unless `CONTROL.SPSEL` is cleared before `bxns`.
- Python-only trace replay on 4 MB `ssram1`: Without `Memory.TraceReplayEngine` in `platforms/mps2_an521.repl` and direct `bytearray` conversion in `to_py_bytes`, replaying `81,834+` writes and reading 4 MB of flash in IronPython took ~150 seconds per point and timed out.
- Default `preserve_critical_tiers: true` on SRAM-backed flash: Word-by-word 4 KB sector erases produce `4,134` Tier 1 trailer writes, which exceeds a practical Renode execute budget unless `max_heuristic_points: 64` and `preserve_critical_tiers: false` are set.
- Default `--max-batch-points 0` on 64-point AN521 sweeps under host load: `audit_bootloader.py` places `32` points per worker into a single Robot Framework batch with a hard `180`-second test timeout, causing recursive batch bisection from `32` down to `2` to consume most of a `3,000`-second wall-time budget when each AN521 recovery boot takes `15` to `25` seconds under multi-container host load.
- Unbounded or uniformly sampled 64-point `OVERWRITE_ONLY` sweeps under `timeout 2400`: In `OVERWRITE_ONLY`, `An521NvmInterceptor` records `591,898` word writes because erasing and copying two 512 KB primary slots and erasing four 4 KB secondary header and trailer sectors expands each 4 KB sector erase into `1,024` word writes of `0xFFFFFFFF`. Unbounded heuristic classification plans `13,531` points, and a `64`-point run with `max_heuristic_points: 64` and `preserve_critical_tiers: false` timed out at `2,400` seconds after `44` completed points because per-point trace validation over `591,898` entries in IronPython plus `9` to `22` seconds of Phase 2 emulation pushed `4`-point batches past the `180`-second Robot suite timeout and uniformly sampled `0xFFFFFFFF` padding writes inside the 4 KB trailer pages while stepping over the 16-byte trailer magic regions. Promoting the `10` slot erase and 16-byte trailer magic bus-address ranges via `heuristic.critical_regions` and capping `max_heuristic_points: 34` kept every erase boundary and every trailer magic write and completed in `900.6` seconds.

## Multi-image consistency

Confirmed staging images signed with `MCUBOOT_CONFIRM_IMAGE=ON` or `--confirm` and the default `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY` strategy both eliminate the mixed-version recovery cycle and the update loss completely. The mixed-version recovery boot and subsequent update loss occur only under `MCUBOOT_IMAGE_NUMBER=2` with `MCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE` and unconfirmed test-swap staging images where `MCUBOOT_CONFIRM_IMAGE=OFF` leaves secondary `image_ok = 0xFF`. In that unconfirmed test-swap configuration, after gating `check_tfm_multi_image_consistency` to the post-recovery state and requiring both primary trailers to have been written in the trace when evaluating a pre-recovery snapshot, all `29` fault points in the `44011..60339` band fail on the post-recovery state. On the first recovery boot after power loss at `fault_at = 55099`, the device boots and executes with Secure `secure_exec` at `2.4.0+0` and `image_ok = unset` alongside Non-Secure `ns_exec` reverted to `2.3.1+0` with `image_ok = set`. On the second recovery boot without runtime confirmation, BL2 reverts `secure_exec` to `2.3.1+0` with `image_ok = set`, and on the third recovery boot both `secure_exec` and `ns_exec` remain at `2.3.1+0` with `image_ok = set`. The Non-Secure image never reaches `2.4.0+0` again.

### Gating Fix

`targets/tf_m_bl2/README.md` specifies `fault_sweep.tracking_start_address` gated to `fwu_bootloader_mark_image_accepted` for acceptance-atomicity sweeps that set `semantic_state_stage: fault_snapshot`, and specifies that swap-consistency sweeps must include both primary trailer offsets in the trace and evaluate the post-recovery state. Because `results/tfm_an521/bl2.axf` does not contain `fwu_bootloader_mark_image_accepted`, `targets/tf_m_bl2/generate_runtime_profile.py` resolves `tracking_start_address` to `0x0`. Three changes separated the invariant-stage modeling gap from the bootloader behaviour:

1. In `targets/tf_m_bl2/generate_runtime_profile.py`, `render_runtime_profile` now switches `invariant_config.semantic_state_stage` from `fault_snapshot` to `final` whenever `tracking_start_address` resolves to `0x0`, and sets `expect.should_find_issues: true` to match the verified AN521 recovery behaviour.
2. In `targets/tf_m_bl2/invariants.py`, `check_tfm_multi_image_consistency` resolves the post-recovery state from `result_dict["semantic_state"]` or `result_dict["recovery_semantic_state"]` when `result.nvm_state` is a `fault_snapshot` capture, gates out `fault_snapshot` states when `write_spans` up to `fault_at` have not yet written both the `secure_exec` and `ns_exec` trailer sectors, and flags primary slot pairs where both `copy_done` fields are `set` while `image_ok` is `{"set", "unset"}` because one image completed a forward test swap while the peer image reverted and marked itself permanent.
3. In `tests/test_tfm_bl2_target_package.py`, `test_multi_image_consistency_gating_on_synthetic_trace` tests pre-trailer gating on a synthetic trace, post-recovery resolution when both images converge, and failure when recovery leaves `secure_exec` at `2.4.0+0` with `image_ok = unset` and `ns_exec` at `2.3.1+0` with `image_ok = set`.

### Before and After Sweep Numbers

Single-point reruns after the gating fix under `timeout 600` with `--workers 2`:

- `fault_at = 55099` at `0x00080E28` in `results/tfm_an521/fp55099_v2.json`: completed in `65.0` seconds wall time with verdict `FAIL`, `security_aggregate.status` `FINDINGS`, `1` issue point, `0` bricks, and `0` timeouts. Both `tfm_multi_image_consistency` and `tfm_multi_image_acceptance_consistency` fail on the post-recovery state where `secure_exec` is `2.4.0+0` with `copy_done = set` and `image_ok = unset` while `ns_exec` is `2.3.1+0` with `copy_done = set` and `image_ok = set`.
- `fault_at = 44011` at `0x000FF110` in `results/tfm_an521/fp44011_v2.json`: completed in `73.4` seconds wall time with verdict `FAIL`, `security_aggregate.status` `FINDINGS`, `1` issue point, `0` bricks, and `0` timeouts, failing both `tfm_multi_image_consistency` and `tfm_multi_image_acceptance_consistency` on the identical post-recovery state.

Full 64-point heuristic sweep before and after the gating fix:

| Metric | Before Gating Fix | After Gating Fix in `results/tfm_an521/power_loss_full_v2.json` |
| --- | --- | --- |
| Command | `timeout 1800 python3 scripts/audit_bootloader.py --profile results/tfm_an521/tf_m_bl2_an521_native.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --max-batch-points 4 --no-assert-verdict` | `timeout 2400 python3 scripts/audit_bootloader.py --profile results/tfm_an521/tf_m_bl2_an521_native.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --max-batch-points 4 --no-assert-verdict --output results/tfm_an521/power_loss_full_v2.json` |
| Evaluated stage | `fault_snapshot` | `final` post-recovery state |
| Verdict | `FAIL` | `FAIL` with `29` issue points, `0` boot mismatches, `0` semantic failures, and `29` invariant failures |
| `security_aggregate.status` | `FINDINGS` | `FINDINGS` |
| Points completed | `52` of `64` fault points plus `1` control point | `64` of `64` fault points plus `1` control point |
| Issue points | `19` | `29`, `issue_rate = 0.453125` |
| Clean recoveries | `33` | `35` |
| Bricks | `0` | `0`, `brick_rate = 0.0` |
| Timeouts | `0` | `0` |
| Failing fault-index band | `44011..45906` and `60339` among completed points | All `29` points in `44011..60339`: `44011, 44084, 44157, 44230, 44303, 44375, 44448, 44521, 44594, 44667, 44740, 44813, 44886, 44959, 45032, 45104, 45177, 45250, 45323, 45396, 45469, 45542, 45615, 45688, 45761, 45833, 45906, 45979, 60339` |
| Passing fault-index bands | `0..43938` and `108150` | All `32` points in `0..43938` before `ns_exec.copy_done` is written at write `43942` and all `3` points at `81741, 108150, 110197` after `secure_exec.copy_done` is written at write `70585` |
| Wall time | `1,800.0` seconds | `1,769.4` seconds |

### TF-M Build Configuration Facts and Divergence Step

At `TF-Mv2.3.1` commit `0b40d7806136baadf489febf8e2f91bf87aca63d` and MCUboot `v2.4.0` commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`:

- `MCUBOOT_IMAGE_NUMBER=2` is the default in `third_party/trusted-firmware-m/bl2/ext/mcuboot/mcuboot_default_config.cmake:18` and `platform/ext/target/arm/mps2/an521/config.cmake`.
- `MCUBOOT_UPGRADE_STRATEGY`: TF-M defaults to `OVERWRITE_ONLY` in `mcuboot_default_config.cmake:23`. The AN521 campaign build configures `-DMCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE`, which `third_party/trusted-firmware-m/docs/design_docs/booting/tfm_secure_boot.rst:238,276-279` documents as one of the four supported upgrade strategies.
- `MCUBOOT_DEPENDENCY_CHECK` and image dependencies: MCUboot `v2.4.0` does not use a `MCUBOOT_DEPENDENCY_CHECK` macro; instead, `boot_verify_dependencies` in `third_party/mcuboot/boot/bootutil/src/loader.c:214,1786-1802` is compiled unconditionally whenever `BOOT_IMAGE_NUMBER > 1`. In `mcuboot_default_config.cmake:87-88` and `results/tfm_an521/build_test/spe/CMakeCache.txt`, `MCUBOOT_S_IMAGE_MIN_VER` and `MCUBOOT_NS_IMAGE_MIN_VER` default to `0.0.0+0`, and `bl2/ext/mcuboot/CMakeLists.txt:244` and `cmake/spe-CMakeLists.cmake:227` pass the `-d` dependency argument with peer image `1` and version `0.0.0+0` when signing `tfm_s_signed.bin` and peer image `0` and version `0.0.0+0` when signing `tfm_ns_signed.bin`. Both signed images therefore contain `IMAGE_TLV_DEPENDENCY` entries and BL2 compiles `boot_verify_dependencies`, with the minimum required peer version set to `0.0.0+0`.
- TF-M documentation claims: `tfm_secure_boot.rst:68-74,290-320,369-373` states that under `MCUBOOT_IMAGE_NUMBER=1` the S and NS images are concatenated, signed together, and updated only together, whereas under `MCUBOOT_IMAGE_NUMBER=2` they are signed independently so that S and NS can be updated separately or together. To prevent incompatible S and NS pairs under `MCUBOOT_IMAGE_NUMBER=2`, `tfm_secure_boot.rst:297-316` documents `MCUBOOT_S_IMAGE_MIN_VER` and `MCUBOOT_NS_IMAGE_MIN_VER`, stating that the minimum version of the other image must be present on the device by the end of the upgrade when one or both images are updated at the same time. `tfm_secure_boot.rst:172-186` also states that the swap operation is fail-safe and resistant to power-cut failures and that an unconfirmed test image reverts on the next boot.

The two images' swap decisions diverge because `third_party/trusted-firmware-m/bl2/ext/mcuboot/bl2_main.c:203-238` calls `boot_go_for_image_id` in a reverse per-image loop instead of calling `boot_go`:

1. In `third_party/mcuboot/boot/bootutil/src/loader.c:1716-1883`, `context_boot_go` is structured to run once across all images with an unmasked `boot_data.img_mask`. Its first `IMAGES_ITER` loop at `loader.c:1751-1784` runs `boot_prepare_image_for_update` for every image before any swap executes. When `boot_prepare_image_for_update` resumes an interrupted swap at `loader.c:1513-1516` or prepares a fresh swap at `loader.c:1553-1565`, it invokes `boot_review_image_swap_types` at `loader.c:1381-1427`. In `boot_review_image_swap_types`, MCUboot checks all previously prepared images and resets any `BOOT_SWAP_TYPE_REVERT` entry to `BOOT_SWAP_TYPE_NONE` because a reboot during a multi-image upgrade leaves earlier already-swapped images with `copy_done = set` and `image_ok = unset`, which `boot_swap_type_multi` otherwise classifies as `BOOT_SWAP_TYPE_REVERT`. Only after all images are prepared does `context_boot_go` run `boot_verify_dependencies` at `loader.c:1787-1801` and then execute `boot_perform_update` in the second `IMAGES_ITER` loop at `loader.c:1813-1883`.
2. In `bl2_main.c:203-238`, TF-M instead loops from `image_id = MCUBOOT_IMAGE_NUMBER - 1` down to `0` and calls `boot_go_for_image_id` at `bl2_main.c:221`. In `loader.c:2503-2518`, `boot_go_for_image_id` sets `boot_data.img_mask` to `1` for every image except `image_id` and calls `context_boot_go`.
3. When power is lost between write `43942`, where BL2 finishes the Non-Secure swap by writing `ns_exec.copy_done = 0x01`, and write `70585`, where BL2 writes `secure_exec.copy_done = 0x01`, the first recovery boot executes two isolated `context_boot_go` calls:
   - First, `boot_go_for_image_id` runs for `image_id = 1` with `state->img_mask[0] = 1`. At `loader.c:1553`, `boot_prepare_image_for_update` calls `boot_validated_swap_type` and `boot_swap_type_multi`, sees `ns_exec` with `magic = good`, `copy_done = set`, and `image_ok = unset`, and sets `state->swap_type[1] = BOOT_SWAP_TYPE_REVERT`. Because `state->img_mask[0]` is `1`, the first `IMAGES_ITER` loop at `loader.c:1751-1784` skips `image_id = 0` and never runs `boot_review_image_swap_types` for `image_id = 0`. `context_boot_go` proceeds directly to the second `IMAGES_ITER` loop at `loader.c:1847-1855`, where `boot_perform_update` reverts `ns_exec` to `2.3.1+0` and calls `swap_set_image_ok` at `loader.c:1285` to set `ns_exec.image_ok = 0x01`.
   - Second, `boot_go_for_image_id` runs for `image_id = 0` with `state->img_mask[1] = 1`. For `fault_at` `44011..44959` before the first Secure swap status byte is written at write `45029`, `boot_prepare_image_for_update` at `loader.c:1553` sets `state->swap_type[0] = BOOT_SWAP_TYPE_TEST` and `boot_perform_update` at `loader.c:1853` swaps `secure_exec` forward to `2.4.0+0` with `image_ok = unset`. For `fault_at` `45032..60339` after write `45029`, `boot_prepare_image_for_update` sees `!boot_status_is_reset` at `loader.c:1513` and calls `boot_complete_partial_swap` at `loader.c:1528`, completing the interrupted forward swap of `secure_exec` to `2.4.0+0` with `image_ok = unset`.
   - Even if non-zero dependency versions were configured in `MCUBOOT_S_IMAGE_MIN_VER` and `MCUBOOT_NS_IMAGE_MIN_VER`, `boot_verify_dependencies` at `loader.c:236` skips every masked image when `state->img_mask[i]` is non-zero, and `boot_complete_partial_swap` at `loader.c:1528-1549` finishes writing `secure_exec = 2.4.0+0` and sets `state->swap_type[0] = BOOT_SWAP_TYPE_NONE` before `context_boot_go` reaches `boot_verify_dependencies` at `loader.c:1788`.

### Per-Cycle Recovery Reproduction on `fault_at = 55099`

Running `fault_at = 55099` with `fault_sweep.boot_cycles: 3` in `results/tfm_an521/fp55099_boot3.json` over `257.1` seconds wall time:

```bash
timeout 600 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_boot3.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 55099 --fault-end 55100 \
  --no-assert-verdict \
  --output results/tfm_an521/fp55099_boot3.json
```

| Stage | Boot Outcome and PC | `secure_exec` at `0x10080000` | `secure_staging` at `0x10180000` | `ns_exec` at `0x00100000` | `ns_staging` at `0x00200000` |
| --- | --- | --- | --- | --- | --- |
| `pre_state` before faulted boot | `success` in `tertiary` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| `fault_semantic_state` at write `55099`, `0x00080E28` | Power lost during BL2 Secure swap | `erased`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=unset` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 1, `boot_cycles[0]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=unset` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 2, `boot_cycles[1]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 3, `boot_cycles[2]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |

On recovery cycle 1, the device boots into `tertiary` at `0x00101E2E` and executes Secure `2.4.0+0` with `image_ok = unset` against Non-Secure `2.3.1+0` with `image_ok = set`. If the runtime application confirms the update during recovery cycle 1, `secure_exec = 2.4.0+0` is marked `image_ok = set` and the mixed-version state persists across subsequent reboots. When no runtime confirmation occurs during recovery cycle 1, recovery cycle 2 sees `secure_exec` at `2.4.0+0` with `image_ok = unset`, reverts `secure_exec` to `2.3.1+0` with `image_ok = set`, and leaves `ns_exec` untouched at `2.3.1+0` with `image_ok = set`. On recovery cycle 3, both `secure_exec` and `ns_exec` run `2.3.1+0` with `image_ok = set`, and `ns_exec` never reaches `2.4.0+0` again.

### Confirmed Staging Images Under `SWAP_USING_MOVE`

Confirmed staging images remove both the mixed-version recovery cycle and the update loss. TF-M exposes confirmed image signing via `MCUBOOT_CONFIRM_IMAGE` in `third_party/trusted-firmware-m/bl2/ext/mcuboot/mcuboot_default_config.cmake:27`, which defaults to `OFF` and passes `--confirm` to `mcuboot_imagesign_wrapper` in `third_party/trusted-firmware-m/bl2/ext/mcuboot/CMakeLists.txt:246` and `third_party/trusted-firmware-m/cmake/spe-CMakeLists.cmake:229`.

Re-signing the same `tfm_s.bin` and `tfm_ns.bin` payloads at version `2.4.0` with `--confirm` alongside `tfm_s_staging_signed.bin` and `tfm_ns_staging_signed.bin`:

```bash
mcuboot_imagesign_wrapper \
  --version 2.4.0 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_s.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_s_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  --confirm \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(1, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451243 \
  "$BUILD_ROOT/spe/api_ns/bin/tfm_s.bin" \
  "$OUT_DIR/tfm_s_staging_confirmed.bin"

mcuboot_imagesign_wrapper \
  --version 2.4.0 \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_ns.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_ns_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  --confirm \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(0, 0.0.0+0)" \
  --measured-boot-record \
  --psa-key-ids 2147451244 \
  "$BUILD_ROOT/nspe/bin/tfm_ns.bin" \
  "$OUT_DIR/tfm_ns_staging_confirmed.bin"
```

Across the `524,288`-byte padded slot images, only a single trailer byte differs between the unconfirmed and confirmed staging binaries: at image offset `0x07FFE8`, `24` bytes before the end of the `0x080000` slot where the `image_ok` trailer field sits under `max_align = 8`, raw byte `0xFF` becomes `0x01`. The final `32` bytes at `0x07FFE0..0x07FFFF` in both `tfm_s_staging_confirmed.bin` and `tfm_ns_staging_confirmed.bin` change from `ffffffffffffffffffffffffffffffff77c295f360d2ef7f3552500f2cb67980` to `ffffffffffffffff01ffffffffffffff77c295f360d2ef7f3552500f2cb67980`.

Passing `--confirmed-staging` to `targets/tf_m_bl2/generate_runtime_profile.py` selects `tfm_s_staging_confirmed.bin` and `tfm_ns_staging_confirmed.bin` and sets `expect.should_find_issues: false`:

```bash
python3 targets/tf_m_bl2/generate_runtime_profile.py \
  --build-dir results/tfm_an521 \
  --confirmed-staging \
  --boot-cycles 3 \
  --output results/tfm_an521/tf_m_bl2_an521_confirmed_boot3.yaml

timeout 900 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_confirmed_boot3.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 55099 --fault-end 55100 \
  --no-assert-verdict \
  --output results/tfm_an521/fp55099_confirmed_boot3.json

python3 targets/tf_m_bl2/generate_runtime_profile.py \
  --build-dir results/tfm_an521 \
  --confirmed-staging \
  --output results/tfm_an521/tf_m_bl2_an521_confirmed.yaml

timeout 1500 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_confirmed.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --quick \
  --no-assert-verdict \
  --output results/tfm_an521/quick_confirmed.json

timeout 2400 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521/tf_m_bl2_an521_confirmed.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --max-batch-points 4 \
  --no-assert-verdict \
  --output results/tfm_an521/power_loss_full_confirmed.json
```

When the secondary slot trailer has `image_ok = 0x01`, `boot_swap_type_multi` in `third_party/mcuboot/boot/bootutil/src/bootutil_public.c:425-492` matches the `BOOT_SWAP_TYPE_PERM` table entry in `boot_swap_tables` at `bootutil_public.c:309-340` instead of `BOOT_SWAP_TYPE_TEST`. During `boot_perform_update` in `third_party/mcuboot/boot/bootutil/src/loader.c:1283-1315`, BL2 calls `swap_set_image_ok` at `loader.c:1285` to write `image_ok = 0x01` in the primary trailer and calls `boot_update_security_counter` at `loader.c:1302` before calling `swap_set_copy_done` at `loader.c:1311`. That permanently confirms `ns_exec` during the initial forward swap, adding `13,206` flash word writes for the security-counter NV update so `calibrated_writes` increases from `110,198` to `123,404`.

In `results/tfm_an521/fp55099_confirmed_boot3.json`, completed in `93.0` seconds wall time with `fault_at = 55099` at `0x00083704` mapped to `0x10083704` inside `secure_exec`, power is lost during the Secure swap after `ns_exec` has finished its permanent swap:

| Stage | Boot Outcome and PC | `secure_exec` at `0x10080000` | `secure_staging` at `0x10180000` | `ns_exec` at `0x00100000` | `ns_staging` at `0x00200000` |
| --- | --- | --- | --- | --- | --- |
| `pre_state` before faulted boot | `success` in `tertiary` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=set` | `2.3.1+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=set` |
| `fault_semantic_state` at write `55099`, `0x00083704` | Power lost during BL2 Secure swap | `2.3.1+0`, `magic=good`, `copy_done=unset`, `image_ok=set` | `2.4.0+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 1, `boot_cycles[0]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 2, `boot_cycles[1]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 3, `boot_cycles[2]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=set`, `image_ok=set` | `2.3.1+0`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |

On recovery cycle 1, `boot_go_for_image_id` runs for `image_id = 1` first, sees `ns_exec` with `magic = good`, `copy_done = set`, and `image_ok = set`, and assigns `BOOT_SWAP_TYPE_NONE`. Next, `boot_go_for_image_id` runs for `image_id = 0`, resumes the interrupted permanent swap via `boot_complete_partial_swap` at `loader.c:1528`, and finishes writing `secure_exec = 2.4.0+0` with `copy_done = set` and `image_ok = set`. All three recovery cycles boot `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` in `tertiary` at `PC = 0x00101E2E`.

In `results/tfm_an521/quick_confirmed.json`, completed in `161.9` seconds wall time across `3` fault points at `fault_at = 0` at `0x00309000`, `fault_at = 61702` at `0x00080E24`, and `fault_at = 123403` at `0x0030AFFC` plus `1` control point at `fault_at = -1`, the sweep finishes with verdict `PASS`, `0` issue points, `0` bricks, `0` timeouts, `4` of `4` invariants passing at every point, and no failing fault-index band.

Full 64-point power-loss sweep in `results/tfm_an521/power_loss_full_confirmed.json`:

- Verdict: `PASS`, whole-device layout not assessed.
- `security_aggregate.status`: `INCONCLUSIVE`, with `issue_points = 0`, `brick_rate = 0.0`, and `security_bypass_points = 0`, because `ownership_manifest_complete` is not asserted in the profile and `geometry_preflight` is unavailable for `An521NvmInterceptor`.
- Points planned and completed: `64` planned and `64` completed fault points across `123,404` calibrated writes at `fault_at = 0, 2047, 17333..19318, 29596, 48497, 50614..52599, 71042, 93698, 121356, 123403`, plus `1` control point at `fault_at = -1`.
- Issue points: `0`, `issue_rate = 0.0`, `recoveries = 64`.
- Bricks: `0`, `brick_rate = 0.0`.
- Timeouts: `0`.
- Invariant results: `0` violations and `64` passed for each of `tfm_multi_image_consistency`, `tfm_multi_image_acceptance_consistency`, `tfm_no_partial_magic`, and `tfm_secure_slot_not_empty`. All `64` fault points, including the `30` points across `48497..71042` after `ns_exec.copy_done` is set and before `secure_exec.copy_done` is set, recovered in Phase 2 to `secure_exec = 2.4.0+0` with `magic = good`, `copy_done = set`, `image_ok = set` and `ns_exec = 2.4.0+0` with `magic = good`, `copy_done = set`, `image_ok = set` in `tertiary` at `PC = 0x00101E2E`.
- Wall time: `1,133.2` seconds, with `replay_ms` average `62` ms, `emulation_ms` average `10,646` ms, and `total_ms` average `11,673` ms per point.

### Default Upgrade Strategy `OVERWRITE_ONLY`

Building BL2 and images with TF-M's default `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY` into `results/tfm_an521_overwrite/` also removes both the mixed-version recovery cycle and the update loss. Under `OVERWRITE_ONLY`, a power cut between the Non-Secure copy and the Secure copy leaves a transient pre-recovery flash state where `ns_exec` holds `2.4.0+0` and `secure_exec` is partially erased while `secure_staging` still holds `2.4.0+0`, but BL2 never boots that mixed state and completes the Secure copy on the first recovery boot.

Build, profile generation, quick sweep, and 3-cycle midpoint verification commands:

```bash
./targets/tf_m_bl2/build_public_target.sh \
  --output-dir results/tfm_an521_overwrite \
  --upgrade-strategy OVERWRITE_ONLY

python3 targets/tf_m_bl2/generate_runtime_profile.py \
  --build-dir results/tfm_an521_overwrite

timeout 1500 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --quick \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/quick.json

python3 targets/tf_m_bl2/generate_runtime_profile.py \
  --build-dir results/tfm_an521_overwrite \
  --boot-cycles 3 \
  --output results/tfm_an521_overwrite/tf_m_bl2_an521_boot3.yaml

timeout 900 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_boot3.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 295949 --fault-end 295950 \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/fp295949_boot3.json

timeout 600 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 284790 --fault-end 284791 \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/fp284790_v2.json

timeout 600 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 552283 --fault-end 552284 \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/fp552283_v2.json

timeout 2400 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_native.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --max-batch-points 4 \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/power_loss_full.json

timeout 900 python3 scripts/audit_bootloader.py \
  --profile results/tfm_an521_overwrite/tf_m_bl2_an521_boot3.yaml \
  --renode-test docker://tardigrade-oss-validation:latest \
  --workers 2 \
  --fault-start 284790 --fault-end 284791 \
  --no-assert-verdict \
  --output results/tfm_an521_overwrite/fp284790_boot3.json
```

Key measurements from `results/tfm_an521_overwrite/`:

- Build time for `build_public_target.sh --output-dir results/tfm_an521_overwrite --upgrade-strategy OVERWRITE_ONLY`: `62.86` seconds wall time.
- Clean control point at `fault_at = -1`: `boot_outcome = success`, `boot_slot = tertiary`, `pc = 0x00101E2E`, `phase1_emulated_s = 1.96`, `actual_writes = 591898` with `slot_data_writes = 522240`, `slot_trailer_writes = 6144`, and `outside_slot_writes = 63514`. Post-boot slots have `secure_exec = 2.4.0+0` with `magic = good`, `copy_done = unset`, `image_ok = unset`, `ns_exec = 2.4.0+0` with `magic = good`, `copy_done = unset`, `image_ok = unset`, and both `secure_staging` and `ns_staging` erased with `magic = unset` because `boot_copy_image` in `third_party/mcuboot/boot/bootutil/src/loader.c:966-1107` erases the secondary slot after copying it to the primary slot.
- Quick sweep in `results/tfm_an521_overwrite/quick.json`: completed in `137.3` seconds wall time with verdict `PASS`, `0` issue points, `0` bricks, `0` timeouts across `3` fault points at `fault_at = 0` at `0x00309000`, `fault_at = 295949` at `0x0008AE50`, and `fault_at = 591897` at `0x0030AFFC` plus `1` control point at `fault_at = -1`, and no failing fault-index band.
- Midpoint 3-cycle run at `fault_at = 295949` at `0x0008AE50` inside `secure_exec` in `results/tfm_an521_overwrite/fp295949_boot3.json`, completed in `117.8` seconds wall time: at `fault_semantic_state`, `ns_exec` is `2.4.0+0` with `magic = good` and `ns_staging` is erased with `magic = unset`, while `secure_exec` is erased with `magic = good` and `secure_staging` is still `2.4.0+0` with `magic = good`. On recovery cycle 1, `boot_swap_type_multi` at `bootutil_public.c:425-492` sees `ns_staging` with `magic = unset` and returns `BOOT_SWAP_TYPE_NONE` for `image_id = 1`, then sees `secure_staging` with `magic = good` and invokes `boot_copy_image` at `loader.c:966-1107` to copy `2.4.0+0` from `secure_staging` into `secure_exec` and erase `secure_staging`. All three recovery cycles in `boot_cycles[0..2]` boot `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` in `tertiary` at `PC = 0x00101E2E`.
- Point-selection bounding for the full sweep: across `591,898` calibrated writes, unbounded heuristic classification with `preserve_critical_tiers: true` plans `13,531` fault points including `7,351` Tier 1 writes and all `6,144` word writes to the four 4 KB trailer pages because `An521NvmInterceptor` models each 4 KB sector erase as `1,024` word writes of `0xFFFFFFFF`. Even a `64`-point run with `max_heuristic_points: 64` and `preserve_critical_tiers: false` timed out at `2,400` seconds after `44` completed points because per-point trace validation over `591,898` records in IronPython plus `9` to `22` seconds of Phase 2 emulation pushed `4`-point batches past the `180`-second Robot suite timeout and triggered batch bisection. Using the profile point-selection controls documented in `docs/writing-profiles.md`, we set `fault_sweep.max_heuristic_points: 34`, `fault_sweep.heuristic.preserve_critical_tiers: false`, and `10` `fault_sweep.heuristic.critical_regions` address ranges in `targets/tf_m_bl2/generate_runtime_profile.py`: `0x00100000..0x00100004`, `0x0017FFF0..0x00180000`, `0x10080000..0x10080004`, `0x100FFFF0..0x10100000`, `0x00200000..0x00200004`, `0x0027F000..0x0027F004`, `0x0027FFF0..0x00280000`, `0x10180000..0x10180004`, `0x101FF000..0x101FF004`, and `0x101FFFF0..0x10200000`. That retains all `8` slot erase and copy start boundaries at `fault_at = 17300, 148372, 282745, 283769, 284793, 415865, 550238, 551262`, all `24` writes across the four 16-byte slot trailer magic regions at `fault_at = 148368..148371, 279440..279443, 284789..284792, 415861..415864, 546933..546936, 552282..552285` including the `4` erase-end and `2` copy-end boundaries, and the first and last trace writes at `fault_at = 0` and `fault_at = 591897`, while bounding out the `585,754` bulk data and padding writes and the `6,120` `0xFFFFFFFF` word erases in the non-magic bytes of the 4 KB trailer pages.
- Single-point reruns at `fault_at = 284790` in `results/tfm_an521_overwrite/fp284790_v2.json` and `fault_at = 552283` in `results/tfm_an521_overwrite/fp552283_v2.json`: completed in `76.1` seconds and `75.9` seconds wall time with verdict `PASS`, whole-device layout not assessed, `0` issue points, `0` bricks, `0` timeouts, and `0` invariant violations across all `4` invariants.
- Bounded full 34-point power-loss sweep in `results/tfm_an521_overwrite/power_loss_full.json`:
  - Verdict: `PASS`, whole-device layout not assessed.
  - `security_aggregate.status`: `INCONCLUSIVE`, with `issue_points = 0`, `brick_rate = 0.0`, and `security_bypass_points = 0`, because `ownership_manifest_complete` is not asserted in the profile and `geometry_preflight` is unavailable for `An521NvmInterceptor`.
  - Points planned and completed: `34` planned and `34` completed fault points across `591,898` calibrated writes at `fault_at = 0, 17300, 148368..148372, 279440..279443, 282745, 283769, 284789..284793, 415861..415865, 546933..546936, 550238, 551262, 552282..552285, 591897`, plus `1` control point at `fault_at = -1`.
  - Issue points: `0`, `issue_rate = 0.0`, `recoveries = 34`.
  - Bricks: `0`, `brick_rate = 0.0`.
  - Timeouts: `0`.
  - Invariant results: `0` violations and `34` passed for each of `tfm_multi_image_consistency`, `tfm_multi_image_acceptance_consistency`, `tfm_no_partial_magic`, and `tfm_secure_slot_not_empty`. Every point booted `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` in `tertiary` at `PC = 0x00101E2E`.
  - Wall time: `554.1` seconds, with `replay_ms` average `264` ms, `emulation_ms` average `6,357` ms, and `total_ms` average `7,109` ms per point.

Secondary-slot trailer erase points in `results/tfm_an521_overwrite/power_loss_full.json`:

| Fault Index | Flash Offset and Bus Address | Secondary Trailer Magic State | Phase 2 Outcome | `fault_semantic_state` Across Both Image Pairs | Post-Recovery `semantic_state` Across Both Image Pairs |
| --- | --- | --- | --- | --- | --- |
| `284790` | `0x0027FFF4`, bus `0x0027FFF4` in `ns_staging` | `ns_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.3.1+0` `magic=good`, `secure_staging = 2.4.0+0` `magic=good`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=unset`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` |
| `284791` | `0x0027FFF8`, bus `0x0027FFF8` in `ns_staging` | `ns_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.3.1+0` `magic=good`, `secure_staging = 2.4.0+0` `magic=good`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=unset`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` |
| `284792` | `0x0027FFFC`, bus `0x0027FFFC` in `ns_staging` | `ns_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.3.1+0` `magic=good`, `secure_staging = 2.4.0+0` `magic=good`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=unset`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=other`; all `copy_done=unset`, `image_ok=unset` |
| `552283` | `0x001FFFF4`, bus `0x101FFFF4` in `secure_staging` | `secure_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` |
| `552284` | `0x001FFFF8`, bus `0x101FFFF8` in `secure_staging` | `secure_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` |
| `552285` | `0x001FFFFC`, bus `0x101FFFFC` in `secure_staging` | `secure_staging` `magic_state = other`, `mcuboot_magic = bad`, `0` violations | `success` in `tertiary`, `pc = 0x00101E2E` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` | `secure_exec = 2.4.0+0` `magic=good`, `secure_staging = erased` `magic=other`, `ns_exec = 2.4.0+0` `magic=good`, `ns_staging = erased` `magic=unset`; all `copy_done=unset`, `image_ok=unset` |

Three-boot-cycle rerun at `fault_at = 284790` in `results/tfm_an521_overwrite/fp284790_boot3.json`, completed in `98.0` seconds wall time:

| Stage | Boot Outcome and PC | `secure_exec` at `0x10080000` | `secure_staging` at `0x10180000` | `ns_exec` at `0x00100000` | `ns_staging` at `0x00200000` |
| --- | --- | --- | --- | --- | --- |
| `pre_state` before faulted boot | `success` in `tertiary` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=unset`, `copy_done=unset`, `image_ok=unset` |
| `fault_semantic_state` at write `284790`, `0x0027FFF4` | Power lost during `ns_staging` trailer sector erase | `2.3.1+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=other`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 1, `boot_cycles[0]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=other`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 2, `boot_cycles[1]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=other`, `copy_done=unset`, `image_ok=unset` |
| Recovery cycle 3, `boot_cycles[2]` | `success` in `tertiary`, `pc = 0x00101E2E` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=unset`, `copy_done=unset`, `image_ok=unset` | `2.4.0+0`, `magic=good`, `copy_done=unset`, `image_ok=unset` | `erased`, `magic=other`, `copy_done=unset`, `image_ok=unset` |

In `results/tfm_an521_overwrite/fp284790_boot3.json`, `fault_at = 284790` stops after `284,790` writes at `write_index = 284790` at `0x0027FFF0` and before `write_index = 284791` at `0x0027FFF4`. By that point in `boot_copy_image` at `third_party/mcuboot/boot/bootutil/src/loader.c:966-1107`, BL2 has already copied `2.4.0+0` into `ns_exec` and erased the `ns_staging` header sector at `0x00200000..0x00200FFC`, and is erasing the `ns_staging` trailer sector at `0x0027F000..0x0027FFFC` word-by-word with `0xFFFFFFFF`. Because `write_index = 284790` erased `0x0027FFF0` to `0xFFFFFFFF` while `0x0027FFF4..0x0027FFFC` still hold `0x7FEFD260`, `0x0F505235`, and `0x8079B62C`, `boot_read_swap_state` at `third_party/mcuboot/boot/bootutil/src/bootutil_public.c:251-260` and `boot_magic_decode` at `third_party/mcuboot/boot/bootutil/src/bootutil_misc.h:19-26` return `BOOT_MAGIC_BAD` on recovery cycle 1, which `boot_find_status` at `third_party/mcuboot/boot/bootutil/src/bootutil_misc.c:184-201` and `boot_swap_tables` and `boot_magic_compatible_check` at `bootutil_public.c:105-194` reject as a valid trailer magic. As a result, `boot_swap_type_multi` returns `BOOT_SWAP_TYPE_NONE` for Non-Secure `image_id = 1` without touching `ns_staging` again, then copies `2.4.0+0` from `secure_staging` into `secure_exec` and erases `secure_staging`. All three recovery cycles boot `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` at `PC = 0x00101E2E`, and `tfm_no_partial_magic` passes at `284790..284792` and `552283..552285` because MCUboot decodes the half-erased secondary trailer magic as `BOOT_MAGIC_BAD` and recovery boots a valid image pair.

### Decision and Platform Owner Remediation

Confirmed staging images signed with `MCUBOOT_CONFIRM_IMAGE=ON` or `--confirm` and the default `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY` strategy both remove the mixed-version recovery boot and the update loss completely. The mixed-version recovery cycle and the subsequent update loss occur only when `MCUBOOT_IMAGE_NUMBER=2` is combined with `MCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE` and unconfirmed test-swap staging images where `MCUBOOT_CONFIRM_IMAGE=OFF` leaves secondary `image_ok = 0xFF`.

| Configuration | Calibrated Writes | Sweep Points Planned and Completed | Verdict and `security_aggregate.status` | Issue Points, Bricks, Timeouts | Invariant Results | Wall Time | Pre-Recovery State After Power Cut Between NS and S | Recovery Cycle 1 Booted Versions | Recovery Cycle 2 and 3 Booted Versions | Mixed-Version Boot | Update Loss |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `SWAP_USING_MOVE`, unconfirmed staging, `MCUBOOT_CONFIRM_IMAGE=OFF` | `110,198` | `64` of `64` fault points plus `1` control point in `power_loss_full_v2.json` | `FAIL`, `FINDINGS` | `29` issue points across `44011..60339`, `0` bricks, `0` timeouts | `29` violations of `tfm_multi_image_consistency` and `tfm_multi_image_acceptance_consistency`, `35` passed; `0` violations of `tfm_no_partial_magic` and `tfm_secure_slot_not_empty` | `1,769.4` s | `ns_exec = 2.4.0+0` with `copy_done = set`, `image_ok = unset`; `secure_exec` interrupted mid-swap | `secure_exec = 2.4.0+0` with `image_ok = unset`, `ns_exec = 2.3.1+0` with `image_ok = set` | `secure_exec = 2.3.1+0` with `image_ok = set`, `ns_exec = 2.3.1+0` with `image_ok = set` | Yes, on cycle 1 | Yes, on cycles 2 and 3 |
| `SWAP_USING_MOVE`, confirmed staging, `MCUBOOT_CONFIRM_IMAGE=ON` or `--confirm` | `123,404` | `64` of `64` fault points plus `1` control point in `power_loss_full_confirmed.json` | `PASS`, whole-device layout not assessed; `INCONCLUSIVE` | `0` issue points, `0` bricks, `0` timeouts | `0` violations and `64` passed across all `4` invariants | `1,133.2` s | `ns_exec = 2.4.0+0` with `copy_done = set`, `image_ok = set`; `secure_exec` interrupted mid-swap | `secure_exec = 2.4.0+0` with `image_ok = set`, `ns_exec = 2.4.0+0` with `image_ok = set` | `secure_exec = 2.4.0+0` with `image_ok = set`, `ns_exec = 2.4.0+0` with `image_ok = set` | No | No |
| `OVERWRITE_ONLY`, TF-M default | `591,898` | `34` of `34` bounded fault points plus `1` control point in `power_loss_full.json` | `PASS`, whole-device layout not assessed; `INCONCLUSIVE` | `0` issue points, `0` bricks, `0` timeouts | `0` violations and `34` passed across all `4` invariants | `554.1` s | `ns_exec = 2.4.0+0`, `ns_staging = erased`; `secure_exec = erased`, `secure_staging = 2.4.0+0` | `secure_exec = 2.4.0+0`, `ns_exec = 2.4.0+0` | `secure_exec = 2.4.0+0`, `ns_exec = 2.4.0+0` | No | No |

All three TF-M BL2 AN521 configurations are now covered by full power-loss sweeps:

- For `SWAP_USING_MOVE` with unconfirmed staging images where `MCUBOOT_CONFIRM_IMAGE=OFF`, the 64-point full sweep in `results/tfm_an521/power_loss_full_v2.json` established that power loss at any of the `29` points across `fault_at = 44011..60339` after `ns_exec.copy_done` is written and before `secure_exec.copy_done` is written causes BL2 to revert `ns_exec` to `2.3.1+0` with `image_ok = set` while completing the forward test swap of `secure_exec` to `2.4.0+0` with `image_ok = unset` on recovery boot 1, and then revert `secure_exec` to `2.3.1+0` on recovery boot 2 so both images remain at `2.3.1+0` on recovery boot 3.
- For `SWAP_USING_MOVE` with confirmed staging images signed with `MCUBOOT_CONFIRM_IMAGE=ON` or `--confirm`, the 64-point full sweep in `results/tfm_an521/power_loss_full_confirmed.json` established that BL2 writes `image_ok = 0x01` to `ns_exec` during the initial `BOOT_SWAP_TYPE_PERM` upgrade and resumes the interrupted `secure_exec` swap on recovery boot 1, with all `64` fault points across `123,404` calibrated writes passing all `4` invariants and booting `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` at `PC = 0x00101E2E` with `0` issues, `0` bricks, and `0` timeouts.
- For the default `OVERWRITE_ONLY` configuration, the 34-point bounded full sweep in `results/tfm_an521_overwrite/power_loss_full.json` covering every slot erase boundary and every 16-byte trailer magic write across `591,898` calibrated writes established that all `34` fault points recover to boot `secure_exec = 2.4.0+0` and `ns_exec = 2.4.0+0` at `PC = 0x00101E2E` with `0` issues, `0` bricks, `0` timeouts, and `0` violations across all `4` invariants. At the `6` secondary-slot trailer erase points `fault_at = 284790..284792` and `552283..552285`, BL2 decodes the half-erased 16-byte magic as `BOOT_MAGIC_BAD` in `boot_magic_decode` at `bootutil_misc.h:19-26`, ignores the already-consumed secondary slot, and boots both images at `2.4.0+0` across all three recovery cycles.

Unconfirmed test-swap semantics are a precondition for the revert and update loss because MCUboot only schedules `BOOT_SWAP_TYPE_REVERT` in `boot_swap_type_multi` at `third_party/mcuboot/boot/bootutil/src/bootutil_public.c:309-340,425-492` when a primary slot trailer has `magic = good`, `copy_done = 0x01`, and `image_ok = 0xFF`. At MCUboot `v2.4.0` commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2` and TF-M `TF-Mv2.3.1` commit `0b40d7806136baadf489febf8e2f91bf87aca63d`, the `img_mask` call path bypasses `boot_review_image_swap_types` at the following lines:

1. `third_party/trusted-firmware-m/bl2/ext/mcuboot/bl2_main.c:203-238` iterates from `image_id = MCUBOOT_IMAGE_NUMBER - 1` down to `0` and calls `boot_go_for_image_id` at `bl2_main.c:221`.
2. `third_party/mcuboot/boot/bootutil/src/loader.c:2503-2518` defines `boot_go_for_image_id`, which sets `boot_data.img_mask` to `1` for every image at `loader.c:2513`, clears `boot_data.img_mask[image_id] = 0` at `loader.c:2514`, and calls `context_boot_go` at `loader.c:2516`.
3. `third_party/mcuboot/boot/bootutil/src/loader.c:1716-1883` defines `context_boot_go`, where the first `IMAGES_ITER` loop at `loader.c:1751-1784` skips masked images at `loader.c:1753-1755` when `state->img_mask[state->cur_img_index]` is non-zero and calls `boot_prepare_image_for_update` at `loader.c:1778` only for the unmasked `image_id`.
4. `boot_prepare_image_for_update` calls `boot_review_image_swap_types` at `loader.c:1516` when resuming a partial swap and at `loader.c:1565` when preparing a fresh swap. `boot_review_image_swap_types` at `loader.c:1381-1427` loops over `i < BOOT_CURR_IMG` at `loader.c:1422-1426` and resets any earlier `state->swap_type[i] == BOOT_SWAP_TYPE_REVERT` to `BOOT_SWAP_TYPE_NONE`. Because `boot_go_for_image_id` runs a separate `context_boot_go` pass per image with the peer masked in `state->img_mask`, the `image_id = 1` pass skips `image_id = 0` at `loader.c:1753-1755` and executes `boot_perform_update` at `loader.c:1847-1855` to revert `ns_exec` before `image_id = 0` is prepared.
5. In the same `context_boot_go` function, `boot_verify_dependencies` is called at `loader.c:1787-1801` and implemented at `loader.c:214-273`, where the `state->img_mask[i]` check at `loader.c:236` skips every masked image regardless of upgrade strategy or confirmation mode.

A TF-M platform owner can avoid the remaining exposure in two ways:

1. Keep the default `MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY`, set `MCUBOOT_IMAGE_NUMBER=1`, or set `MCUBOOT_CONFIRM_IMAGE=ON` so staged images are signed with `--confirm` and upgraded with `BOOT_SWAP_TYPE_PERM`.
2. If runtime-confirmed test swaps with `MCUBOOT_CONFIRM_IMAGE=OFF` under `MCUBOOT_IMAGE_NUMBER=2` and `SWAP_USING_MOVE` or `SWAP_USING_SCRATCH` are required, or if cross-image `IMAGE_TLV_DEPENDENCY` checks in `boot_verify_dependencies` are relied upon, update `bl2_main.c` so BL2 runs `boot_prepare_image_for_update`, `boot_review_image_swap_types`, and `boot_verify_dependencies` across all images with an unmasked `boot_data.img_mask` before calling `boot_perform_update`.

### Draft note for the TF-M maintainers

```text
Subject: Per-image img_mask in boot_go_for_image_id skips boot_review_image_swap_types on unconfirmed multi-image test swaps

Hi TF-M maintainers,

Confirmed staging images signed with MCUBOOT_CONFIRM_IMAGE=ON or --confirm and the default MCUBOOT_UPGRADE_STRATEGY=OVERWRITE_ONLY strategy both recover cleanly from power loss between the Non-Secure and Secure image updates and boot both images at the new version without a mixed-version cycle or update loss.

The remaining exposure in TF-Mv2.3.1 at commit 0b40d7806136baadf489febf8e2f91bf87aca63d with MCUboot v2.4.0 at commit 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 is limited to two cases caused by bl2/ext/mcuboot/bl2_main.c calling boot_go_for_image_id with peer images masked in boot_data.img_mask:

1. Unconfirmed multi-image test swaps under MCUBOOT_IMAGE_NUMBER=2, MCUBOOT_UPGRADE_STRATEGY=SWAP_USING_MOVE, and MCUBOOT_CONFIRM_IMAGE=OFF:
   - Unconfirmed test-swap semantics leave secondary image_ok = 0xFF, so MCUboot selects BOOT_SWAP_TYPE_TEST on the initial swap and BOOT_SWAP_TYPE_REVERT on the next boot when primary copy_done = 0x01 and image_ok = 0xFF.
   - In bl2/ext/mcuboot/bl2_main.c:203-238, BL2 loops from image_id = MCUBOOT_IMAGE_NUMBER - 1 down to 0 and calls boot_go_for_image_id at bl2_main.c:221.
   - In boot/bootutil/src/loader.c:2503-2518, boot_go_for_image_id sets boot_data.img_mask to 1 for all images at loader.c:2513, clears boot_data.img_mask[image_id] = 0 at loader.c:2514, and calls context_boot_go at loader.c:2516.
   - Inside context_boot_go at loader.c:1716-1883, the preparation loop at loader.c:1751-1784 skips masked images at loader.c:1753-1755 and calls boot_prepare_image_for_update at loader.c:1778 only for image_id.
   - In an unmasked multi-image context_boot_go call, boot_prepare_image_for_update calls boot_review_image_swap_types at loader.c:1516 for a partial swap and at loader.c:1565 for a fresh swap, and boot_review_image_swap_types at loader.c:1381-1427 loops at loader.c:1422-1426 to reset earlier BOOT_SWAP_TYPE_REVERT entries to BOOT_SWAP_TYPE_NONE when another image is still upgrading.
   - Because state->img_mask[0] = 1 during the image_id = 1 call after a reset between the Non-Secure and Secure swaps, image_id = 0 is skipped at loader.c:1753-1755 and boot_perform_update at loader.c:1847-1855 reverts Non-Secure image_id = 1 to 2.3.1 with image_ok = 0x01 before the image_id = 0 call completes the forward test swap of Secure image_id = 0 to 2.4.0 with image_ok = 0xFF.
   - Recovery boot 1 then boots Secure 2.4.0 with image_ok = 0xFF alongside Non-Secure 2.3.1 with image_ok = 0x01, and if unconfirmed during recovery boot 1, recovery boot 2 reverts Secure to 2.3.1 so both images remain at 2.3.1 on recovery boot 3 and the staged update is lost.

2. Cross-image dependency checks in boot_verify_dependencies:
   - In context_boot_go at loader.c:1787-1801, BL2 calls boot_verify_dependencies at loader.c:214-273, which skips any image with state->img_mask[i] != 0 at loader.c:236.

Running context_boot_go preparation and boot_verify_dependencies across all images with an unmasked boot_data.img_mask before executing boot_perform_update would restore boot_review_image_swap_types for unconfirmed multi-image test swaps and enable cross-image dependency verification.
```

