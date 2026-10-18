# NuttX nxboot canary verification

All sixteen planned canary runs across the four NuttX nxboot canary profiles have completed with JSON reports under `results/nuttx_canary/`, covering three `--no-assert-verdict` runs and one CI-mode asserting run each for `nuttx_nxboot_real_update`, `nuttx_nxboot_power_loss`, `nuttx_nxboot_bit_corruption`, and `nuttx_nxboot_instruction_skip`. No run differed from the others in issue points, bricks, security bypass points, or timeout points: every completed report recorded zero issue points, zero bricks, zero security bypass points, zero timeout points, `security_aggregate.status: INCONCLUSIVE`, and a clean two-cycle control boot inside the 120-second recovery wall-time budget. Every run within each profile produced the same `verdict` string, with the twelve `nuttx_nxboot_real_update`, `nuttx_nxboot_power_loss`, and `nuttx_nxboot_bit_corruption` runs reporting `PASS; whole-device layout not assessed` and all four `nuttx_nxboot_instruction_skip` runs reporting `PASS; 0 security bypass points [1 DoS crash points, expected for glitch model]; whole-device layout not assessed`. Across all sixteen runs, every clean control booted the primary image in 2.8 emulated seconds on cycle 0 with `phase1_stop_reason: vtor_captured` and completed its cycle 1 follow-up boot in 1.45 emulated seconds with `phase_followup_stop_reason: vtor_captured`.

All sixteen runs from the matrix of three `--no-assert-verdict` runs and one asserting run per profile are complete; two intermediate `multi_fault_power_loss_run2` attempts and two intermediate `multi_fault_bit_corruption_assert` attempts were stopped before writing reports:

- `nuttx_nxboot_real_update` revert canary: all three `--no-assert-verdict` runs and the asserting run are complete: `revert_canary_run1.json` at 7802.9 s, `revert_canary_run2.json` at 1493.4 s, `revert_canary_run3.json` at 1517.5 s, and `revert_canary_assert.json` with exit code 0 at 2274.4 s.
- `nuttx_nxboot_power_loss` multi-fault canary: all three `--no-assert-verdict` runs and the asserting run are complete: `multi_fault_power_loss_run1.json` at 1460.9 s, `multi_fault_power_loss_run2.json` at 1827.3 s, `multi_fault_power_loss_run3.json` at 869.6 s, and `multi_fault_power_loss_assert.json` with exit code 0 at 1088.4 s.
- `nuttx_nxboot_bit_corruption` multi-fault canary: all three `--no-assert-verdict` runs and the asserting run are complete: `multi_fault_bit_corruption_run1.json` at 1412.4 s, `multi_fault_bit_corruption_run2.json` at 697.5 s, `multi_fault_bit_corruption_run3.json` at 698.0 s, and `multi_fault_bit_corruption_assert.json` with exit code 0 at 859.0 s, each with 18 points, 9 immediate cycle-0 recoveries, and 9 cycle-1 self-healed recoveries after cycle-0 `no_progress_stall`.
- `nuttx_nxboot_instruction_skip` multi-fault canary: all three `--no-assert-verdict` runs and the asserting run completed with exit code 0 in 113.8 s to 231.3 s.

## Workflow command sequences and pinned inputs

All three NuttX workflows run on `ubuntu-22.04` with `timeout-minutes: 120` for sweep jobs, `OTA_RENODE_POINT_TIMEOUT_S=900`, `PYTHONUNBUFFERED=1`, xPack `arm-none-eabi-gcc` `13.2.1-1.1` with SHA-256 `1252a8cafe9237de27a765376697230368eec21db44dc3f1edeb8d838dabd530`, and Renode `1.16.1` portable Linux dotnet archive with SHA-256 `62629caa331ed4bd4eb7abe13ee2e4834fbcaa70de492db3965fafa4edc5694f`. By default each workflow normalizes `nuttx_ref=master` and `nuttx_apps_ref=master` via `scripts/action_helpers.py normalize-git-ref`, fetches depth-1 checkouts of `https://github.com/apache/nuttx.git` and `https://github.com/apache/nuttx-apps.git`, and records `NUTTX_SHA` and `NUTTX_APPS_SHA`.

1. `.github/workflows/nuttx-nxboot-revert-canary.yml` builds with `targets/nuttx_nxboot/build_public_target.py --jobs 8`, generates a single profile with `targets/nuttx_nxboot/generate_runtime_profile.py --fault-max-writes auto --boot-cycles 2`, computes `step = (196608 + fault_budget - 1) / fault_budget` which gives `--fault-step 3072` at the default `fault_budget=64`, and runs `scripts/audit_bootloader.py --workers 2 --max-batch-points 16 --robot-var "TEST_TIMEOUT:10 minutes" --fault-step 3072 --output results/nuttx_nxboot_revert_canary.json` without `--no-assert-verdict`.
2. `.github/workflows/nuttx-nxboot-multi-fault-canary.yml` builds once in the `build` job with `timeout-minutes: 30`, records `build-artifacts/provenance.json`, and fans out across `fault_type` values `power_loss`, `bit_corruption`, and `instruction_skip`. Each matrix leg runs `targets/nuttx_nxboot/generate_runtime_profile.py --build-dir build-artifacts --output-profile profile.yaml --fault-max-writes auto --boot-cycles 2 --fault-types "${fault_type}" --name "nuttx_nxboot_${fault_type}"`, computes `step = (196608 + fault_budget - 1) / fault_budget` which gives `--fault-step 6144` at the default `fault_budget=32`, and runs `scripts/audit_bootloader.py --profile profile.yaml --workers 2 --max-batch-points 16 --robot-var "TEST_TIMEOUT:10 minutes" --fault-step 6144 --output "results/nuttx_nxboot_${fault_type}.json"` without `--no-assert-verdict`.
3. `.github/workflows/nuttx-nxboot-real-exploratory.yml` is a manual `workflow_dispatch` workflow over campaigns `baseline`, `sector_boundary_resume`, `metadata_erase_resume`, and `sector_boundary_writeback`. It selects `--image-layout sector_boundary` for the two sector-boundary campaigns and `--image-layout baseline` otherwise, generates the profile with `--fault-max-writes auto --campaign "${NXBOOT_CAMPAIGN}"`, computes `--fault-step 12288` at the default `fault_budget=16`, and runs `scripts/audit_bootloader.py` with `--workers 2 --max-batch-points 16 --robot-var "TEST_TIMEOUT:10 minutes" --no-assert-verdict`.

## Pinned upstream revisions, build command, and generated profiles

The first session cloned `apache/nuttx` and `apache/nuttx-apps` at `master` into `third_party/` in 25 seconds:

```sh
NUTTX_REF="$(python3 scripts/action_helpers.py normalize-git-ref --name nuttx_ref --value master)"
NUTTX_APPS_REF="$(python3 scripts/action_helpers.py normalize-git-ref --name nuttx_apps_ref --value master)"
checkout_public_ref() {
  local url="$1" ref="$2" destination="$3"
  rm -rf "${destination}"
  git init --quiet "${destination}"
  git -C "${destination}" remote add origin "${url}"
  git -C "${destination}" fetch --quiet --depth 1 origin "${ref}"
  git -C "${destination}" checkout --quiet --detach FETCH_HEAD
}
checkout_public_ref https://github.com/apache/nuttx.git "${NUTTX_REF}" third_party/nuttx
checkout_public_ref https://github.com/apache/nuttx-apps.git "${NUTTX_APPS_REF}" third_party/nuttx-apps
```

The checked-out commits and build artifacts recorded in `third_party/nuttx-build/provenance.json` are present on disk and match their SHA-256 digests:

- `apache/nuttx`: `17747ded0aaba11af1dd07422c15354200e65e3e`
- `apache/nuttx-apps`: `297f998262f844ee37ec653b68e665efb61b4a94`
- `nxboot-loader.elf`: 2,069,056 bytes, SHA-256 `e4f06d8aeebce635d00586595ba62bcdfecded9abca0664f7811895a6810ce85`
- `nxboot-loader.bin`: 149,420 bytes, SHA-256 `d61733d4641996c530b3bc56bc71d0cbfde0d9f31dd0ce73432c4a882abd54b3`
- `nxboot-app.elf`: 2,402,464 bytes, SHA-256 `48324753744fd380f5f1ed182902368b59bc560bdeecb687c890fa1b8cc9c050`
- `nxboot-app.bin`: 204,224 bytes, SHA-256 `9d597a3d533e0c407bc6fe90fe2fe16b40ddce3e1477977b03ec5003968937b0`
- `images/nxboot-primary-v1-h400.img`: 205,248 bytes, SHA-256 `7489c73ca5fc3873f1f6e1f85cec75ed3097564bbf7a2cff8a8084204a28b741`
- `images/nxboot-update-v2-h400.img`: 205,248 bytes, SHA-256 `1cbf8bff28229b4c85354946c1558995efb13a536de4a7c4285b28ce1caa4f9d`

Running `build_public_target.py` inside `tardigrade-oss-validation:latest` failed immediately with `RuntimeError: kconfig-tweak not found on PATH; install kconfig-frontends or provide kconfig-tweak before building NuttX.` because the validation container does not install `kconfig-frontends`. The build ran on the macOS host using `/opt/homebrew/bin/arm-none-eabi-gcc` and the host `kconfig-tweak` and `kconfig-conf` wrappers in `/Users/neil/.local/bin` backed by `/Users/neil/.local/share/nuttx-kconfig-venv/bin`, finishing in 294.49 seconds:

```sh
python3 targets/nuttx_nxboot/build_public_target.py \
  --nuttx-root third_party/nuttx \
  --apps-root third_party/nuttx-apps \
  --output-dir third_party/nuttx-build \
  --jobs 8
```

Because `generate_runtime_profile.py` resolves `--build-dir` to an absolute path, running the generator on the host writes host paths that do not exist inside the `/workspace` container mount. Regenerating all four profiles inside `tardigrade-oss-validation:latest` sets `bootloader.elf` and `images.*` to `/workspace/third_party/nuttx-build/...`:

```sh
docker run --rm --platform linux/amd64 -v "$PWD:/workspace" -w /workspace \
  tardigrade-oss-validation:latest bash -lc '
python3 targets/nuttx_nxboot/generate_runtime_profile.py \
  --build-dir third_party/nuttx-build \
  --output-profile results/nuttx_canary/nuttx-revert-canary-profile.yaml \
  --fault-max-writes auto \
  --boot-cycles 2
for ft in power_loss bit_corruption instruction_skip; do
  python3 targets/nuttx_nxboot/generate_runtime_profile.py \
    --build-dir third_party/nuttx-build \
    --output-profile "results/nuttx_canary/nuttx-multi-fault-${ft}-profile.yaml" \
    --fault-max-writes auto \
    --boot-cycles 2 \
    --fault-types "${ft}" \
    --name "nuttx_nxboot_${ft}"
done
'
```

All four generated YAML files exist under `results/nuttx_canary/` and carry `phase2_wall_timeout_s: 120.0`, `max_step_limit: 1000000000`, `run_duration: "8.0"`, and `progress_stall_timeout_s: 4.0`.

## Audit commands and per-run results

Session 1 ran `revert_canary_run1.json`, `multi_fault_instruction_skip_run{1,2,3}.json`, `multi_fault_instruction_skip_assert.json`, and `multi_fault_power_loss_run1.json` with `OTA_RENODE_POINT_TIMEOUT_S=900` and `--robot-var "TEST_TIMEOUT:10 minutes"`. Session 2, Session 3, and Session 4 wrapped every run in an explicit `timeout` and ran the remaining `nuttx_nxboot_real_update`, `nuttx_nxboot_power_loss`, and `nuttx_nxboot_bit_corruption` runs with `OTA_RENODE_POINT_TIMEOUT_S=1800` and `--robot-var "TEST_TIMEOUT:40 minutes"` after two `multi_fault_power_loss_run2` attempts under `--robot-var "TEST_TIMEOUT:10 minutes"` hit 600-second Robot batch timeouts and bisected until the outer `timeout` stopped them:

```sh
docker run --rm --platform linux/amd64 -v "$PWD:/workspace" -w /workspace \
  -e OTA_RENODE_POINT_TIMEOUT_S=1800 -e PYTHONUNBUFFERED=1 \
  tardigrade-oss-validation:latest bash -lc '
timeout 2100 python3 scripts/audit_bootloader.py \
  --profile results/nuttx_canary/nuttx-multi-fault-bit_corruption-profile.yaml \
  --renode-test /opt/renode/renode-test \
  --workers 2 \
  --max-batch-points 16 \
  --robot-var "TEST_TIMEOUT:40 minutes" \
  --fault-step 6144 \
  --no-assert-verdict \
  --output results/nuttx_canary/multi_fault_bit_corruption_run1.json
'
```

Report verdict strings in the JSON files use an em-dash separator between clauses and parentheses around the glitch crash count. The table below replaces em-dashes with semicolons and brackets the glitch note and stop-reason durations. `Control wall` reports `phase1_ms + followup_ms` in seconds alongside cycle 0 `elapsed_s` and cycle 1 `elapsed_s` from `boot_cycles`.

| Run file | Profile | Mode and batch budget | Status | Wall time | `verdict` | `security_aggregate.status` | Points | Issues | Bricks | Timeouts | DoS crash | Control wall total / c0 / c1 | Control stop reasons c0 / c1 | Fault-point stop reasons p1 / p2 / fup |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `revert_canary_run1.json` | `nuttx_nxboot_real_update` | `--no-assert-verdict`, batch 16, Robot 10m | complete | 7802.9 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 34 | 0 | 0 | 0 | 0 | 31.82 s / 9.20 s / 4.24 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `revert_canary_run2.json` | `nuttx_nxboot_real_update` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 1493.4 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 34 | 0 | 0 | 0 | 0 | 30.89 s / 8.51 s / 3.65 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `revert_canary_run3.json` | `nuttx_nxboot_real_update` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 1517.5 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 34 | 0 | 0 | 0 | 0 | 30.35 s / 8.33 s / 3.59 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `revert_canary_assert.json` | `nuttx_nxboot_real_update` | assert verdict, exit 0, batch 16, Robot 40m | complete | 2274.4 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 34 | 0 | 0 | 0 | 0 | 38.74 s / 10.57 s / 6.27 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `multi_fault_power_loss_run1.json` | `nuttx_nxboot_power_loss` | `--no-assert-verdict`, batch 16, Robot 10m | complete after session 1 cutoff | 1460.9 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 31.30 s / 8.39 s / 3.76 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `multi_fault_power_loss_run2.json` attempt 1 | `nuttx_nxboot_power_loss` | `--no-assert-verdict`, batch 16, Robot 10m | stopped by `timeout 2400`, exit 124 | 2400.7 s | no report | no report | 18 planned | - | - | - | - | - | - | 9-point and 5-point batches hit `Test timeout 10 minutes exceeded` at 600.0 s |
| `multi_fault_power_loss_run2.json` attempt 2 | `nuttx_nxboot_power_loss` | `--no-assert-verdict`, batch 3, Robot 10m | stopped by `timeout 1800`, exit 124 | 1800.7 s | no report | no report | 18 planned | - | - | - | - | - | - | chunk 1 finished in 460.5 s; chunk 2 hit `Test timeout 10 minutes exceeded` at 600.0 s |
| `multi_fault_power_loss_run2.json` | `nuttx_nxboot_power_loss` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 1827.3 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 72.25 s / 24.53 s / 11.59 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `multi_fault_power_loss_run3.json` | `nuttx_nxboot_power_loss` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 869.6 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 31.89 s / 8.91 s / 3.91 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `multi_fault_power_loss_assert.json` | `nuttx_nxboot_power_loss` | assert verdict, exit 0, batch 16, Robot 40m | complete | 1088.4 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 31.03 s / 8.36 s / 3.71 s | `vtor_captured` / `vtor_captured` | `None` / `vtor_captured` / `vtor_captured` |
| `multi_fault_bit_corruption_run1.json` | `nuttx_nxboot_bit_corruption` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 1412.4 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 38.11 s / 11.62 s / 5.10 s | `vtor_captured` / `vtor_captured` | 9 `vtor_captured` and 9 `no_progress_stall [4.02s_emulated]` / `None` / `vtor_captured` |
| `multi_fault_bit_corruption_run2.json` | `nuttx_nxboot_bit_corruption` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 697.5 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 31.00 s / 8.51 s / 3.85 s | `vtor_captured` / `vtor_captured` | 9 `vtor_captured` and 9 `no_progress_stall [4.02s_emulated]` / `None` / `vtor_captured` |
| `multi_fault_bit_corruption_run3.json` | `nuttx_nxboot_bit_corruption` | `--no-assert-verdict`, batch 16, Robot 40m | complete | 698.0 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 31.68 s / 8.41 s / 3.75 s | `vtor_captured` / `vtor_captured` | 9 `vtor_captured` and 9 `no_progress_stall [4.02s_emulated]` / `None` / `vtor_captured` |
| `multi_fault_bit_corruption_assert.json` attempt 1 | `nuttx_nxboot_bit_corruption` | assert verdict, batch 16, Robot 40m | stopped by `timeout 2100`, exit 124 | 2100.5 s | no report | no report | 18 planned | - | - | - | - | - | - | calibration finished in 248.0 s; both 9-point worker chunks were still running at 1852.5 s inside `TEST_TIMEOUT:40 minutes` when outer `timeout 2100` fired |
| `multi_fault_bit_corruption_assert.json` attempt 2 | `nuttx_nxboot_bit_corruption` | assert verdict, batch 16, Robot 40m | stopped by external `docker kill`, exit 137 | 636.0 s | no report | no report | 18 planned | - | - | - | - | - | - | another host worker sent `SIGKILL` to all seven running `tardigrade-oss-validation:latest` containers at 01:41:14 PDT |
| `multi_fault_bit_corruption_assert.json` | `nuttx_nxboot_bit_corruption` | assert verdict, exit 0, batch 16, Robot 40m | complete | 859.0 s | `PASS; whole-device layout not assessed` | `INCONCLUSIVE` | 18 | 0 | 0 | 0 | 0 | 34.29 s / 10.34 s / 4.34 s | `vtor_captured` / `vtor_captured` | 9 `vtor_captured` and 9 `no_progress_stall [4.02s_emulated]` / `None` / `vtor_captured` |
| `multi_fault_instruction_skip_run1.json` | `nuttx_nxboot_instruction_skip` | `--no-assert-verdict`, batch 16, Robot 10m | complete | 194.5 s | `PASS; 0 security bypass points [1 DoS crash points, expected for glitch model]; whole-device layout not assessed` | `INCONCLUSIVE` | 1 | 0 | 0 | 0 | 1 | 49.59 s / 16.90 s / 7.24 s | `vtor_captured` / `vtor_captured` | `wall_timeout [16s]` / `None` / `None` |
| `multi_fault_instruction_skip_run2.json` | `nuttx_nxboot_instruction_skip` | `--no-assert-verdict`, batch 16, Robot 10m | complete | 231.3 s | `PASS; 0 security bypass points [1 DoS crash points, expected for glitch model]; whole-device layout not assessed` | `INCONCLUSIVE` | 1 | 0 | 0 | 0 | 1 | 61.63 s / 21.72 s / 9.05 s | `vtor_captured` / `vtor_captured` | `wall_timeout [16s]` / `None` / `None` |
| `multi_fault_instruction_skip_run3.json` | `nuttx_nxboot_instruction_skip` | `--no-assert-verdict`, batch 16, Robot 10m | complete | 113.8 s | `PASS; 0 security bypass points [1 DoS crash points, expected for glitch model]; whole-device layout not assessed` | `INCONCLUSIVE` | 1 | 0 | 0 | 0 | 1 | 31.43 s / 8.84 s / 3.60 s | `vtor_captured` / `vtor_captured` | `wall_timeout [7s]` / `None` / `None` |
| `multi_fault_instruction_skip_assert.json` | `nuttx_nxboot_instruction_skip` | assert verdict, exit 0, batch 16, Robot 10m | complete | 114.2 s | `PASS; 0 security bypass points [1 DoS crash points, expected for glitch model]; whole-device layout not assessed` | `INCONCLUSIVE` | 1 | 0 | 0 | 0 | 1 | 30.98 s / 8.24 s / 3.76 s | `vtor_captured` / `vtor_captured` | `wall_timeout [7s]` / `None` / `None` |

All four canary profiles pass in CI verdict-assertion mode on this host with exit code 0 when given the 40-minute Robot batch timeout and `OTA_RENODE_POINT_TIMEOUT_S=1800`: `revert_canary_assert.json` finished in 2274.4 s, `multi_fault_power_loss_assert.json` finished in 1088.4 s, `multi_fault_bit_corruption_assert.json` finished in 859.0 s, and `multi_fault_instruction_skip_assert.json` finished in 114.2 s under the 10-minute Robot budget. Across all sixteen completed runs, no run differed from the others in issue points, bricks, security bypass points, or timeout points, and every run within each profile produced the same `verdict` string. Two-cycle control wall time `phase1_ms + followup_ms` ranged from 30.35 s to 72.25 s across the sixteen runs, with cycle 0 `run_until_done` wall time spanning 8.24 s to 24.53 s and cycle 1 `run_until_done` wall time spanning 3.59 s to 11.59 s. Every run retained 108.41 s to 116.41 s of control cycle 1 `run_until_done` headroom and 72.98 s to 98.19 s of control `followup_ms` headroom against the 120 s `phase2_wall_timeout_s` recovery budget, while 9-point and 16-point multi-point batches under shared host load required 489.6 s to 1699.0 s and therefore had negative headroom of -1099.0 s against the workflows' 600 s Robot limit and -349.0 s against the 1350 s subprocess guard from `OTA_RENODE_POINT_TIMEOUT_S=900`.

## Control-time headroom against the 120-second recovery budget and outer batch limits

In `scripts/run_runtime_fault_sweep.py`, `phase2_wall_timeout_s: 120.0` is passed as `wall_timeout` to `run_until_done` during phase-2 recovery boots and during each follow-up cycle inside `_boot_followup_cycle`, including the clean control's cycle 1 follow-up boot. Phase 1 of the clean control uses `phase1_wall_timeout` with `run_duration: "8.0"`, which sets a 240-second wall limit.

Across the sixteen completed canary runs under multi-worker Docker Renode load:

- Clean control cycle 0 completed in 2.8 emulated seconds on every run. Its `run_until_done` wall time ranged from 8.24 s to 24.53 s and total `phase1_ms` ranged from 8.44 s to 25.23 s, leaving 214.77 s to 231.56 s of headroom below the 240-second phase-1 wall limit.
- Clean control cycle 1 completed in 1.45 emulated seconds on every run. Its `run_until_done` wall time ranged from 3.59 s to 11.59 s, leaving 108.41 s to 116.41 s of headroom below the 120-second `phase2_wall_timeout_s` cap.
- Including full-flash snapshot readback and `restore_flash_and_boot` before cycle 1, the clean control's `followup_ms` ranged from 21.81 s to 47.02 s, which exceeds the generic 30-second default by up to 17.02 s under host contention while still leaving 72.98 s to 98.19 s below 120.0 s. Combined two-cycle control wall time `phase1_ms + followup_ms` ranged from 30.35 s to 72.25 s.
- Across fault points, cycle 1 `run_until_done` wall time peaked at 22.77 s in `multi_fault_bit_corruption_run1.json`, leaving 97.23 s of headroom below 120.0 s. Phase-2 recovery `emulation_ms` inside `run_until_done` peaked at 27.29 s in `revert_canary_run1.json`, leaving 92.71 s of headroom below 120.0 s. Total per-point `phase2_ms` including flash reset peaked at 81.22 s in `revert_canary_run1.json` and total `followup_ms` peaked at 97.90 s in `multi_fault_bit_corruption_run1.json`.

While the 120-second per-boot recovery budget had at least 92.71 s of `run_until_done` headroom, the workflows' outer `--robot-var "TEST_TIMEOUT:10 minutes"` and `OTA_RENODE_POINT_TIMEOUT_S=900` limits are tighter than multi-point batches need under load:

- `run_batch_points` in `scripts/renode_runner.py` runs an entire chunk of up to 16 fault points inside one `ota_fault_point.Run OTA Fault Point` Robot test case and appends `--robot-var "TEST_TIMEOUT:10 minutes"` after its own computed `TEST_TIMEOUT`, capping the whole batch at 600 s.
- In `multi_fault_power_loss_run1.json`, per-point `total_ms` averaged 54.40 s and peaked at 56.74 s, so a 9-point worker batch needed 489.6 s plus baseline setup and exceeded 600 s once before finishing as 4-point and 5-point sub-batches in 1460.9 s.
- In `multi_fault_power_loss_run2.json`, per-point `total_ms` averaged 124.66 s and peaked at 169.15 s, so a 9-point worker batch required 1121.9 s. Under `TEST_TIMEOUT:10 minutes`, both 9-point batches and both 5-point sub-batches aborted at 600.0 s.
- In `revert_canary_run1.json`, per-point `total_ms` averaged 106.19 s and peaked at 205.15 s, so a 16-point chunk required 1699.0 s. That exceeds both the 600 s Robot limit and the 1350 s subprocess guard derived from `OTA_RENODE_POINT_TIMEOUT_S=900` multiplied by 1.5, forcing bisection from 16 to 8 to 4 to 2 to 1 and inflating the 34-point sweep to 7802.9 s. With `TEST_TIMEOUT:40 minutes` and `OTA_RENODE_POINT_TIMEOUT_S=1800`, `revert_canary_assert.json` averaged 85.83 s per point, peaked at 136.41 s per point, and completed without batch bisection in 2274.4 s, while `revert_canary_run2.json` and `revert_canary_run3.json` averaged 54.47 s and 55.12 s per point and completed without batch bisection in 1493.4 s and 1517.5 s.

## What did not work and why

- Building NuttX inside `tardigrade-oss-validation:latest` failed with `RuntimeError: kconfig-tweak not found on PATH` because the container image does not include `kconfig-frontends`. Building on the host with `/opt/homebrew/bin/arm-none-eabi-gcc` and `/Users/neil/.local/bin/kconfig-tweak` succeeded in 294.49 s.
- Generating profiles on the host wrote host-absolute paths under `/Users/neil/xuku/tardigrade-agents/codex/third_party/nuttx-build` that do not resolve inside the container where the repository is mounted at `/workspace`. Running `generate_runtime_profile.py` inside the container produced `/workspace/third_party/nuttx-build` paths that work in Docker Renode.
- Session 1 was terminated by its 170-minute wall-time cap at 20:43:19 UTC while waiting for `multi_fault_power_loss_run1.json` because `revert_canary_run1.json` consumed 7975.7 s after repeated 600-second Robot batch timeouts. The detached container for `multi_fault_power_loss_run1.json` finished writing its report at 21:01 UTC.
- `multi_fault_power_loss_run2.json` attempt 1 with `--max-batch-points 16` and `TEST_TIMEOUT:10 minutes` was stopped by `timeout 2400` with exit code 124 after 9-point and 5-point batches hit `Test timeout 10 minutes exceeded` at 600.0 s and discarded 1200 s of work. Attempt 2 with `--max-batch-points 3` and `TEST_TIMEOUT:10 minutes` was stopped by `timeout 1800` with exit code 124 after chunk 1 took 460.5 s and chunk 2 hit `Test timeout 10 minutes exceeded` at 600.0 s under host load. Raising the batch budget to `TEST_TIMEOUT:40 minutes` and `OTA_RENODE_POINT_TIMEOUT_S=1800` allowed `multi_fault_power_loss_run2.json`, `multi_fault_power_loss_run3.json`, `multi_fault_power_loss_assert.json`, `multi_fault_bit_corruption_run1.json`, `multi_fault_bit_corruption_run2.json`, `multi_fault_bit_corruption_run3.json`, `multi_fault_bit_corruption_assert.json`, `revert_canary_run2.json`, `revert_canary_run3.json`, and `revert_canary_assert.json` to complete without batch bisection.
- `multi_fault_bit_corruption_assert.json` attempt 1 used an outer `timeout 2100` that was smaller than the 2400-second `TEST_TIMEOUT:40 minutes` batch budget plus the 248.0-second calibration and control phase; `timeout 2100` stopped the run at 2100.5 s with exit code 124 while both 9-point worker chunks were still running at 1852.5 s under five-worker host contention. Attempt 2 under `timeout 3000` was killed at 636.0 s with exit code 137 when another worker on the shared host sent `SIGKILL` to all seven running `tardigrade-oss-validation:latest` containers. Relaunching under `timeout 2400` completed with exit code 0 in 859.0 s.
- In `multi_fault_instruction_skip`, the single fault point `i:0x800F02C` in `validate_image_header` hit the 2.0-second instruction-skip phase-1 wall cap at 7 s to 16 s of wall time and 0.72 s to 0.78 s of emulated time, ending in `bus_fault`. The glitch model classifies that crash as `dos_only` with zero security bypasses.
