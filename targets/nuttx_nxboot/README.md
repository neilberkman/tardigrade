# Real NuttX nxboot campaigns

The target adapter builds NuttX and NuttX-apps from public upstream checkouts,
then packages the resulting application into nxboot images. No NuttX source,
firmware binary, or generated license manifest is stored in this repository.

## Canary timeout budgets

Generated profiles allow 120 seconds of wall time per recovery boot, including
clean-control follow-up boots. Both `nuttx-nxboot-revert-canary.yml` and
`nuttx-nxboot-multi-fault-canary.yml` use this generator. The 8-second
emulated runtime, 4-second emulated stall threshold, and one-billion-instruction
ceiling remain independent limits. The workflows retain their 10-minute Robot
limit and 900-second process limit. A control that exhausts any limit still
aborts fault dispatch as an infrastructure failure.

The September 27 [failed run](https://github.com/neilberkman/tardigrade/actions/runs/36322417397)
returned its control timeout after 43.8 seconds. Its retained profile omitted
`max_step_limit`, so revision `4f43360` supplied the old 500,000-instruction
default. Calibration stopped at 13,416 writes. The October 4
[passing run](https://github.com/neilberkman/tardigrade/actions/runs/37206166803)
used an explicit one-billion-instruction ceiling, completed the control's
initial boot in 2.8 emulated seconds, and completed its follow-up in 1.45
emulated seconds. Commit `ad0b132` raised the generated instruction ceiling on
September 28. This evidence points to the historical instruction budget rather
than the outer wall-clock limits. The failed run retained no control result,
so its precise stop reason cannot be recovered. Future control errors include
per-phase and follow-up-cycle stop reasons and emulated times to distinguish
instruction, emulation, and wall-clock exhaustion. The larger recovery wall
budget also gives slow hosts headroom above the generic 30-second default.

End-to-end Docker Renode verification across all four canary profiles is
recorded in [docs/nuttx-canary-verification.md](../../docs/nuttx-canary-verification.md).
Across sixteen completed runs on `apache/nuttx` commit `17747ded0a` and
`apache/nuttx-apps` commit `297f998262`, including all four CI-mode asserting
runs which exited 0, every clean control completed cycle 0
in 2.8 emulated seconds and cycle 1 in 1.45 emulated seconds. Under concurrent
multi-worker load, control cycle 0 `run_until_done` wall time ranged from 8.24
to 24.53 seconds against the 240-second phase-1 limit, and control cycle 1
`run_until_done` wall time ranged from 3.59 to 11.59 seconds, leaving 108.41
to 116.41 seconds of headroom below `phase2_wall_timeout_s: 120.0`. Including
full-flash snapshot reload before cycle 1, control `followup_ms` reached 21.81
to 47.02 seconds and fault-point `followup_ms` reached 97.90 seconds, exceeding
the generic 30-second default under load while staying within 120 seconds.
Because `run_batch_points` applies `--robot-var "TEST_TIMEOUT:10 minutes"` to
an entire batch of up to 16 fault points and `OTA_RENODE_POINT_TIMEOUT_S=900`
sets a 1350-second subprocess guard, 9-point and 16-point batches averaging
54.40 to 124.66 seconds per point exceeded 600 seconds and bisected repeatedly
under load.

The ordinary campaign is unchanged:

```sh
python3 targets/nuttx_nxboot/build_public_target.py \
  --nuttx-root "$RUNNER_TEMP/nuttx" \
  --apps-root "$RUNNER_TEMP/nuttx-apps" \
  --output-dir "$RUNNER_TEMP/nuttx-build" \
  --image-layout baseline
python3 targets/nuttx_nxboot/generate_runtime_profile.py \
  --build-dir "$RUNNER_TEMP/nuttx-build" \
  --output-profile "$RUNNER_TEMP/nuttx-runtime-profile.yaml" \
  --campaign baseline
```

## Second-wave campaigns

`sector_boundary_resume` uses the same upstream application bytes for the
primary image, while the update image is padded to the next 128 KiB STM32H7
erase-sector boundary. It then runs `swap_progress` cutpoints across three
boot cycles. This tests resume behavior with a different image/erase geometry,
not merely a denser write sweep:

```sh
python3 targets/nuttx_nxboot/build_public_target.py \
  --nuttx-root "$RUNNER_TEMP/nuttx" \
  --apps-root "$RUNNER_TEMP/nuttx-apps" \
  --output-dir "$RUNNER_TEMP/nuttx-build" \
  --image-layout sector_boundary
python3 targets/nuttx_nxboot/generate_runtime_profile.py \
  --build-dir "$RUNNER_TEMP/nuttx-build" \
  --output-profile "$RUNNER_TEMP/nuttx-sector-boundary.yaml" \
  --campaign sector_boundary_resume
```

`metadata_erase_resume` keeps the ordinary real-app pair and combines the
semantic sector-progress selector with partial erase faults. It targets
interrupted metadata/slot transitions and validates the same nxboot role,
recovery, duplicate-update, and rollback invariants:

```sh
python3 targets/nuttx_nxboot/generate_runtime_profile.py \
  --build-dir "$RUNNER_TEMP/nuttx-build" \
  --output-profile "$RUNNER_TEMP/nuttx-metadata-erase.yaml" \
  --campaign metadata_erase_resume
```

`sector_boundary_writeback` uses the existing sector-boundary image artifacts,
the same three-boot sequence, and only `power_loss` faults under the writeback
durability model. The model uses its automatic buffer capacity and does not
invent barrier addresses or erase flushes:

```sh
python3 targets/nuttx_nxboot/generate_runtime_profile.py \
  --build-dir "$RUNNER_TEMP/nuttx-build" \
  --output-profile "$RUNNER_TEMP/nuttx-sector-boundary-writeback.yaml" \
  --campaign sector_boundary_writeback
```

Generated profiles declare the platform's two 1 MiB STM32H7 flash banks and
their verified 128 KiB erase sectors. No extra postmortem partition is added;
the platform does not establish a distinct metadata or scratch partition.

All named campaigns require the real build artifacts and reject images
larger than the declared slot. A clean control boot is still required before
the fault sweep; a failing control is a setup/build result, not a finding.
