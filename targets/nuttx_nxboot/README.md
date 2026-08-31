# Real NuttX nxboot campaigns

The target adapter builds NuttX and NuttX-apps from public upstream checkouts,
then packages the resulting application into nxboot images. No NuttX source,
firmware binary, or generated license manifest is stored in this repository.

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

Both second-wave profiles require the real build artifacts and reject images
larger than the declared slot. A clean control boot is still required before
the fault sweep; a failing control is a setup/build result, not a finding.
