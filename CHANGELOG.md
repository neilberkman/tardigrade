# Changelog

All notable changes to this project will be documented in this file.

The format follows [common-changelog](https://common-changelog.org/).

## [Unreleased]

### Added

- Configurable function-return fault injection and per-call return probes.
- Success-implies-effect, atomic-state, monotonic-state, and cross-component
  security invariants.
- Update artifact authentication/metadata coverage and reviewed-versus-signed
  authorization analyzers.
- Grammar-aware authenticated-equivalence campaigns for supplied parser or
  harness evidence, with authenticated-identity checks and fail-closed
  semantic findings.
- Security-counter boundary campaigns, persistent erase-domain analysis,
  production-assert checks, and emitted-binary terminal-error escape analysis.
- Native TF-M BL2/AN521 target support and supporting Renode peripherals.
- Explicit access-width write traces from the bundled flash backends and
  width-aware, fail-closed writeback snapshot reconstruction for traced
  storage operations.
- Current-head MCUboot STM32F4 scratch and NuttX nxboot
  `sector_boundary_writeback` campaign presets.
- Bounded no-boot postmortem evidence for image slots, non-uniform erase
  geometry, and auxiliary flash partitions.
- Reproducible second-wave NuttX nxboot build and runtime-profile presets.
- Fail-closed source-release license certification with exact file digests and
  tracked-file completeness enforcement in CI.
- Freshness-aware authenticated-metadata campaigns and valid/invalid parser
  harness preflight qualification.
- A generic persistent-state invariant that rejects writes or successful boot
  outcomes after a configured security-state read fails.
- Explicit `target_source` provenance is preserved across audit, scenario,
  self-test, merged, and OSS-validation reports; `expect.mode` supports
  explicit exploratory and hunt campaigns.
- Authenticated-equivalence campaigns can use explicit before/after evidence
  to detect persistent security-state changes caused by rejected mutants.

### Changed

- Fast and direct-MRAM recovery boots now derive the initial SP and PC from a
  restored faulted vector table when it resides in the backend array, exposing
  interrupted vector writes as boot failures instead of retaining clean-ELF
  register values. An all-zero restored vector pair leaves the core halted.
- GitHub Action results now separate assertion status from security status and
  require an explicit regression mode for known-vulnerable profiles.
- Runtime reports include richer fault classification, probe evidence, and
  security-state diagnostics.
- Calibration exports preserve write widths. Writeback preflight rejects
  malformed or invalid traces; valid traces whose widths are unsupported by the
  fixed-width native replay use the width-aware path.
- Writeback replay refuses backends that explicitly declare non-operation-accurate
  write traces instead of reconstructing durability from address differences.
- MCUboot HEAD swap-scratch validation uses mirrored STM32F429 bank geometry
  and dedicated signed slot images.
- Recovery-boot wall-clock budgets are profile-configurable and remain
  distinct from emulated-time stall detection.
- Optional selector coverage no longer makes unrelated campaigns incomplete;
  explicitly configured selectors remain fail-closed.
- Renode-test receives the configured Robot timeout so healthy long-running
  controls are not terminated by its shorter default suite timeout.
- The README states that MCUboot PR #2199 is detected by the control-boot
  state probe rather than by a fault point, documents the four retained MCUboot
  PR differentials and the removal of the PR #1597, PR #2205, and PR #2206
  pairs, and lists which fault types run against real upstream firmware.

### Fixed

- The clean-control gate requires `image_hash` evidence only from
  `evaluation_mode: execute` controls. State mode copies the staging slot
  itself and judges the vector table alone, so it never produced that
  evidence and the gate rejected the thirteen state-mode profiles that declare
  `image_hash`, five of them in the CI self-test. The loader now warns that
  `image_hash` has no effect outside execute mode.
- The Robot suites that load `platforms/mps2_an521.repl` include
  `peripherals/TraceReplayEngine.cs` first, since the platform now declares a
  `trace_replay` peripheral of that type.
- Generated NuttX nxboot campaigns allow 120 seconds of recovery wall time,
  including clean-control follow-ups; control failures include phase and cycle
  stop reasons while remaining infrastructure failures.
- Heuristic sweeps now fail before planning when their selected backend lacks
  an address-bearing write trace, while direct word-write MRAM-style memory
  supplies width-aware traces for tiered planning and replay. Explicit
  heuristics force fine trace capture on fast backends, controller trace stubs
  are excluded, and direct-MRAM replay preserves the model's torn-word
  power-loss behavior.
- Recovery boots now verify and clear profile-declared volatile memory, and
  report an unmapped range or a volatile success marker that survives clearing
  as inconclusive instead of accepting stale SRAM as recovery evidence.
- Flash/OTP persistence and reset handling across multi-boot fault campaigns.
- Calibration caching and coverage validation for expanded fault plans.
- Probe state isolation between instruction-skip points and normalized,
  fail-closed GitHub Action result accounting.
- Update-protocol commit-path coverage and wildcard terminal-sink propagation.
- Trace-less trigger discovery now requires exact configured target evidence,
  and incomplete recovery observations remain timeouts instead of bricks.
- Removed three trace-less NVMemory writeback profiles that could not produce
  executable durability evidence under the fail-closed runtime contract.
- Clean writeback controls now execute normally without rerouting non-writeback
  state controls, and STM32F4 fine calibration exports complete address-bearing
  write traces.
- MCUboot hybrid evaluation now uses the backing-flash trace base, derives
  vectors from MCUboot image headers, validates secondary-slot images at their
  eventual execution address, and sends scratch or other out-of-slot writes
  through real execute-mode recovery.
- Calibration caches accept the explicit-width write traces emitted by current
  backends while retaining legacy three-column trace compatibility.
- Automatic batching treats writeback recovery replay as expensive work,
  isolating fault points and assigning conservative Robot timeout budgets.
- The experimental MCUboot state evaluator is now disabled for CLI audits
  unless `--allow-mcuboot-state-evaluator` is explicitly supplied; hybrid
  routing accepts only the exact ordinary power-loss wire type `w`, preserves
  per-point fault types, and remains conservative for overlapping trailers.
- Self-test expectation checks reject incomplete or infrastructure-invalid
  campaign reports before evaluating expected findings.
- OSS validation initializes and verifies a clean managed source worktree
  before attributing a built target to its exact revision.
- The MCUboot HEAD matrix build signs each test image with the application's
  `CONFIG_ROM_START_OFFSET` instead of a fixed 0x200 header and fails when the
  vector table at the signed header size is not a real handoff target. Current
  Zephyr links STM32 MCUboot applications at 0x400, so the zero-day STM32F4
  writeback sweep had been branching to address 0 and reporting
  `INCONCLUSIVE -- could not trigger firmware update`. The writeback profile
  again inherits the base VTOR and marker success criteria.
- Verified all four NuttX nxboot canary presets across 12 runs in `docs/nuttx-canary-verification.md`.
- Audited the MCUboot PR differential pairs in `docs/mcuboot-differentials.md`, verified all six profiles in `.github/workflows/mcuboot-head-zero-day.yml` in `docs/zero-day-results.md`, and removed the non-separating PR #1597, PR #2205, and PR #2206 pairs, their dedicated ELFs and images, and their helper scripts.
- Added `scripts/check_mcuboot_swap_tables.py` and `scripts/check_mcuboot_images.py` with `docs/mcuboot-asset-provenance.md` and `docs/mcuboot-pr2214-swap-offset.md`, rebuilt the PR #2214 nRF52840 swap-offset ELFs and `0x74000`-padded slot-1 image so `mcuboot_pr2214_offset_broken.yaml` and `mcuboot_pr2214_offset_fixed.yaml` separate on the control boot, and rebuilt `mcuboot_pr2199_move_{broken,fixed}.elf`, `mcuboot_head_offset.elf`, `mcuboot_pr2214_offset_geom_{broken,fixed}.elf`, and the full-slot offset images.
- Added `targets/tf_m_bl2/build_public_target.sh` and `targets/tf_m_bl2/generate_runtime_profile.py` for upstream `TF-Mv2.3.1` with MCUboot `v2.4.0` on MPS2 AN521, updated `scripts/run_runtime_fault_sweep.py` to preserve non-slot memory regions before Phase 1 when `erase_all_slots` is enabled, and documented the `SWAP_USING_MOVE` unconfirmed, confirmed, and `OVERWRITE_ONLY` findings in `docs/tfm-bl2-an521.md`.
- Updated `scripts/run_runtime_fault_sweep.py` to count `rc_injection` points toward calibration write requirements and route `driver_error` and `rc_injection` through `fault_peripheral`, added `profiles/mcuboot_head_nrf52_driver_faults.yaml`, and recorded runs for all 12 MCUboot fault types in `docs/mcuboot-fault-type-coverage.md`.
- Fixed the `FaultTracker` writeback overlay so erase operations evict overlapping uncommitted buffered writes instead of replaying stale pre-erase bytes, added `mcuboot_head_scratch_nrf52_writeback.yaml`, `mcuboot_head_move_nrf52_writeback.yaml`, and `mcuboot_head_move_stm32f4_writeback.yaml` with `docs/mcuboot-writeback-triage.md`, and ran exhaustive 100-branch sweeps across all 12 MCUboot instruction-skip profiles in `docs/mcuboot-instruction-skip-results.md`.
- Raised `profiles/mcuboot_stm32f4_upgrade.yaml` to `run_duration: "3.3"` and `max_step_limit: 330000000` so STM32F4 128 KB swap-move calibration completes all 393,242 byte-program transitions instead of stopping at 100,000,000 instructions, enabled `quick_use_heuristic: true` on the four PR #2100 profiles, removed `sweep_hash_bypass_symbols` from `mcuboot_pr2109_scratch_broken.yaml` and `mcuboot_pr2109_scratch_fixed.yaml` so `bootutil_img_validate` executes on swap-scratch resume, and gated all 14 remaining `profiles/mcuboot_pr*.yaml` profiles under `--quick --workers 2` in `docs/mcuboot-differentials.md`.

## [0.5.0] - 2026-07-10

### Changed

- Explicit `PassthroughMode` controller capability for fast-path peripherals.
- Native STM32H7 trace replay support.
- Slot-relative metadata fault regions in profiles.
- Dynamic Robot timeouts for large batch runs.
- Per-fault-type summary counts and clearer skip-reason reporting.
- Read-fault backend preflight checks and clearer backend capability messages.
- GitHub Action runtime isolation, input validation, and verified dependency downloads.
- Reproducible public validation inputs and firmware-asset builds.

### Added

- Generic Phase 2 recovery fault injection.
- Seeded initial-state expansion for sweep matrices.
- Metadata-write fault injection and metadata-region classification.
- Read-time bit-flip fault injection.
- Multi-fault sweep planning and execution.
- Boot-cycle hooks, rollback-aware multi-boot analysis, and rollback invariants.
- Generic hook-fault coverage for between-boot hook writes.
- Bootloader self-update, NVS/config corruption, partial-staging, and multi-component capability surfaces.
- Real NuttX `nxboot` exploratory and revert-canary workflows.
- Multi-fault plan preview and dry-run explain mode.
- Generic postcondition invariants with profile-level invariant configuration.
- Third-party license and notice inventory for distributed source and firmware assets.

### Removed

- Unsupported RIOTboot standalone, TF-M AN521, and prebuilt rustBoot target bundles.

### Fixed

- Multi-boot verdicting now uses effective final outcomes for converged rollback flows.
- Read-fault runtime wiring, parser mismatches, and peripheral Robot assertions.
- Multi-fault execution path and deterministic fallback planning.
- Metadata-fault timing/reporting gaps.
- Execute-mode follow-up timing unpack regression.
- Calibration JSON serialization failure.

[0.5.0]: https://github.com/neilberkman/tardigrade/releases/tag/v0.5.0
