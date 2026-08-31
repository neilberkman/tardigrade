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

### Fixed

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
