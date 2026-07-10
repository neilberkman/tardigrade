# Changelog

All notable changes to this project will be documented in this file.

The format follows [common-changelog](https://common-changelog.org/).

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
