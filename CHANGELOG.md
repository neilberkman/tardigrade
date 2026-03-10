# Changelog

All notable changes to this project will be documented in this file.

The format follows [common-changelog](https://common-changelog.org/).

## Unreleased

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

### Changed

- Explicit `PassthroughMode` controller capability for fast-path peripherals.
- Native STM32H7 trace replay support.
- Slot-relative metadata fault regions in profiles.
- Dynamic Robot timeouts for large batch runs.
- Per-fault-type summary counts and clearer skip-reason reporting.
- Read-fault backend preflight checks and clearer backend capability messages.

### Fixed

- Multi-boot verdicting now uses effective final outcomes for converged rollback flows.
- Read-fault runtime wiring, parser mismatches, and peripheral Robot assertions.
- Multi-fault execution path and deterministic fallback planning.
- Metadata-fault timing/reporting gaps.
- Execute-mode follow-up timing unpack regression.
- Calibration JSON serialization failure.
