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
- Configurable MRAM torn-word modes via `fault_sweep.mram_torn_word` and the
  `MramTornWordMode` peripheral property across live MRAM backends and trace
  replay for `half`, `half_retain`, `untouched`, `erased`, `programmed`,
  `uncorrectable` (marks the interrupted word unreadable so CPU reads raise a
  bus error while tooling reads return stored bytes and report marked words,
  with recovery read-disposition reporting), and `corrupted` (deterministic
  multi-bit flips seeded via `fault_sweep.mram_torn_word_seed`).
- Strict MCUboot PR #2206 align-32 multi-sector swap-scratch trailer erase
  regression pair (`profiles/mcuboot_pr2206_scratch_geom_broken.yaml` at
  commit `66d41e73` vs `profiles/mcuboot_pr2206_scratch_geom_fixed.yaml` at
  PR #2206 head `d00b11dc`), tracked STM32F429 ELFs and signed `0x7D50`
  revert image, `MCUBOOT_BOOTSTRAP_SCOPE=pr2206_geom` rebuild support, and
  inclusion in the default CI self-test corpus.
- Two-cycle recovery and three-cycle oscillating fixture
  (`examples/two_cycle_recovery/`) exercising `boot_cycles: 2` failure-then-
  success recovery, `boot_cycles: 3` alternation, `memory_checks`, and
  non-zero `tracking_start_address` recovery-write accounting.

### Changed

- Re-enabled all four MCUboot PR #2214 swap-offset differential profiles
  (`mcuboot_pr2214_offset_{broken,fixed}.yaml` and
  `mcuboot_pr2214_offset_geom_{broken,fixed}.yaml`) as strict regression
  self-tests in `scripts/self_test_runtime_manifest.json`, regenerated their
  boundary-hitting staging binaries (`swap_size=0x74000` on nRF52840 sector+1
  and `swap_size=0x8000` on mirrored-bank STM32F429) with `imgtool verify`
  enabled for both scopes, and added boundary-drift regression tests modeling
  `find_last_idx` at `429e2fea` versus `90fd59d2`.
- `load_profile` accepts an optional `strict_root` directory boundary for strict
  `base_profile` resolution, permits `..` segments in relative `base_profile`
  paths when the resolved target remains inside that boundary, and
  `audit_bootloader.py` forwards `--repo-root` as `strict_root` when `--repo-root`
  is explicitly passed.
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

- ARMv6-M targets (Cortex-M0, M0+, M1 — identified automatically from the
  platform's CPU type via `cpu.Model` and `.repl` `cpuType`, with no new
  profile key) now ignore `CFSR` (`0xE000ED28`) and `HFSR` (`0xE000ED2C`),
  which do not exist on ARMv6-M silicon even though Renode models them. Fault
  classification on ARMv6-M relies on the active exception number (`IPSR`),
  HardFault handler entry, and lockup only, while ARMv7-M and ARMv8-M keep
  full `CFSR`/`HFSR` checks. Simplified `HardFault_Spin` in
  `examples/deliberate_crash_report/app.c` to spin directly on `b .` without
  clearing nonexistent `CFSR`/`HFSR` bits.
- Erased Cortex-M exception vectors (`0xFFFFFFFF`, or `0xFFFFFFF0..0xFFFFFFFF`
  in the `EXC_RETURN` range) no longer trap Renode in an infinite zero-progress
  exception-return loop until wall-clock timeout. `prime_bootloader_entry` and
  `run_until_done` in `scripts/run_runtime_fault_sweep.py` now detect erased
  Reset and runtime exception vectors (as well as architectural `cpu_lockup`
  states on Renode 1.17.0+), halt cleanly, record `lockup_observed` /
  `erased_vector_lockup` evidence, and classify the run as `hard_fault` (the
  same outcome a real lockup gets). Added the erased-vector fixture
  (`examples/recovery_vector_fault/profile_erased_vector.yaml`).
- `analyze_boot_cycles` in `scripts/boot_cycle_analysis.py` now labels a
  single-transition sequence whose initial boot succeeded and whose follow-up
  boot ended in a failure outcome (`hard_fault`, `no_boot`,
  `memory_checks_unmet`, `bus_fault`, `wrong_pc`, `misaligned_vtor`,
  `config_crash`, `config_lost`, `rollback_accepted`, `toctou_corruption`) as
  `failed_after_success` (with `failed_at_cycle`), rather than
  `changed_unconfirmed`. Unconfirmed slot/image reverts (`changed_unconfirmed`)
  and rollback statuses keep their existing treatment.
- `_effective_boot_result`, `_effective_boot_cycle_is_final`, and
  `classify_failure_class` in `scripts/fault_classification.py` now promote
  `failed_after_success` (and `oscillating` sequences that start with `success`
  and end in a failure outcome) to the failing cycle's outcome, slot, signals,
  and failure class so second-boot failures count as bricks or `boot_mismatch`
  issues in the verdict breakdown instead of disappearing behind cycle 0's
  `success`. Added second-boot fault (`profile_fail_second_boot.yaml`) and
  second-boot unmet-checks (`profile_unmet_checks_second_boot.yaml`) companion
  fixtures to `examples/two_cycle_recovery/`.
- `analyze_boot_cycles` in `scripts/boot_cycle_analysis.py` no longer labels a
  two-cycle observation `[X, Y]` with `X != Y` as `oscillating`. Single-transition
  failure-then-success runs (such as `['hard_fault', 'success']`) now report
  `recovered_after_failure` (with `recovered_at_cycle`), other unconfirmed
  single-transition changes report `changed_unconfirmed` (or
  `rollback_observed_unconfirmed` under an expected rollback schedule), and
  `oscillating` is reserved for three or more cycles with at least two
  transitions (`len(pairs) >= 3` and `transitions >= 2`).
- `_effective_boot_result` and `_effective_boot_cycle_is_final` in
  `scripts/fault_classification.py` now check `multi_boot_analysis["status"]`
  before honoring `final_boot_outcome` / `final_boot_slot`, promoting only
  success statuses (`converged`, `rollback_converged`,
  `recovered_after_failure`). Non-success multi-boot statuses (`oscillating`,
  `changed_unconfirmed`, `initial_no_boot_recovered`, `rollback_missing`,
  `rollback_late`, `rollback_observed_unconfirmed`,
  `rollback_observed_oscillating`, `stuck_revert`, `timeout`) are no longer
  promoted to their last cycle's outcome even after `annotate_boot_span_result`
  populates `final_boot_outcome`.
- `scripts/fault_classification.py` and `scripts/audit_report.py` now read
  per-boot criteria signals from the effective boot cycle
  (`_effective_boot_signals`, matching `_effective_boot_result`) instead of
  leaking stale cycle-0 failures onto a promoted final cycle, explicitly
  classify cycle-0 failure followed by final-cycle recovery via
  `result_recovered_after_failure`, and partition every issue point into a
  mutually exclusive `issue_breakdown` (`boot_mismatch`,
  `recovered_after_failure`, `semantic`, `invariant`, `metadata_delta`,
  `confirm_cycle`, `terminal_error_escape`, `other`) so `compute_verdict`
  always sums to `issue_points` (including a `recovered after failure`
  category when present).
- Recovery resets (`prepare_recovery_shell_state`, `reset_nvmc_for_recovery`,
  and slow-path Phase 2 resets in `scripts/run_runtime_fault_sweep.py`) now
  bypass `tracking_start_address` (`TrackingStartAddress = 0` and Python
  tracking-gate hook removed) so `recovery_writes` and Phase 2 write-progress
  observation count NVM writes performed during recovery regardless of the
  profile's Phase 1 tracking gate. Trace-replay fault runners
  (`run_trace_replay_fault_native` and `run_trace_replay_fault`) now also
  record `recovery_writes` in their result payloads.
- Scoped post-success fault suppression in `scripts/run_runtime_fault_sweep.py`
  and `scripts/profile_loader.py` behind an explicit
  `success_criteria.allow_fault_after_success: true` opt-in (default `false`),
  restored content-criteria evaluation (`memory_checks`, `config_checks`,
  `bootloader_integrity`, volatile/non-slot `marker_address`, `image_hash`, and
  `anti_rollback`) on follow-up boot cycles in `_boot_followup_cycle` (skipping
  only cycle-0-only assertions — `otadata_expect`, unconfirmed static in-slot
  header markers, and unconfirmed staging-only hash restrictions — without ever
  letting a skipped criterion count as held), and gated the `HardFault`
  vector-entry PC check in `collect_recovery_execution_evidence` identically to
  the `BusFault` vector-entry and `IPSR` checks when opted in. Uncorrectable
  MRAM reads remain `hard_fault` regardless of `allow_fault_after_success`.
  Updated `examples/deliberate_crash_report` to opt in and added no-opt-in,
  vector-entry-spin, and follow-up-cycle-before-checks fixture variants.
- `run_until_done` and `collect_recovery_execution_evidence` in
  `scripts/run_runtime_fault_sweep.py` now record when success checks first hold
  and when a fault exception (`IPSR` 3–6) becomes active (via an interrupt-begin
  hook and slice-boundary tracking) and compare their ordering. A fault
  exception that becomes active only after the run's success checks have already
  held (and continue to hold at stop, without being triggered by an
  uncorrectable MRAM read) no longer overrides success via `IPSR`, restoring
  pre-`c7c20c0` (`ca02138`) classification for firmware that deliberately enters
  a fault handler to record a crash report while keeping `hard_fault` detection
  (including `IPSR` and `mram_torn_word: uncorrectable`) for runs that fault
  before their success checks hold.
- `_boot_followup_cycle` in `scripts/run_runtime_fault_sweep.py` now passes
  `marked_at_fault=` (with formatted uncorrectable word addresses) and
  `p2_status=status` to `_attach_uncorrectable_read_signals` instead of the
  invalid `marked_offsets=` keyword, preventing a `TypeError` on follow-up boot
  cycles in `mram_torn_word: uncorrectable` mode when a marked word survives
  cycle 0.
- Short-image digest padding (in `ProfileConfig._compute_image_digests`,
  `scripts/sweep.py`, `scripts/trigger_discovery.py`, and writeback
  reconstruction) now supports an optional `memory.erase_fill` byte and
  otherwise classifies MRAM backends via `_is_mram_backend` (`0x00` for MRAM
  backends including `mramTracker`, `0xFF` for non-MRAM backends) instead of
  matching only the literal `flash_backend: mram`. At runtime, before images
  load, `run_runtime_fault_sweep.py` stops with a clear error naming
  `memory.erase_fill` and both values if the padding byte differs from the
  live backend's `EraseFill`.
- `_warn_fault_backend_compat` in `scripts/profile_loader.py` now matches
  platform heuristics against the platform filename (`Path(platform).name`)
  rather than the full path string, preventing spurious MRAM
  backend-compatibility warnings when a non-MRAM platform path passes through a
  directory whose name contains `mram`.
- `scripts/report_security_status.py` no longer appends a spurious
  `summary.runtime_sweep calibration coverage is unavailable` inconclusive
  reason to verified intentional zero-point control-only campaigns
  (`campaign_integrity.intentional_control_only: true`), aligning security
  aggregation with `scripts/audit_report.py` and `scripts/self_test.py`.
- The runtime fault sweep normalizes missing follow-up cycle records to an
  empty sequence before collecting state-probe observations for a single-cycle
  clean update phase.
- `fault_sweep.boot_cycle_hook` and per-phase `update_sequence` `boot_cycle_hook`
  paths now resolve through the shared profile input path helper across
  absolute paths, `repo_root`, the current working directory, and the profile
  directory, and missing hooks raise `ProfileError` at load time listing every
  tried path.
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
- Write and erase counts no longer restart when the firmware resets the
  machine during a run. Every bundled flash and MRAM peripheral gains
  `PreserveCountersAcrossReset`, which the runtime sweep enables for the run
  and disables around its own `machine Reset` for cold-reset preparation and
  Phase 2 recovery. A fault index past a firmware-initiated reset now names
  the write after the reset; before, the count restarted and the same index
  named an earlier write. Campaigns whose firmware resets mid-run calibrate
  to a larger write count. External peripherals keep the old behavior unless
  they expose the property.
- Reset-gated runtime sweeps (`success_criteria.terminal_after_reset: true`)
  now observe resets directly via Renode's `IMachine.MachineReset` and
  `IMachine.PeripheralReset` events (keeping `boot_entry_reentered` and
  `instruction_counter_reset` as corroboration) and separate decisive content
  evidence from reachable `memory_checks`. Content mismatches after reset
  remain immediately terminal `wrong_image`, whereas unmet `memory_checks`
  continue polling across post-reset slices until everything holds (`success`)
  or the emulation/instruction budget ends with valid content, reporting the
  dedicated `memory_checks_unmet` outcome and naming every failed check.
  Reports now record exact reset virtual time and post-reset check latency in
  `phase1_reset_observation`, `phase2_reset_observation`,
  `calibration.stop.reset_observation`, and `summary.runtime_sweep.control`.
  Added the direct-reset delayed-liveness fixture under
  `examples/runtime_self_update_delayed/`.

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
