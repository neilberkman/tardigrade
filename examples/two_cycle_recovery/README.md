# Two-cycle recovery and recovery-write counting example

This Cortex-M0+ fixture (derived from `examples/deliberate_crash_report` and
`examples/runtime_self_update`) exercises multi-cycle recovery reporting and
Phase 2 NVM write counting when `fault_sweep.tracking_start_address` is set.

## Profiles

- `profile.yaml` (`app.bin`, `boot_cycles: 2`, `tracking_start_address: 0x20000400`):
  - Phase 1 enters `write_record()` at `0x20000400` and writes 5 distinct
    16-byte MRAM units (`REC_MAGIC`, `REC_HDR`, `REC_PAYLOAD`, `REC_CRC`,
    `REC_COMMIT`).
  - Fault point 0 tears `REC_MAGIC` to `0`, so recovery boots cleanly on both
    cycles (`converged`, `recovery_writes = 0`).
  - Fault point 1 tears `REC_HDR` while `REC_MAGIC` is committed, causing a
    permanent `hard_fault` across both cycles (`converged`, 1 boot mismatch,
    `recovery_writes = 0`).
  - Fault points 2, 3, and 4 leave a repairable torn record. On cycle 0,
    recovery performs 3 MRAM writes (`REC_MAGIC = 0`, `REC_HDR = 0`,
    `REPAIR_LOG = "CLR1"`) and faults before memory checks hold (`hard_fault`,
    `recovery_writes = 3`). On cycle 1, the scrubbed state boots cleanly
    (`success`). Those 3 points report `multi_boot_analysis.status =
    "recovered_after_failure"` and appear in the verdict's `recovered after
    failure` category so the breakdown sums to `issue_points` (`1 + 3 + 0 + 0
    = 4`).
- `profile_oscillating.yaml` (`oscillating.bin`, `boot_cycles: 3`):
  - Fault points 2, 3, and 4 toggle `OSCILLATE_FLAG` in MRAM on each boot,
    producing `['hard_fault', 'success', 'hard_fault']` across 3 cycles, which
    reports `multi_boot_analysis.status = "oscillating"`.

## Build

```sh
make -C examples/two_cycle_recovery
```
