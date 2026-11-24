# Deliberate terminal fault after success checks example

This Cortex-M0+ fixture models firmware that starts normally, satisfies its
profile success checks (scheduler flag and tick counter), and then deliberately
takes a fault so its fault handler can write a crash record to persistent MRAM
and spin.

The profile uses `pc_in_slot: exec`, `allow_fault_after_success: true`, and
`memory_checks` on the scheduler flag (`0x20000200 == 1`) and tick count
(`0x20000204 >= 5`). On a healthy clean control run:

1. `boot.elf` jumps to `exec` (`0x10100000`).
2. `app.bin` relocates `VTOR` to SRAM (`0x20000100`), publishes
   `SCHEDULER_FLAG = 1`, and advances `TICK_COUNT` to `5`.
3. Seeing the volatile pre-boot crash-dump request (`0x20000400 == 0xC0A50001`),
   the firmware deliberately executes `udf #0`.
4. The fault handler records and clears `CFSR`/`HFSR`, writes a 4-unit crash
   record to MRAM (`0x10102000..0x1010203F`), and spins in the handler with an
   active fault exception in `IPSR`.

Because the profile opts in with `success_criteria.allow_fault_after_success: true`
and its success checks held before the fault became active (and still hold at
stop), the clean control is classified as `success` rather than `hard_fault`,
and the power-loss sweep interrupts the 4 crash-record MRAM writes to verify
startup recovery.

## Additional variants

- `profile_no_opt_in.yaml` (`app.bin`): runs the same post-success fault
  firmware with `allow_fault_after_success: false`. Must classify as
  `hard_fault`.
- `profile_vector_entry_spin.yaml` (`vector_entry_spin.bin`): keeps `VTOR` at
  `exec` (`0x10100000`), clears `CFSR`/`HFSR` and writes the crash record in
  `Fault_Handler`, and then branches to the shared `HardFault` vector entry
  instruction (`b .`) after checks hold with `allow_fault_after_success: true`.
  Must classify as `success`.
- `profile_followup_fault_before_checks.yaml`
  (`followup_fault_before_checks.bin`): boots cleanly on cycle 0 (writing a
  persistent marker word to MRAM), then faults on follow-up boot cycles before
  its memory checks hold. Must classify as `hard_fault` even with
  `allow_fault_after_success: true`.
- `profile_fault_before_checks.yaml` (`fault_before_checks.bin`): faults and
  spins in the fault handler before `SCHEDULER_FLAG` or `TICK_COUNT` are set.
  Must classify as `hard_fault`.
- `profile_fault_forges_checks.yaml` (`fault_forges_checks.bin`): faults before
  the checks hold, then writes `SCHEDULER_FLAG = 1` and `TICK_COUNT = 5` from
  inside the fault handler. Must still classify as `hard_fault` because the
  fault became active before the success checks held.

## Build

```sh
make -C examples/deliberate_crash_report
```
