# Runtime self-update terminal example

This Cortex-M0+ fixture models a ROM that branches to an executable slot and
an application that copies a staged image over itself from SRAM before issuing
`SYSRESETREQ`. After reset, the updated application relocates its vector table
to SRAM and publishes scheduler and tick liveness values.

The profile uses `success_criteria.terminal_after_reset: true`. Execution in
the executable slot before the copy is therefore not a successful terminal;
the runtime must observe an in-run reset and then satisfy the image hash and
memory checks.

Build the fixture with:

```sh
make -C examples/runtime_self_update
```

`no_reset.bin` and `hung_update.bin` provide negative variants for tests that
must not reach the success terminal. Their control-only profiles are
`profile_no_reset.yaml` and `profile_hung_update.yaml`.
