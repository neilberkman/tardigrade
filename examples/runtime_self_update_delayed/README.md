# Delayed-liveness direct-reset self-update fixture

This Cortex-M0+ fixture models a runtime self-update target with two properties
that exposed slice-dependent clean-control outcomes:

1. `boot.elf` lives at `0x10200000` while `mramStorage` (`0x10100000`) is
   aliased at `0x00000000` for hardware reset vector fetch. Initial boot enters
   `boot.elf` and jumps to `exec`, whereas `SYSRESETREQ` resets hardware `VTOR`
   to `0x00000000` and restarts the CPU directly from the application's vector
   table at `0x10100000` without re-entering `bootloader.entry`.
2. Pre-reset update work lasts ~165 ms of emulated time before `SYSRESETREQ`,
   and post-reset start-up delays ~37 ms of emulated time before raising the
   progress counter at `0x20000200` to `>= 1`.

Build the fixture with:

```sh
make -C examples/runtime_self_update_delayed
```

`never_ready.bin` and `profile_checks_unmet.yaml` provide a negative variant
whose post-reset image hash matches `staging` while the progress counter stays
at `0` until the run budget ends.
