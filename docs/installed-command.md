# Install and check Tardigrade

Python 3.10 or later can install the command from a local checkout or a Git URL.
Activate a virtual environment and choose one installation command.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install /path/to/tardigrade
# Or, for a revision containing pyproject.toml
pip install 'git+https://github.com/neilberkman/tardigrade.git@REVISION'
tardigrade doctor
```

`doctor` prints the Python executable, the installed Renode version and the Docker
server version. Set `RENODE_TEST` to the executable inside a Renode portable
distribution if it is outside your PATH. The supported versions are 1.17.0 and
1.16.1. Exit status 0 means either a supported local runner or a Docker daemon
answered. A local audit or clean control requires the Renode runner.

## Generate a starter profile

Pass the loader ELF, the current primary image, and the image intended to replace
it. For Zephyr, use the **bootloader** build directory containing
`zephyr/zephyr.dts` and `zephyr/.config`. For the real NuttX nucleo-h743zi
nxboot target, the public target builder
saves the loader's generated `.config` beside `nxboot-loader.elf`. When using an
older build, supply the directory containing the loader configuration.

```sh
tardigrade init --bootloader build/zephyr/zephyr.elf \
  --primary release/current.bin --update release/update.bin \
  --build-dir build --output audit/starter.yaml --control
```

The generator looks beside the ELF for build metadata when `--build-dir` is
omitted. It also recognizes the exact two tracked nRF52840 and STM32F429
MCUboot move ELFs produced by `scripts/build_mcuboot_head_matrix.sh`. Those
ELFs contain their slot IDs, partition table and trailer magic. The build recipe
identifies the board and swap mode. Renaming these artifacts preserves detection.

Zephyr slot labels come from the chosen internal flash's fixed partitions.
The generator checks the flash map compiled into the ELF when present. The
chosen SRAM and flash write block supply the memory settings. A move or scratch
upgrade starts at the staging base. For offset swap, the generator prepares a staging-slot image with one erased
sector before the header. Flash geometry determines the sector length. A
correctly padded staging slot can also be supplied directly. Compressed images, RAM-load images, multi-image upgrades
and unknown boards need a hand-written profile.

For NuttX, the compiled three-entry OTA table must agree with all three
configured slot offsets, sizes and device assignments. The platform uses the
repository's STM32H743/H753 board model. The nxboot header supplies the vector
offset, version marker and CRC. The primary and update must target the same
platform ID.

A completed starter uses an execute-mode sweep with zero fault points. VTOR
must reach the primary slot's application vectors. Ordinary MCUboot starters
also require the staged image digest. A version marker distinguishes an
installed nxboot or offset image.

The output YAML uses relative paths. Inputs outside its parent directory are
copied into a sibling `.inputs` directory for use on another machine. Use a
fresh output name for each generation. An incomplete layout produces a marked
draft, a diagnostic, and exit status 2. Malformed input headers fail before
publication. A completed profile passes the strict loader before any boot.

## Run the commands

```sh
tardigrade audit --profile audit/starter.yaml --output audit/control.json
tardigrade report --input audit/control.json --output audit/control.html
tardigrade demo --output-dir results/demo
```

`audit` runs the profile-driven audit runtime (`scripts/audit_bootloader.py`,
`scripts/run_runtime_fault_sweep.py`, `tests/ota_fault_point.robot` and the
packaged platforms, peripherals and target probes/invariants). It accepts the
same flags as `scripts/audit_bootloader.py` (such as `--quick`, `--workers`,
`--fault-start` and `--fault-end`), plus an optional `--timeout` wall-clock
budget in seconds. `init --control` runs the same clean-control path on the
generated starter profile and writes `<output>.control.json`.

`demo` runs the broken-versus-recovering power-loss demo directly from the
installed package without requiring a checkout. The existing `./demo --docker`
command in a checkout remains available for Docker-only hosts.

## Open a failing point in GDB

`tardigrade debug` (or `python3 scripts/debug_point.py` in a checkout) takes an
audit report (`--report` / `--input` / `--sarif`), a state-search checkpoint
(`*.checkpoint.json`), or a SARIF reproduction block (`--reproduction`) together
with a `--point` or `--state` selector, rebuilds the exact persistent state in
Renode (flash or MRAM bytes, uncorrectable or torn-word marks, and peripheral
state), verifies that the restored state matches any recorded state identity,
pre-recovery snapshot, checkpoint chunks, and failure-explanation byte ranges or
ECC marks, starts Renode's GDB server on `--port` (default `3333`), prints the
exact `gdb` command with the profile's ELF and port, and keeps Renode running
until the debugger detaches or `--timeout` expires.

### Supported NVM backends

`tardigrade debug` supports every execute-mode NVM backend in the audit runtime:

- **Fast internal flash controllers and interceptors (`kind: fast`)**:
  `NRF52NVMC` (`faultFlash`), `STM32F1FlashController`,
  `STM32F4FlashController`, `STM32F4FastFlash`, `STM32H7FlashController`,
  `STM32H7FastFlash`, `STM32L4FlashController`, `An521NvmInterceptor`, and
  `CFIFlash`.
- **External NVM models (`kind: fast`)**: `SPINORFlash` (`spiNor`, both
  standalone SPI NOR on `nrf52840_external_nvm.repl` and companion-backed SPI
  NOR + internal `NRF52NVMC` sharing a unified `MappedMemory` and `FaultTracker`
  on `nrf52840_mcuboot_spi_nor.repl`) and `I2CEEPROM` (`i2cEeprom`, 24-series
  I2C EEPROM on `nrf52840_external_nvm.repl`).
- **MRAM models (`kind: mram`)**: `MappedMRAMTracker` (`mramTracker`, including
  4/8/16-byte program units, torn-word modes, uncorrectable ECC word marks, and
  deferred tracking-base snapshots) and execute-mode `NVMemory` (`mram` on
  `cortex_m0_mram.repl`).
- **Controller-backed hybrid NVM (`kind: slow`)**: `NVMemoryController` and
  `GenericNvmController` (`nvm_ctrl` with backing `NVMemory` on hybrid
  platforms such as `cortex_m0_hybrid_nvm.repl`, `cortex_m0_otp.repl`, and
  `cortex_m0_traceless.repl`, where code executes from `MappedMemory`).
- **Auxiliary persistent and bus-fault peripherals**: `OTPMemory`
  (`otp_peripheral` fuse state preserved across resets via
  `TestSnapshot`/`TestRestore`) and `I2CFaultProxy` (`i2c_fault_peripheral`
  single-boot bus faults with `--stop-at cut` or `--stop-at first-fault`).

Profiles with `fault_sweep.evaluation_mode: state` (including non-hybrid
`NVMemory` platforms where code cannot execute in `execute` mode) are refused
with an explicit diagnostic because `state` mode simulates word copies without
CPU execution.

Choose where execution pauses before GDB attaches with `--stop-at`:

- `recovery-reset` (default): replay every cut in the point or chain, restore
  the resulting persistent state, and stop at the recovery reset vector before
  the recovery boot executes.
- `cut`: replay any earlier cuts in a chain and stop at the instruction where
  the final cut fires.
- `first-fault`: replay the cuts, boot into recovery (or the faulted single
  boot), and stop at the first CPU exception, lockup, uncorrectable MRAM read,
  or terminal fault loop.

### Worked session

Run an audit on the MRAM recovery state-search example and open failing state
`601330377439` (`write[2]@0x10100110 -> write[0]@0x10100100`) at the recovery
reset vector:

```sh
tardigrade audit \
  --profile examples/phase2_mram_parity/profile_deferred_state_search_16_uncorrectable.yaml \
  --output results/mram_state_search.json

tardigrade debug \
  --report results/mram_state_search.json \
  --state 601330377439 \
  --stop-at recovery-reset \
  --port 3333
```

`tardigrade debug` rebuilds the two-cut state, verifies its SHA-256 persistent
state identity (`601330377439036885f5929df921e7c6de4d7f4a9e990de02ec0b58ccbf7d0fd`),
and prints the attachment command:

```text
arm-none-eabi-gdb examples/phase2_mram_parity/firmware_deferred.elf -ex "target remote :3333"
[debug] stop_at=recovery-reset port=3333 pc=0x10000024 sp=0x20002000 state_identity=601330377439036885f5929df921e7c6de4d7f4a9e990de02ec0b58ccbf7d0fd
```

Attach with `arm-none-eabi-gdb` (interactively or with `-batch` / `--ex`), break
at `tracking_gate`, step into the recovery check, inspect registers and
both torn MRAM words (`0x10100108` and `0x10100110`), and continue to the
`no_boot` verdict:

```sh
arm-none-eabi-gdb -batch examples/phase2_mram_parity/firmware_deferred.elf \
  -ex "target remote :3333" \
  -ex "break tracking_gate" \
  -ex "continue" \
  -ex "stepi" \
  -ex "info registers pc sp lr r0 r1" \
  -ex "x/8wx 0x10100100" \
  -ex "continue" \
  -ex "detach" \
  -ex "quit"
```

Example debugger output and post-detach verdict:

```text
Reset_Handler () at firmware.c:85
Breakpoint 1, tracking_gate () at firmware.c:77
0x10000040 in Reset_Handler () at firmware.c:121
pc             0x10000040          0x10000040 <Reset_Handler+28>
sp             0x20001fe0          0x20001fe0
lr             0x10000041          268435521
r0             0x0                 0
r1             0x0                 0
0x10100100:     0x56414c31      0x54524754      0x31444c4f      0x54524754
0x10100110:     0x00000000      0x00000000      0x444f4e45      0x50524f47

Program received signal SIGINT, Interrupt.
Reset_Handler () at firmware.c:127
[debug] verdict: boot_outcome=no_boot boot_slot=None fault_class=unrecoverable
```

You can also pass `-ex` commands directly to `tardigrade debug` via repeatable
`--ex` flags (or pass a SARIF finding's reproduction block directly via
`--reproduction`):

```sh
tardigrade debug \
  --report results/pr3011_move_broken.json \
  --point "power_loss[3] → power_loss[0]" \
  --stop-at recovery-reset \
  --ex "break main" \
  --ex "continue" \
  --ex "stepi" \
  --ex "info registers pc sp lr" \
  --ex "x/4wx 0x00024ff0" \
  --ex "continue"
```
