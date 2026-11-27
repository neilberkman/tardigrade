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
