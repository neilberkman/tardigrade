# tardigrade

Tardigrade tests whether firmware survives losing power in the middle of an update. It runs your real bootloader binary in the [Renode](https://renode.io/) emulator, cuts power at individual flash writes and erases, boots the device again, and checks that it still boots the right image.

It was built for Cortex-M bootloaders: MCUboot, NuttX nxboot, TF-M BL2 and wolfBoot. It also tests storage code such as Zephyr NVS, and besides power loss it can inject bit corruption, failed writes, skipped instructions, and I2C and OTP faults.

## Try it

You need Docker or a local Renode.

```bash
git clone https://github.com/neilberkman/tardigrade.git
cd tardigrade
./demo
```

`./demo` uses `renode-test` if it is on your `PATH` and falls back to Docker; `--docker` and `--local` force one or the other. It cuts power during two updates, a deliberately broken copy-in-place updater and an MCUboot swap that recovers, and it passes only if the first has findings and the second has none. For the first finding it prints the operation that was cut, the address, and what the next boot did. The full reports go to `results/demo/`.

## Test your own firmware

You need Python 3.10 or later and Renode 1.16.1 or 1.17.0. From the clone:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .
tardigrade doctor
```

A profile describes one test. It is a YAML file with the memory layout, the firmware images, and what counts as a successful boot. For MCUboot built with Zephyr, and for NuttX nxboot, `tardigrade init` writes a starter profile from your build output and boots one clean update to check it:

```bash
tardigrade init --bootloader build/zephyr/zephyr.elf \
  --primary current.bin --update update.bin \
  --build-dir build --output starter.yaml --control
```

The starter runs no fault points (`fault_sweep.max_writes: 0`). Set that to `auto` to turn on the power-loss sweep, then run the audit and render the report:

```bash
tardigrade audit --profile starter.yaml --output report.json
tardigrade report --input report.json --output report.html
```

For other bootloaders, and for boards `init` does not recognise, you write the profile by hand. [Writing profiles](docs/writing-profiles.md) documents every field, and `profiles/` has about 190 to copy from.

### In CI

```yaml
- uses: neilberkman/tardigrade@<reviewed-commit-sha>
  with:
    profile: path/to/your/profile.yaml
```

The Action runs on Linux x86-64 runners. Its `verdict` output is `PASS` only when no issues were found and the evidence is complete. [GitHub Action](docs/github-action.md) lists the inputs and outputs. A profile can run Renode commands and host Python through its setup scripts and hooks, so do not run one taken from an untrusted pull request. Audits can also write JUnit XML, SARIF and HTML ([report formats](docs/report-formats.md)).

### Guides

- [Getting started](docs/getting-started.md) walks through the demo and a first sweep.
- [Install and commands](docs/installed-command.md) covers `doctor`, `init`, `audit`, `debug` and `export-repro`.
- [Writing profiles](docs/writing-profiles.md) is the profile reference.

## Results

The NuttX nxboot failure below is the one tardigrade found. Every other bug named in this section was found and fixed by other people. Tardigrade reproduces those after the fact, as a check that it catches real failures.

### Found by tardigrade

A campaign against upstream NuttX nxboot found that at 92 of 94 tested power cuts the bootloader jumped into partially written firmware. The fixes went into NuttX in two pull requests, both merged in March 2026. [apache/nuttx#18552](https://github.com/apache/nuttx/pull/18552) fixed a flash translation layer that ignored `O_DIRECT` and buffered writes in RAM. [apache/nuttx-apps#3428](https://github.com/apache/nuttx-apps/pull/3428) added flush barriers to nxboot and made it check the image CRC, where before it checked only the header.

### Contributed upstream

Tardigrade's torn-write power-loss model was proposed to MCUboot in [#2648](https://github.com/mcu-tools/mcuboot/pull/2648) and merged into MCUboot's simulator with [#3011](https://github.com/mcu-tools/mcuboot/pull/3011) in November 2026.

### Known bugs it reproduces

MCUboot and Zephyr developers reported and fixed each of these. The repository keeps them as test cases, with one profile for the build before the fix and one for the build after. The first has findings and the second is clean.

| Upstream bug | What goes wrong before the fix |
| --- | --- |
| MCUboot [#2100](https://github.com/mcu-tools/mcuboot/pull/2100), swap-move | Revert magic is left in a bad state; the wrong image boots or the device bricks |
| MCUboot [#2109](https://github.com/mcu-tools/mcuboot/pull/2109), swap-scratch | The header is reloaded from the wrong slot after an interrupted swap; the device bricks |
| MCUboot [#2199](https://github.com/mcu-tools/mcuboot/pull/2199), swap-move | A revert never completes. No power cut is involved; a state probe catches it on a clean boot |
| MCUboot [#2206](https://github.com/mcu-tools/mcuboot/pull/2206), swap-scratch | A trailer erase is skipped across sectors and a rejected image boots |
| MCUboot [#2214](https://github.com/mcu-tools/mcuboot/pull/2214), swap-offset | An off-by-one sector index makes the bootloader refuse the upgrade |
| MCUboot [#3009](https://github.com/mcu-tools/mcuboot/issues/3009), swap-move | After a second power loss the revert is lost and the unconfirmed image keeps booting |
| MCUboot [#3010](https://github.com/mcu-tools/mcuboot/issues/3010), swap-offset | After repeated power loss the device asserts on every boot |
| Zephyr NVS, commit `c200ff1e` | A torn metadata entry at the end of a sector makes the mount fail |

The recovery-state search finds #3009 without anyone choosing the pair of cuts by hand. The pairs for #2100, #2206, #2214 and #3009 run in CI. [Findings and validation history](docs/findings.md) has the point counts, the commits, and two candidate pairs that were examined and dropped.

## What a pass means

- Tardigrade gives a clean verdict only when calibration shows the update moving slot data. If the update never ran, the verdict is `INCONCLUSIVE`.
- Where it computes a flash state from a recorded trace instead of running to the cut, it also runs a sample of those points with live injection (every 100th by default) and compares every persistent byte.
- A point that times out or hits an infrastructure error is an incomplete observation. The report counts it separately and never as a recovery.

## What it covers

| | |
| --- | --- |
| Power loss | Cuts before any flash program or erase. The profile picks what the interrupted operation leaves behind: the old bytes, the new bytes, a subset of the bits, a half-finished erase, or a word that fails ECC on read (STM32L4 and MRAM). |
| Repeated power loss | More cuts during the recovery boots. The [recovery-state search](docs/writing-profiles.md#recovery-state-search) follows each recovery and cuts it again, skips flash states it has already booted, and can be sized in advance, resumed, and split across machines. |
| Other faults | 28 fault types in all, among them bit corruption, silent write failure, write rejection, write disturb, driver errors, instruction skip, and I2C and OTP faults. |
| Buffered storage | A write-back mode for storage stacks that hold writes in RAM until a flush. A power cut discards whatever was not yet committed. |
| Resets | Power loss, software reset and watchdog reset are modelled separately, with reset-cause registers, backup registers and retained RAM on nRF52840, STM32F1, STM32F4 and STM32H7. |
| Memory models | nRF52840 NVMC; STM32F1, F4, L4 and H7 flash; MRAM; SPI NOR; I2C EEPROM; CFI flash; OTP fuses; a generic command-register controller. |
| Targets | MCUboot (swap-move, swap-scratch and swap-offset, on nRF52840 and STM32), NuttX nxboot, TF-M BL2, wolfBoot, and Zephyr storage on SPI NOR and EEPROM. See [supported targets](docs/targets.md). |
| Verdicts | Which slot booted, whether its bytes match an approved image, and whether the CPU is executing inside it. State probes and invariants check trailer state, rollback counters and other persistent fields. |
| Reports | JSON, JUnit XML, SARIF and HTML. Each report also lists its evidence against paragraphs of UN R156 and the EU Cyber Resilience Act, without making a legal determination ([details](docs/software-update-clause-evidence.md)). |

### When a point fails

- The report explains the failure: the operation that was cut and the function that issued it, how the flash differs from a passing point, and where the recovery boot ended up.
- `tardigrade debug` rebuilds the failing flash state in Renode and opens a GDB server on it.
- `tardigrade bisect` finds the commit where a point's verdict changes ([guide](docs/verdict-bisect.md)).
- `tardigrade export-repro` writes a bundle with the flash state, the firmware (or a script that builds it) and a run script. It reproduces the failure on a machine that has Docker or Renode and no tardigrade.
- With recovery coverage turned on in the profile, the report lists the bootloader basic blocks that no recovery boot reached.

## How it works

1. Run the update once without faults and record every flash program and erase.
2. Choose the cut points: all of them, a sample weighted toward bootloader metadata, or one per distinct flash state.
3. For each point, rebuild the flash as the cut would leave it and reset the device.
4. Let the real bootloader binary boot from that state.
5. Judge the outcome against the profile's success criteria and invariants.
6. Optionally cut again during the recovery boot, and repeat.

[How tardigrade works](docs/how-it-works.md) covers the fault model, every fault type, and how results are classified.

## More tools

The repository also has analyzers that run without the emulator: an update-protocol checker, authenticated-content and pre-authentication bounds campaigns, and a reviewed-versus-signed authorization analyzer. Two bridges turn fuzzer crashes and CBMC counterexamples into profiles. See [security analyzers and bridges](docs/analyzers.md).

## Limitations

- Power loss is modelled per write and erase operation. There is no analog brownout simulation.
- The fault sweep runs only on Cortex-M targets.
- Some fault types only run on a particular backend. Read faults work where the backend intercepts CPU reads, I2C faults go through the I2C proxy, and OTP faults go through the OTP model.
- A semantic bug that does not change the boot outcome is caught only if the profile has a probe or invariant for it.
- The static analyzers check a model you declare. They do not prove that the model matches deployed firmware.

## Repository and license

[Repository layout and CI workflows](docs/repository-layout.md) says where things live.

Apache 2.0. See [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

The name: tardigrades survive vacuum, radiation and temperature extremes.
