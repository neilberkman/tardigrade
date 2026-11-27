# Getting Started

Get a first power-loss result from a fresh clone with one command. The demo
cuts a deliberately broken direct-copy update and a recovering update at a
small quick selection of operations. It succeeds only when the broken flow has
a finding and the recovering flow has none.

For pip installation, environment checks and generation of a starter profile from
firmware build artifacts, see [Install and check Tardigrade](installed-command.md).

## Run the demo

Clone the repository, enter it, and choose either Docker or a local Renode.

### Docker only

On Linux x86-64 or macOS arm64 with Docker Desktop:

```bash
./demo --docker
```

The command builds a checksum-pinned Linux x86-64 image. Docker Desktop runs
that image under emulation on Apple silicon. The image contains Renode 1.16.1
and hash-locked Python packages; it does not build firmware or download source
trees.

### Local Renode

If `renode-test` is on `PATH`:

```bash
./demo --local
```

Or give its location explicitly:

```bash
./demo --renode-test /path/to/renode-test
```

When the required Python packages are not already available, the command
installs their checksum-locked versions in `results/demo/.venv`. With no mode
flag, `./demo` prefers local Renode and falls back to Docker.

### Read the result

The final output is a short text summary. For each profile it reports the
number of points run and findings; for the first finding it also reports the
cut operation, address, and next-boot behavior. Detailed JSON reports and run
logs are written under `results/demo/`. The summary prints the command for
rendering either JSON report with `scripts/render_results_html.py`.

The demo uses these tracked inputs:

- `profiles/naive_bare_copy.yaml`: a deliberately broken direct-copy update.
- `profiles/demo_mcuboot_offset_upgrade.yaml`: a power-loss-only demo of an
  MCUboot offset-swap update that recovers.

The same command runs as an independent Linux CI job, so the demo is also a
smoke test.

## Run a profile directly

The rest of this guide walks you through invoking the underlying audit command.
By the end, you will have injected power-loss faults into a reference
bootloader and inspected its detailed report.

## Prerequisites

- **Python 3.10+**
- **pip** (for installing dependencies)
- **Renode** -- the emulation framework that tardigrade runs firmware under. Download the portable release from [renode.io/downloads](https://renode.io/downloads/) or install via your package manager. You need the `renode-test` binary on PATH or a known path to it.

## Installation

Clone the repository and install Python dependencies:

```bash
git clone https://github.com/neilberkman/tardigrade.git
cd tardigrade
pip install -r requirements.txt
```

The dependencies are minimal: `pyyaml`, `pyelftools`, and `capstone`.

If you downloaded Renode as a portable release, note the path to `renode-test` inside the extracted directory. You will pass it via `--renode-test`.

## Your first sweep

Tardigrade ships with a deliberately vulnerable bootloader under `examples/vulnerable_ota/`. The profile `profiles/naive_bare_copy.yaml` describes a worst-case OTA: direct copy from staging to exec with no validation or recovery. Power loss during the copy bricks the device.

Run it with `--quick` for a 3-point smoke test:

```bash
python3 scripts/audit_bootloader.py \
  --profile profiles/naive_bare_copy.yaml \
  --renode-test /path/to/renode-test \
  --output /tmp/my_first_sweep.json \
  --quick
```

Replace `/path/to/renode-test` with the actual path to your Renode test runner.

### What happens

1. **Calibration** -- tardigrade loads the bootloader ELF and firmware images into emulated NVM, runs the bootloader once without faults, and records every NVM write. This establishes the total write count and produces a write trace.

2. **Fault injection** -- for each fault point (with `--quick`, just three: first, middle, last), tardigrade replays the write trace up to that point, then simulates a power loss that truncates the write. The device is reset and the bootloader runs again from the faulted NVM state.

3. **Verdict** -- tardigrade checks whether the device booted to the correct slot with the correct firmware image. If the bootloader fails to recover, that fault point is classified as a brick.

Because `naive_bare_copy` has `expect.should_find_issues: true`, tardigrade expects to find bricks. A PASS verdict here means "yes, we found the issues we expected."

### Full sweep

Drop `--quick` to run the default heuristic sweep. Point count and runtime
depend on the trace, enabled fault families, target, and worker count:

```bash
python3 scripts/audit_bootloader.py \
  --profile profiles/naive_bare_copy.yaml \
  --renode-test /path/to/renode-test \
  --output /tmp/full_sweep.json
```

Add `--workers N` for parallelism across N Renode instances.

## Understanding results

The output JSON report contains a top-level verdict and detailed per-fault-point results.

### Verdict

Start with `summary.runtime_sweep.point_counts`. Its `kinds` entries separate
single-cut programs and erases, state-search cuts, explicit and grid two-cut
points, deeper cuts, multi-fault and cascading runs, instruction skips, read
faults, controls, and other configured mechanisms. Every entry reports
`requested`, `run`, `evaluated`, `skipped`, `infrastructure_error`, `timeout`,
`reused`, `missing`, and `issues`, with `skip_reasons` beside the skipped
count. `point_counts.calibration` says how many calibrated writes and erases
were cut directly, represented by heuristic or quick selection without a cut,
outside the planned range, or neither cut nor represented.
`point_counts.trace_replay_cross_checks` reports sampled replay checks as
`run`, `passed`, and `failed` separately from fault-point totals. A failed
check leaves its point in the matching kind's `run` count and records it as an
`infrastructure_error`, not an evaluated point or product issue.

These older fields remain for consumers of pre-existing reports. They cover
only the main runtime sweep and deliberately exclude its control, the
multi-fault follow-on, and the terminal-error instruction-skip campaign:

| Field                | Compatibility meaning                                                |
| -------------------- | -------------------------------------------------------------------- |
| `total_fault_points` | Main-runtime records where a fault reported that it fired             |
| `bricks`             | Main-runtime injected points with unrecoverable boot outcomes         |
| `issue_points`       | Main-runtime injected points with reportable non-success observations |
| `brick_rate`         | `bricks / total_fault_points` for the main runtime sweep               |

The CLI's top-level `verdict` begins with `PASS`, `FAIL`, or `INCONCLUSIVE`.
CI must treat only `PASS` as passing. The verdict evaluates the profile's
declared expectation:

- **PASS + `should_find_issues: false`**: The bootloader survived all faults. No bricks, no wrong-image boots, no invariant violations.
- **PASS + `should_find_issues: true`**: Issues were found, as expected for known-vulnerable code.
- **PASS + `expect.mode: exploratory`**: The complete hunt passed even with zero findings; use the default `regression` mode when findings are required.
- **FAIL**: Unexpected result -- either issues found when none expected, or no issues found when they were expected.
- **INCONCLUSIVE**: Required coverage, runtime, trace, or infrastructure evidence was unavailable or incomplete.

The GitHub Action adds a fail-safe security gate around this assertion. Its
default `verdict` passes only clean profiles; see the Action quick start in the
README for its separate `security-status` and regression mode.

### Per-fault-point detail

The `runtime_sweep_results` array contains one entry per fault point with:

- `fault_at` -- which NVM write was interrupted
- `boot_outcome` -- `success`, `wrong_image`, `memory_checks_unmet`, `no_boot`, `wrong_pc`, `hard_fault`, or `timeout`
- `fault_class` -- `recoverable`, `wrong_image`, `memory_checks_unmet`, `silent_corruption`, or `unrecoverable`

For a visual report, render the JSON as HTML:

```bash
python3 scripts/render_results_html.py \
  --input /tmp/my_first_sweep.json \
  --output /tmp/report.html
```

## Testing your own bootloader

To test your own bootloader, you need to write a YAML profile that describes your memory layout, slot addresses, firmware images, and success criteria. See [**Writing Profiles**](writing-profiles.md) for the complete guide.

The minimal profile structure:

```yaml
schema_version: 1
name: my_bootloader
description: "Power-loss resilience during firmware upgrade"

platform: platforms/cortex_m4_flash_fast.repl
flash_backend: faultFlash

bootloader:
  elf: path/to/bootloader.elf
  entry: 0x00000000

memory:
  sram: { start: 0x20000000, end: 0x20040000 }
  write_granularity: 4
  slots:
    exec: { base: 0x0000C000, size: 0x76000 }
    staging: { base: 0x00082000, size: 0x76000 }

images:
  exec: path/to/current_firmware.bin
  staging: path/to/new_firmware.bin

success_criteria:
  vtor_in_slot: exec

fault_sweep:
  mode: runtime
  evaluation_mode: execute
  max_writes: auto

expect:
  should_find_issues: false
```

### Choosing a platform

Common platform `.repl` files (see [Writing Profiles](writing-profiles.md#choosing-a-platform) for the full matrix with backend details and write granularity):

| Platform file                         | NVM type          | Use for                         |
| ------------------------------------- | ----------------- | ------------------------------- |
| `platforms/cortex_m4_flash_fast.repl` | NOR flash (NVMC)  | nRF52, generic Cortex-M4 flash  |
| `platforms/stm32f4.repl`              | STM32F4 NOR flash | STM32F4xx parts                 |
| `platforms/stm32h743_tardigrade.repl` | STM32H7 dual-bank | STM32H7xx parts                 |
| `platforms/cortex_m0_nvm.repl`        | Generic NVM       | Custom NVM or MRAM-like storage |

See [Writing Profiles -- Choosing a platform](writing-profiles.md#choosing-a-platform) for the full table.

### What you need from your bootloader

- **An ELF binary** of the bootloader (with symbols if possible -- enables hash bypass optimization).
- **Raw firmware binaries** for each slot (current and update images).
- **Slot addresses and sizes** from your linker script or partition table.
- **Entry point address** (usually the base of the boot partition or 0x0).

## GitHub Action

Tardigrade can run in CI via a reusable GitHub Action:

```yaml
- id: tardigrade
  uses: neilberkman/tardigrade@<reviewed-commit-sha>
  with:
    profile: profiles/your_profile.yaml
    quick: false
    workers: 2
```

The action outputs `verdict`, `brick-rate`, `point-counts-json`, and
`report-path`. See [`action.yml`](../action.yml) and the
[README](../README.md#quick-start) for all inputs and outputs.

Profile assets are resolved against the caller workspace by default. If the
profile's relative paths start from a subdirectory, pass that directory as
`asset-root`. When overriding `renode-url`, also provide the archive's exact
`renode-sha256`; the action verifies it before extraction. The Action enables
strict profile validation, rejecting unknown keys and missing observable
success criteria.

The bundled runtime supports Linux x86-64 runners. It uses Renode's verified
portable .NET archive and a temporary virtual environment, so its pinned
Python packages do not alter later caller steps.

Treat every profile and referenced asset as trusted executable input. Platform
definitions, setup scripts, boot hooks, and invariant providers can execute
Renode commands or host Python. Use reviewed, open-source revisions rather than
untrusted pull-request files or artifacts.

## Common issues

**"renode-test not found" or connection errors**

Ensure `--renode-test` points to the actual `renode-test` binary, not the `renode` binary. If using a portable download, it is inside the extracted directory. If Renode is installed system-wide, it may be at `/usr/bin/renode-test` or similar.

**Calibration timeout**

The bootloader did not complete its update within the emulation time budget. Check that your `fault_sweep.run_duration` is long enough for the bootloader to finish copying firmware. Increase it in the profile YAML (value is in seconds, as a string: `run_duration: "1.0"`).

**"No NVM writes detected" or zero write count**

The bootloader ran but did not write to the tracked flash backend. This usually means one of:

- `flash_backend` in the profile does not match the sysbus peripheral your bootloader actually writes to.
- The bootloader's entry point is wrong and it never reached the update code path.
- The firmware images are missing or at wrong addresses, so the bootloader has nothing to copy.

Double-check your `flash_backend`, `bootloader.entry`, and `memory.slots` addresses against your linker script.

**"Control run failed"**

The unfaulted (no-fault) run did not boot successfully. This means the bootloader cannot complete a normal update even without faults. Fix your profile configuration (images, addresses, entry point) before running a fault sweep.
