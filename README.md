# tardigrade

Fault-injection resilience auditing for embedded bootloaders under [Renode](https://renode.io/).

## What it does

Profile-driven fault injection that sweeps every NVM write point during a firmware update, injects faults (power loss, bit corruption, interrupted erase), and verifies the bootloader recovers correctly. Works with any Cortex-M firmware under Renode. You bring your ELF and binary images, define success criteria in a YAML profile, and tardigrade tells you whether your OTA path survives.

## Quick start: GitHub Action

The fastest integration path is the reusable GitHub Action:

```yaml
- id: tardigrade
  uses: neilberkman/tardigrade@v1
  with:
    profile: profiles/mcuboot_swap_current.yaml
    quick: true # smoke test; set false for full heuristic sweep
    workers: 2
```

Outputs: `verdict` (PASS/FAIL), `brick-rate`, `report-path`.

In CI, upload `report-path` as an artifact so failures include the full per-point diagnostics:

```yaml
- name: Upload tardigrade report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: tardigrade-report
    path: ${{ steps.tardigrade.outputs.report-path }}
```

The JSON report includes failure context such as `fault_window`, and for `no_boot` points in execute mode, `postmortem_partition_dump` and `resume_trace`.

See [`action.yml`](action.yml) for all inputs and outputs.

## Quick start: local

Prerequisites: `python3`, `pyyaml`, `renode-test` on PATH.

```bash
python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_pr2100_broken.yaml \
  --renode-test /path/to/renode-test \
  --output results/report.json
```

Add `--quick` for a smoke test (3 fault points, seconds). Add `--workers 4` for parallel sweep.

## Run modes

| Mode       | Flag              | Points | Time    | Use case        |
| ---------- | ----------------- | ------ | ------- | --------------- |
| Quick      | `--quick`         | 3      | seconds | smoke test      |
| Heuristic  | _(default)_       | ~1K    | 2-4 min | CI gate         |
| Exhaustive | `--fault-start 0` | ~15K   | 15 min  | full validation |

Heuristic mode uses write-trace analysis to prune the ~15K write points down to ~1K high-value targets (trailer boundaries, slot transitions) with no loss of defect coverage.

## Fault injection model

```mermaid
flowchart TD
    subgraph setup["Setup"]
        A["Load profile YAML"] --> B["Calibration: run firmware,<br/>count total NVM writes"]
        B --> C["Generate fault point list"]
    end

    C --> D

    subgraph pf["Per fault point"]
        D["Phase 1: run firmware to write N"] --> E{"Fault type"}
        E -->|power_loss| F["Truncate write N<br/>(partial word)"]
        E -->|bit_corruption| G["Flip random bits<br/>in write N (NOR physics)"]
        E -->|interrupted_erase| H["Partial page erase<br/>(first half only)"]

        F --> I["Faulted NVM state"]
        G --> I
        H --> I

        I --> J{"evaluation_mode"}

        J -->|state| K["Infer boot outcome<br/>from NVM contents"]
        J -->|execute| L["Phase 2: reset CPU,<br/>recovery boot"]

        L --> M{"Platform path"}
        M -->|"NVMC<br/>(flash_fast)"| N["Restore flash snapshot<br/>+ reload ELF"]
        M -->|"NVMemory<br/>(slow path)"| O["Storage persists<br/>across reset"]
        M -->|"Hybrid<br/>(nvm_hybrid)"| P["Metadata persists,<br/>reload code + slot images"]

        N --> Q["Boot from faulted state"]
        O --> Q
        P --> Q
        Q --> R["VTOR polling<br/>captures boot slot"]
    end

    K --> S
    R --> S
    S["Classify outcome + failure class"] --> T["Aggregate into results JSON"]
```

**Flow:**

1. Load profile YAML. Calibration pass counts total NVM writes and records a write trace.
2. Heuristic pruning classifies writes into tiers (trailer=exhaustive, boundary=dense, bulk=sparse) to reduce sweep points ~10x.
3. For each fault point, Phase 1 replays the write trace up to write N and injects the fault. Trace replay eliminates O(N^2) prefix re-emulation.
4. In `state` mode, boot outcome is inferred from NVM contents. In `execute` mode, Phase 2 resets the CPU and performs a recovery boot.
5. Results are classified (`success`, `wrong_image`, `no_boot`, `wrong_pc`) plus a failure class (`recoverable`, `wrong_image`, `silent_corruption`, `unrecoverable`) and aggregated into the final verdict.

For `no_boot` outcomes in runtime execute mode, the result also includes:

- a post-mortem partition dump (slot header/trailer content, erased-sector map, trailer flag bytes)
- an optional second-boot resume trace with per-NVM-operation PC samples

**Fault types:** `power_loss` (partial write), `bit_corruption` (NOR-physics bit flips), `interrupted_erase` (partial page erase), `multi_sector_atomicity` (cross-page partial erase), `silent_write_failure`, `write_rejection` (dropped write), `write_disturb` (adjacent-word corruption), `wear_leveling_corruption` (extra spurious write), `reset_at_time`.

**Evaluation modes:** `state` (fast inference from NVM contents) or `execute` (full CPU recovery boot).

## Included bootloader families

Six architectures, from worst-case patterns to hardened OSS boot flows:

| Family         | Architecture                        | Brick rate | Why                                          |
| -------------- | ----------------------------------- | ---------- | -------------------------------------------- |
| `naive_copy`   | Copy staging to exec, no fallback   | ~100%      | Any mid-copy fault bricks; no recovery path  |
| `vulnerable`   | Copy-in-place with pending flag     | ~88%       | Overwrites only image; mid-copy fault bricks |
| `nxboot_style` | Three-partition copy, CRC, recovery | ~0%        | Recovery slot enables revert on corruption   |
| `esp_idf`      | Dual otadata CRC + rollback FSM     | varies     | Clean-room model of ESP-IDF OTA selection    |
| `mcuboot`      | Swap-move / swap-scratch on nRF52   | varies     | Real MCUboot ELFs from upstream CI           |
| `riotboot`     | Slot selection via header metadata  | varies     | Standalone RIOTboot model                    |

68 profiles total, including intentional-defect variants for self-testing.

## OSS validation

Retroactive validation against known MCUboot bugs, proving the tool catches these bug classes:

| PR                                                      | Bug                                                  | Algorithm    | Broken               | Fixed      |
| ------------------------------------------------------- | ---------------------------------------------------- | ------------ | -------------------- | ---------- |
| [#2100](https://github.com/mcu-tools/mcuboot/pull/2100) | Revert magic: `BOOT_MAGIC_BAD` left in REVERT row    | swap-move    | 3 bricks (9.7%)      | 0 bricks   |
| [#2109](https://github.com/mcu-tools/mcuboot/pull/2109) | Header reload from wrong slot after interrupted swap | swap-scratch | 19 bricks (33.3%)    | 0 bricks   |
| [#2199](https://github.com/mcu-tools/mcuboot/pull/2199) | Stuck revert: primary REVERT trailer never cleared   | swap-move    | 1 wrong_image (100%) | 0 failures |

Additional differential pairs for PRs [#2205](https://github.com/mcu-tools/mcuboot/pull/2205), [#2206](https://github.com/mcu-tools/mcuboot/pull/2206), and [#2214](https://github.com/mcu-tools/mcuboot/pull/2214) are included as profiles.

## Profile YAML schema

Profiles define everything the audit needs. Annotated example:

```yaml
schema_version: 1
name: mcuboot_pr2100_broken
description: "MCUboot swap-move BEFORE PR #2100 fix"

platform: platforms/cortex_m4_flash_fast.repl # Renode platform definition

bootloader:
  elf: results/oss_validation/assets/oss_mcuboot_pr2100_broken.elf
  entry: 0x00000000

memory:
  sram: { start: 0x20000000, end: 0x20040000 }
  write_granularity: 4
  slots:
    exec: { base: 0x0000C000, size: 0x76000 }
    staging: { base: 0x00082000, size: 0x76000 }

images:
  exec: results/oss_validation/assets/zephyr_slot1_padded.bin
  staging: results/oss_validation/assets/zephyr_slot0_padded.bin

pre_boot_state: # Seed NVM with specific state
  - { address: 0x00081FF0, u32: 0xF395C277 } # MCUboot trailer magic
  # ...

success_criteria:
  marker_address: 0x0000C014 # Check image header version
  marker_value: 0x00000001 # Expected value after revert

fault_sweep:
  mode: runtime
  evaluation_mode: execute
  max_writes: auto
  hash_bypass_symbols: ["bootutil_img_validate"] # Patch out crypto in emulation

expect:
  should_find_issues: true # Self-test: tool must find bricks
```

Key fields: `platform`, `bootloader`, `memory`, `images`, `success_criteria`, `fault_sweep`, `expect`. See [`scripts/profile_loader.py`](scripts/profile_loader.py) for the full schema.

## Performance

Optimizations that make profile sweeps feasible on CI runners:

- **Trace replay** -- calibration records every write address+value; sweep replays from trace (~20ms) instead of re-emulating Phase 1, eliminating O(N^2) prefix cost
- **Cached flash restore** -- single `WriteBytes` call per fault point instead of per-page erase+load
- **VTOR early exit** -- polling detects boot slot quickly; HardFault confirmation avoids false negatives
- **Hash bypass** -- patches out crypto validation in emulation (`hash_bypass_symbols` in profile)
- **Parallel workers** -- `--workers N` splits fault points across N Renode instances
- **Heuristic pruning** -- write-trace classification reduces ~15K points to ~1K with no coverage loss
- **Interleaved distribution** -- round-robin point assignment balances load across workers

## Execute-mode hardening

In `execute` mode, Phase 2 performs a full CPU recovery boot from faulted flash:

- **VTOR polling**: after each time slice, the VTOR register (`0xE000ED08`) is polled to detect which slot the bootloader jumped to. SCB registers are CPU-private, so watchpoints don't fire -- polling is required.
- **5ms confirmation window + CFSR HardFault check**: after a VTOR change is detected, a confirmation window verifies the boot is stable and checks for HardFault via the Configurable Fault Status Register.
- **Sticky fault signal**: `FaultEverFired` stays set once any fault fires, surviving subsequent writes and resets. Explicitly cleared only when a new iteration is armed.
- **Write stabilization early-exit**: `run_until_done` exits when writes stabilize across multiple time slices, reducing per-point runtime without losing coverage.
- **No-boot introspection hooks**: when a point ends in `no_boot`, tardigrade can emit a partition post-mortem dump and replay a second recovery boot with per-operation PC tracing to show where resume logic stalls.

## Report structure

Primary report fields:

- `summary.runtime_sweep`: aggregate outcomes (`failure_outcomes`), aggregate failure classes (`failure_classes`), brick rate, control result, and timing.
- `runtime_sweep_results[]`: per-point records with `fault_type`, `boot_outcome`, `fault_class`, `signals`, and optional diagnostics.
- `clean_trace`: calibration-trace metadata when available (write/erase counts and how many points were window-annotated).

Per-point diagnostics are attached only when relevant:

- `fault_window`: clean-run context around the injected operation (`before`, `at`, `after`) so you can map a failing point to adjacent NVM operations.
- `postmortem_partition_dump`: for `no_boot`, slot header/trailer raw data plus decoded structure (header validity, trailer flags, erased-sector map).
- `resume_trace`: for `no_boot`, a second boot from the faulted flash snapshot with per-NVM-operation PC samples.

## CI workflows

| Workflow                   | Trigger           | What it does                                              |
| -------------------------- | ----------------- | --------------------------------------------------------- |
| `ci.yml`                   | push, PR          | Robot suites + sharded self-test                           |
| `profile-sweep.yml`        | workflow_dispatch | On-demand single-profile sweep with optional exhaustive mode |
| `action-validation.yml`    | push, PR          | Validates the reusable GitHub Action                      |
| `oss-validation.yml`       | workflow_dispatch | Runs OSS bootloader profiles                              |
| `renode-latest-canary.yml` | workflow_dispatch | Tests against latest Renode build                         |

## Repository layout

```text
tardigrade/
├── action.yml                                   # Reusable GitHub Action
├── peripherals/
│   ├── NVMemoryController.cs                    # NVMemory + controller with fault hooks
│   ├── NRF52NVMC.cs                             # nRF52 NVMC with write/erase tracking
│   ├── GenericNvmController.cs                  # Configurable command/address/data NVM
│   ├── TraceReplayEngine.cs                     # Native trace replay for fast sweeps
│   ├── NRF52UARTE.cs                            # UART stub for nRF52 platforms
│   └── SimpleCacheController.cs                 # Cache controller stub
├── platforms/                                   # Renode platform definitions (.repl)
├── profiles/                                    # 68 YAML audit profiles
├── scripts/
│   ├── audit_bootloader.py                      # Profile-driven audit runner (primary CLI)
│   ├── profile_loader.py                        # YAML profile parser + validation
│   ├── self_test.py                             # Meta-test: audit catches all known defects
│   ├── run_runtime_fault_sweep.resc             # Renode runtime fault sweep engine
│   ├── write_trace_heuristic.py                 # Write-trace classification for pruning
│   ├── render_results_html.py                   # HTML report renderer
│   ├── run_oss_validation.py                    # OSS profile orchestrator
│   ├── mcuboot_state_fuzzer.py                  # MCUboot trailer state exploration
│   ├── geometry_matrix.py                       # Parametric slot-layout generator
│   └── cbmc_to_profile.py                       # CBMC counterexample → profile converter
├── examples/                                    # Built-in bootloader firmware
│   ├── naive_copy/
│   ├── vulnerable_ota/
│   ├── nxboot_style/
│   ├── esp_idf_ota/
│   └── riotboot_standalone/
├── tests/                                       # Robot Framework test suites
└── results/oss_validation/assets/               # Pre-built MCUboot ELFs + slot images
```

## Writing your own profile

1. Build your bootloader ELF and slot binary images.
2. Pick or create a Renode platform (`.repl`) that matches your memory map.
3. Write a profile YAML: define `platform`, `bootloader`, `memory.slots`, `images`, and `success_criteria`.
4. Run:

```bash
python3 scripts/audit_bootloader.py \
  --profile your_profile.yaml \
  --renode-test /path/to/renode-test \
  --output results/your_report.json
```

See the 74 included profiles for examples covering NVMemory, NVMC, and hybrid platforms.

## Beyond the primary audit

The main workflow is `audit_bootloader.py --profile`, but the repo includes deeper analysis tools for bootloader authors:

- **Geometry matrix** (`scripts/geometry_matrix.py`) -- generates parametric slot-layout permutations (alignment, sector size, slot count) to catch geometry-dependent bugs. This is how PR [#2206](https://github.com/mcu-tools/mcuboot/pull/2206) was validated across layout variants.
- **State fuzzer** (`scripts/mcuboot_state_fuzzer.py`) -- property-based exploration of MCUboot trailer states. Seeds arbitrary metadata combinations and checks boot decisions against an oracle. Useful for any swap-based bootloader.
- **CBMC bridge** (`scripts/cbmc_to_profile.py`) -- converts formal verification counterexamples (from CBMC model checking) into tardigrade profiles for dynamic replay. Bridges static and dynamic analysis.

## Limitations

- Fault model operates at write-operation granularity, not analog brownout simulation.
- Cortex-M targets currently; non-Cortex architectures are not first-class.
- Full exhaustive sweeps take ~15 min on a 2-core CI runner; heuristic mode covers this in 2-4 min.

## Why "tardigrade"

Tardigrades are microscopic animals known for surviving extreme conditions: vacuum, radiation, and severe temperature swings. That maps directly to the goal of this project -- OTA update paths that stay recoverable even under harsh power and storage fault conditions.

## License

Apache 2.0. See `LICENSE`.
