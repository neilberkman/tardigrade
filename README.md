# tardigrade

High-speed fault-injection testing for embedded OTA bootloaders. Tardigrade systematically injects NVM faults along the firmware update path under [Renode](https://renode.io/) emulation, then checks whether the device recovers -- going beyond boot/no-boot to catch state-correctness bugs that corrupt the update state machine without necessarily bricking the device.

Trace replay and write-address heuristics make exhaustive fault sweeps (~15K points) feasible in minutes, not hours -- fast enough for CI gating. An optional CBMC bridge connects formal verification to empirical testing by converting counterexamples into replay profiles.

## Validation

These are retroactive tests against known MCUboot bugs -- not discoveries. The point is showing that tardigrade's generic sweep catches real bug classes without target-specific tuning:

| PR                                                      | Bug                                                                 | Broken               | Fixed    |
| ------------------------------------------------------- | ------------------------------------------------------------------- | -------------------- | -------- |
| [#2100](https://github.com/mcu-tools/mcuboot/pull/2100) | Revert magic left in bad state (swap-move)                          | 3 bricks (9.7%)      | 0 bricks |
| [#2109](https://github.com/mcu-tools/mcuboot/pull/2109) | Header reload from wrong slot after interrupted swap (swap-scratch) | 19 bricks (33.3%)    | 0 bricks |
| [#2199](https://github.com/mcu-tools/mcuboot/pull/2199) | Stuck revert: primary trailer never cleared (swap-move)             | 1 wrong_image (100%) | 0 issues |

Additional differential profiles for PRs [#2205](https://github.com/mcu-tools/mcuboot/pull/2205), [#2206](https://github.com/mcu-tools/mcuboot/pull/2206), and [#2214](https://github.com/mcu-tools/mcuboot/pull/2214).

## How this works under the hood

### Formal-to-empirical bridge

`scripts/cbmc_to_profile.py` converts CBMC counterexamples into tardigrade replay profiles. CBMC proves a fault sequence _could_ cause corruption at the source level; tardigrade then runs the compiled bootloader firmware under that fault sequence to confirm whether it manifests in practice. The bridge maps source-level state violations to NVM write indices using the counterexample's variable traces and the calibration write log. This requires a CBMC harness that models NVM writes as observable state.

### Trace replay engine

Naive fault injection re-emulates the entire firmware prefix for each fault point -- O(N^2) total emulation for N fault points. Tardigrade records a write trace during calibration, then replays it from the trace file (~20ms) instead of re-emulating Phase 1. This is what makes 15,000-point exhaustive sweeps feasible in minutes instead of hours.

### Write-address heuristic

Not all NVM writes are equally interesting. The heuristic classifier (`scripts/write_trace_heuristic.py`) analyzes write addresses and groups them into tiers: trailer metadata (exhaustive coverage), slot boundaries (dense sampling), and bulk data copies (sparse sampling). Result: ~10x reduction in sweep points while preserving coverage of the writes most likely to cause state-machine corruption. This makes fault injection practical for CI pipelines.

### Semantic assertions beyond boot/no-boot

A device that boots to the wrong slot, confirms a corrupt image, or gets stuck in a revert loop is not "working." Tardigrade's state probes, semantic assertions, and composable invariant providers catch state-correctness bugs that pass a naive boot check. PR #2199 (stuck revert) is an example: the device boots, but it boots the wrong image permanently. Tardigrade catches it.

## Quick start

### GitHub Action

```yaml
- id: tardigrade
  uses: neilberkman/tardigrade@v1
  with:
    profile: profiles/mcuboot_swap_current.yaml
    quick: false
    workers: 2
```

Outputs: `verdict` (PASS/FAIL), `report-path`, `brick-rate`. Use `verdict` as the CI gate signal.

```yaml
- name: Upload tardigrade report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: tardigrade-report
    path: ${{ steps.tardigrade.outputs.report-path }}
```

See [`action.yml`](action.yml) for all inputs and outputs.

### Local

Prerequisites: `python3`, `pyyaml`, and either `renode-test` on PATH or Docker.

```bash
python3 scripts/audit_bootloader.py \
  --profile profiles/mcuboot_pr2100_broken.yaml \
  --renode-test /path/to/renode-test \
  --output results/report.json
```

`--quick` runs a 3-point smoke test. Default is the heuristic sweep (~1K points, 2-4 min). Add `--workers N` for parallelism. Docker: `--renode-test docker://renode-patched:test`.

### Run modes

| Mode       | Flag              | Points | Time    | Use case               |
| ---------- | ----------------- | ------ | ------- | ---------------------- |
| Quick      | `--quick`         | 3      | seconds | smoke only             |
| Heuristic  | _(default)_       | ~1K    | 2-4 min | normal CI / canary     |
| Exhaustive | `--fault-start 0` | ~15K   | 15 min  | deep manual validation |

## How it works

### Fault injection model

```mermaid
flowchart TD
    subgraph setup["Setup"]
        A["Load profile YAML"] --> B["Calibration: run firmware,<br/>record NVM write trace"]
        B --> C["Heuristic: classify writes<br/>by address (~15K → ~1K)"]
        C --> D["Fault point list"]
    end

    D --> E

    subgraph pf["Per fault point"]
        E["Phase 1: replay trace<br/>to write N (~20ms)"] --> F{"Fault type"}
        F -->|power_loss| G["Truncate write N<br/>(partial word)"]
        F -->|bit_corruption| H["Flip random bits<br/>(NOR physics model)"]
        F -->|interrupted_erase| I["Partial page erase"]
        F -->|"8 others<br/>(command_drop,<br/>write_disturb, ...)"| J["Backend-specific<br/>fault injection"]

        G --> K["Faulted NVM state"]
        H --> K
        I --> K
        J --> K

        K --> L{"evaluation_mode"}

        L -->|state| M["Infer boot outcome<br/>from NVM contents"]
        L -->|execute| N["Phase 2: reset CPU,<br/>recovery boot"]

        N --> O{"Backend"}
        O -->|"NVMC<br/>(flash)"| P["Restore flash snapshot<br/>+ reload ELF"]
        O -->|"MRAM"| Q["MRAM persists,<br/>restore + reload ELF"]
        O -->|"NVMemory<br/>(slow path)"| R["Storage persists<br/>across reset"]

        P --> S["Boot from faulted state"]
        Q --> S
        R --> S
        S --> T["VTOR detection +<br/>invariant checks"]
    end

    M --> U
    T --> U
    U["Classify outcome + failure class"] --> V["Aggregate into results JSON"]
```

1. **Calibration** -- run the firmware once, count total NVM writes, record a write trace.
2. **Heuristic pruning** -- classify writes by address into tiers, reduce sweep points ~10x.
3. **Phase 1** -- replay the write trace up to write N and inject the fault (trace replay eliminates O(N^2) prefix re-emulation).
4. **Phase 2** -- `execute` mode resets the CPU and performs a full recovery boot from faulted NVM; `state` mode infers the outcome from NVM contents alone.
5. **Follow-up cycles / hooks** -- optional repeated boots and between-cycle hook actions model confirm-or-rollback flows and staged recovery.
6. **Classification** -- boot outcomes (`success`, `wrong_image`, `no_boot`, `wrong_pc`, `hard_fault`) and failure classes (`recoverable`, `wrong_image`, `silent_corruption`, `unrecoverable`).

### Fault types

11 fault types across 3 backend architectures (MRAM, NVMC flash-fast, NVMemory slow-path): `power_loss`, `bit_corruption`, `interrupted_erase`, `multi_sector_atomicity`, `silent_write_failure`, `write_rejection`, `write_disturb`, `wear_leveling_corruption`, `reset_at_time`, `read_bit_flip` (NVMemory), `command_drop` (GenericNvmController).

Faults can be injected at different lifecycle stages: during the initial update write path, during pre-boot metadata/setup writes (`metadata_fault`), during between-boot confirm/accept hooks (`hook_fault`), during the recovery write path itself (`phase2_fault`), or as compound sequences (`multi_fault`).

### Execute-mode hardening

In `execute` mode, Phase 2 performs a full CPU recovery boot from faulted NVM:

- **VTOR polling** detects which slot the bootloader jumped to.
- **5ms confirmation window + CFSR HardFault check** verifies boot stability.
- **Sticky fault signal** (`FaultEverFired`) survives subsequent writes and resets.
- **Write stabilization early-exit** reduces per-point runtime when writes settle.
- **No-boot introspection** emits partition post-mortem dumps and per-operation PC traces for `no_boot` outcomes.

### Performance

- **Trace replay** -- recorded trace replay (~20ms) replaces full Phase 1 re-emulation
- **Cached flash restore** -- single `WriteBytes` per fault point instead of per-page erase+load
- **Hash bypass** -- patches out crypto validation via `hash_bypass_symbols` profile field
- **Parallel workers** -- `--workers N` distributes fault points across N Renode instances
- **Heuristic pruning** -- ~15K to ~1K points for routine CI
- **Interleaved distribution** -- round-robin assignment balances load across workers

## Profile-driven architecture

Sweeps are purely declarative YAML -- describe the memory layout, slots, images, and success criteria. Advanced semantic checking (state probes, custom invariants, boot register capture, write-order constraints) requires small Python hooks.

See **[`docs/writing-profiles.md`](docs/writing-profiles.md)** for the complete profile-writing guide: field-by-field reference, platform selection, success criteria options, invariant configuration, and result interpretation.

## Supported targets

### Real upstream integrations

**MCUboot** -- narrow canary profiles against MCUboot HEAD, retroactive differential profiles for 3 known bugs (broken/fixed pairs), and multi-step exploratory scenarios with semantic probes and invariant checking. See `profiles/mcuboot_*.yaml` and [`targets/mcuboot/`](targets/mcuboot/).

**NuttX nxboot** -- real upstream NuttX firmware built from source. Exploratory validation, a revert canary workflow, and a full target adapter (build, runtime profile generation, audit). See [`targets/nuttx_nxboot/`](targets/nuttx_nxboot/).

### Reference examples

The `examples/` directory contains standalone bootloader firmware for engine validation and self-testing:

| Example                  | Purpose                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `naive_copy`             | Worst-case baseline; proves the engine catches obvious brick paths |
| `vulnerable_ota`         | Copy-in-place OTA with frequent boot-visible failures              |
| `nxboot_style`           | Modeled nxboot family for adapter/probe/invariant development      |
| `esp_idf_ota`            | Clean-room model of ESP-IDF OTA slot-selection behavior            |
| `riotboot_standalone`    | Standalone RIOTboot-style slot-selection model                     |
| `bootloader_self_update` | Bootloader-region integrity and self-update fault modeling         |
| `nvs_config_migration`   | Config/NVS-region corruption and migration validation              |

## Report structure

Top-level verdict is `PASS` or `FAIL` -- use this as the CI gate signal. `bricks` counts unrecoverable failures (device didn't boot). `issue_points` includes broader mismatches (wrong slot, semantic assertions, invariant violations). Boot outcomes: `success`, `wrong_image`, `no_boot`, `wrong_pc`, `hard_fault`.

See **[`docs/writing-profiles.md`](docs/writing-profiles.md)** for the full report JSON structure and how to interpret results.

## Additional tools

- **Scenarios** ([`scripts/run_scenario.py`](scripts/run_scenario.py)) -- multi-step discovery runs with profile overrides per step. See [`scenarios/`](scenarios/).
- **CBMC bridge** (`scripts/cbmc_to_profile.py`) -- converts CBMC counterexamples into tardigrade replay profiles, bridging formal verification and empirical fault injection.
- **Geometry matrix** (`scripts/geometry_matrix.py`) -- parametric slot-layout permutations to catch geometry-dependent bugs.
- **State fuzzer** (`targets/mcuboot/state_fuzzer.py`) -- MCUboot-specific trailer-state exploration _(not yet wired into the main sweep engine)_.
- **HTML report** (`scripts/render_results_html.py`) -- renders JSON reports as HTML.

## CI workflows

| Workflow                            | Trigger                  | What it does                         |
| ----------------------------------- | ------------------------ | ------------------------------------ |
| `ci.yml`                            | push, PR                 | Robot suites + sharded self-test     |
| `profile-sweep.yml`                 | workflow_dispatch        | On-demand single-profile sweep       |
| `action-validation.yml`             | push, PR                 | Validates the reusable GitHub Action |
| `oss-validation.yml`                | push to `main`, schedule | OSS validation guards                |
| `mcuboot-head-exploratory.yml`      | workflow_dispatch        | MCUboot exploratory scenario         |
| `nuttx-nxboot-real-exploratory.yml` | workflow_dispatch        | Real NuttX nxboot exploratory sweep  |
| `nuttx-nxboot-revert-canary.yml`    | schedule, dispatch       | NuttX revert property canary         |
| `renode-latest-canary.yml`          | schedule, dispatch       | Tests against latest Renode build    |

## Repository layout

```text
tardigrade/
├── action.yml                       # Reusable GitHub Action
├── scripts/
│   ├── audit_bootloader.py          # Primary CLI entry point
│   ├── run_scenario.py              # Multi-step scenario runner
│   ├── profile_loader.py            # YAML profile parser + validation
│   ├── self_test.py                 # Self-test across known defect corpus
│   ├── run_runtime_fault_sweep.resc # Renode fault sweep engine
│   ├── write_trace_heuristic.py     # Write-trace classification
│   ├── render_results_html.py       # HTML report renderer
│   ├── geometry_matrix.py           # Parametric slot-layout generator
│   └── cbmc_to_profile.py          # CBMC counterexample converter
├── targets/
│   ├── mcuboot/                     # MCUboot probe, invariants, state fuzzer
│   ├── nuttx_nxboot/                # Real NuttX build + runtime profile gen
│   └── nxboot/                      # Shared nxboot-style probe + invariants
├── profiles/                        # YAML audit profiles
├── scenarios/                       # Multi-step scenario definitions
├── examples/                        # Built-in reference bootloader firmware
├── peripherals/                     # Renode C# peripherals with fault hooks
├── platforms/                       # Renode platform definitions (.repl)
├── tests/                           # Robot Framework test suites
├── results/oss_validation/assets/   # Pre-built MCUboot ELFs + slot images
└── docs/
    └── writing-profiles.md          # Profile-writing guide + result interpretation
```

## Limitations

- Fault model operates at write-operation granularity, not analog brownout simulation.
- Cortex-M targets only; non-Cortex architectures are not first-class.
- Some fault types are backend-specific: `read_bit_flip` requires the NVMemory slow-path backend; `command_drop` requires GenericNvmController. The profile loader warns at load time for incompatible combinations.
- Multi-fault sweeps currently execute all stages as power-loss faults regardless of the original fault type.
- Semantic bugs that don't change boot outcome require explicit target instrumentation.
- Exhaustive sweeps take ~15 min on a 2-core CI runner; heuristic mode is 2-4 min.

## Why "tardigrade"

Tardigrades survive vacuum, radiation, and temperature extremes. The name maps to the goal: OTA update paths that stay recoverable under harsh fault conditions.

## License

Apache 2.0. See `LICENSE`.
