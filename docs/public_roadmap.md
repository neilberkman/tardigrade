# Public roadmap

This file tracks the current public `tardigrade` direction so the work does
not live only in thread history.

## Big goal

Make `tardigrade` a credible clean-room OSS tool for resilience discovery and
validation:

- keep the core generic
- validate it on real public targets
- keep target-specific logic in target adapters, not in the core

## Current validated surface

- reusable GitHub Action for narrow audit/canary use
- public MCUboot exploratory scenario:
  - `scenarios/mcuboot_head_exploratory.yaml`
  - green on GitHub after temp isolation and batch tuning
- target-side adapters:
  - `targets/mcuboot/`
  - `targets/nuttx_nxboot/` scaffold

## In progress

### Real NuttX nxboot target

Status:

- adapter scaffold exists
- no real runnable public profile/workflow yet
- current best board candidate is `nucleo-h743zi`
- blocker: existing upstream board support is two OTA slots plus scratch, not
  nxboot's required three-slot model

Next:

1. derive a real public `nxboot` build/config path
2. expose a third public slot
3. add real `profiles/nuttx_nxboot_*.yaml`
4. add a manual exploratory workflow only after local runs are credible

### Docs pass

Still worth doing:

1. another holistic README pass
2. tighten terminology around:
   - `brick` vs `issue`
   - `quick` vs heuristic
   - exploratory vs CI/canary use

## Surfaces to de-emphasize

If we were starting from scratch, we would de-emphasize or avoid:

- `state_probe_script` legacy shorthand in favor of structured `state_probe`
- synthetic `nxboot_style` as an OSS credibility story
- older wording that centered `quick` mode as a default-facing path
- legacy profile glue that duplicates the newer scenario/probe/invariant path

## Boundary rules

Keep in public `tardigrade`:

- generic fault injection
- generic scenario runner
- generic state-probe contract
- generic semantic assertions and invariants
- public target adapters

Keep out of public `tardigrade`:

- Mirala-specific metadata models
- Mirala setup scripts
- Mirala scenarios
- Mirala probe/invariant logic
- private platform/peripheral semantics
