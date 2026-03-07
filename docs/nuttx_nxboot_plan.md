# NuttX nxboot target plan

This repo now includes a real `targets/nuttx_nxboot/` adapter scaffold based on
the public upstream `apache/nuttx-apps/boot/nxboot` semantics.

What exists:

- `targets/nuttx_nxboot/probe.py`
  - models public `nxboot_get_state()`-style slot roles
  - exports `update_slot`, `recovery_slot`, `primary_confirmed`,
    `recovery_valid`, `recovery_present`, and `next_boot`
- `targets/nuttx_nxboot/invariants.py`
  - `nuttx_nxboot_roles_distinct`
  - `nuttx_nxboot_confirmed_has_recovery`
  - `nuttx_nxboot_duplicate_update_consumed`
- unit coverage in `tests/test_nuttx_nxboot_target_package.py`

What does not exist yet:

- a real runnable public profile/workflow
- actual NuttX-built ELFs/images in this repo
- a public Renode platform/layout for an upstream-supported nxboot board

Why this is the next real OSS target:

- upstream has real public bugs in this state machine:
  - `#2824` incorrect confirm state for directly flashed image
  - `#3169` unwanted confirm on double update
- those bugs are closer to the semantic discovery story than the synthetic
  `nxboot_style` model

Planned next steps:

1. Build a real public NuttX nxboot artifact set from upstream sources.
2. Add a real `profiles/nuttx_nxboot_*.yaml` family against those artifacts.
3. Wire a public exploratory scenario using `targets/nuttx_nxboot/*`.
4. Focus the first upstream-facing scenario on the double-update / confirm /
   revert class, not generic copy-fault counts.
