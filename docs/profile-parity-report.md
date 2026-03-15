# Profile Parity Report

[`scripts/profile_parity_report.py`](../scripts/profile_parity_report.py) is a
maintainer-facing coverage accounting tool. It is intentionally more detailed
than the public README because it answers a different question: "what coverage
can we honestly claim from the repo today?"

## Target classes

- `upstream`: real upstream bootloader integrations that can count toward
  public support and parity claims
- `reference`: clean-room or modeled examples used to exercise the engine and
  target adapters
- `scaffolding`: target packages or docs that exist, but do not yet have a real
  runnable profile surface
- `support`: profiles that exercise generic security/configuration machinery and
  should not be counted as bootloader parity

## Claimable totals

The report emits both `totals` and `claimable_totals`.

- `totals` counts everything in `profiles/`
- `claimable_totals` counts only `upstream` targets

This keeps internal bean counting useful without conflating reference examples
with real bootloader support.

## Current target mapping

- `mcuboot`: `upstream`
- `nuttx_nxboot`: `upstream`
- `rustboot`: `upstream`
- `esp_idf`: `reference`
- `nxboot_style`: `reference`
- `tf_m_bl2`: `scaffolding`
- `other`: `support`
