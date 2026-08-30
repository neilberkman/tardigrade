# TF-M BL2 Target

ARM Trusted Firmware-M (TF-M) BL2 is the second-stage bootloader for
TrustZone-enabled Cortex-M devices (M23, M33, M55, M85). It wraps MCUboot
with ARM-specific extensions for secure boot, SAU/MPC configuration, and
optional Fault Injection Hardening (FIH).

## What makes TF-M BL2 different from vanilla MCUboot

- **Multi-image boot**: TF-M can manage secure (SPE) and non-secure (NSPE)
  images independently, with separate slot pairs and signing keys. A fault
  campaign can test whether interruption permits a version mismatch between
  the two synthetic slot roles.

- **Security boundary setup**: Before jumping to the secure image, BL2
  configures SAU regions and MPC block attributes. A fault during this
  window could leave secure memory accessible to the non-secure world.

- **FIH countermeasures**: TF-M adds software fault injection hardening
  (control flow integrity, complex constants, redundant checks) to MCUboot's
  boot path. Tardigrade can test whether these countermeasures actually
  survive storage-level faults during the update process.

This package contains reusable state probes and invariants. The repository
supplies `platforms/mps2_an521.repl` for register-driver compatibility and
fault instrumentation; compiled TF-M firmware is not bundled. The current
AN521 target does not validate live SAU/MPC memory isolation: its MPC model is
register-only, and security-boundary enforcement is reported as unavailable,
not as a passed check.

## Persisted snapshot evaluation

The vendor-neutral evaluator reads a persisted 4-slot flash snapshot, uses
`probe.py` for trailer parsing, and resolves the configured invariants through
Tardigrade's normal registry. From the repository root, run:

```text
python3 targets/tf_m_bl2/snapshot_evaluator.py \
  --snapshot /path/to/flash-snapshot.bin \
  --profile profiles/tf_m_bl2_an521_snapshot.json
```

The included AN521 profile describes the compiled
`MCUBOOT_IMAGE_NUMBER=2` slot geometry and enables the TF-M multi-image
consistency, acceptance, partial-magic, and secure-slot checks alongside
`atomic_state_groups`. Its declared joint-version policy allows minor,
revision, and build differences while requiring matching major versions. The
evaluator is a post-fault observation tool; it does not invoke TF-M or inject
faults. Synthetic snapshots assembled from slot fixtures validate detector
behavior, but are not raw post-reboot dumps and must not be presented as
persistent recovery evidence.

## Native-runner template

`profiles/tf_m_bl2_an521_native.template.yaml.in` is a path-neutral interface
for running locally built TF-M artifacts. Substitute the `${TFM_*}` tokens,
rename the result to `.yaml`, and run the normal profile command:

```text
python3 scripts/audit_bootloader.py --profile profiles/tf_m_bl2_an521_native.yaml \
  --renode-test /path/to/renode-test --quick
```

The required substitutions are the BL2 ELF and entry, four slot bases and the
common slot size, four signed image paths, a positive write cap, and the run
duration. `TFM_VTOR_SETTLE_ITERS` is an explicit opt-in number of post-VTOR
run slices; leave it at `0` to retain the usual early-handoff behavior, or set
it high enough for the NS application to emit its completion marker. This
template contains no compiled artifacts or developer-specific paths. Confirm
the resulting trace includes both primary trailer offsets before starting a
campaign. On the RAM-backed AN521 view, `power_loss` suppression and the
persisted pre-write snapshot are the supported evidence path; a mode-6 tracker
flag is not evidence that TF-M's production flash driver observed a hardware
driver error.

The template has `expect.should_find_issues: false` because it is a reusable
interface, not a statement about any current build. Set a different expectation
only in a private, build-specific campaign after establishing its baseline.

Set `fault_sweep.tracking_start_address` to the secure
`fwu_bootloader_mark_image_accepted` entry address (obtain it with `nm` from
the clean BL2 ELF, for example `nm -n bl2.elf | grep
fwu_bootloader_mark_image_accepted`). The secure address is intentional: the
Renode Cortex-M target does not reliably dispatch the internal C# instruction
hook at the non-secure test application entry.

For acceptance atomicity profiles, set
`invariant_config.semantic_state_stage: fault_snapshot`. Runtime results then
retain both `fault_semantic_state` (captured immediately at power loss) and the
final `semantic_state`/`recovery_semantic_state`; only invariant evaluation uses
the selected boundary state, while final-state assertions remain unchanged.

## Files

- `probe.py` -- state collection from MCUboot trailers, extended for
  multi-image TF-M layouts (4 slots)
- `invariants.py` -- TF-M-specific postcondition checks:
  - `tfm_multi_image_consistency` -- S and NS swap state must match; when
    `invariant_config.tfm_joint_version_policy` is declared, their image
    versions must satisfy its `equal` or major-version `compatible` policy
  - `tfm_multi_image_acceptance_consistency` -- S and NS primary images must
    be accepted together after `psa_fwu_accept` when the profile declares
    `invariant_config.tfm_joint_acceptance: true`
  - `tfm_no_partial_magic` -- every recovered trailer has valid or erased magic
  - `tfm_secure_slot_not_empty` -- secure slot must never be erased after fault
