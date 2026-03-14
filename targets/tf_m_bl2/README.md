# TF-M BL2 Target

ARM Trusted Firmware-M (TF-M) BL2 is the second-stage bootloader for
TrustZone-enabled Cortex-M devices (M23, M33, M55, M85). It wraps MCUboot
with ARM-specific extensions for secure boot, SAU/MPC configuration, and
optional Fault Injection Hardening (FIH).

## What makes TF-M BL2 different from vanilla MCUboot

- **Multi-image boot**: TF-M can manage secure (SPE) and non-secure (NSPE)
  images independently, with separate slot pairs and signing keys. A fault
  that interrupts the swap of one image but not the other creates a version
  mismatch between S and NS firmware.

- **Security boundary setup**: Before jumping to the secure image, BL2
  configures SAU regions and MPC block attributes. A fault during this
  window could leave secure memory accessible to the non-secure world.

- **FIH countermeasures**: TF-M adds software fault injection hardening
  (control flow integrity, complex constants, redundant checks) to MCUboot's
  boot path. Tardigrade can test whether these countermeasures actually
  survive storage-level faults during the update process.

## Status

Scaffolding only. The probe and invariants are implemented but no working
profile or Renode platform exists yet. See `docs/tf-m-bl2-target.md` for the
full design document and implementation plan.

## Files

- `probe.py` -- state collection from MCUboot trailers, extended for
  multi-image TF-M layouts (4 slots) and SAU/MPC probing (stubbed)
- `invariants.py` -- TF-M-specific postcondition checks:
  - `tfm_multi_image_consistency` -- S and NS swap state must match
  - `tfm_no_partial_magic` -- no partially-written trailer magic in any slot
  - `tfm_secure_slot_not_empty` -- secure slot must never be erased after fault
