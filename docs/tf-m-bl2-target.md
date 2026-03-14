# TF-M BL2 Target Design

## Background

ARM Trusted Firmware-M (TF-M) is the reference Secure Processing Environment
(SPE) implementation for ARMv8-M TrustZone devices. Its second-stage
bootloader, BL2, wraps MCUboot with ARM-specific integration for secure boot,
hardware key management, and optional Fault Injection Hardening (FIH).

TF-M BL2 is BSD-3 licensed, widely deployed on Cortex-M33/M55/M85 platforms,
and the default secure boot solution for PSA Certified devices. It is used by
silicon vendors including STMicroelectronics (STM32L5/U5), Nordic (nRF5340/
nRF9160), and Nuvoton, as well as the ARM MPS2+ AN521 FPGA reference board.

## Architecture differences from vanilla MCUboot

### Multi-image boot (MCUBOOT_IMAGE_NUMBER=2)

The most significant difference. TF-M can manage S and NS images as
independent MCUboot image pairs:

```
Flash layout (multi-image, swap-move):

  +-------------------+
  | BL2 bootloader    |  (executes in secure world)
  +-------------------+
  | S primary slot    |  (secure image, exec)
  +-------------------+
  | NS primary slot   |  (non-secure image, exec)
  +-------------------+
  | S secondary slot  |  (secure image, staging)
  +-------------------+
  | NS secondary slot |  (non-secure image, staging)
  +-------------------+
  | Scratch/status    |  (if swap-scratch mode)
  +-------------------+
```

Each slot pair has its own MCUboot trailer (magic, image_ok, copy_done).
BL2 swaps S and NS images sequentially -- first image 0 (secure), then
image 1 (non-secure). A power loss between the two swaps leaves the
device with mismatched S/NS firmware versions.

### Single-image boot (MCUBOOT_IMAGE_NUMBER=1)

S and NS images are concatenated and signed as one blob. Structurally
identical to vanilla MCUboot with 2 slots. This is the default for
TF-M Profile Small (constrained devices).

### Security boundary configuration

After image validation, BL2 configures:

- **SAU (Security Attribution Unit)**: Defines which address ranges are
  Secure, Non-Secure, or Non-Secure Callable. Misconfiguration exposes
  secure memory/peripherals to the NS world.
- **MPC (Memory Protection Controller)**: Per-block S/NS attribution for
  SRAM and flash regions. Platform-specific (AN521, Musca, STM32L5 each
  have different MPC implementations).
- **PPC (Peripheral Protection Controller)**: S/NS attribution for
  peripherals. Less relevant for OTA faults but part of the boot path.

### Fault Injection Hardening (FIH)

TF-M adds software countermeasures to MCUboot's critical paths:

- **OFF**: No countermeasures (default).
- **LOW**: Control flow integrity checks, failure loop hardening.
- **MEDIUM**: Complex constants (not 0/1), redundant variable checks.
- **HIGH**: Random delays via TRNG to desynchronize glitch attacks.

FIH protects the boot validation path (signature check, hash check,
security counter comparison). It does NOT protect the swap/copy path --
storage-level faults during the swap are the same attack surface as
vanilla MCUboot, and tardigrade's existing write-fault model covers this.

### Image authentication

- RSA-2048 or ECDSA-P256 signature verification
- SHA-256 image hash (stored in TLV area)
- Public key hash provisioned in OTP or HUK-derived
- Security counter in TLV for anti-rollback (compared against
  platform-specific monotonic counter, often in OTP)

## Attack surface for fault injection

### 1. Swap-path faults (same as vanilla MCUboot)

Power loss during the slot swap (copy/move/scratch) can corrupt image
data or trailer metadata. Tardigrade's existing MCUboot sweep covers
this directly. TF-M uses the same swap algorithms as upstream MCUboot.

**Tardigrade approach**: Existing MCUboot profiles work for single-image
TF-M. Multi-image mode needs the extended 4-slot probe.

### 2. Multi-image desynchronization (TF-M specific)

Power loss between swapping image 0 (S) and image 1 (NS) leaves them at
different versions. The S/NS veneer interface may be incompatible,
causing hard faults when NS calls secure services.

**Tardigrade approach**: The `tfm_multi_image_consistency` invariant
detects this. Fault sweep needs to cover the window between the two
sequential swap operations.

### 3. Security boundary misconfiguration (TF-M specific)

BL2 writes SAU/MPC/PPC configuration registers before jumping to the
secure image. A fault during this sequence could:

- Leave SAU regions unconfigured (all memory defaults to secure, NS
  world cannot access its own code/data -- functional brick)
- Partially configure SAU (some secure regions exposed to NS)
- Corrupt MPC block tables (flash region security attribution wrong)

**Tardigrade approach**: Requires Renode Cortex-M33 SAU emulation. The
probe would read SAU_RNR/SAU_RBAR/SAU_RLAR registers after boot and
compare against expected values. New invariant needed:
`tfm_sau_correctly_configured`.

### 4. Anti-rollback counter faults

TF-M stores security counters in OTP (One-Time Programmable) or
platform-specific NVM. A fault during counter comparison could allow a
downgrade, or a fault during counter update could spike the counter to a
garbage value, locking out all valid firmware.

**Tardigrade approach**: The generic `rollback_version_bounded` invariant
covers counter spiking. Counter comparison bypass requires instruction-
level fault injection (instruction skip), which tardigrade supports via
the `instruction_skip` fault type.

### 5. FIH bypass

FIH adds redundant checks that a single storage fault should not bypass
(they protect the code path, not storage). However, if FIH state is
stored in NVM (it typically isn't -- it's stack/register based), a
storage fault could theoretically corrupt a FIH control flow variable.

**Tardigrade approach**: Low priority. FIH operates on CPU registers and
stack, not flash/NVM. Storage-level faults are unlikely to bypass FIH.
Worth documenting but not a primary test target.

## Required Renode platform support

### Current state

Renode has Cortex-M33 CPU emulation (`CortexM` class supports M33) and
some M33-based platforms:

- `stm32l552.repl` -- STM32L552 (Cortex-M33 with TrustZone)
- `stm32wba52.repl` -- STM32WBA52 (Cortex-M33)

Renode does NOT currently have:

- MPS2+ AN521 platform (the TF-M primary reference board)
- Musca-B1/S1 platforms
- Full SAU emulation with configurable regions
- MPC peripheral models

### What needs to be built or verified

1. **Cortex-M33 with TrustZone basics** -- Verify that Renode's CortexM
   class correctly handles:
   - Secure/Non-Secure state transitions
   - SAU register access (may already work via system register emulation)
   - VTOR_S and VTOR_NS (separate vector tables for S and NS)
   - BXNS/BLXNS instructions for S->NS transitions

2. **AN521 platform file** -- Create a `.repl` for MPS2+ AN521:
   - Dual Cortex-M33 (CPU0 secure + CPU1 non-secure)
   - SSRAM (secure) and NSRAM regions
   - Flash regions for S and NS images
   - UART for boot log capture
   - For tardigrade, only CPU0 matters (BL2 runs on CPU0 in secure mode)

3. **Flash controller** -- AN521 uses a simple flash model. Tardigrade
   needs either `MappedMemory` (fast path) or a flash controller
   peripheral with write tracking. The existing `NRF52NVMC.cs` pattern
   could be adapted, or `MappedMemory` with `faultFlash` may suffice if
   the AN521 flash has no special write semantics.

### Minimal viable platform (recommended first step)

Skip the full AN521 and instead use STM32L5 (already has a Renode
platform file) with a TF-M build targeting `stm32l552e_dk`. This avoids
building a new Renode platform from scratch.

Alternatively, use a stripped-down AN521-like platform with:

- Single Cortex-M33 CPU (no dual-core complexity)
- MappedMemory for flash (tardigrade's faultFlash handles write tracking)
- Basic memory map matching TF-M's AN521 flash layout

## Estimated work to get a working profile

### Phase 1: Single-image TF-M on existing MCUboot infrastructure

**Effort: ~2 days**

TF-M single-image mode is structurally identical to vanilla MCUboot.
Build a TF-M+MCUboot ELF for a supported Renode platform (STM32L552 or
a minimal Cortex-M33 `.repl`) and use existing MCUboot profiles with
minor adjustments (entry point, slot addresses).

Deliverables:

- TF-M BL2 ELF built for target platform
- Profile YAML using existing `cortex_m4_flash_fast.repl` or new M33 platform
- Validation that existing MCUboot sweep finds/doesn't find issues

### Phase 2: Multi-image TF-M with extended probe

**Effort: ~3 days**

Enable `MCUBOOT_IMAGE_NUMBER=2` in the TF-M build. Use the 4-slot probe
from `targets/tf_m_bl2/probe.py`. Create profiles that exercise the
window between S and NS swap operations.

Deliverables:

- Multi-image TF-M BL2 ELF
- 4-slot profile YAML with `slot_s_exec_base` etc.
- `tfm_multi_image_consistency` invariant validated against real faults

### Phase 3: SAU/security boundary verification

**Effort: ~5 days (depends on Renode SAU support)**

Verify Renode's SAU emulation, implement SAU register probing in the
state probe, and add `tfm_sau_correctly_configured` invariant.

Deliverables:

- SAU probe implementation in `probe.py`
- New invariant checking SAU region configuration post-boot
- Profile exercising BL2's SAU setup path

### Phase 4: FIH effectiveness testing

**Effort: ~3 days**

Build TF-M with FIH=MEDIUM or FIH=HIGH. Run instruction-skip fault
injection against the boot validation path. Verify that FIH
countermeasures prevent signature/hash bypass.

Deliverables:

- FIH-enabled TF-M BL2 ELF
- Instruction-skip profile targeting `boot_go` / `bootutil_img_validate`
- Differential: FIH=OFF vs FIH=MEDIUM showing countermeasure effectiveness

## References

- TF-M secure boot design: https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/tfm_secure_boot.html
- TF-M physical attack mitigation: https://tf-m-user-guide.trustedfirmware.org/design_docs/tfm_physical_attack_mitigation.html
- TF-M BL1 immutable bootloader: https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/bl1.html
- MCUboot FIH header: https://github.com/mcu-tools/mcuboot/blob/master/boot/bootutil/include/bootutil/fault_injection_hardening.h
- TF-M Profile Large (FIH Medium): https://trustedfirmware-m.readthedocs.io/en/latest/configuration/profiles/tfm_profile_large.html
- MPS2+ AN521 in Zephyr: https://docs.zephyrproject.org/latest/boards/arm/mps2/doc/mps2_an521.html
