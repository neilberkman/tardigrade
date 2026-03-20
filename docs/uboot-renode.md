# U-Boot `qemu_arm64` On Renode

This repo now includes a small bringup harness for booting an externally built
`qemu_arm64` U-Boot binary on Renode's generic Cortex-A53 platform and stopping
at a shell prompt.

The harness lives in:

- `scripts/boot_uboot_qemu_arm64_renode.py`
- `scripts/uboot_qemu_arm64_renode.dts`
- `peripherals/QEMUFwCfg.cs`

## Why this exists

New AArch64 targets keep failing for the same reason: Renode's generic boards
do not model enough of the QEMU `virt` machine to support full boot out of the
box. For `qemu_arm64` U-Boot, the minimum working path is:

1. keep the existing Cortex-A53 + GICv2 + PL011 + RAM platform,
2. advertise only devices that Renode actually models,
3. add a minimal `fw_cfg` MMIO stub so U-Boot's `qfw` probe succeeds,
4. stop autoboot over a PTY-backed PL011 console.

This is intentionally a bringup tool, not a full QEMU `virt` reimplementation.

## Usage

The harness expects an externally built U-Boot ELF. It does not vendor or copy
any GPL U-Boot artifacts into tardigrade.

Example:

```bash
python3 /Users/neil/source/tardigrade/scripts/boot_uboot_qemu_arm64_renode.py \
  --u-boot-elf /Users/neil/source/uboot-fault-lab/u-boot/u-boot \
  --renode-repo /Users/neil/source/renode
```

If your environment follows the local lab layout, these also work:

- `RENODE_REPO=/path/to/renode`
- `UBOOT_QEMU_ARM64_ELF=/path/to/u-boot`

## Current limits

- This proves shell bringup, not full QEMU `virt` fidelity.
- PCIe ECAM and VirtIO MMIO are still absent from the Renode-friendly DT.
- Flash probing still uses the stock A53 platform memory map, so this is not
  yet the path for real flash-environment testing.

The practical next steps are either:

1. replace the stock flash mapping with tardigrade's CFI NOR peripheral, or
2. keep expanding the local Renode extension layer until the full QEMU `virt`
   device tree becomes usable.
