# rustBoot Target

rustBoot is an MIT-licensed Rust bootloader for embedded systems. It uses a
swap-scratch algorithm with 3 flash partitions: BOOT, UPDATE, and SWAP.

This directory is a clean-room protocol adapter; it does not contain rustBoot
source or prebuilt firmware. See `docs/rustboot-target.md` for layout and probe
configuration.

## Trailer Layout

Each of BOOT and UPDATE has a trailer at the end of the partition:

```
offset from partition end:
  -4    magic: "BOOT" = 0x544F4F42 (little-endian)
  -5    state byte: 0xFF=New, 0x70=Updating, 0x10=Testing, 0x00=Success
  -5-N  per-sector flags (packed nibbles, 2 per byte)
```

Per-sector flag nibbles: 0x0F=New, 0x07=Swapping, 0x03=Backup, 0x00=Updated.

The SWAP partition is scratch space with no trailer.

## Known Bugs

- **#77** -- Interrupted swap bricks device (BOOT left without valid image)
- **#79** -- Corrupted boot image runs without validation
- **#80** -- Damaged update image bricks during swap

## Attack Surfaces

1. **Partial swap** -- Power loss during sector copy leaves BOOT incomplete
2. **Packed nibble corruption** -- Two flags share a byte; partial write corrupts neighbor
3. **State byte corruption** -- Single byte controls entire partition lifecycle
4. **Missing swap resume** -- No mechanism to detect and resume interrupted swaps
