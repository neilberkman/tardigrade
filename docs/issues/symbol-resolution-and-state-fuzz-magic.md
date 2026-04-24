# Two coverage/correctness issues with `instruction_skip` symbol resolution and `state_fuzzer` magic-field configuration

This document writes up two issues observed while running the
`mram_bootloader_glitch`-style profile against a Cortex-M0+ A/B-slot
bootloader on Renode 1.15.3. Both cause the reported sweep to silently
under-cover or mischaracterize the firmware under test, with no warning.

## Issue 1: compiler-split functions silently drop out of the sweep

### Symptom

A profile lists named functions to sweep:

```yaml
instruction_skip_config:
  target_addresses:
    - { symbol: bootloader_main }
    - { symbol: BOOT_META_ValidateSlotImage }
    - { symbol: BOOT_META_ComputeCrc }
    - { symbol: BOOTLOADER_ReadEfuseSpare }
```

The audit log resolves these to ELF address ranges:

```
Resolved 'bootloader_main' -> bootloader_main [0x10000ad0, 0x100012b8) (2024 bytes, 949 fault points)
```

After a code change that introduces a new helper function used from two
call sites, the compiler creates a `.constprop.0` clone for one of the
call sites and `bootloader_main` shrinks:

```
Resolved 'bootloader_main' -> bootloader_main [0x10000798, 0x10000c24) (1164 bytes, 536 fault points)
```

The 860 bytes that moved into the `.constprop.0` clone are not in the
sweep. There is no warning. The reported "fault_points_tested" simply
goes from 1146 to 894 between runs. A user comparing two sweeps and
seeing fewer findings has no signal that part of the change is
"hardened" and part of it is "we stopped looking at this code."

### Reproduction

1. Define `static void helper(...)` with two call sites in a swept
   function.
2. Build with `-Os -ffunction-sections`.
3. Inspect the ELF: `objdump -d ... | grep '\.constprop\.\|\.part\.'`.
4. Run the sweep. The clone is excluded.

### Why this is a footgun

This is a coverage gap that masquerades as a passing run, specifically
in fault-injection campaigns where the user is making safety/security
claims like "no instruction skip in this function leads to bypass." If
the compiler quietly moves a third of the function elsewhere, the claim
becomes "no instruction skip in *some* of this function leads to
bypass" without any indication.

### Proposed fixes (any of)

1. When resolving `symbol: foo`, also resolve and include all
   `foo.constprop.*`, `foo.part.*`, `foo.isra.*`, `foo.cold.*` siblings
   from the ELF symbol table. Log all included sub-symbols so the user
   can audit coverage.
2. If a previous resolution result is on disk for the same
   `(profile, elf_path)` pair, diff the byte ranges and warn loudly
   when coverage shrinks: `WARNING: bootloader_main resolved to 1164
   bytes (was 2024 bytes in last run); 860 bytes no longer covered`.
3. At minimum, log the full list of GCC-mangled symbols matching the
   user's request, even when only one matches, so a comparison run
   makes the difference visible.

Option 1 is the safest default: include the family of related symbols
unless the user opts out. Option 3 is the cheapest correctness band-aid
that keeps the audit log honest.

## Issue 2: `state_fuzzer` `magic` field accepts any value with no cross-check against firmware

### Symptom

A profile's structured-model state fuzzer takes a `magic` field with a
`valid` list of acceptable magic values:

```yaml
state_fuzzer:
  metadata_model:
    base_address: 0x10070000
    fields:
      - { name: magic, offset: 0, size: 4, valid: [0x4F54414D] }
      - { name: seq, offset: 4, size: 4, type: uint32 }
      ...
```

If the value listed in `valid` does not match the magic constant the
firmware actually checks for, every scenario the fuzzer generates
writes "valid magic" to the model that the firmware then rejects as
invalid. The firmware takes the same code path in all 50 scenarios
(empty-replica recovery / Issue B probe), and the report shows "50/50
scenarios completed" with whatever the recovery outcome is.

In the case I hit, the firmware's actual magic was `0x424F4F54`
("BOOT") but the profile had `0x4F54414D` ("OTAM") left over from a
prior firmware version. The state-fuzz oracle reported either "0
findings" (when control was the same recovery outcome) or "50
findings, all identical" (when control wasn't), and neither is
informative about whether slot-selection logic survives interesting
metadata states.

### Reproduction

1. Configure a structured-model `state_fuzzer` with `magic` set to any
   value the firmware does not recognize.
2. Run the sweep.
3. The state-fuzz section reports either uniformly successful or
   uniformly failing scenarios with no warning that the input
   distribution collapsed to a single point.

### Why this is a footgun

State-fuzz exists to vary metadata across realistic combinations and
catch oracle violations. If the magic is wrong, none of the variation
matters because the firmware sees only one effective input class. The
report's "50/50 scenarios" implies coverage that doesn't exist.

### Proposed fixes (any of)

1. Pre-flight check: at startup, write the model's "default valid"
   metadata to MRAM, run a single boot, and assert that the firmware's
   own `BOOT_META_CrcValid`-equivalent (or whatever oracle the user
   provides) returns true. If it doesn't, fail loudly:
   `ERROR: state_fuzzer magic 0x4F54414D produces invalid metadata for
   this firmware; check your profile.`
2. Diversity check: after the run, if all 50 scenarios produced
   exactly the same `boot_outcome`/`boot_slot` tuple, warn:
   `WARNING: state_fuzz produced a single outcome across all
   scenarios; the metadata model may be misconfigured for this
   firmware.`
3. Documentation fix: explicitly state in `writing-profiles.md` that
   `magic` values must match a constant in the target firmware and how
   to extract them (e.g., `nm bootloader.elf | grep MAGIC`).

(1) is the strongest. (2) is cheap to add and would catch any future
similar misconfiguration. (3) alone is not enough because the failure
mode is silent.

## Combined impact

Together these two issues let a sweep report "PASS, 50/50 state-fuzz
scenarios passed" when in reality (a) part of the target function was
never actually touched by the instruction-skip pass and (b) the
state-fuzz pass ran one effective scenario fifty times. Both failure
modes silently inflate confidence in the firmware's hardening claims.

## Versions and environment

- tardigrade: latest (from this repo)
- Renode: 1.15.3 portable
- Target: Cortex-M0+ ARM bootloader, `-Os -ffunction-sections`
- Toolchain: arm-none-eabi-gcc 13.x
