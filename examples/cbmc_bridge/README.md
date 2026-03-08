# CBMC Bridge Example

This example demonstrates the pipeline from formal verification
(CBMC) and fuzzing (AFL/libFuzzer) crash inputs to Tardigrade
fault-injection profiles.

## The bug

`boot_meta.h` contains a metadata parser with an intentional CRC
coverage gap. The CRC-32 is computed over only the first 8 bytes
(magic + sequence number) instead of the first 12 bytes (magic + seq

- active_slot). This means a corrupted `active_slot` field passes
  validation, causing the bootloader to boot from the wrong slot.

## Files

| File                    | Purpose                                                 |
| ----------------------- | ------------------------------------------------------- |
| `boot_meta.h`           | Buggy metadata parser (+ fixed version for comparison)  |
| `cbmc_harness.c`        | CBMC harness that finds the CRC gap                     |
| `cbmc_output.json`      | Pre-generated CBMC JSON counterexample                  |
| `cbmc_output.xml`       | Same counterexample in CBMC XML format                  |
| `address_map.yaml`      | Maps CBMC `meta_bytes` array to flash address           |
| `template.yaml`         | Base Tardigrade profile template                        |
| `sample_crash.bin`      | Sample fuzzer crash input (same data as counterexample) |
| `fuzz_address_map.yaml` | Region map for fuzzer input partitioning                |

## Pipeline

### 1. Run CBMC (optional -- output is pre-generated)

```sh
cbmc examples/cbmc_bridge/cbmc_harness.c --trace --json-ui \
    > examples/cbmc_bridge/cbmc_output.json
```

### 2. Convert CBMC counterexample to Tardigrade profile

From JSON:

```sh
python3 scripts/cbmc_to_profile.py \
    --cbmc-output examples/cbmc_bridge/cbmc_output.json \
    --template    examples/cbmc_bridge/template.yaml \
    --address-map examples/cbmc_bridge/address_map.yaml \
    --meta-size 16 \
    --output      /tmp/cbmc_crc_gap.yaml
```

From XML (same result):

```sh
python3 scripts/cbmc_to_profile.py \
    --cbmc-output examples/cbmc_bridge/cbmc_output.xml \
    --template    examples/cbmc_bridge/template.yaml \
    --address-map examples/cbmc_bridge/address_map.yaml \
    --meta-size 16 \
    --output      /tmp/cbmc_crc_gap_xml.yaml
```

### 3. Convert fuzzer crash input to Tardigrade profile

```sh
python3 scripts/fuzz_to_profile.py \
    --crash-input examples/cbmc_bridge/sample_crash.bin \
    --template    examples/cbmc_bridge/template.yaml \
    --address-map examples/cbmc_bridge/fuzz_address_map.yaml \
    --output      /tmp/fuzz_crc_gap.yaml
```

### 4. Run Tardigrade with the generated profile

```sh
python3 scripts/audit_bootloader.py --profile /tmp/cbmc_crc_gap.yaml
```

## How it works

**cbmc_to_profile.py** parses CBMC output (JSON or XML), extracts
byte-level array assignments from the counterexample trace, maps them
to absolute flash addresses using the address map, and injects them as
`pre_boot_state` writes in a copy of the template profile.

**fuzz_to_profile.py** takes a raw binary crash file and an address
map that describes how to partition the bytes into flash regions. Each
region maps a contiguous slice of crash bytes to an absolute flash
address. The result is the same `pre_boot_state` format.

Both tools produce standard Tardigrade profiles that can be run with
`audit_bootloader.py` for full power-loss fault-injection sweeps.
