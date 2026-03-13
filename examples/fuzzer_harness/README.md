# Fuzzer Harness Example

This directory shows the end-to-end pattern for turning parser crashes into
tardigrade regression profiles.

Workflow:

1. Build a small fuzz target around the parser you care about.
2. Run the fuzzer long enough to collect crashes.
3. Convert the crashes into tardigrade profiles.
4. Audit the generated profiles under emulation.

Example commands:

```bash
make
mkdir -p corpus crashes
./fuzz_header_parser corpus/ -artifact_prefix=crashes/

python3 scripts/fuzz_corpus.py convert \
  --crash-dir crashes/ \
  --base-profile profiles/esp_idf_ota_upgrade.yaml \
  --output-dir profiles/regression/

python3 scripts/audit_bootloader.py \
  --profile profiles/esp_idf_ota_upgrade.yaml \
  --fuzz-crash-dir crashes/ \
  --output results/fuzz_regression_audit.json
```

The sample harness is intentionally generic. Replace `parse_ota_header()` with
your parser under test and add the real include paths and source files in the
`Makefile`.
