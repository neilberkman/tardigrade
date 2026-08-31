# Fuzzer Harness Example

This directory shows the end-to-end pattern for turning parser crashes into
tardigrade regression profiles.

Workflow:

1. Build a small fuzz target around the parser you care about.
2. Run the fuzzer long enough to collect crashes.
3. Convert the crashes into tardigrade profiles.
4. Audit the generated profiles under emulation.

Before fuzzing, qualify the parser contract with a known-valid seed and a
known-invalid control. The example builds the same C source twice: once as a
libFuzzer target and once as a small command-line adapter that emits the JSON
preflight result:

```bash
make -C examples/fuzzer_harness preflight_adapter.bin
python3 scripts/fuzzer_harness.py \
  --config examples/fuzzer_harness/preflight.yaml --json
```

The command resolves its working directory and seed paths relative to the
configuration file, so it is runnable from any current directory. Building
the libFuzzer target with plain `make` additionally requires a compiler that
ships the libFuzzer runtime.

The command must emit the declared outcome field as JSON. A setup error,
intentional abort, non-zero exit, timeout, malformed output, or mismatch in
either control is reported as `INFRASTRUCTURE_FAILURE`; it cannot be promoted
to a product finding. Keep the valid and invalid controls representative of
the parser contract, and rerun qualification after changing the harness. The
preflight stages both inputs under opaque temporary paths and exposes no case
label to the command, so the adapter must distinguish their contents. Review
the adapter to ensure it calls the same parser entry point as the fuzzer.

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
