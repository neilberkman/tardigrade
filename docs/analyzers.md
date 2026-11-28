# Security analyzers and bridges

Tools that sit beside the fault-injection engine: bridges from fuzzers and formal verification, and declarative analyzers for update protocols. Each one states what evidence it consumes; none of them proves that a model matches deployed firmware.

## Fuzzer bridge

[`scripts/fuzz_crash_to_profile.py`](../scripts/fuzz_crash_to_profile.py) converts libFuzzer/AFL/honggfuzz crash artifacts into tardigrade regression profiles. When a fuzzer finds a crash that corrupts an OTA header or metadata region, the bridge tests whether the corruption actually bricks the device or whether the bootloader recovers. Pipeline: `fuzzer finds crash` → `fuzz_crash_to_profile.py` → `tardigrade sweep from corrupted state`. Supports batch mode, staging-image injection, and auto-detection of fuzzer types.

## Formal verification bridge (CBMC)

[`scripts/cbmc_to_profile.py`](../scripts/cbmc_to_profile.py) converts CBMC counterexamples into tardigrade replay profiles. CBMC proves a fault sequence _could_ cause corruption at the source level; tardigrade runs the compiled firmware under that sequence to confirm whether it manifests in practice. The bridge maps source-level state violations to NVM write indices using the counterexample's variable traces and the calibration write log.

## Declarative update-protocol analysis

[`scripts/update_protocol_analyzer.py`](../scripts/update_protocol_analyzer.py) enumerates the paths through a declared update protocol, including optional event groups, and checks that every commit follows required policy gates, metadata bindings, and authenticated-content coverage. The model is vendor-neutral and evidence-limited: a clean result says the declaration is internally safe, not that the declaration matches a particular implementation.

```bash
python3 scripts/update_protocol_analyzer.py \
  --profile profiles/update_protocol_artifact_binding_fixed.yaml \
  --json
```

## Authenticated-content equivalence

[`scripts/authenticated_equivalence.py`](../scripts/authenticated_equivalence.py)
runs a grammar-aware, black-box campaign against a supplied parser or harness.
It supports legacy duplicate/reorder mutations and declarative coupled
post-authentication copy/patch/replace cases, mutates only records after both
the declared authentication boundary and signature record, and compares
canonical semantic outcomes while failing closed on malformed evidence or
authenticated-identity drift. Findings are semantic divergences in the
supplied harness; the campaign does not claim to discover cryptographic
weaknesses. See
[`docs/authenticated-equivalence.md`](authenticated-equivalence.md) and
the synthetic fixtures in
[`examples/authenticated_equivalence/`](../examples/authenticated_equivalence/).

## Pre-authentication nested-header bounds

[`scripts/preauth_bounds_oracle.py`](../scripts/preauth_bounds_oracle.py) runs a
target-neutral, synthetic-only campaign for attacker-controlled total, used,
signature, and key lengths. Its independent layout model flags a
`PREAUTH_BOUNDS_ESCAPE` when invalid nested extents reach signature/key
consumption or cryptographic verification, even if the parser later rejects
the input. See [`docs/preauth-bounds-oracle.md`](preauth-bounds-oracle.md)
and the original minimal vulnerable/fixed fixtures in
[`examples/preauth_bounds_oracle/`](../examples/preauth_bounds_oracle/).

## Freshness-aware metadata state

[`scripts/freshness_oracle.py`](../scripts/freshness_oracle.py) models synthetic
update protocols in which installed image state and authenticated metadata can
advance through separate channels. It exercises time advancement, refresh
failure, and expiry-aware acceptance/commit/rollback decisions. It also flags
accepted selections that regress an independently advanced installed channel,
even while the metadata remains within its wall-clock validity period. See
[`examples/freshness_oracle/`](../examples/freshness_oracle/).

## Reviewed-versus-signed authorization

The vendor-neutral `authorization_review` analyzer compares observed parsed,
reviewed, digested, signed, and authorized value identities. It fails closed
when required trace evidence is missing or incomplete; it consumes supplied
JSON traces and does not automatically extract vendor traces from firmware.

The vulnerable and fixed fixtures are [`profiles/authorization_review_vulnerable.yaml`](../profiles/authorization_review_vulnerable.yaml) with [`examples/authorization_review/vulnerable_trace.json`](../examples/authorization_review/vulnerable_trace.json), and [`profiles/authorization_review_fixed.yaml`](../profiles/authorization_review_fixed.yaml) with [`examples/authorization_review/fixed_trace.json`](../examples/authorization_review/fixed_trace.json).

```bash
python3 scripts/authorization_review_analyzer.py \
  --profile profiles/authorization_review_fixed.yaml \
  --trace examples/authorization_review/fixed_trace.json \
  --json
```

The fixed fixture reports `PASS`; substitute the vulnerable profile and trace
to see the reviewed-versus-signed mismatch finding.

To create a starting point for collecting runtime evidence for every expanded
sequence path, emit incomplete trace templates:

```bash
python3 scripts/authorization_review_analyzer.py \
  --profile profiles/my_profile.yaml \
  --emit-trace-template-dir traces/authorization
```

Template files contain the exact model digest and sequence name, ordered event
occurrences, and empty evidence placeholders. The command only writes files
and warns that they are incomplete observations; it does not run analysis or
produce a verdict. Existing output files are never overwritten.

## Security-state and emitted-code campaigns

`persistent_state_layout` maps monotonic-security, authorization, secret,
recovery, and mutable fields to physical erase units. The offline analyzer flags risky
co-location, while the `security_state_erase` selector creates power-loss
cutpoints around erase and restoration boundaries. `boundary_campaigns`
expands logical counters around zero, storage capacity, and integer limits,
with optional lower-value follow-ups that verify rejection and persistence.
Profiles also emit a normalized durable-memory ownership plan. Set
`ownership_manifest_complete: true` to require fail-closed whole-device checks;
otherwise reports explicitly mark whole-device layout safety as not assessed.

For CPU-fault campaigns, `terminal_error_paths` derives direct calls and tail
branches to fatal handlers from the emitted ELF. A finding requires a terminal
control run, an applied instruction skip against the same artifact and restored
state, and observation of a declared forbidden sink. Missing or ambiguous
evidence is inconclusive rather than clean.

## Additional tools

- **Scenarios** ([`scripts/run_scenario.py`](../scripts/run_scenario.py)) -- multi-step discovery runs with profile overrides per step. See [`scenarios/`](../scenarios/).
- **CBMC bridge** ([`scripts/cbmc_to_profile.py`](../scripts/cbmc_to_profile.py)) -- converts CBMC counterexamples into tardigrade replay profiles, bridging formal verification and empirical fault injection.
- **Fuzzer bridge** ([`scripts/fuzz_crash_to_profile.py`](../scripts/fuzz_crash_to_profile.py)) -- converts libFuzzer/AFL/honggfuzz crash inputs into regression profiles; supports batch mode, staging-image injection, and auto-detection of fuzzer types. Workflow helpers live in [`scripts/fuzz_corpus.py`](../scripts/fuzz_corpus.py), with an end-to-end template in [`examples/fuzzer_harness/`](../examples/fuzzer_harness/). Legacy converter: `scripts/fuzz_to_profile.py`.
- **Fuzzer harness preflight** ([`scripts/fuzzer_harness.py`](../scripts/fuzzer_harness.py)) -- validates a known-valid seed and known-invalid control before a parser campaign. Setup errors, aborts, timeouts, malformed evidence, and mismatched controls are infrastructure failures, never findings.
- **State fuzzer** -- structured metadata-state fuzzing via the `state_fuzzer` profile block, plus the MCUboot-specific scenario generator in [`targets/mcuboot/state_fuzzer.py`](../targets/mcuboot/state_fuzzer.py).
- **Update-protocol analyzer** ([`scripts/update_protocol_analyzer.py`](../scripts/update_protocol_analyzer.py)) -- checks declarative commit paths for required security gates, metadata bindings, and authenticated content.
- **Authenticated-equivalence campaign** ([`scripts/authenticated_equivalence.py`](../scripts/authenticated_equivalence.py)) -- supports legacy duplicate/reorder and declarative coupled post-authentication copy/patch/replace mutations, then compares canonical semantic outcomes while preserving the authenticated identity. Explicit before/after evidence can also expose persistent security-state changes caused by rejected mutants. See [`docs/authenticated-equivalence.md`](authenticated-equivalence.md).
- **Pre-authentication bounds oracle** ([`scripts/preauth_bounds_oracle.py`](../scripts/preauth_bounds_oracle.py)) -- mutates synthetic nested-header length fields and detects extent escapes before signature/key consumption. See [`docs/preauth-bounds-oracle.md`](preauth-bounds-oracle.md) and [`examples/preauth_bounds_oracle/`](../examples/preauth_bounds_oracle/).
- **Authorization-review analyzer** ([`scripts/authorization_review_analyzer.py`](../scripts/authorization_review_analyzer.py)) -- compares observed parsed, reviewed, digested, signed, and authorized values using complete trace evidence.
- **NuttX runtime profile generator** ([`targets/nuttx_nxboot/generate_runtime_profile.py`](../targets/nuttx_nxboot/generate_runtime_profile.py)) -- emits `baseline`, `sector_boundary_resume`, `metadata_erase_resume`, and `sector_boundary_writeback` profiles from built nxboot artifacts.
- **Production-assert analyzer** ([`scripts/production_assert_analyzer.py`](../scripts/production_assert_analyzer.py)) -- identifies Python assertions that disappear under optimization and need reachability and impact review; candidates are not confirmed vulnerabilities.
- **Persistent-state layout analyzer** ([`scripts/security_state_layout.py`](../scripts/security_state_layout.py)) -- maps declared fields to erase units and identifies security state co-located with mutable or recovery data.
- **HTML report** ([`scripts/render_results_html.py`](../scripts/render_results_html.py)) -- renders JSON reports as HTML.
