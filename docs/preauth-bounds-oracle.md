# Synthetic pre-authentication bounds oracle

`scripts/preauth_bounds_oracle.py` is a small, standalone campaign for nested
binary headers.  It is useful when a parser reads attacker-controlled total,
used, signature, and key lengths before authentication.  The independent
model computes half-open component and authentication extents using checked
integer arithmetic.  It reports `PREAUTH_BOUNDS_ESCAPE` when a black-box
harness begins consuming signature/key material or cryptographic verification,
accepts, or commits an input that the model says must be rejected first.  This
does not require the target to accept the input: reaching authentication and
then rejecting is still evidence that the pre-auth extent check was skipped.

The model is deliberately generic and target-neutral.  Field offsets are
relative to `layout.component_offset`; component and authentication extents are
declared by the campaign, while the four field names identify the length roles:

```yaml
layout:
  byteorder: little
  component_offset: 0
  component_length: 40
  authentication_offset: 8
  authentication_length: 16
  authentication_header_size: 4
  fields:
    total_length: {offset: 0, width: 2}
    used_length: {offset: 2, width: 2}
    signature_length: {offset: 8, width: 2}
    key_length: {offset: 10, width: 2}
```

The harness command receives `{input}` and may receive `{mode}` and mutation
identifiers.  It must print one JSON object containing boolean `accepted`,
`committed`, and `auth_attempted`, plus the SHA-256 `input_sha256`.
`auth_attempted` means that the target began consuming signature/key material
or began cryptographic verification; dispatching to an authentication wrapper
alone does not count.  A canonical input must be accepted and reach
authentication.  The harness remains
responsible for any real parser or cryptographic behavior; this oracle does
not claim to verify signatures and does not classify crashes.

Run the original minimal fixture with:

```sh
python3 scripts/preauth_bounds_oracle.py \
  --config examples/preauth_bounds_oracle/vulnerable.yaml \
  --report /tmp/preauth-bounds.json
```

The vulnerable fixture intentionally omits the extent checks and reports
findings.  Change `mode` to `fixed` (or use `fixed.yaml`) to see unsafe mutants
rejected before authentication.  The fixture is synthetic and does not copy or
import any vendor bootloader code.  This campaign is opt-in and does not alter
existing profile schemas, runtime sweeps, or CLI commands.

Limitations: the model checks only the declared four fields and fixed extents;
it cannot prove that a target parser uses those fields, detects machine-word
wraparound, or checks every other header invariant.  Keep campaign inputs and
harnesses small; long-running fuzzing and CPU-heavy execution belong on a
separate worker.
