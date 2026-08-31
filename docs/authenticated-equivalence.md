# Authenticated-equivalence campaigns

`scripts/authenticated_equivalence.py` checks whether a parser gives the same
security result when unauthenticated TLV records are duplicated or reordered.
The campaign is grammar-aware: it parses a bounded TLV stream, locates exactly
one declared authentication-boundary record and signature record, and mutates
only records after both (the later record when they are distinct). A single
record may serve as both boundary and signature. The authenticated bytes and
signature must remain byte-for-byte identical.

The black-box harness command receives a temporary input path through
`{input}` and must print one JSON object. It must hash the exact bytes it read
and include:

- `input_sha256`;
- `authenticated_bytes_b64`, `authenticated_digest`, and `signature_bytes_b64`;
- every field named in `outcomes`, including `accepted` and `committed`.

The campaign independently checks `input_sha256` against the supplied bytes,
and checks the authenticated identity against the parsed records. The harness
is responsible for real cryptographic signature verification; this campaign
does not implement or imply cryptographic verification.

The campaign fails closed for malformed input/configuration, empty mutations,
timeouts, non-zero harness exits, malformed output, missing fields, or any
authenticated-identity drift. A safe parser rejection is never a finding. A
finding is semantic only: it records a divergent declared outcome such as
acceptance, commit, version, target, size, installed payload digest, or rollback
result. Parser crashes are not findings.

The synthetic vulnerable/fixed harness is in
[`examples/authenticated_equivalence/`](../examples/authenticated_equivalence/):

```sh
python3 scripts/authenticated_equivalence.py \
  --config examples/authenticated_equivalence/vulnerable.yaml \
  --report /tmp/authenticated-equivalence.json
```

The example's `mode` can be changed from `vulnerable` to `fixed`; the former
produces a duplicate-payload finding, while the latter safely rejects that
mutant and passes. Mutation IDs are stable (`m0001`, `m0002`, ...) and reports
use sorted JSON keys for reproducible postmortems. Reports include the
normalized campaign configuration, configured harness argv (with `{input}`
left as a placeholder), and each mutant's exact input SHA-256 and byte size;
runtime temporary paths are not recorded. Retain the report, configuration,
and harness executable/source together so a result can be reproduced.

Configuration and harness commands are trusted executable inputs. The
subprocess timeout limits campaign waiting only; it is not a sandbox or a
containment boundary.

Configurations are intentionally standalone rather than silently expanding the
runtime fault-sweep schema. They can be referenced by a profile or CI job that
has an authenticated parser/harness command. Keep campaign additions generic
and Apache-2.0-only.
