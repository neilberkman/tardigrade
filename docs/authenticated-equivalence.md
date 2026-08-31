# Authenticated-equivalence campaigns

Schema version 2 is the current format. `scripts/authenticated_equivalence.py`
checks whether a parser gives the same
canonical semantic outcome when unauthenticated TLV records are duplicated or
reordered, or when declarative coupled copy/patch/replace cases mutate the
post-authentication tail. The campaign is grammar-aware: it parses a bounded
TLV stream, locates exactly one declared authentication-boundary record and
signature record, and mutates only records after both (the later record when
they are distinct). A single record may serve as both boundary and signature.
The authenticated bytes and signature must remain byte-for-byte identical.

The black-box harness command receives a temporary input path through
`{input}` and must print one JSON object. It must hash the exact bytes it read
and include:

- `input_sha256`;
- `authenticated_bytes_b64`, `authenticated_digest`, and `signature_bytes_b64`;
- every field named in `outcomes`, including `accepted` and `committed`.

In schema version 2, the `outcomes` list must also include the campaign's canonical semantic fields:
`rollback_outcome`, `version`, `target`, `size`, `installed_payload_digest`,
and `security_state`. Additional target-specific fields may be listed. This
prevents a profile from accidentally omitting the accepted version, destination,
payload size, installed payload identity, or post-authentication security state
from the equivalence check.

Harness values are validated as well: `security_state` must be a JSON object,
`rollback_outcome` must be a non-empty string, an accepted result must report a
non-negative integer `size`, and a committed result must report a lowercase
SHA-256 `installed_payload_digest`. Rejected mutants may use null or otherwise
inapplicable install fields because they are not treated as accepted installs.
For rejected-mutant side-effect detection, a harness may additionally provide
`security_state_before` and `security_state_after` JSON objects. Both must be
present for every run, the `before` object must match the base run, and `after`
must equal the required `security_state` field. A rejected mutant is reported
only when this explicit transition changes state. This avoids treating the
accepted base's new absolute state versus a rejected mutant's unchanged old
state as a finding. Existing v2 harnesses without transition evidence remain
valid, but cannot establish rejected side effects. The ordinary rejection value
of `rollback_outcome` is not compared on rejection because it commonly changes
from the baseline's successful outcome to a rejection label; any persistent
rollback effect belongs in the explicit state transition or `security_state`.
Accepted mutants compare every canonical semantic outcome, including the
rollback result.

The campaign independently checks `input_sha256` against the supplied bytes,
and checks the authenticated identity against the parsed records. The harness
is responsible for real cryptographic signature verification; this campaign
does not implement or imply cryptographic verification.

By default, `authentication.coverage` is `prefix_through_boundary`, preserving
the original behavior. Formats whose signature precedes the covered region may
use `signature_before_boundary`; it requires one signature strictly before one
boundary and covers the records immediately after the signature through the
boundary (respecting `include_boundary`). The signature and covered bytes are
reconstructed independently for every mutant, and any drift fails closed.

Declarative mutation cases can express coupled, deterministic operations while
legacy `duplicate_types`/`reorder_types` remains supported:

```yaml
mutations:
  max_mutants: 8
  cases:
    - id: replace-streamed-descriptor
      operations:
        - operation: duplicate
          source: {type: 16, occurrence: 1}
          insert_index: 5
          patches:
            - {offset: 0, bytes_hex: "ff"}
        - operation: patch
          target: {type: 32, occurrence: 1}
          patches:
            - {offset: 0, bytes_file: payload.bin}
```

Selectors use either an exact zero-based `index`, or a one-based
`type`/`occurrence` pair; omitting an occurrence is ambiguous and rejected.
Duplicate sources may come from anywhere, but insertion destinations and
replace/patch targets must be strictly after both authentication delimiters.
`insert_index` inserts before that index; `insert_after` accepts the same
selector form. `value_hex`/`value_file` replace a complete target value, while
patches replace non-overlapping in-bounds byte ranges. Files are resolved under
the configuration directory and bounded in size. New TLV headers are rebuilt
with the grammar's widths and byte order; no-op, malformed, ambiguous, or
out-of-bounds cases fail closed.

The campaign fails closed for malformed input/configuration, missing canonical
semantic outcome fields in v2, empty mutations, timeouts, non-zero harness exits,
malformed output, missing fields, or any
authenticated-identity drift. A safe parser rejection is not a finding. A
finding is semantic only: it records a divergent declared outcome such as
acceptance, commit, version, target, size, installed payload digest, or rollback
result for an accepted mutant, or an explicit persistent security-state
transition for a rejected mutant. Parser crashes are not findings.

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

Explicit schema version 1 remains accepted for older campaigns. It requires
only the legacy `accepted` and `committed` outcomes, so it cannot detect
divergence in version, target, size, installed payload, rollback, or security
state; v2 is required for those canonical checks. Version 1 is limited to
legacy duplicate/reorder mutations with `prefix_through_boundary` coverage;
declarative `cases` and `signature_before_boundary` are v2-only. Reports
preserve the selected schema version.

Configuration and harness commands are trusted executable inputs. The
subprocess timeout limits campaign waiting only; it is not a sandbox or a
containment boundary.

Configurations are intentionally standalone rather than silently expanding the
runtime fault-sweep schema. They can be referenced by a profile or CI job that
has an authenticated parser/harness command. Keep campaign additions generic
and Apache-2.0-only.
