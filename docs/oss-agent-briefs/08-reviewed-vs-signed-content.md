# Detect reviewed-versus-signed authorization content mismatches

## Problem

An authorization flow can display some fields to the user while authenticating
a larger message. A field that is signed but never reviewed can therefore be
changed without the user seeing it. Conversely, a field can appear in the
review but be omitted from the signed digest or authorization input. Device-
owned or derived values are not exempt in v1: they must be visibly reviewed
like every other authorization input. Trusted validation is reserved for a
future version with an enforceable code-side semantic verifier.

The analyzer must reason about the actual structured values parsed, reviewed,
authenticated, and authorized. Field names, source paths, or the presence of a
digest alone are not evidence that the same value was used at each stage. The
example below is a synthetic resource-authorization request.

## Required behavior

Add an optional top-level `authorization_review` profile block. It is separate
from `update_protocol`; it describes the authorization values and their review
events, while protocol event paths continue to provide the execution context:

```yaml
authorization_review:
  scalars:
    operation_token:
      path: synthetic_request.operation_token
      type: bytes
      max_bytes: 64
      review: required
      authorization: required
    requested_level:
      path: synthetic_request.requested_level
      type: uint
      width_bits: 64
      encoding: big_endian_fixed
      review: required
      authorization: required
    quota:
      path: synthetic_request.quota
      type: uint
      width_bits: 64
      encoding: big_endian_fixed
      review: required
      authorization: required
    context_token:
      path: synthetic_request.context_token
      type: bytes
      max_bytes: 64
      review: required
      authorization: required

  collections:
    resources:
      path: synthetic_request.resources
      max_items: 16
      review: required
      authorization: required
      item_scalars:
        identifier:
          type: bytes
          max_bytes: 64
          review: required
        access_level:
          type: uint
          width_bits: 64
          encoding: big_endian_fixed
          review: required

  digests:
    authorization_digest:
      algorithm: sha256
      covers: [operation_token, requested_level, quota, resources, context_token]

  events:
    parse_request:
      kind: parse
      produces: [operation_token, requested_level, quota, resources, context_token]
    review_request:
      kind: user_review
      reviews: [operation_token, requested_level, quota, resources, context_token]
    compute_authorization_digest:
      kind: digest
      digest: authorization_digest
    verify_authorization:
      kind: signature
      digest: authorization_digest
    authorize:
      kind: authorization
      requires: [operation_token, requested_level, quota, resources, context_token]

  sequences:
    - name: normal
      events:
        - parse_request
        - review_request
        - compute_authorization_digest
        - verify_authorization
        - authorize
```

Scalar declarations must include a stable field name, source path, and type.
Supported scalar types must have an unambiguous canonical encoding and bounded
representation: at minimum unsigned and signed integers, booleans, bounded
UTF-8 strings, bounded byte strings, enums, and flat collection members.
Structured scalar layouts are explicitly rejected in v1; a generic object or
an implementation-defined serializer is not a canonical value.

Every integer must declare its signedness, exact `width_bits`, and `encoding`.
Fixed-width encodings must state endianness. A variable-length encoding is
allowed only when its maximum encoded length is declared. Reject widths,
encodings, or integer ranges outside the implementation-supported set; never
coerce a signed value, unsigned value, decimal string, or floating-point value
into another integer type.

Collections must declare their source path, item-field schema, and positive
`max_items`. Every item field has the same type and size rules as a scalar.
Collection order, item count, and duplicate items are part of the canonical
value unless the declaration explicitly states an approved normalization.
There must be no unbounded traversal or implicit truncation.

`review: required` means the field or every item field must be covered by a
user-review event on the path to authorization. v1 requires that policy for
every authorization-required field and item member. Trusted exemptions are
disabled until an enforceable, code-side semantic verifier exists: profiles
using `trusted_bindings`, `trusted_binding`, `required_or_trusted`, `hidden`, or
`trusted_validation` are rejected. `authorization: required` marks an input
that must also be covered by the accepted signed authorization. v1 is flat-only:
structured scalar layouts are rejected until recursive member evidence is
defined.

Digest and signature events must name declared coverage. A digest covers only
the listed fields and collections after canonicalization. Coverage must not be
inferred from a common source path, matching field names, or a signature over a
containing object. If a digest contains another digest, propagation requires an
explicit declared digest binding and an observed verification event before
authorization.

There is no trusted-validation event in v1. A matching `pass: true` field,
authority, or rule in a forged trace is never authorization evidence.

## Trace and evidence input

Declarations alone must never produce a `PASS`. When `authorization_review` is
enabled, the analyzer consumes one `authorization_review_trace` JSON record for
each run or expanded sequence variant. The record has this minimum form:

```json
{
  "model_digest": "sha256:<64 lowercase hexadecimal characters>",
  "sequence": "normal",
  "events": [
    {
      "name": "review_request",
      "occurrence": 0,
      "complete": true,
      "reviewed": {
        "recipient": {
          "canonical_type": "bytes",
          "cardinality": 1,
          "digest": "sha256:<64 lowercase hexadecimal characters>"
        },
        "outputs": {
          "canonical_type": "collection",
          "cardinality": 2,
          "complete": true,
          "reviewed_indices": [0],
          "digest": "sha256:<64 lowercase hexadecimal characters>",
          "items": [
            {
              "index": 0,
              "fields": {
                "recipient": {
                  "canonical_type": "bytes",
                  "cardinality": 1,
                  "digest": "sha256:<64 lowercase hexadecimal characters>"
                },
                "value": {
                  "canonical_type": "uint<64,big_endian_fixed>",
                  "cardinality": 1,
                  "digest": "sha256:<64 lowercase hexadecimal characters>"
                }
              }
            }
          ]
        }
      }
    },
    {
      "name": "verify_authorization",
      "occurrence": 0,
      "complete": true,
      "accepted": true,
      "covered": ["recipient", "value", "fee", "outputs", "change"],
      "covered_values": {
        "recipient": {
          "canonical_type": "bytes",
          "cardinality": 1,
          "digest": "sha256:<64 lowercase hexadecimal characters>"
        },
        "value": {
          "canonical_type": "uint<64,big_endian_fixed>",
          "cardinality": 1,
          "digest": "sha256:<64 lowercase hexadecimal characters>"
        },
        "fee": {
          "canonical_type": "uint<64,big_endian_fixed>",
          "cardinality": 1,
          "digest": "sha256:<64 lowercase hexadecimal characters>"
        },
        "outputs": {
          "canonical_type": "collection",
          "cardinality": 2,
          "complete": true,
          "digest": "sha256:<64 lowercase hexadecimal characters>",
          "items": [
            {"index": 0, "fields": {"recipient": {"canonical_type": "bytes", "cardinality": 1, "digest": "sha256:<64 lowercase hexadecimal characters>"}, "value": {"canonical_type": "uint<64,big_endian_fixed>", "cardinality": 1, "digest": "sha256:<64 lowercase hexadecimal characters>"}}},
            {"index": 1, "fields": {"recipient": {"canonical_type": "bytes", "cardinality": 1, "digest": "sha256:<64 lowercase hexadecimal characters>"}, "value": {"canonical_type": "uint<64,big_endian_fixed>", "cardinality": 1, "digest": "sha256:<64 lowercase hexadecimal characters>"}}}
          ]
        },
        "change": {
          "canonical_type": "bytes",
          "cardinality": 1,
          "digest": "sha256:<64 lowercase hexadecimal characters>"
        }
      }
    }
  ]
}
```

`model_digest` is the digest of the canonical normalized
`authorization_review` declaration (excluding runtime evidence). The analyzer
computes it and rejects traces for another model. `sequence` must identify the
exact expanded variant. Each event occurrence is a zero-based ordinal and must
be unique for its event on that trace; `complete: true` is required for any
event used as evidence. Missing, duplicate, stale, or incomplete occurrences
are infrastructure results, not security passes.

Every produced, reviewed, covered, and authorized reference must
carry a canonical type tag, a cardinality, and a digest. The digest is over a
versioned authorization-review domain tag, the canonical type tag, an explicit
length, and canonical bytes; its external form is `sha256:` followed by
exactly 64 lowercase hexadecimal characters. For collections, parse and signed-coverage
evidence must include the exact source count and every contiguous item index
from zero through `cardinality - 1`; item-field digests are required. A
complete review event may intentionally cover a subset, but it must state the
same total `cardinality`, list exact `reviewed_indices`, and include each
reviewed index and member digest. The count must be within `max_items`, and
`complete: true` must be present. The analyzer must reject truncation, omitted
or duplicate indices, out-of-range indices, or cardinality disagreement. It
must analyze every signed `collection[index].member` reference separately.
Reports contain bounded digests and paths, not unrestricted secret values.

Parse events provide `produced` evidence; user-review events provide
`reviewed`; digest/signature events provide `covered`; and the authorization
event provides its complete required input set. The analyzer must verify event
order and compare only complete evidence from the same model, sequence variant,
and run. A missing counterpart is not a value mismatch.

## Findings

Emit:

- `AUTHORIZATION_FIELD_NOT_SIGNED` when a field or collection marked both
  `review: required` and `authorization: required`
  is present in complete parse/review/authorization evidence but is absent
  from the accepted digest/signature coverage. For collections, evaluate each
  required item/member reference separately.
- `SIGNED_FIELD_NOT_REVIEWED` when an accepted digest/signature covers a field
  or individual `collection[index].member` whose declaration is `review:
  required`, but complete review evidence does not cover that same reference
  before authorization. Analyze each signed collection item/member separately;
  two unreviewed items produce two affected paths.
- `REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE` only when complete observed
  canonical type-tagged digests for the same field or collection item are
  present in both the review and accepted signed coverage and the digests
  differ. Lack of a binding, missing coverage, or missing evidence must produce
  the more specific coverage/infrastructure result, never this finding.

Every finding must identify the model digest, exact sequence variant,
authorization event and occurrence, affected field or collection/item path,
parse event, review event or its absence, digest/signature event, cardinalities,
canonical type tags, and bounded digest evidence. A declaration error, unknown reference,
ambiguous canonicalization, missing runtime observation, or failed
instrumentation is a configuration/infrastructure result and cannot yield a
passing verdict.

## Path analysis and strict validation

Reuse or extract the existing optional-event and sequence expansion helper; do
not add a second path-expansion engine. Analyze every expanded path, including
paths where an optional review, digest, or signature event
is omitted. Enforce the existing maximum sequence-variant limit (currently
`MAX_SEQUENCE_VARIANTS`) and existing runtime observation limits. Reject a
profile or trace that would exceed those limits. Authorization must fail closed
on every path lacking required coverage, review, or complete evidence.

Reject unknown top-level fields, event kinds, scalar/collection/item names,
 references, paths, types, algorithms, and encodings.
Reject duplicate names, empty paths, non-positive or overflowing bounds,
malformed integer declarations, ambiguous structured layouts, duplicate
collection members where uniqueness is required, and events before their
inputs are produced. Reject `trusted_bindings`, `trusted_binding`,
`required_or_trusted`, `hidden`, and `trusted_validation` declarations with a
clear no-verifier error. Reject authorization rules that omit required inputs
or refer outside the declared model.

Canonicalization must be deterministic and type-strict. An absent optional
field remains distinct from explicitly encoded zero, an empty string, an empty
byte string, or an empty collection. No finding may be inferred from a source
path or declaration when the required trace evidence is unavailable.

## Implementation areas

- `scripts/authorization_review_analyzer.py` and profile parsing/serialization
- Integration with `scripts/update_protocol_analyzer.py`, including extraction/
  reuse of existing sequence-variant expansion and event-path logic
- Canonical structured-value extraction and bounded collection comparison
- Trace ingestion, model-digest validation, and finding validation
- JSON and HTML report rendering
- `tests/test_authorization_review_analyzer.py`
- Vulnerable and fixed vendor-neutral example profiles and traces
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. A required reviewed authorization field omitted from signed coverage emits
   `AUTHORIZATION_FIELD_NOT_SIGNED`.
2. A signed required-review field with complete coverage but no review emits
   `SIGNED_FIELD_NOT_REVIEWED`.
3. Hidden and `required_or_trusted` fields, trusted bindings, and trusted
   validation events are rejected because v1 has no enforceable verifier;
   forged matching `pass: true` evidence cannot produce `PASS`.
4. Identical complete canonical digests pass, and a changed operation token,
   requested level, authorization field, or quota emits
   `REVIEWED_VALUE_DIFFERS_FROM_SIGNED_VALUE`.
5. Missing signed coverage or incomplete evidence never emits a value-diff
   finding and never produces `PASS`.
6. A two-resource collection with only index 0 reviewed emits
   `SIGNED_FIELD_NOT_REVIEWED` for each signed index-1 member; reviewing both
   indices passes.
7. Trusted bindings and trusted-validation events are rejected, including
   unknown providers and rules.
8. Collection additions, removals, reordering, duplicate handling, exact
   cardinality, and item-field changes are detected within `max_items`.
9. Integer widths and encodings, booleans, strings, bytes, and
    absent-versus-empty values are compared type-strictly; structured scalar
    declarations are rejected as unsupported in v1.
10. Model-digest mismatch, wrong sequence variant, duplicate occurrences,
    incomplete events, missing fields, stale traces, and failed instrumentation
    are rejected as infrastructure/configuration results.
11. Review, digest, and signature events before parsing or authorization are
    rejected or produce unavailable-evidence results.
12. Optional groups are analyzed on both present and omitted paths using the
    existing variant limit, with findings naming the omitted event and variant.
13. Unknown declarations, references, types, algorithms, paths, bounds,
    duplicate names, malformed bindings, and ambiguous canonicalization are
    rejected.
14. Profiles without `authorization_review` parse and produce unchanged
    verdicts.

## Acceptance criteria

- The analyzer distinguishes parsed, user-reviewed, signed/digested, and
  authorized values on every expanded path.
- A `PASS` requires complete trace evidence tied to the canonical model digest,
  exact sequence variant, event occurrences, cardinalities, and type-tagged
  field digests; declarations alone cannot pass.
- It covers scalar fields and bounded flat collections without silently
  dropping, truncating, reordering, or normalizing values.
- Collection review is evaluated per signed item/member: total source
  cardinality and exact reviewed indices are required.
- The finding IDs are emitted only under their specified evidence conditions;
  malformed models and unavailable instrumentation fail closed as
  configuration/infrastructure results.
- Trusted exemptions are rejected until an enforceable code-side semantic
  verifier is available.
- Existing update-protocol profiles, command-line behavior, findings, and
  verdicts remain unchanged when the optional block is absent.
- The implementation uses only existing repository dependencies and adds no
  third-party code or generated binaries.
