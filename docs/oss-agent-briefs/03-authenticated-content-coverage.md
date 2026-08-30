# Analyze authenticated coverage of committed content

## Problem

A protocol can authenticate a signed control record while committing a separate
resource bundle that is not transitively covered by the accepted authentication
result. Event-level authentication analysis cannot distinguish “a signature was
checked” from “the bytes placed in the active store were covered by that
signature.” The example is a synthetic deployment transaction, not a model of a
particular product or package format.

## Required behavior

Extend `update_protocol` with content and destination declarations:

```yaml
update_protocol:
  content:
    control_record: {semantic: signed_control_record}
    resource_bundle: {semantic: resource_bundle}

  destinations:
    quarantine: {role: staging}
    active_store: {role: executable, require_modeled_content: true}

  content_bindings:
    resource_digest:
      authenticated_parent: control_record
      child: resource_bundle
      method: digest

  events:
    verify_control_record:
      kind: authentication
      covers: [control_record]
    verify_resource_digest:
      kind: content_binding
      content_binding: resource_digest
    write_resource_bundle:
      kind: write
      content: resource_bundle
      destination: active_store
    commit_bundle:
      kind: commit
      destinations: [active_store]
```

Add `write` and `content_binding` as event kinds. Authentication events may
declare directly covered content. A content-binding event propagates coverage
from an already covered parent to a child only when it references a declared
binding. Commit events may declare `destinations`. A content item written to a
committed destination must have direct or transitively derived coverage on
every path before that commit.

A string content reference denotes the entire item. To model block or range
verification, a content declaration may include a byte `size`, and an event may
refer to `{content: resource_bundle, offset: 0, size: 4096}`. Ranges are half-open,
must stay within the declared size, and are valid only for content with a known
size. The analyzer must normalize interval unions rather than tracking bytes
individually. Coverage of several ranges counts as complete only when their
union covers every range written to the committed destination. Whole-item
bindings such as a signed digest cover the entire child item.

Reject a binding event that occurs before its parent is covered. Do not treat a
control-record signature as covering a resource bundle merely because both
content items are present in the model. The digest or equivalent relation
between them must have its own event on the analyzed path.

Emit:

- `UNAUTHENTICATED_COMMITTED_CONTENT` when committed content lacks coverage.
- `CONTENT_AUTHENTICATED_AFTER_COMMIT` when coverage occurs only after commit.
- `COMMIT_DESTINATION_WITH_UNKNOWN_CONTENT` when a committed destination has no
  modeled write and the model requires complete destination coverage.

Multiple authentication strategies must work. For example, either a final
global content hash or complete per-block verification may cover a resource bundle.
Use explicit alternative sequences or optional groups already supported by the
protocol analyzer; do not add a second path-expansion engine.

`require_modeled_content` defaults to `false`. When true, committing a
destination without any preceding modeled write emits
`COMMIT_DESTINATION_WITH_UNKNOWN_CONTENT`. `role: staging` does not itself
require authenticated coverage. Moving or copying staging content into an
executable destination must be represented by a write event and becomes
subject to the rule.

## Implementation areas

- `scripts/update_protocol_analyzer.py`
- Update-protocol parsing and profile serialization
- `tests/test_update_protocol_analyzer.py`
- Vulnerable and fixed vendor-neutral example profiles
- `docs/writing-profiles.md`

## Tests

Add tests covering:

1. Control-record-only authentication followed by resource-bundle commit fails.
2. An authenticated control record plus a resource-digest binding before commit passes.
3. A resource-digest binding before control-record authentication does not create
   coverage.
4. Direct resource authentication before commit passes.
5. Per-block authentication covering the entire resource passes.
6. Partial or overlapping byte ranges are normalized correctly, and a gap in
   coverage fails.
7. An optional verification path omitted on one sequence fails only that path.
8. Verification after commit reports the ordering-specific finding.
9. Writes to staging without activation do not fail.
10. A quarantine-to-active-store copy without resource coverage fails.
11. Unknown content, destination, binding, or event references are rejected.
12. Invalid, overflowing, and out-of-bounds ranges are rejected.
13. Path expansion remains bounded by the existing maximum.

## Acceptance criteria

- The analyzer can distinguish control-record authenticity from resource authenticity.
- Every finding names the sequence, content item, destination, write event,
  commit event, and authentication events observed on that path.
- Existing update-protocol profiles parse and produce unchanged verdicts.
