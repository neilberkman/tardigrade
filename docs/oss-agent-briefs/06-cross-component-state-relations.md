# Add relational invariants across components

## Problem

Atomic-state checks can detect a partial transition where one component is
updated and another remains old. They cannot express broader compatibility
rules such as equal generations, bounded generation distance, or an explicit
set of allowed controller/worker generation pairs. A system may start while
running a forbidden combination.

## Required behavior

Add a built-in invariant named `state_relations`:

```yaml
invariants: [state_relations]
invariant_config:
  state_relations:
    - name: controller_and_worker_generation_match
      compare:
        left: {source: post, path: components.controller.generation}
        op: eq
        right: {source: post, path: components.worker.generation}

    - name: approved_component_pairs
      when:
        left: {source: post, path: update.activated}
        op: eq
        right: {value: true}
      allowed_tuples:
        fields:
          - {source: post, path: components.controller.generation}
          - {source: post, path: components.worker.generation}
        values:
          - [1, 4]
          - [2, 5]
```

Comparison operators are `eq`, `ne`, `lt`, `le`, `gt`, and `ge`. Operands may
reference `pre` or `post` state, or provide a literal `value`. Numeric ordering
uses the same strict numeric conversion as `monotonic_state_fields`; equality
also supports strings and booleans without coercing their types.

`allowed_tuples` requires at least two fields and one allowed tuple. Every tuple
must match the field count and value types. Duplicate tuples are rejected.

Evaluate relations on control and faulted runs by default. Allow an optional
`when` condition using the same operand and comparison format so a relation can
apply only after activation or only when a component reports itself valid.

Each operand must contain exactly one of `path` or `value`. A path operand must
also contain `source: pre` or `source: post`; a literal value must not contain a
source. Reject a comparison whose operator is incompatible with the resolved
types.

Emit `STATE_RELATION_VIOLATION` with the relation name, resolved operands or
tuple, expected rule, run phase, and component identifiers. Missing paths and
invalid types are evaluation errors.

## Implementation areas

- `scripts/profile_loader.py` validation
- `scripts/invariants.py`
- Multi-component state reporting
- `scripts/finding_validator.py`
- JSON and HTML rendering
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. Equal and ordered comparisons pass and fail correctly.
2. Pre-state to post-state comparisons work.
3. Allowed tuples accept listed combinations and reject mixed combinations.
4. String, boolean, and numeric type handling is strict.
5. `when` skips or enables a relation correctly.
6. Missing paths and malformed relations fail closed.
7. A two-component synthetic update produces an atomic all-after state that is
   nevertheless version-incompatible and is caught only by `state_relations`.
8. JSON and HTML output identify both components and their observed versions.

## Acceptance criteria

- Profiles can express compatibility requirements without custom Python
  invariant providers.
- A successful boot that violates a configured compatibility rule is reported
  as a security finding.
- Existing atomic and monotonic invariants remain unchanged.
