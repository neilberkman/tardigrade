# Generate boundary campaigns for security counters

## Problem

Counter implementations commonly confuse byte capacity, element count, bit
count, encoded width, and logical maximum. These defects may appear only at the
first value beyond physical capacity and do not require an injected storage
fault. The metadata state fuzzer mutates stored bytes, but it does not drive a
real update sequence with systematically chosen logical counter values.

## Required behavior

Add top-level boundary campaign declarations that expand into ordinary named
initial-state or scenario runs:

```yaml
boundary_campaigns:
  - name: synthetic_epoch_capacity
    parameter: candidate_epoch
    type: unsigned_integer
    width_bits: 32
    capacity:
      storage_bytes: 64
      element_bytes: 4
    values:
      - zero
      - one
      - capacity_minus_one
      - capacity
      - capacity_plus_one
      - type_max
    setup_environment: CANDIDATE_EPOCH
```

`capacity` accepts exactly one of these forms:

- `{elements: 16}` for an explicitly known physical slot count;
- `{storage_bytes: 64, element_bytes: 4}` for an array of fixed-size entries;
- `{storage_bytes: 8, bits_per_increment: 1}` for bit-packed monotonic state.

Byte-based division must be exact. Bit-packed capacity is
`storage_bytes * 8 / bits_per_increment` and must also divide exactly. All
intermediate arithmetic is checked against the implementation safety limit.

Value names resolve as follows:

- `capacity` is the logical capacity derived from the selected capacity form.
- `capacity_minus_one` and `capacity_plus_one` use checked arithmetic.
- `type_max` is `(1 << width_bits) - 1` with an implementation safety limit.
- Literal integer values are also accepted.
- Duplicate resolved values are removed while preserving declaration order.

For each resolved value, pass its canonical decimal representation to the setup
script using the configured environment variable. Expand the profile into a
named run such as `synthetic_epoch_capacity__17`. The setup script may build or
select the corresponding signed test artifact, but campaign expansion itself
must remain deterministic and cacheable.

Support a two-phase relation check:

```yaml
    follow_up:
      parameter_value: previous
      expect: rejected
```

For a candidate value `N`, `previous` means `N - 1`. The first phase installs or
boots `N`; the second phase attempts `N - 1`. Profiles express each phase using
the existing update-sequence mechanism. The campaign runner supplies parameter
values; it does not duplicate update execution logic.

## Reporting

Aggregate results by campaign and resolved value. A report must distinguish:

- candidate rejected before persistence;
- candidate accepted and correctly persisted;
- candidate accepted but persisted state is smaller;
- lower follow-up value accepted;
- infrastructure/setup failure.

## Implementation areas

- `scripts/profile_loader.py`
- Initial-state/scenario expansion helpers
- `scripts/audit_bootloader.py` and `scripts/sweep.py`
- Setup-script environment handling and cache identity
- JSON and HTML summary rendering
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. Named and literal boundary values resolve correctly.
2. Invalid widths, zero element size, non-divisible capacity, overflow, and an
   invalid `previous` value are rejected.
3. Expansion order and names are deterministic.
4. Cache keys differ for different parameter values.
5. Setup scripts receive the declared campaign variable and value without any
   undeclared campaign-specific variables.
6. Explicit, entry-array, and bit-packed capacities resolve to the expected
   logical boundary.
7. A synthetic counter with 16 physical entries accepts and persists 16.
8. A defective synthetic counter accepts 17 but persists 16, then accepts the
   follow-up value 16; the aggregate verdict is a monotonic-policy failure.
9. A corrected counter rejects 17 and passes the campaign.

## Acceptance criteria

- One declarative campaign exercises the first value beyond physical capacity
  and proves its downstream monotonic-policy consequence.
- Control-only bugs are reported without requiring a fake injected fault.
- Existing manually enumerated `initial_states` remain supported.
