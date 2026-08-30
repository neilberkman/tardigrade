# Add success-implies-effect contracts

## Problem

State-changing operations sometimes report success even though the required
durable transition did not occur. The examples below use a synthetic generation
marker that must increase after a successful commit. Current invariants can
inspect persistent state, but they cannot condition a postcondition on a
captured function return value.

## Required behavior

Add function-return probes that work in every execute-mode campaign, independent
of instruction-skip faults:

```yaml
fault_sweep:
  function_return_probes:
    - label: persist_generation
      symbol: commit_generation
      return_register: 0
      capture: last
```

Supported `capture` modes are `first`, `last`, and `all`. Results record call
count, raw 32-bit values, and resolved entry/return addresses.

Implement this by generalizing the existing verification-probe hook and
telemetry code. Keep `verification_probes` as the compatible instruction-skip
configuration and evaluation path. Do not create a second runtime hook system.

Add a built-in invariant named `success_implies_effect`:

```yaml
invariants: [success_implies_effect]
invariant_config:
  success_implies_effect:
    - name: generation_is_persisted
      probe: persist_generation
      success_values: [0]
      call: last
      evaluate_control: true
      require:
        all:
          - {source: post, path: state.commit_generation, op: ge, value: 6}
          - {source: post, path: state.commit_generation, op: gt_pre}
```

The condition language must support `eq`, `ne`, `lt`, `le`, `gt`, `ge`,
`gt_pre`, `ge_pre`, `lt_pre`, `le_pre`, `changed`, and `unchanged`. Conditions
read values from the existing semantic pre-state and post-state dictionaries.
An `any` group succeeds when at least one child condition succeeds; an `all`
group requires every child.

`call` selects the captured invocation used by the contract. It accepts
`first`, `last`, or a zero-based non-negative integer. It defaults to the
probe's `capture` mode when that mode is `first` or `last`. A probe using
`capture: all` must set `call` explicitly. Reject an index that is absent in the
run rather than silently selecting another invocation. A later extension may
add aggregate call semantics, but they are not part of this ticket.

If the probe returns a configured success value and the required effect is not
observed, emit `SUCCESS_WITHOUT_REQUIRED_EFFECT`. A non-success return does not
violate the contract. Missing probes, missing paths, ambiguous multi-call data,
or malformed values are evaluation errors.

## Implementation areas

- A reusable function-entry/return probe module shared with verification probes
- `scripts/profile_loader.py`
- `scripts/run_runtime_fault_sweep.py`
- `scripts/invariants.py`
- `scripts/finding_validator.py`
- JSON and HTML reporting
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. A successful return plus the required mutation passes.
2. A successful return with unchanged state produces the new finding.
3. A failure return with unchanged state does not produce the finding.
4. `any` and `all` groups evaluate correctly.
5. Pre/post numeric comparisons accept integer and hexadecimal text values.
6. Missing return telemetry or semantic state fails closed.
7. Control runs are evaluated when `evaluate_control: true`.
8. `capture: all` requires an explicit call selector, and an absent selected
   call is an evaluation error.
9. A synthetic runtime target demonstrates both normal and injected
   false-success behavior.

## Acceptance criteria

- A profile can prove that a security API returned success and that its promised
  durable effect did not occur in the same run.
- The report contains the return value, pre-state value, post-state value, fault
  point, and contract name.
- Existing verification probes and invariants retain their behavior.
