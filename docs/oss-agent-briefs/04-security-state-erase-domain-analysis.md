# Analyze security-state erase-domain coupling

## Problem

Flash erases operate on physical units that are often larger than individual
state records. A synthetic monotonic policy epoch or authorization record
can therefore share an erase unit with frequently updated non-security state.
Updating the unrelated field creates a power-loss window that can erase or
reinitialize the security state even when the logical records do not overlap.
Address-overlap validation does not identify this risk.

## Required behavior

Add an optional top-level declaration:

```yaml
persistent_state_layout:
  erase_regions:
    - {start: 0x08010000, end: 0x08020000, erase_size: 0x2000}
  fields:
    - name: policy_epoch
      base: 0x08012000
      size: 8
      role: security_monotonic
    - name: display_preference
      base: 0x08012020
      size: 4
      role: mutable
```

Supported roles are `security_monotonic`, `security_authorization`,
`security_secret`, `recovery`, and `mutable`. Fields must be nonempty,
non-overlapping address intervals. Erase regions must be non-overlapping,
ordered, and exactly divisible by their erase size.

All address intervals use `[start, end)` semantics. Every field must be fully
contained in the union of declared erase regions. A field may cross erase-unit
boundaries, but it may not cross a gap or a boundary between regions with
conflicting geometry. Reject arithmetic overflow and geometry that cannot map
every byte of a field to exactly one physical erase unit.

Add an offline analyzer that maps every field to the physical erase units it
occupies. Emit `SECURITY_STATE_SHARED_ERASE_UNIT` when an erase unit contains
both a security-role field and a mutable or recovery field. The finding must
name the physical unit and every resident field. Classify this as a candidate
risk, not a validated security failure; the runtime campaign and invariants
determine whether the coupling is exploitable.

Add a semantic fault selector named `security_state_erase`. It selects power
cuts at:

1. the erase operation for each flagged physical unit;
2. the first write after that erase;
3. the last write restoring each security-role field in that unit.

Prefer the calibration erase/write trace. If the trace lacks erase events, use
the declared geometry. If neither source can identify the physical erase unit,
fail the campaign preflight.

When trace-derived erase boundaries disagree with declared geometry, report an
infrastructure error with both ranges. Do not silently choose one model.

This selector reuses the existing power-loss execution and reboot path. It does
not introduce a new storage fault implementation.

## Implementation areas

- `scripts/profile_loader.py`
- `scripts/layout_validation.py` or a dedicated layout-risk analyzer
- `scripts/fault_plan.py`
- Calibration trace utilities
- JSON and HTML reporting
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. Two logical fields in the same uniform erase unit are reported.
2. Fields in adjacent units are not reported.
3. Nonuniform erase regions map addresses correctly.
4. A field crossing an erase boundary is mapped to both units.
5. Overlapping fields and malformed geometry fail profile loading.
6. Calibration erases take precedence over fallback geometry.
7. The semantic selector emits the erase, first-restoration, and
   final-restoration cutpoints without duplicates.
8. A synthetic target loses a policy epoch only when power is cut during an
   unrelated mutable-field update in the shared unit.
9. The same target with the fields separated into different units passes.

## Acceptance criteria

- Tardigrade can report physical erase coupling before running a full sweep.
- A runtime campaign automatically concentrates on the relevant recovery
  window and reports the resulting monotonic-state violation.
- Profiles without `persistent_state_layout` behave unchanged.
