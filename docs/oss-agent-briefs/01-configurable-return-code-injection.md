# Make return-code injection target-configurable

## Problem

The `rc_injection` fault type can reject a storage write and replace a function's
return value, but the callable symbols and return value are runtime defaults.
Profiles cannot configure them. As a result, the feature is effectively tied to
one storage wrapper and cannot accurately exercise other bootloaders or security
state writers.

## Required behavior

Add a validated configuration block under `fault_sweep`:

```yaml
fault_sweep:
  fault_types: [rc_injection]
  rc_injection_config:
    symbols: [storage_write]
    return_value: -5
    return_register: 0
    require_applied: true
```

Rules:

- `symbols` is a non-empty list of unique ELF symbol names.
- `return_value` accepts a signed or unsigned 32-bit integer and is emitted to
  the target register as its 32-bit two's-complement value.
- `return_register` defaults to `0` for the existing Arm AAPCS behavior.
- `require_applied` defaults to `true`. A run in which the requested function is
  never entered or its return hook never fires is an infrastructure failure.
- Existing profiles without this block retain the current defaults:
  `symbols: [flash_area_write]`, `return_value: -5`, `return_register: 0`.

Pass the configuration through profile inheritance, scenario resolution,
initial-state expansion, audit planning, Robot variables, and runtime telemetry.
The runtime must support nested instrumented calls by tracking active return
frames rather than storing only one active return address.

## Telemetry

Each result must include:

```json
{
  "rc_injection": {
    "configured_symbols": ["storage_write"],
    "resolved_symbols": {"storage_write": [268439552]},
    "return_value": 4294967291,
    "return_register": 0,
    "entered_calls": 1,
    "applied": true,
    "applied_symbol": "storage_write",
    "applied_return_address": 268440010
  }
}
```

Do not silently fall back to a default symbol when an explicit symbol cannot be
resolved.

## Implementation areas

- `scripts/profile_loader.py`
- `scripts/audit_bootloader.py`
- `scripts/run_runtime_fault_sweep.py`
- Robot variable wiring in `tests/ota_fault_point.robot`
- Result validation and HTML reporting
- `docs/writing-profiles.md`

## Tests

Add tests proving:

1. Strict parsing, inheritance, and serialization of every field.
2. Backward-compatible defaults for an existing MCUboot profile.
3. Unknown fields, duplicate symbols, empty symbols, and out-of-range values are
   rejected.
4. A synthetic ELF function receives the configured nonzero return value after
   the selected write is rejected.
5. Two nested configured wrappers receive the correct return hooks without
   frame confusion.
6. Missing symbols and never-applied injections fail closed.
7. JSON and HTML reports expose the configured and applied function.

## Acceptance criteria

- A profile can target an arbitrary unstripped Arm function without editing a
  RESC or Python runtime file.
- A negative-control run proves the underlying write is stored and returns
  success.
- The faulted run proves the write is absent and the selected wrapper returns
  the configured error.
- Existing `rc_injection` profiles produce unchanged results.
