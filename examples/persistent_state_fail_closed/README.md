# Persistent-state fail-closed invariant

This target-neutral fixture models a security-sensitive persistent-state
operation. A failed state read must not cause the operation to write state or
reach an accepted, committed, or booted outcome.

The vulnerable trace demonstrates both prohibited effects. The fixed trace
aborts without a write. A real profile emits the same records from its
`state_probe`; the built-in `persistent_state_fail_closed` invariant reads
them from the resulting semantic state.

```bash
python3 examples/persistent_state_fail_closed/harness.py --mode vulnerable
python3 examples/persistent_state_fail_closed/harness.py --mode fixed
```

The vulnerable trace is a regression fixture, not evidence of a vendor bug.
It becomes a reportable finding only when a real target supplies equivalent
telemetry and a clean control plus concrete downstream security impact.
