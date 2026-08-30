# Generate terminal-error escape campaigns from emitted code

## Problem

Validation and policy failures often terminate through a single panic,
fatal-handler, or declared non-returning call. Skipping that call can let
execution continue toward a forbidden state commit even when source-level
control flow appears terminal. Source-only review is insufficient because
optimization may tail-merge handlers, remove return paths, or eliminate
attempted redundancy. The names below describe a synthetic state machine.

## Required behavior

Add a binary-driven campaign declaration:

```yaml
terminal_error_paths:
  - name: rejected_request
    handler_symbols: [reject_request]
    containing_symbols: [process_candidate]
    forbidden_sink_symbols: [commit_state]
    expected_control: terminal
```

For every direct call or tail call from a containing symbol to a handler symbol:

1. Resolve the emitted instruction address from the ELF and disassembly.
2. Run a control that triggers the failure path and prove the handler callsite
   is reached while no forbidden sink is reached.
3. Run an instruction-skip fault at that exact emitted instruction.
4. Continue execution for the configured observation window.
5. Emit `TERMINAL_ERROR_PATH_ESCAPED` if any forbidden sink is reached.

The control and faulted runs must begin from the same restored snapshot and use
the same input. Record hashes of the snapshot identity and injected artifact in
both results so the report can prove the differential changed only the selected
instruction.

Use existing Thumb instruction classification and instruction-skip execution.
Do not infer a finding from source annotations alone. Unsupported indirect calls
must be reported as unresolved candidates, not silently ignored or treated as
passing.

Record the containing symbol, handler symbol, callsite address, instruction
bytes, disassembly text, control evidence, fault-applied evidence, and first
forbidden sink reached.

Support an optional `required_failure_marker` from existing success/failure
observation facilities so the control proves the intended validation error was
actually triggered.

If `required_failure_marker` is configured, use the existing success-criteria
memory-check representation rather than adding another marker grammar. The
control must satisfy that marker before the handler callsite; a marker first
observed after the callsite is inconclusive.

## Implementation areas

- ELF symbol and disassembly helpers
- `scripts/thumb_instructions.py` and instruction-skip planning
- `scripts/audit_bootloader.py`
- Runtime symbol hooks and result telemetry
- JSON and HTML reporting
- `docs/writing-profiles.md`

## Tests

Add emitted-code fixtures proving:

1. A direct `BL reject_request` callsite is discovered.
2. A tail call to the handler is discovered.
3. An unrelated call to the same handler outside `containing_symbols` is not
   selected.
4. The control must reach the callsite and remain terminal.
5. Skipping the sole handler call and reaching `commit_state` produces the new
   finding.
6. A second independent status gate or explicit terminal fallback prevents the
   sink and passes.
7. A source-level return path optimized out of the ELF is not credited as a
   mitigation.
8. Missing symbols, ambiguous ranges, unsupported indirect calls, and a control
   that never triggers the failure are reported as infrastructure or unresolved
   results.

## Acceptance criteria

- The campaign is generated from the exact ELF being tested.
- A finding requires a successful fault application and observed forbidden sink,
  not merely a skipped instruction.
- The hardened negative control proves the sink remains unreachable under the
  same skip model.
