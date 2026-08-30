# Tardigrade engineering briefs

These specifications document target-independent additions implemented in the
current release. Each remains a standalone design and acceptance record.

## Implementation and dependency order

1. [Configurable return-code injection](01-configurable-return-code-injection.md):
   make the existing runtime fault usable across bootloaders.
2. [Success-implies-effect contracts](02-success-implies-effect-contracts.md):
   detect security APIs that return success without making the promised durable
   change.
3. [Authenticated content coverage](03-authenticated-content-coverage.md):
   prove that bytes placed in an active store are transitively covered by
   accepted authentication.
4. [Security-state erase-domain analysis](04-security-state-erase-domain-analysis.md):
   find and exercise power-loss windows created by shared erase units.
5. [Security-counter boundary campaigns](05-security-counter-boundary-campaigns.md):
   run real updates at logical and physical capacity boundaries.
6. [Cross-component state relations](06-cross-component-state-relations.md):
   detect bootable but incompatible component combinations.
7. [Terminal-error escape campaigns](07-terminal-error-escape-campaigns.md):
   test emitted fatal paths against single-instruction skips.
8. [Reviewed-versus-signed authorization content](08-reviewed-vs-signed-content.md):
   detect review/signature coverage gaps, compare complete observed values,
   and require ordinary review for every authorization input in v1.

## Shared requirements

- Preserve existing profiles and command-line behavior.
- Reject unknown or malformed configuration fields instead of ignoring them.
- Emit deterministic JSON suitable for CI and report generation.
- Treat configured-but-unavailable instrumentation as an infrastructure error,
  not a passing security result.
- Add focused unit tests and at least one end-to-end synthetic target or fixture
  for every runtime feature.
- Add no new dependencies. Use the Python standard library and existing
  repository dependencies only.
- Do not copy third-party implementation code or add generated binaries or
  third-party source trees.
