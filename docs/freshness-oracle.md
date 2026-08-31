# Freshness-aware metadata oracle

`scripts/freshness_oracle.py` is a target-neutral state oracle for update
protocols that keep installed-image state and authenticated metadata in
separate storage or refresh channels. It is designed for synthetic fixtures
and black-box harnesses.

The profile declares an initial state and scenarios containing four event
types:

- `advance_time`: move the modeled clock forward;
- `refresh_failure`: make metadata refresh unavailable or failed;
- `update_installed`: advance only the installed-image channel;
- `update_metadata`: replace the authenticated metadata channel.

Authenticated metadata includes the version, target, and payload digest that
the implementation claims to select. Keeping that payload digest separate from
the installed-channel digest lets a mixed-channel campaign demonstrate an
actual stale-selection differential rather than merely observing a metadata
read.

Every campaign must begin with exactly one empty-event `baseline` scenario.
That control must be accepted and must not already report an installed-state
regression. The harness is invoked with a JSON scenario path (`{scenario}`)
and must return:

```json
{
  "accepted": false,
  "committed": false,
  "rollback_outcome": "rejected-expired",
  "version": null,
  "target": null,
  "size": null,
  "installed_payload_digest": "<sha256>",
  "metadata": {
    "authenticated_digest": "<sha256>",
    "version": 1,
    "target": "stable",
    "payload_digest": "<sha256>",
    "expires_at": 100,
    "now": 101,
    "expired": true,
    "refresh_failed": true
  },
  "metadata_used": false,
  "security_state": {}
}
```

`metadata` must exactly match the independent model. `metadata_used` is the
harness's explicit statement that authenticated metadata participated in the
security decision. A finding requires expired metadata to be used by an
accepted or committed decision and for at least one canonical outcome (or the
post-decision `security_state`) to differ from the fresh baseline. Merely
reading expired metadata, rejecting it, or accepting an identical result is
not a finding. The report records `EXPIRED_AUTHENTICATED_METADATA_USE` and
includes any differences from the baseline in acceptance, commit, rollback,
version, target, size, installed payload, or security state.

The oracle also checks every accepted result against the installed channel
itself, including scenarios whose metadata is still fresh. It records an
`INSTALLED_STATE_REGRESSION` when an accepted selection is older than the
installed version, changes the same-version target, or commits a different
payload at an equal-or-older version. An expired scenario that already
qualifies for `EXPIRED_AUTHENTICATED_METADATA_USE` keeps that finding ID and
includes the installed-state regression as nested evidence, so one scenario
does not produce duplicate findings. This check does not depend on the harness
redundantly echoing `installed_version` in `security_state`.

The declaration must match the real implementation's clock, expiry comparison,
refresh behavior, persistence boundaries, and channel semantics. A clean
synthetic result is not evidence that an undeclared implementation behaves the
same way.

This oracle models authenticated metadata only: `authenticated_digest` denotes
metadata that has already passed the target's signature/authentication check.
Unauthenticated, unsigned, or malformed metadata is a separate parser or
authentication campaign and cannot be reported as expired authenticated
metadata by this oracle.

For grammar-aware post-authentication content mutations where authenticated
bytes and signature bytes must remain identical while canonical outcomes are
compared, use the separate
[`authenticated-equivalence` campaign](authenticated-equivalence.md). This
freshness oracle intentionally models time and channel transitions rather than
duplicating that record-level equivalence contract.

## Fuzzer harness preflight

`scripts/fuzzer_harness.py` qualifies a parser harness before fuzzing. Declare
one known-valid seed and one known-invalid control. The default contract is
JSON output containing a boolean `accepted` field, with `true` for the valid
seed and `false` for the invalid seed. Output markers can instead be declared
when a harness does not expose a JSON outcome. Every control must exit
successfully; a non-zero exit is an infrastructure failure, not an expected
parser result.

Use `--json` for CI:

```bash
python3 scripts/fuzzer_harness.py \
  --config examples/fuzzer_harness/preflight.yaml --json
```

The preflight returns `PASS` or `INFRASTRUCTURE_FAILURE`. Missing seeds,
non-zero exits, aborts, timeouts, malformed output, and mismatched controls are
always infrastructure failures and carry an empty `product_findings` list.
They must be fixed or explicitly investigated before interpreting fuzzer
results. Seed files are staged under opaque temporary paths, and the harness
receives no valid/invalid case label; it must derive its result from the input
bytes.
