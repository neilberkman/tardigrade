# Freshness oracle example

This synthetic campaign models a device whose installed image and authenticated
update metadata can move through separate channels. It runs a baseline, then
advances time past the metadata expiry while the refresh fails, and finally
advances only the installed-image channel. The black-box harness receives a
JSON scenario and must return the decision plus a freshness envelope:

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
    "version": 3,
    "target": "stable",
    "payload_digest": "<sha256>",
    "expires_at": 20,
    "now": 30,
    "expired": true,
    "refresh_failed": true
  },
  "metadata_used": false,
  "security_state": {}
}
```

The oracle reports `EXPIRED_AUTHENTICATED_METADATA_USE` only when the harness
states that expired metadata was used by an accepted or committed decision and
the result differs from the fresh baseline. A rejection because metadata is
expired, or an identical accepted result, is expected behavior and is not a
finding. Independently, an accepted result that selects older state after an
`update_installed` event reports `INSTALLED_STATE_REGRESSION` even while the
metadata remains fresh. If the same expired scenario also consumes expired
metadata, the expired-metadata finding includes the installed-state evidence
instead of producing a duplicate finding.

Run the campaign with:

```bash
python3 scripts/freshness_oracle.py \
  --config examples/freshness_oracle/profile.yaml \
  --report results/freshness.json
```

The declaration is a model of the implementation under test. Before treating
any result as evidence, verify that its channel names, expiry semantics, and
state transitions match the real update protocol.
