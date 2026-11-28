# GitHub Action

Run a profile in CI with the reusable Action.

```yaml
- id: tardigrade
  uses: neilberkman/tardigrade@<reviewed-commit-sha>
  with:
    profile: path/to/your/profile.yaml
    quick: false
    workers: 2
```

Outputs include `verdict` (PASS/FAIL), `security-status` (CLEAN/FINDINGS/
INCONCLUSIVE), `assertion-status`, `issue-points`, `security-bypass-points`,
`report-path`, and `brick-rate`. By default, `verdict` is a fail-safe security
gate: it is PASS only when the profile expects no issues, no issues were found,
the evidence is complete, and the CLI assertion passed.

Known-vulnerable profiles used as regression tests must opt in explicitly with
`regression-mode: true`. In that mode, `verdict` is PASS only when the
regression assertion passes, `security-status` is `FINDINGS`, and the evidence
has no inconclusive reasons. Do not use regression mode as a release security
gate.

Relative ELF, image, platform, setup, and hook paths are resolved from the
caller's workspace. Set `asset-root` to a workspace subdirectory when those
assets do not live at the repository root. A custom `renode-url` must be paired
with its exact `renode-sha256`; downloads are rejected before extraction when
the digest does not match. The default digest comes from Renode's public
v1.16.1 release metadata. The Action also enables strict profile validation,
so unknown keys and profiles without observable success criteria are rejected.
The bundled runtime supports Linux x86-64 runners. It uses Renode's verified
portable .NET archive and installs Python packages in a temporary virtual
environment, leaving the caller's Python environment intact.

Profiles are trusted executable input, not a sandbox. Platform definitions,
setup scripts, boot hooks, and invariant providers can execute Renode commands
or host Python. Run only profiles and referenced assets from reviewed,
open-source revisions; do not accept them directly from an untrusted pull
request or artifact.

```yaml
- name: Upload tardigrade report
  if: always()
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
  with:
    name: tardigrade-report
    path: ${{ steps.tardigrade.outputs.report-path }}
```

See [`action.yml`](../action.yml) for all inputs and outputs.
