# Release license certification

`scripts/license_certify.py` provides a fail-closed gate for an explicitly
bounded release. It consumes a manifest and a policy of allowed/prohibited
SPDX identifiers. It does not infer licenses from filenames, text scans, or
copyright notices.

The checked-in manifest certifies the `tardigrade-core-source` package only.
Its `include_paths` are the package boundary, and `file_digests` must contain
every non-excluded file below that boundary. An added, removed, or modified
included file makes certification fail until a reviewer updates the exact
digest inventory. Symbolic links are rejected. The package is declared
Apache-2.0 and tied to the local, digest-verified repository `LICENSE`.

The checked-in manifest also sets `require_tracked_completeness` to `true`.
Every included source file must be Git-tracked, and every Git-tracked path must
be either in the certified digest inventory or matched by an explicit
`tracked_exclude_globs` rule. Any added file under an included path fails until
it is staged and inventoried. A newly tracked top-level path outside the
declared boundary fails unless explicitly included or excluded. Run
certification after staging the prospective release. The check fails closed
when Git cannot provide the tracked-file list.

This result does **not** certify the full Git checkout. In particular, the
source package excludes:

- every prebuilt or generated `.elf`, `.bin`, `.o`, and `.pyc` file;
- `results/oss_validation/`, including retained MCUboot/Zephyr fixtures;
- `docker/`, `.github/`, and `requirements-oss-build.txt`;
- the certification manifest itself, which is reviewed as control data and
  cannot recursively include its own digest;
- third-party source checkouts, local research scratch, run snapshots, and
  generated reports; and
- the separate third-party legal-text collection under `LICENSES/` and
  `THIRD_PARTY_NOTICES.md`.

External compilers, downloaded SDKs, Python distributions, emulator archives,
and binaries built from this source package require their own certification.
A passing checked-in manifest must not be described as certifying those inputs
or outputs.

Entries use one of these kinds:

- `distributed`: an artifact shipped with a Tardigrade release;
- `linked`: an object or binary linked into a retained artifact;
- `runtime`: a dependency needed while Tardigrade runs;
- `build-only`: a tool used to produce or test an artifact but not shipped or
  linked into it.

`distributed` and `linked` entries must also name a `link_manifest` containing
the exact link inputs and its SHA-256 digest. Every link input carries an
`artifact_id`, path, and digest. The ID must resolve to a different manifest
entry that independently passes certification, and the path/digest must match
one of that entry's verified files. The checker verifies that all declared
files exist under the manifest directory and that supplied digests match.
It reports build-only copyleft inputs separately as warnings only when the
policy explicitly says `"build_only_copyleft": "report"`; `--strict` always
turns those warnings into certification failures. If the policy omits this
field, the fail-closed default is `"fail"`. Use an explicit policy of
`"fail"` or `--strict` for a no-copyleft release decision.

The checked-in policy is deliberately stricter than an obligations-only
policy: it rejects copyleft even when an exception could remove reciprocal
source obligations, and it rejects copyleft used only at build time. This is
the repository's policy gate for reviewer-supplied license declarations. A
separately reviewed policy would be required to make a narrower,
obligations-only decision.

A passing result verifies the declared boundary, exact inventory, evidence
digest, and policy decision. It does not infer per-file licenses or replace
provenance review.

Check the current inventory:

```console
python3 scripts/license_certify.py path/to/release-manifest.json
python3 scripts/license_certify.py path/to/release-manifest.json --strict --format json
```

For the checked-in source package, use strict mode:

```console
python3 scripts/license_certify.py license-certification-manifest.json --strict
```

The `renode-tests` job in the main CI workflow runs that command immediately
after checkout, before that job downloads toolchains or dependencies. This
enforces both the exact source inventory and complete classification of tracked
paths on pushes and pull requests.

After intentionally changing package contents, refresh the exact digest map
and review the manifest diff before accepting it:

```console
python3 scripts/license_certify.py license-certification-manifest.json \
  --refresh-source-inventory
python3 scripts/license_certify.py license-certification-manifest.json --strict
```

The refresh operation changes only `source_release.file_digests`. It does not
change the package boundary, tracked-file classification, exclusions, license
decision, evidence, or provenance declaration.

For a grouped entry, `file_digests` is a map from every matched repository
relative path to its digest. The checker sorts glob matches, rejects missing or
extra map keys, and emits the expanded paths in JSON. A link-manifest file is
also JSON rather than opaque bytes. Its provenance uses a matching `snapshots`
map; each snapshot records a local path and digest plus an `artifact_sha256`
equal to the verified output digest:

```json
{
  "schema_version": 2,
  "inputs": [
    {"artifact_id": "object", "path": "build/object.o", "sha256": "..."},
    {"artifact_id": "linker-script", "path": "build/linker-script.ld", "sha256": "..."}
  ],
  "verification_status": "verified"
}
```

Unknown fields are rejected so a typo cannot silently weaken the gate. The
`--policy` override is explicit and may select a policy outside the manifest
directory; the policy named by the manifest itself must remain underneath that
directory.

The command exits 0 only when certification passes, 1 for a policy or
evidence failure, and 2 when the JSON inputs are malformed. The JSON output
is intended for CI and records each finding with an actionable code.

The existing `LICENSES/README.md` and `THIRD_PARTY_NOTICES.md` remain useful
human-readable records for development fixtures outside the certified source
package. They are not evidence that those fixtures passed the strict policy.
Any future package that distributes or links such artifacts must declare each
one and tie it to its own provenance and link evidence.
