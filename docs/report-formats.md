# Audit reports for CI

Add any combination of `--junit FILE`, `--sarif FILE` and `--html FILE` to a profile audit. Each output needs its own path. The audit writes its usual JSON first and exports the observations even when the profile assertion fails.

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_small_upgrade.yaml \
  --quick --output results/audit.json --junit results/audit.xml \
  --sarif results/audit.sarif --html results/audit.html
```

The same options work on `self_test.py`, `run_scenario.py` and `merge_runtime_sweep_reports.py`. Self-test HTML shows the profile assertions. Its XML and SARIF include the underlying audit runs. For an initial-state matrix, request the formats during the audit so that the writers can read the child observations before the runner removes them.

To export existing runtime audit JSON, repeat `--input` for each run. For raw Renode batches, `--profile` supplies the profile location for SARIF. Use `--elf` to supply a relocated copy of the firmware ELF with debug information.

```sh
python3 scripts/report_formats.py --input results/audit.json \
  --junit results/audit.xml --sarif results/audit.sarif --html results/audit.html
```

## JUnit XML

Each profile run has a suite. Each returned runtime record has a case, including its campaign's clean control. The case class includes the canonical point kind. Explicit pairs, ordered chains and searched states include their cut indices and fault types. For a runtime sweep, the suite's test count is `point_counts.totals.run`. A suite property carries the entire canonical accounting block, including requested, missing and reused counts. Reused paths reference an already evaluated state. Only that state's execution produces a case.

| Observation | JUnit element |
| --- | --- |
| Evaluated point with a finding | `failure` with the finding class and reason |
| Runner or infrastructure error | `error` with the recorded diagnostic |
| Initial timeout, skipped injection or inconclusive observation | `skipped` with a reason |
| Evaluated point with an acceptable outcome | Passing testcase |

A later timeout preserves a concrete finding from the initial boot. With no finding, an incomplete follow-up is skipped. A profile can expect findings and pass its regression assertion while its affected cases still show failures. The suite's `verdict` property and the audit exit status preserve the profile-level assertion, including coverage gates.

Case `time` is wall time in seconds from the point's timing fields, rounded to milliseconds. Missing timing contributes zero. Suite time sums the point timings. A setup failure before any records are available produces an error case.

## SARIF 2.1.0

The driver registers each observed finding class once. A result groups affected points by class, check or outcome, component and source location. Named invariants and metadata fields retain their identity when they share a profile location. The writer uses the runtime's effective boot outcome and issue classification, including the exclusions for timed-out initial boots and dismissed findings. Inconclusive campaign diagnostics also appear in the invocation record.

Each result lists its points and reproductions under `properties.points`. Use the original profile, firmware, calibration and seed. For a single point, the reproduction gives the existing Renode Robot point variables. For a pair or chain, replace the profile's `fault_sweep.phase2_fault` with the supplied block, and apply the indicated first-erase setting if present. For state search these selectors identify the operations in the evaluated path. The auxiliary staging, fuzz and authorization-review campaigns retain their own selectors.

When firmware debug line tables cover a reported code address or symbol, the location contains the source file and line. A stripped ELF or unmapped address uses the profile at line 1. Paths under the checkout are relative to its root. For a saved report with a moved profile, use `--profile` to select its current path.

## GitHub Actions

On the Tardigrade action step, enable the optional boolean inputs and give the step an ID. This example assumes the repository contains the action. For a consumer repository, retain its existing Tardigrade `uses` reference.

```yaml
permissions:
  contents: read
  security-events: write
  actions: read

steps:
  - uses: actions/checkout@v6
  - id: audit
    uses: ./
    with:
      profile: profiles/mcuboot_head_move_small_upgrade.yaml
      junit: 'true'
      sarif: 'true'
      html: 'true'
  - uses: github/codeql-action/upload-sarif@v4
    if: ${{ !cancelled() && steps.audit.outputs.sarif-path != '' }}
    with:
      sarif_file: ${{ steps.audit.outputs.sarif-path }}
```

Use `steps.audit.outputs.junit-path` with your JUnit publisher and `steps.audit.outputs.html-path` with an artifact upload step. The action publishes the paths before applying its existing gate. GitHub documents repository eligibility, permissions and upload limits in its [SARIF upload guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

## Schema validation

With `jsonschema` and `lxml` installed in the checking environment, run the following command. It fetches the published SARIF 2.1.0 JSON schema and the Jenkins xUnit plugin's JUnit XSD on demand.

```sh
python3 scripts/check_report_formats.py --sarif results/audit.sarif --junit results/audit.xml
```
