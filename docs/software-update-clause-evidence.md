# Software update clause evidence

Each audit JSON contains a `clause_evidence` section. The HTML audit renders the same observations under **Software update clause evidence**. Read each entry as *evidence relevant to* the cited paragraph. Assessors decide applicability and weigh this material alongside other evidence. The section makes no legal determination.

The default map refers to UN Regulation No. 156 paragraphs 7.2.2.1.1 (recovery after an interrupted OTA update) and 7.2.1.1 (update integrity and authenticity), and to Regulation (EU) 2024/2847 Annex I, Part I, point (2)(f) (integrity and reporting corruption). Follow the official citation in each entry for the text and context. [UN Regulation No. 156](https://eur-lex.europa.eu/eli/reg/2021/388/oj/eng) · [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)

## Reading a clause

Use the profile identifier and campaign name to locate the observations in the source report. Each campaign lists the number of requested and returned fault points, points evaluated **for this clause**, and returned points omitted from that count. Clean controls are excluded. Missing plan counts are null. Multiple criteria can describe one point, so adding criterion counts can double-count it. A point can also inform more than one clause.

* **Point verdicts** count evaluated points with a finding and evaluated observations without a finding. Boot outcomes describe the effective boot cycle. A profile that expects findings can pass its own regression assertion while the mapping still reports those findings.
* **Success criteria** pair a configured check with measured signals. A slot handoff can support a recovery observation. The running-image check includes image identity and the profile's execution checks. A digest match identifies reference bytes. Verification probes describe the instrumented checks. Each missing criterion is listed explicitly.
* **Campaign coverage** gives calibrated program and erase operations, directly cut operations, operations represented without a direct cut, omissions inside the plan, and operations outside its range, when recorded. Recovery searches also report states booted, reused and excluded by their budgets when recorded. These are campaign-wide denominators. An operation represented by sampling adds no evaluated clause point.
* **Gaps** include absent campaigns, missing records, unknown completeness, skipped injections, timeouts and infrastructure errors. If a campaign is incomplete its returned rows remain visible in the accounting and contribute zero clause points. Old reports without an independently supplied plan and merged reports whose plans cannot be reconstructed receive the same treatment. Parent matrices and combined-component summaries can be reviewed via their individual audit reports. Other recorded campaigns outside the mapping are identified separately.

All observations concern emulation. The profile establishes what software and fault model ran. A successful boot alone cannot establish vehicle-level safety or restoration of a particular earlier release. Reference hashes alone cannot establish signer identity. A run also cannot establish corruption notification in the deployed product.

## Using another mapping

Copy the shipped YAML file, increase its positive integer `mapping_version`, and edit its clauses. Append entries to extend it or supply a smaller or different set to replace it. The audit and saved-report renderer accept the same option.

```sh
tardigrade audit --profile profiles/demo_mcuboot_offset_upgrade.yaml \
  --quick --output results/audit.json --clause-map update-clauses.yaml
tardigrade report --input results/audit.json --output results/audit.html \
  --clause-map update-clauses.yaml
```

To extract just the evidence section from an existing audit, run the following command from the source checkout. Omit `--html` for JSON alone. It reads only the input report and mapping. The saved section carries its mapping definitions so it can be rendered again. Supply `--clause-map` to override them.

```sh
python3 scripts/report_clause_evidence.py --input results/audit.json \
  --output results/clauses.json --html results/clauses.html
```

The mapping schema requires a regulation, paragraph identifier, HTTPS citation, short original paraphrase, clause-specific limit, campaign list, fault scope and criteria for each entry. The pair of regulation and paragraph must be unique. Use a direct official source and neutral descriptions of the clause. The loader rejects duplicate YAML keys, unknown fields, unsupported versions and selectors, and assessment wording. Profile identifiers containing assessment wording are replaced by a stable digest label in the section.

| Selector | Values |
| --- | --- |
| Campaign | `runtime_sweep`, `multi_fault_runtime_sweep` |
| Fault scope | `interruption` selects observed power loss, interrupted erase and timed reset, including sequences of those cuts. `any_injection` includes all evaluated fault mechanisms in the chosen campaign. |
| Criterion | `boot_handoff`, `running_image`, `image_digest`, `verification_probe` |

Applications can validate the YAML data against the published JSON Schema. The audit also enforces paragraph uniqueness and wording rules. Verdict and gap accounting applies to every mapping. [Default mapping](../scripts/clause_maps/update-v1.yaml) · [JSON Schema](../scripts/clause_maps/schema.json)
