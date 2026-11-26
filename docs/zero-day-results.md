# MCUboot HEAD zero-day canary results

In `.github/workflows/mcuboot-head-zero-day.yml`, `scripts/zero_day_summary.py` records the upstream MCUboot commit, the paired Zephyr commit, and the eight zero-day canary profile verdicts, and `scripts/zero_day_results.py` formats one row per MCUboot commit with a link to the workflow run.

| MCUboot commit | Zephyr commit | Run | move-nrf52-revert | move-nrf52-revert-nohashbypass | move-nrf52-upgrade | offset-nrf52-revert | offset-nrf52-upgrade | scratch-nrf52-revert | scratch-nrf52-upgrade | scratch-stm32f4-writeback |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `5c039f4842cf` | `unknown` | [run 38291661310][run-38291661310] | 0 main-runtime issues/30 injected main-runtime points, `PASS`, `INCONCLUSIVE` | not run | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/6 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/0 injected main-runtime points, `INCONCLUSIVE`, `INCONCLUSIVE` |
| `a8ffd2c31291` | `unknown` | [run 37351314938][run-37351314938] | 0 main-runtime issues/30 injected main-runtime points, `PASS`, `INCONCLUSIVE` | not run | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/6 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/0 injected main-runtime points, `INCONCLUSIVE`, `INCONCLUSIVE` |
| `aa32eaaad41c` | `unknown` | [run 36499483003][run-36499483003] | 0 main-runtime issues/30 injected main-runtime points, `PASS`, `INCONCLUSIVE` | not run | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/6 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/0 injected main-runtime points, `INCONCLUSIVE`, `INCONCLUSIVE` |
| `ccf3885809a0` | `unknown` | [run 35748096297][run-35748096297] | 0 main-runtime issues/30 injected main-runtime points, `PASS`, `INCONCLUSIVE` | not run | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/6 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/9 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/12 injected main-runtime points, `PASS`, `INCONCLUSIVE` | 0 main-runtime issues/0 injected main-runtime points, `INCONCLUSIVE`, `INCONCLUSIVE` |

[run-38291661310]: https://github.com/neilberkman/tardigrade/actions/runs/38291661310
[run-37351314938]: https://github.com/neilberkman/tardigrade/actions/runs/37351314938
[run-36499483003]: https://github.com/neilberkman/tardigrade/actions/runs/36499483003
[run-35748096297]: https://github.com/neilberkman/tardigrade/actions/runs/35748096297

## Regenerating this table

Authenticate the GitHub CLI and run `scripts/zero_day_results.py` from the repository root:

```bash
gh auth status
python3 scripts/zero_day_results.py --output docs/zero-day-results.md
```

To render from an existing directory of downloaded artifacts without network calls:

```bash
python3 scripts/zero_day_results.py --from-dir path/to/artifacts --output docs/zero-day-results.md
```
