# MCUboot instruction-skip campaign results

Every report written for these campaigns has `security_bypass_points: 0`.
Four runs are complete, with `campaign_complete: true`: the `candidates` quick
and full runs, the `revert_instruction_skip` quick run, and the
`verify_instruction_skip_probe` quick run.

The other runs are incomplete:

- The `critical` quick and full runs and the `corrupt_staging_full` quick run
  wrote reports with timed-out fault points and `FAIL` verdicts for
  incompleteness.
- The `verify_instruction_skip` quick run wrote a report with one
  infrastructure error and a `FAIL` verdict for incompleteness.
- The `corrupt_staging_full` and `verify_instruction_skip_probe` full runs were
  stopped by `timeout 1800` and wrote no report.
- The `revert_instruction_skip` and `verify_instruction_skip` full runs were not
  started, because their quick runs took longer than 600 s.

All runs used upstream MCUboot at commit
`f84b9d3fd019fb1945e532924bee7a9c03c77373`, read from
`results/oss_validation/assets/mcuboot_head_commit.txt`, and the Docker image
`tardigrade-oss-validation:latest` with image ID
`sha256:71688b83df0aa5f2164f0fe9e73aaa80753a0a3d72d8fe9b700c7a0009d7e8f9`.
The reports do not contain a `tool_versions` field. That field exists only in
calibration cache entries, and these profiles skip calibration. The Renode
version below comes from running `renode --version` inside that image, which
printed `Renode v1.16.1.17033`, build `d66b0c2a-202602160923`. Every report
records tardigrade commit `cdd3cf8` with `git.dirty: "true"`.

The report verdict strings use an em-dash character between clauses. This
document shows each such separator as a semicolon and otherwise quotes the
verdict unchanged. Wall time is `summary.runtime_sweep.wall_time_s` for runs
that wrote a report and elapsed time until the process stopped for runs that
did not. All clock times are UTC.

| Profile | MCUboot | Renode | Mode | Fault points | Timeout | Bypass | DoS crash | `verdict` | `security_aggregate.status` | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|
| `upgrade_verify_corrupt_staging_candidates` | `f84b9d3` | 1.16.1.17033 | quick | 2 | 0 | 0 | 0 | `PASS` | `CLEAN` | 69.5 s |
| `upgrade_verify_corrupt_staging_candidates` | `f84b9d3` | 1.16.1.17033 | full | 2 | 0 | 0 | 0 | `PASS` | `CLEAN` | 68.3 s |
| `upgrade_verify_corrupt_staging_critical` | `f84b9d3` | 1.16.1.17033 | quick | 10 | 10 | 0 | 0 | `FAIL; campaign incomplete: 10 fault point(s) timed out (WARNING: 10 points timed out; consider increasing run_duration)` | `FINDINGS` | 272.6 s |
| `upgrade_verify_corrupt_staging_critical` | `f84b9d3` | 1.16.1.17033 | full | 10 | 4 | 0 | 6 | `FAIL; campaign incomplete: 4 fault point(s) timed out (WARNING: 4 points timed out; consider increasing run_duration)` | `FINDINGS` | 258.3 s |
| `upgrade_verify_corrupt_staging_full` | `f84b9d3` | 1.16.1.17033 | quick | 15 | 6 | 0 | 9 | `FAIL; campaign incomplete: 6 fault point(s) timed out (WARNING: 6 points timed out; consider increasing run_duration)` | `FINDINGS` | 527.1 s |
| `upgrade_verify_corrupt_staging_full` | `f84b9d3` | 1.16.1.17033 | full | 202 planned | no report | no report | no report | no report | no report | 1800 s, stopped |
| `revert_instruction_skip` | `f84b9d3` | 1.16.1.17033 | quick | 10 | 0 | 0 | 10 | `PASS; 0 security bypass points (10 DoS crash points, expected for glitch model); whole-device layout not assessed` | `INCONCLUSIVE` | 667.1 s |
| `revert_instruction_skip` | `f84b9d3` | 1.16.1.17033 | full | not run | not run | not run | not run | not run | not run | not run |
| `verify_instruction_skip` | `f84b9d3` | 1.16.1.17033 | quick | 14 of 15 requested | 0 | 0 | 14 | `FAIL; campaign incomplete: 1 infrastructure error(s)` | `INCONCLUSIVE` | 1516.5 s |
| `verify_instruction_skip` | `f84b9d3` | 1.16.1.17033 | full | not run | not run | not run | not run | not run | not run | not run |
| `verify_instruction_skip_probe` | `f84b9d3` | 1.16.1.17033 | quick | 5 | 0 | 0 | 5 | `PASS; 0 security bypass points (5 DoS crash points, expected for glitch model); whole-device layout not assessed` | `INCONCLUSIVE` | 382.4 s |
| `verify_instruction_skip_probe` | `f84b9d3` | 1.16.1.17033 | full | 90 planned | no report | no report | no report | no report | no report | 1800 s, stopped |

Profile names in the table drop the shared `mcuboot_head_move_nrf52_` prefix.
Fault points is `summary.runtime_sweep.total_fault_points`. Timeout is
`timeout_points`, bypass is `security_bypass_points`, and DoS crash is
`dos_crash_points`, all from `summary.runtime_sweep`. Planned counts for the
stopped runs come from the `Running N fault points` line in their logs. Every
report has `dos_recovery_points: 0` and `missing_result_points: 0`. Every report
except `verify_instruction_skip` quick has `infrastructure_error_points: 0`.

In the three `FINDINGS` reports, `security_aggregate.issue_points` is 1 and
`finding_sources` is `{"summary.runtime_sweep": 1}`. In those same reports
`summary.runtime_sweep.issue_points` is 0 and
`summary.runtime_sweep.control.issue_count` is 1. The control run in those
three profiles booted `wrong_image`, which matches each profile's
`expect.control_outcome: wrong_image`.

## Where the 2 s wall budget comes from

The 2 s budget is a constant in the runtime script, not a profile field.
`scripts/run_runtime_fault_sweep.py:9069` sets `_skip_p1_wall_s = 2.0` for
phase 1 of every instruction-skip fault point and passes it to
`run_until_done` as `wall_timeout`. The same block lowers
`progress_stall_timeout_s` to 1 emulated second for that phase. No profile
field or CLI flag overrides either value. The profiles' `run_duration: "20.0"`
does not change this cap, although the `FAIL` verdict text says
`consider increasing run_duration`.

The number inside `wall_timeout(Ns)` is the elapsed wall time when the check
fired, formatted at `scripts/run_runtime_fault_sweep.py:8322`. The check runs
once per emulation slice, so a slow slice can push the recorded value past the
2 s budget. That is why the `revert_instruction_skip`,
`verify_instruction_skip`, and `verify_instruction_skip_probe` reports contain
values from `wall_timeout(2s)` up to `wall_timeout(49s)`.

Every timed-out point in these reports has
`phase1_stop_reason: wall_timeout(2s)`, a `phase1_ms` between 2192 and 2673,
and `phase1_emulated_s` between 0.06 and 1.02. The control run of the
`critical` and `corrupt_staging_full` profiles reached `vtor_captured` at 1.08
emulated seconds after 1631 to 1853 ms of wall time on this host.

A separate per-point budget does derive from `run_duration`. The Robot
`TEST_TIMEOUT` passed to `renode-test` is set by
`profile_robot_timeout_minutes` in `scripts/renode_runner.py:239`, which
computes `max(120, run_duration * 30)` seconds. With `run_duration: "20.0"`
that is 10 minutes, the limit the `verify_instruction_skip` infrastructure
error hit.

Recommendation: make the instruction-skip phase-1 wall cap configurable from
the profile or the CLI, or derive it from `run_duration` the way
`phase1_wall_timeout` does. On this host the cap stopped every timed-out point
at 1.02 emulated seconds or less, short of the 1.08 emulated seconds the
control run used to reach `vtor_captured`. Until the cap is configurable,
timeout counts for these profiles depend on host speed. The profiles were not
changed.

## How the defense-in-depth summary counts points

`summary.runtime_sweep.defense_in_depth_layers` is built in
`scripts/audit_report.py:917` from `reportable_injected`, which
`scripts/audit_report.py:539` defines as injected points without an initial
timeout. Timed-out points are therefore absent from the summary even though
their per-point `signals.verification_probe_classification` is populated. Both
counts are given below.

Classification names come from `scripts/bypass_probe.py`. Its
`classify_layer_status` docstring defines a layer as `breached` when its first
invocation returned the configured success value or any invocation was
bypassed, `held` when it was reached without either, and `not_reached` when it
never executed.

## `mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates`

Targets two addresses, `0x5CE` and `0x76E`, with probes on
`bootutil_img_validate` as `hash_validation` and `boot_validate_slot.isra.3` as
`slot_validation`. Success is booting the `exec` image. The control booted
`success`.

Commands:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates_quick.json
timeout 1800 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates_full.json
```

Quick and full select the same 2 points and produced the same counts.

| Mode | `points_by_classification` | Per-point classification | `hash_validation` held/breached/not_reached | `slot_validation` held/breached/not_reached | `aggregate_classification` |
|---|---|---|---|---|---|
| quick | `first_layer_held`: 2 | `first_layer_held`: 2 | 2/0/0 | 2/0/0 | `held` |
| full | `first_layer_held`: 2 | `first_layer_held`: 2 | 2/0/0 | 2/0/0 | `held` |

Both points ended `boot_outcome: success`, `fault_class: recoverable`, with
`phase1_stop_reason: vtor_captured` at 0.06 emulated seconds.

Completed: quick and full, both `campaign_complete: true`. Rerunning under `timeout 900` after `compute_slot_hash` switched to the `mcuboot_header` extent of `0x50E4`, 20,708 bytes, produces `boot_outcome: success`, `matched_image: exec`, `image_hash_actual: 1dae8b477293d6d004e26e5528777ef75e9983877576221638735e89e4c6c7b8`, and `vtor: 0x0000C200` on control, with both fault points `i:0x5CE` and `i:0x76E` recovering in 39.4 s.

## `mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical`

Targets `0x5C4` to `0x5D0` and `0x76E` to `0x77C` with the same two probes.
Success is booting the `staging` image. The profile expects the control to
boot `wrong_image`, and it did.

Commands:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical_quick.json
timeout 1800 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical_full.json
```

Quick and full select the same 10 points.

| Mode | `points_by_classification` | Per-point classification | `hash_validation` held/breached/not_reached | `slot_validation` held/breached/not_reached | `aggregate_classification` |
|---|---|---|---|---|---|
| quick | summary is `null` | `first_layer_held`: 10 | not in summary | not in summary | summary is `null` |
| full | `first_layer_held`: 6 | `first_layer_held`: 10 | 6/0/0 | 6/0/0 | `held` |

Quick: all 10 points ended `boot_outcome: timeout`, `fault_class: incomplete`,
`phase1_stop_reason: wall_timeout(2s)`. With every point timed out,
`defense_in_depth_layers` is `null`.

Full: 6 points ended `no_boot`, `fault_class: unrecoverable`, with
`phase1_stop_reason: no_boot_stall(1.00s_emulated)` at `0x5C4`, `0x5C6`,
`0x76E`, `0x772`, `0x774`, and `0x776`. These are the 6 DoS crash points. The
other 4 points at `0x5CA`, `0x5CC`, `0x5CE`, and `0x770` timed out with
`wall_timeout(2s)`.

Completed: both runs wrote reports. Neither is complete:
`campaign_complete: false` in both, with 10 and 4 timed-out points. Because the control `wrong_image` outcome relies on `image_hash` while `vtor: 0x0000C200` and `pc: 0x000103E8` pass in-slot checks, rerunning `--quick --workers 2 --no-assert-verdict` under `timeout 900` with the `mcuboot_header` extent confirms `control.boot_outcome: wrong_image`, `matched_image: exec`, and `image_hash_actual: 1dae8b477293d6d004e26e5528777ef75e9983877576221638735e89e4c6c7b8` across the 20,708-byte `exec` image, while all 10 fault points complete in 123.2 s with 0 timeouts, 10 DoS crash points, 0 security bypass points, and `first_layer_held: 10`.

## `mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full`

Targets the whole of `bootutil_img_validate`, `boot_validate_slot.isra.3`, and
`bootutil_img_hash`, with the same two probes. Success is booting `staging`.
The control booted `wrong_image`, as the profile expects.

Commands:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full_quick.json
timeout 1800 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --no-assert-verdict --output results/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full_full.json
```

| Mode | `points_by_classification` | Per-point classification | `hash_validation` held/breached/not_reached | `slot_validation` held/breached/not_reached | `aggregate_classification` |
|---|---|---|---|---|---|
| quick | `first_layer_held`: 6, `first_layer_not_reached`: 3 | `first_layer_held`: 12, `first_layer_not_reached`: 3 | 6/0/3 | 4/0/5 | `unknown` |
| full | no report | no report | no report | no report | no report |

Quick: 9 points ended `hard_fault`, `fault_class: unrecoverable`, and are the
9 DoS crash points. The 3 `first_layer_not_reached` points are among them, at
`0xB98`, `0x46EE`, and `0x475A`. The 6 timed-out points are `0xC72`, `0xE12`,
`0xE28`, `0xE7C`, `0x4706`, and `0x4708`, all `first_layer_held` and all
`wall_timeout(2s)`.

Full: started at 11:55:59 and stopped by `timeout 1800` at about 12:26:00. The log
records 25 of 202 points completed before the stop, 10 on worker 0 and 15 on
worker 1. One point on worker 0, fault address `0xBB4`, took 617.3 s. No
report was written. The per-chunk `result.json` files left in the run's
temporary directory were copied to
`results/instruction_skip_run2/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full_full_unaggregated_chunks/`.
There are 27 of them. No report aggregated these files, so they are not
counted in the table. Their raw `boot_outcome` values are `hard_fault` 24,
`timeout` 2, and `wrong_image` 1, and none is `success`. Their raw
`verification_probe_classification` values are `first_layer_not_reached` 16
and `first_layer_held` 11.

Completed: the quick run wrote a report with `campaign_complete: false` and 6
timed-out points. The full run did not complete and wrote no report. Rerunning `--quick --workers 2 --no-assert-verdict` under `timeout 900` with the `mcuboot_header` extent confirms `control.boot_outcome: wrong_image`, `matched_image: exec`, and `image_hash_actual: 1dae8b477293d6d004e26e5528777ef75e9983877576221638735e89e4c6c7b8`, with all 15 quick fault points completing in 182.1 s with 0 timeouts, 15 DoS crash points, 0 security bypass points, `first_layer_held: 12`, and `first_layer_not_reached: 3`.

## `mcuboot_head_move_nrf52_revert_instruction_skip`

Targets `boot_swap_type_multi` and `boot_swap_image` during a swap-move revert.
The profile has no `verification_probes`, so the report has no
`defense_in_depth_layers` and no per-point probe classification.

Command:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_revert_instruction_skip.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/mcuboot_head_move_nrf52_revert_instruction_skip_quick.json
```

| Mode | `points_by_classification` | Per-point classification | Layers | `aggregate_classification` |
|---|---|---|---|---|
| quick | none, no probes configured | none on all 10 points | none | none |

Quick: all 10 points ended `hard_fault`, `fault_class: unrecoverable`, and are
the 10 DoS crash points. The control booted `success`. Two points stopped at
`wall_timeout(2s)` and eight at values from `wall_timeout(28s)` to
`wall_timeout(49s)`. All ten are classified `hard_fault`, not `timeout`.

Completed: the quick run, `campaign_complete: true`. The full run was not
started because the quick run took 667.9 s by the runner's clock, over the
600 s threshold. The quick run ran concurrently with the
`verify_instruction_skip_probe` quick run.

## `mcuboot_head_move_nrf52_verify_instruction_skip`

Targets the whole of `bootutil_img_validate`, `boot_validate_slot.isra.3`, and
`bootutil_img_hash` during a swap-move boot. The profile has no
`verification_probes`, so the report has no `defense_in_depth_layers` and no
per-point probe classification. The control booted `success`.

The previous session's quick run wrote no report. Its log records 14 of 15
points completed and the 15th, fault address `0x475A`, starting at 12:05:28.
The log ends two seconds later with no result for that point. This session reran the quick command:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_verify_instruction_skip.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/instruction_skip_run2/mcuboot_head_move_nrf52_verify_instruction_skip_quick.json
```

| Mode | `points_by_classification` | Per-point classification | Layers | `aggregate_classification` |
|---|---|---|---|---|
| quick | none, no probes configured | none on all 15 results | none | none |

Quick: the run started at 12:15:46 and finished at 12:41:03. 14 points ended
`hard_fault`, `fault_class: unrecoverable`, and are the 14 DoS crash points.
Their phase-1 stop reasons range from `wall_timeout(2s)` to
`wall_timeout(49s)`. The 15th point, fault address `0x475A`, is recorded as
`boot_outcome: infra_error` with `error_kind: runner_error`. Its error text is
the Robot message `Test timeout 10 minutes exceeded.` after 600.03 s.
`summary.runtime_sweep` reports `requested_fault_points: 15`,
`injected_fault_points: 14`, `infrastructure_error_points: 1`, and
`campaign_complete: false`. In the `corrupt_staging_full` quick report, the
same address `0x475A` ended `hard_fault` with `wall_timeout(3s)`.

Completed: the quick run wrote a report with `campaign_complete: false` and one
infrastructure error. The full run was not started because the quick run took
1517 s, over the 600 s threshold.

## `mcuboot_head_move_nrf52_verify_instruction_skip_probe`

Targets `bootutil_img_validate` during a swap-move boot with the two probes.
The control booted `success`.

Commands:

```sh
python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_verify_instruction_skip_probe.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --quick --no-assert-verdict --output results/mcuboot_head_move_nrf52_verify_instruction_skip_probe_quick.json
timeout 1800 python3 scripts/audit_bootloader.py --profile profiles/mcuboot_head_move_nrf52_verify_instruction_skip_probe.yaml --renode-test docker://tardigrade-oss-validation:latest --workers 2 --no-assert-verdict --output results/mcuboot_head_move_nrf52_verify_instruction_skip_probe_full.json
```

| Mode | `points_by_classification` | Per-point classification | `hash_validation` held/breached/not_reached | `slot_validation` held/breached/not_reached | `aggregate_classification` |
|---|---|---|---|---|---|
| quick | `first_layer_held`: 3, `first_layer_not_reached`: 1, `all_layers_breached`: 1 | same as summary | 3/1/1 | 3/1/1 | `partial` |
| full | no report | no report | no report | no report | no report |

Quick: all 5 points ended `hard_fault`, `fault_class: unrecoverable`, and are
the 5 DoS crash points. The summary records `full_bypass_count: 1` for the
point at `0xC72`, classified `all_layers_breached`. `security_bypass_points` is
0 and that point's `boot_outcome` is `hard_fault`. The control run, which
applies no skip and booted `success`, also carries
`verification_probe_classification: all_layers_breached`.

Full: started at 11:59:20 and stopped by `timeout 1800` at about 12:29:21. The log
records 33 of 90 points completed before the stop, 16 on worker 0 and 17 on
worker 1. No report was written. The per-chunk `result.json` files left in the
run's temporary directory were copied to
`results/instruction_skip_run2/mcuboot_head_move_nrf52_verify_instruction_skip_probe_full_unaggregated_chunks/`.
There are 36 of them. No report aggregated these files, so they are not
counted in the table. Their raw `boot_outcome` values are `hard_fault` 35 and
`success` 1. Their raw `verification_probe_classification` values are
`all_layers_breached` 20, `first_layer_held` 11, and
`first_layer_not_reached` 5.

Completed: the quick run, `campaign_complete: true`. The full run did not
complete and wrote no report.

## Other run not used

An earlier attempt ran the `candidates` quick profile against the arm64 image
`tardigrade-renode-contained:local` with `OTA_RENODE_DOCKER_PLATFORM=linux/arm64`.
Its report has verdict `FAIL; campaign incomplete: 1 infrastructure error(s)`
and is kept as
`results/instruction_skip_run2/mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates_arm64_quick.json`.
It is excluded from the table.

## How to reproduce

Build the MCUboot assets and the `tardigrade-oss-validation` image as described
in the README, then run each profile from the repository root:

```sh
P=mcuboot_head_move_nrf52_verify_instruction_skip_probe
python3 scripts/audit_bootloader.py --profile profiles/$P.yaml \
  --renode-test docker://tardigrade-oss-validation:latest --workers 2 \
  --quick --no-assert-verdict --output results/${P}_quick.json
timeout 1800 python3 scripts/audit_bootloader.py --profile profiles/$P.yaml \
  --renode-test docker://tardigrade-oss-validation:latest --workers 2 \
  --no-assert-verdict --output results/${P}_full.json
```

The previous session's runner is
`results/instruction_skip_run2/run_campaigns.py`. It runs the full mode only
when the quick run finished in under 600 s. Reports, logs, and per-run
`*_execution.json` records are under `results/` and
`results/instruction_skip_run2/` and are not committed. The
`verify_instruction_skip` rerun log and timing are in
`results/instruction_skip_run2/mcuboot_head_move_nrf52_verify_instruction_skip_quick_session2.log`
and `.timing`.

## Host note

The host was an arm64 Mac running the linux/amd64 image under emulation. Two
other agents were running Docker Renode on the same host at the same time.
Across the 141 single-point chunks that the amd64 logs record as complete,
wall time per chunk ranged from 32.0 s to 617.3 s, with a median of 89.2 s. Wall times and
timeout counts in this document are specific to that host and load. The 2 s
phase-1 cap and the 10-minute Robot timeout are both wall-clock limits, so the
number of points that hit them depends on emulation speed.
