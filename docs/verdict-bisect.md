# Bisecting a point verdict

Use `tardigrade bisect` or `python3 scripts/verdict_bisect.py` to locate the
first change in a repeatable application regression test. Supply a source
checkout, a passing and failing revision, a build command, a profile and optionally a
point-test executable. For a source history containing the dual-record MRAM
example, run this command from the Tardigrade checkout. Set `passing` and
`failing` to the revisions where the same record write recovers and fails.

```sh
tardigrade bisect --repo ../record-history --good "$passing" --bad "$failing" --find fix \
  --build 'cd examples/mram_ecc_record_recovery && make -B firmware_handled.elf initial_mram.bin && cp firmware_handled.elf initial_mram.bin "$BISECT_OUT"' \
  --profile examples/mram_ecc_record_recovery/profile_handled.yaml --point w1 \
  --state-dir ../record-search
```

For a fix, pass `--find fix`. The failing commit must then be an ancestor of
the passing commit. Both endpoints undergo the same trials as intermediate
commits, including when the endpoints are adjacent. The search assumes one
transition in the selected history. See `bisect.log` for Git's decisions.

The build command runs in a fresh detached worktree. It writes all files
needed by the test into the empty directory named by `BISECT_OUT`. Each trial
starts in a fresh copy of those files. The trial executable takes two
arguments, the absolute profile path and the point. Points use zero-based
write or erase indices, such as `w1`, `w1,e2` or `w1,e2,w0`. The test
executable interprets them for its application and checks that the selected
point actually ran. On successful execution, it writes one JSON object to the path in
`BISECT_RESULT`. A passing test writes the following verdict.

```json
{"verdict": "pass"}
```

Valid verdicts are `pass`, `fail`, and `skip`. Supply a `reason` on a skip.
Build failures, trial process errors, missing verdicts, timeouts and mixed
verdicts all skip the revision. An endpoint skip or mismatch stops the search.
A regression test's expected failure should emit `{"verdict":"fail"}` and exit
zero. A trial process error is an infrastructure failure.

Both `tardigrade bisect` and `python3 scripts/verdict_bisect.py` use
`scripts/record_recovery_trial.py` when you omit `--trial`. The installed
command uses the copy packaged under `tardigrade/runtime/scripts/`.
This runner tests a single-state, single-component Tardigrade profile
in Renode at one explicit point: a single write or erase (`w1`, `e51`), a
two-cut `phase2_fault.pairs` point (`w3,w6`, `w484,e3`), or a three-to-eight-cut
`phase2_fault.chains` sequence (`w1,e2,w0`). Export the bootloader ELF and slot
images referenced by the profile into `BISECT_OUT` from each build. Use
`RENODE_TEST` to select the Renode installation. To use a custom point runner,
supply its executable with `--trial`.

The default is three trials, with 300 seconds per build or trial. Set
`--repeat` and `--timeout` to change those limits. Give each search a new
session directory outside the source checkout. Repeating the same command
resumes completed trials. The JSON report in `report.json` records the input
revisions, point, build timing and cache key, individual verdicts and times,
skip reasons, and the result. Skipped commits may leave multiple candidates.
A unique answer exits zero. An inconclusive search or invalid input exits two.

`--cache-dir` can share completed build outputs between sessions. Builds are
keyed by the commit and exact command. Include toolchain or external dependency
versions in the build command when sharing a cache. Keep the profile's external
fixtures and the trial's dependencies fixed over a session. Start a new session
and cache when changing such inputs.
