"""Exercise verdict bisection through a real Git history and subprocesses."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verdict_bisect.py"


def git(repo, *arguments):
    return subprocess.check_output(["git", "-C", repo, *arguments], text=True).strip()


@pytest.fixture
def history(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "-q")
    git(source, "config", "user.name", "Test")
    git(source, "config", "user.email", "test@example.invalid")
    commits = []
    for i, verdict in enumerate(("pass", "pass", "fail", "fail", "fail")):
        (source / "state").write_text(verdict)
        git(source, "add", "state")
        git(source, "commit", "--allow-empty", "-qm", f"revision {i}")
        commits.append(git(source, "rev-parse", "HEAD"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: record\n")
    driver = tmp_path / "test-record"
    driver.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "assert Path(sys.argv[1]).read_text() == 'name: record\\n'\n"
        "assert sys.argv[2] == 'w1,e2,w0'\n"
        "verdict = Path('state').read_text()\n"
        "Path('state').unlink()\n"  # No trial may change the next trial's inputs.
        "Path(os.environ['BISECT_RESULT']).write_text(json.dumps({'verdict': verdict}))\n"
    )
    driver.chmod(0o755)
    args = ["--repo", str(source), "--good", commits[0], "--bad", commits[-1],
            "--build", 'cp state "$BISECT_OUT/state"', "--profile", str(profile), "--point", "w1,e2,w0",
            "--trial", str(driver), "--state-dir", str(tmp_path / "session"), "--timeout", "10"]
    return source, commits, driver, args


def invoke(args, installed=False):
    cli = ["-m", "tardigrade.cli", "bisect"] if installed else [str(SCRIPT)]
    return subprocess.run([sys.executable, *cli, *args], capture_output=True, text=True, cwd=ROOT, timeout=45)


def report(tmp_path):
    return json.loads((tmp_path / "session/report.json").read_text())


@pytest.mark.parametrize("fix", [False, True], ids=["regression", "fix"])
def test_first_transition_and_repetitions(history, tmp_path, fix):
    source, commits, _, args = history
    if fix:
        args += ["--find", "fix", "--good", commits[-1], "--bad", commits[0],
                 "--build", """sed -e 's/^pass$/old/' -e 's/^fail$/pass/' -e 's/^old$/fail/' state > "$BISECT_OUT/state" """]
    (source / "state").write_text("caller's uncommitted data")
    result = invoke(args, installed=fix)
    assert result.returncode == 0, result.stderr
    data = report(tmp_path)
    assert data["first_changed_commit"] == commits[2]
    assert {row["commit"] for row in data["steps"]} >= {commits[0], commits[-1], commits[2]}
    assert all(len(row["runs"]) == 3 and row["build"]["seconds"] > 0 for row in data["steps"])
    assert all(run["seconds"] > 0 and run["verdict"] == row["verdict"]
               for row in data["steps"] for run in row["runs"])
    assert (source / "state").read_text() == "caller's uncommitted data"
    assert len(git(source, "worktree", "list", "--porcelain").splitlines()) == 3


@pytest.mark.parametrize("mode", ["build", "disagree", "invalid", "empty", "process"])
def test_missing_evidence_and_disagreement_are_skips(history, tmp_path, mode):
    _, commits, driver, args = history
    # Make the only unknown commit unclassifiable.
    args += ["--good", commits[1], "--bad", commits[3]]
    if mode in ("build", "empty"):
        action = "exit 7" if mode == "build" else "exit 0"
        args += ["--build", f'test "$(git rev-parse HEAD)" != {commits[2]} || {action}; cp state "$BISECT_OUT/state"']
    else:
        args += ["--build", 'git rev-parse HEAD > "$BISECT_OUT/id"; cp state "$BISECT_OUT/state"']
        action = {
            "invalid": "Path(os.environ['BISECT_RESULT']).write_text('{}')",
            "process": "sys.exit(1)",
            "disagree": (
                f"p = Path({str(tmp_path / 'counter')!r}); n = int(p.read_text()) if p.exists() else 0; "
                "p.write_text(str(n+1)); Path(os.environ['BISECT_RESULT']).write_text("
                "json.dumps({'verdict':'pass' if n%2 else 'fail'}))"
            ),
        }[mode]
        driver.write_text(driver.read_text() + f"if Path('id').read_text().strip() == '{commits[2]}':\n    {action}\n")
    result = invoke(args)
    assert result.returncode == 2, result.stderr
    data = report(tmp_path)
    assert data["status"] == "ambiguous"
    assert set(data["candidates"]) == {commits[2], commits[3]}
    step = next(row for row in data["steps"] if row["commit"] == commits[2])
    assert step["verdict"] == "skip"
    assert {"build": "exited 7", "disagree": "disagree", "invalid": "invalid trial",
            "empty": "no files", "process": "exited 1"}[mode] in step["reason"]


def test_cache_command_and_commit_identity(history, tmp_path):
    _, commits, _, args = history
    args += ["--cache-dir", str(tmp_path / "cache"), "--good", commits[1], "--bad", commits[2]]
    for number, changed in enumerate((False, False, True)):
        state = tmp_path / f"run{number}"
        extra = ["--build", 'cp state "$BISECT_OUT/state" # new toolchain'] if changed else []
        result = invoke([*args, "--state-dir", str(state), *extra])
        assert result.returncode == 0, result.stderr
        rows = json.loads((state / "report.json").read_text())["steps"]
        assert len(rows) == 2
        assert all(row["build"]["cached"] == (number == 1) for row in rows)
        assert len({row["build"]["key"] for row in rows}) == 2


def test_adjacent_endpoints_must_be_observed(history, tmp_path):
    _, commits, _, args = history
    result = invoke([*args, "--good", commits[0], "--bad", commits[1]])
    assert result.returncode == 2
    data = report(tmp_path)
    assert data["status"] == "endpoint_mismatch"
    assert data["actual"] == "pass" and data["expected"] == "fail"
    assert "first_changed_commit" not in data


def test_resume_preserves_completed_trials(history, tmp_path):
    _, commits, driver, args = history
    gate = tmp_path / "started"
    driver.write_text(driver.read_text() + f"""
gate = Path({str(gate)!r})
if not gate.exists():
    gate.write_text('one')
elif gate.read_text() == 'one':
    gate.write_text('two')
    import time
    time.sleep(20)
""")
    args += ["--good", commits[1], "--bad", commits[2]]
    p = subprocess.Popen([sys.executable, SCRIPT, *args], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(300):
            if gate.exists() and gate.read_text() == "two":
                break
            if p.poll() is not None:
                pytest.fail(f"bisector exited {p.returncode} before second trial")
            time.sleep(.025)
        assert gate.read_text() == "two"
        os.killpg(p.pid, signal.SIGINT)
        p.wait(timeout=8)
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
    before = report(tmp_path)["steps"][0]
    assert len(before["runs"]) == 1
    result = invoke(args)
    assert result.returncode == 0, result.stderr
    after = report(tmp_path)["steps"][0]
    assert after["runs"][0] == before["runs"][0]
    assert after["build"] == before["build"]
    assert len(after["runs"]) == 3
    driver.write_text(driver.read_text() + "# changed\n")
    assert "session inputs changed" in invoke(args).stderr


@pytest.mark.parametrize(("outcome", "expected"), [("success", "pass"), ("hard_fault", "fail"),
                                                  ("skipped", None), ("unreached", None), ("wrong-index", None)])
def test_record_oracle_checks_observed_write(tmp_path, monkeypatch, outcome, expected):
    import yaml
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import record_recovery_trial as oracle

    (tmp_path / "firmware_handled.elf").write_bytes(b"this revision's firmware")
    (tmp_path / "initial_mram.bin").write_bytes(b"this revision's data")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BISECT_RESULT", str(tmp_path / "trial-result.json"))

    def audit(command, *, check):
        assert check
        args = lambda flag: command[command.index(flag) + 1]
        generated = yaml.safe_load(Path(args("--profile")).read_text())
        assert Path(generated["bootloader"]["elf"]).read_bytes() == b"this revision's firmware"
        assert Path(generated["images"]["exec"]).read_bytes() == b"this revision's data"
        assert (args("--fault-start"), args("--fault-end")) == ("1", "2")
        row = {"fault_at": 2 if outcome == "wrong-index" else 1, "fault_type": "w",
               "fault_injected": outcome != "unreached", "boot_outcome": outcome}
        Path(args("--output")).write_text(json.dumps({"runtime_sweep_results": [row]}))

    monkeypatch.setattr(oracle.subprocess, "run", audit)
    profile = ROOT / "examples/mram_ecc_record_recovery/profile_handled.yaml"
    if expected:
        assert oracle.measure(profile, "w1")["verdict"] == expected
    else:
        with pytest.raises(ValueError, match="complete observation"):
            oracle.measure(profile, "w1")


@pytest.mark.parametrize(
    ("point", "row", "expected"),
    [
        ("e51", {"fault_at": 51, "fault_type": "e", "fault_injected": True, "boot_outcome": "hard_fault"}, "fail"),
        (
            "w3,w6",
            {
                "fault_at": 3,
                "fault_type": "p2:3:6:w:w",
                "fault_injected": True,
                "boot_outcome": "success",
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 6,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": True,
                    "skip_reason": None,
                },
            },
            "pass",
        ),
        (
            "w3,w6",
            {
                "fault_at": 3,
                "fault_type": "p2:3:6:w:w",
                "fault_injected": False,
                "boot_outcome": "success",
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 6,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": False,
                    "skip_reason": "no_write_at_index",
                },
            },
            None,
        ),
        (
            "w1,e2,w0",
            {
                "fault_at": 1,
                "fault_type": "pc:1:w:2:e:0:w",
                "fault_injected": True,
                "boot_outcome": "wrong_image",
                "phase2_fault_chain": {
                    "cut_count": 3,
                    "requested_cut_count": 3,
                    "skip_reason": None,
                    "cuts": [
                        {"fault_at": 1, "fault_type": "w", "injected": True},
                        {"fault_at": 2, "fault_type": "e", "injected": True},
                        {"fault_at": 0, "fault_type": "w", "injected": True},
                    ],
                },
            },
            "fail",
        ),
    ],
)
def test_oracle_supports_erase_pairs_and_chains(tmp_path, monkeypatch, point, row, expected):
    import yaml
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import record_recovery_trial as oracle

    (tmp_path / "oss_mcuboot_pr3011_move_broken.elf").write_bytes(b"elf")
    (tmp_path / "zephyr_head_move_nrf52_slot1.bin").write_bytes(b"slot1")
    (tmp_path / "zephyr_head_move_nrf52_slot0.bin").write_bytes(b"slot0")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BISECT_RESULT", str(tmp_path / "trial-result.json"))

    def audit(command, *, check):
        assert check
        args = lambda flag: command[command.index(flag) + 1]
        generated = yaml.safe_load(Path(args("--profile")).read_text())
        fs = generated["fault_sweep"]
        cuts = point.split(",")
        if len(cuts) == 1:
            assert (args("--fault-start"), args("--fault-end")) == ("51", "52")
            assert fs["fault_types"] == ["interrupted_erase"]
            assert fs["include_erase_fault_points"] is True
        elif len(cuts) == 2:
            assert args("--fault-start") == "1000000"
            assert fs["phase2_fault"]["pairs"] == [[3, 6]]
        else:
            assert args("--fault-start") == "1000000"
            assert fs["phase2_fault"]["chains"] == [[[1, "power_loss"], [2, "interrupted_erase"], [0, "power_loss"]]]
        Path(args("--output")).write_text(json.dumps({"runtime_sweep_results": [row]}))

    monkeypatch.setattr(oracle.subprocess, "run", audit)
    profile = ROOT / "profiles/mcuboot_pr3011_move_broken.yaml"
    if expected:
        assert oracle.measure(profile, point)["verdict"] == expected
    else:
        with pytest.raises(ValueError, match="complete observation"):
            oracle.measure(profile, point)


def test_bare_source_and_paths_with_spaces(history, tmp_path):
    source, commits, _, args = history
    bare = tmp_path / "record source.git"
    git(source, "clone", "-q", "--bare", str(source), str(bare))
    result = invoke([*args, "--repo", str(bare), "--state-dir", str(tmp_path / "a session")])
    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / "a session/report.json").read_text())["first_changed_commit"] == commits[2]
