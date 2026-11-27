# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
"""Bisect a source history using repeated observations of one explicit point."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


PACKAGE = Path(__file__).resolve().parent
RUNTIME = PACKAGE / "runtime" if (PACKAGE / "runtime").is_dir() else PACKAGE.parent
RECORD_TRIAL = RUNTIME / "scripts/record_recovery_trial.py"


def add_arguments(parser):
    parser.add_argument("--repo", type=Path, required=True, help="source repository")
    parser.add_argument("--good", required=True, help="revision where the point passes")
    parser.add_argument("--bad", required=True, help="revision where the point fails")
    parser.add_argument("--find", choices=("regression", "fix"), default="regression")
    parser.add_argument("--build", required=True, help="shell command exporting build outputs to $BISECT_OUT")
    parser.add_argument("--trial", type=Path, default=RECORD_TRIAL,
                        help="point test executable (default: built-in profile point runner)")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--point", required=True, help="one write or erase, e.g. w0, or an ordered tuple, e.g. w0,e1")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300, help="seconds per build or trial")
    parser.add_argument("--state-dir", type=Path, required=True, help="persistent session and report directory")
    parser.add_argument("--cache-dir", type=Path, help="build cache, defaults to the session's cache directory")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False, encoding="utf-8") as file:
        json.dump(value, file, indent=2)
        file.write("\n")
    os.replace(file.name, path)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def git(repo, *args, check=True):
    result = subprocess.run(
        ["git", "-C", repo, *args], capture_output=True, text=True,
        env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"},
    )
    if check and result.returncode:
        raise ValueError(result.stderr.strip() or result.stdout.strip() or f"git {args[0]} failed")
    return result


@contextmanager
def locked(path, *, wait=False):
    import fcntl

    with path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            raise ValueError(f"session already in use: {path.parent}") from None
        yield lock


def registered(repo, path):
    records = git(repo, "worktree", "list", "--porcelain", "-z").stdout.split("\0")
    return f"worktree {path}" in records


def remove_worktree(repo, path):
    if registered(repo, path):
        git(repo, "worktree", "remove", "--force", str(path))


@contextmanager
def worktree(repo, path, commit):
    # A killed session can leave its private checkout registered.
    remove_worktree(repo, path)
    git(repo, "worktree", "add", "--detach", str(path), commit)
    try:
        yield
    finally:
        remove_worktree(repo, path)


def execute(command, cwd, env, timeout, log):
    start = time.monotonic()
    reason = None
    code = None
    with log.open("wb") as stream:
        try:
            with subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                  stderr=subprocess.STDOUT, start_new_session=True) as process:
                try:
                    code = process.wait(timeout=timeout)
                finally:
                    # Include helpers left behind by a timed-out or interrupted command.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        except subprocess.TimeoutExpired:
            reason = f"timeout after {timeout}s"
        except OSError as exc:
            reason = str(exc)
    return {"seconds": time.monotonic() - start, "exit_code": code, "error": reason, "log": log.name}


def build(config, state, commit, logs):
    # A Git commit identifies its tree. The command must identify its toolchain
    # and other external build inputs for reuse across sessions.
    key = digest(json.dumps([commit, config["build"]]).encode())
    cache = Path(config["cache"])
    cache.mkdir(parents=True, exist_ok=True)
    entry = cache / key
    with locked(cache / (key + ".lock"), wait=True):
        if entry.exists():
            info = read_json(entry / "build.json")
            return entry / "out", {**info, "cached": True, "seconds": 0.0, "log": None}
        with tempfile.TemporaryDirectory(dir=cache, prefix=key + ".") as staging:
            stage = Path(staging)
            out = stage / "out"
            out.mkdir()
            tree = state / "build-tree"
            with worktree(config["repo"], tree, commit):
                info = execute(
                    ["/bin/sh", "-c", config["build"]], tree,
                    {**os.environ, "BISECT_OUT": str(out)}, config["timeout"], logs / "build.log",
                )
            info.update(cached=False, key=key)
            if info["exit_code"] == 0 and not any(p.is_file() for p in out.rglob("*")):
                info["error"] = "build exported no files"
            if info["exit_code"] or info["error"]:
                return None, info
            if any(p.is_symlink() or not (p.is_dir() or p.is_file()) for p in out.rglob("*")):
                info["error"] = "build exports must be regular files and directories"
                return None, info
            save_json(stage / "build.json", info)
            stage.rename(entry)
            return entry / "out", info


def trial(config, artifacts, logs, number):
    with tempfile.TemporaryDirectory(dir=logs) as scratch:
        directory = Path(scratch)
        cwd = directory / "build"
        shutil.copytree(artifacts, cwd)
        result = directory / "result.json"
        command = [config["trial"]]
        if Path(config["trial"]) == RECORD_TRIAL:
            command.insert(0, sys.executable)
        run = execute(
            command + [config["profile"], config["point"]], cwd,
            {**os.environ, "BISECT_RESULT": str(result)}, config["timeout"], logs / f"trial-{number}.log",
        )
        verdict = "skip"
        reason = run["error"]
        if run["exit_code"] == 0:
            try:
                record = read_json(result)
                if not isinstance(record, dict) or record.get("verdict") not in ("pass", "fail", "skip"):
                    raise ValueError("expected a pass, fail or skip verdict")
                verdict = record["verdict"]
                reason = record.get("reason") or ("trial skipped" if verdict == "skip" else None)
            except (ValueError, OSError) as exc:
                reason = f"invalid trial result: {exc}"
        elif reason is None:
            reason = f"trial exited {run['exit_code']}"
        return {**run, "verdict": verdict, "reason": reason}


def verify_inputs(config):
    for name in ("profile", "trial"):
        if digest(Path(config[name]).read_bytes()) != config[f"{name}_sha256"]:
            raise ValueError(f"{name} changed during bisection")


def step(state, commit):
    report_path = state / "report.json"
    report = read_json(report_path)
    config = report["config"]
    rows = report["steps"]
    row = next((item for item in rows if item["commit"] == commit), None)
    if row is None:
        row = {"commit": commit, "runs": []}
        rows.append(row)
    if "verdict" not in row:
        logs = state / "logs" / commit
        logs.mkdir(parents=True, exist_ok=True)
        artifacts, info = build(config, state, commit, logs)
        if "build" not in row or not info["cached"]:
            row["build"] = info
        save_json(report_path, report)
        if artifacts is None:
            row.update(verdict="skip", reason=info["error"] or f"build exited {info['exit_code']}")
        else:
            while len(row["runs"]) < config["repeat"]:
                verify_inputs(config)
                observation = trial(config, artifacts, logs, len(row["runs"]) + 1)
                verify_inputs(config)
                row["runs"].append(observation)
                save_json(report_path, report)
            runs = row["runs"]
            skipped = next((run for run in runs if run["verdict"] == "skip"), None)
            if skipped:
                row.update(verdict="skip", reason=skipped["reason"])
            elif len({run["verdict"] for run in runs}) != 1:
                row.update(verdict="skip", reason="trial verdicts disagree")
            else:
                row.update(verdict=runs[0]["verdict"], reason=None)
        save_json(report_path, report)
    return row["verdict"]


def classify(state, commit):
    verdict = step(state, commit)
    if verdict == "skip":
        return 125
    old = read_json(state / "report.json")["old_verdict"]
    return 0 if verdict == old else 1


def configuration(args, state):
    if args.timeout < 1 or args.repeat < 1:
        raise ValueError("--timeout and --repeat must be positive")
    if not re.fullmatch(r"[we](?:0|[1-9][0-9]*)(?:,[we](?:0|[1-9][0-9]*)){0,7}", args.point):
        raise ValueError("--point requires 1 to 8 explicit write/erase indices, such as w0, w3,w6 or w1,e2,w0")
    source = args.repo.resolve()
    bare = git(source, "rev-parse", "--is-bare-repository").stdout.strip() == "true"
    location = "--absolute-git-dir" if bare else "--show-toplevel"
    repo = Path(git(source, "rev-parse", location).stdout.strip()).resolve()
    cache = (args.cache_dir or state / "cache").resolve()
    if state.is_relative_to(repo) or cache.is_relative_to(repo):
        raise ValueError("place session and cache directories outside the source checkout")
    trial_path = args.trial.resolve(strict=True)
    if not trial_path.is_file() or (trial_path != RECORD_TRIAL and not os.access(trial_path, os.X_OK)):
        raise ValueError("--trial must name an executable file")
    profile = args.profile.resolve(strict=True)
    config = dict(repo=str(repo), build=args.build, point=args.point, find=args.find,
                  profile=str(profile), profile_sha256=digest(profile.read_bytes()),
                  trial=str(trial_path), trial_sha256=digest(trial_path.read_bytes()),
                  repeat=args.repeat, timeout=args.timeout, cache=str(cache))
    for term in ("good", "bad"):
        ref = getattr(args, term)
        config[term] = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").stdout.strip()
    return config


def git_probe(select, state, session_lock):
    command = ["git", "-C", select, "bisect", "run", sys.executable, str(Path(__file__).resolve()),
               "--step", str(state)]
    with (state / "git-run.log").open("w") as log:
        # Keep the session locked while Git drives its callbacks, even if the
        # parent is killed before it can wait for Git.
        with subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                              env={**os.environ, "LC_ALL": "C"}, pass_fds=(session_lock.fileno(),)) as process:
            try:
                return process.wait()
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                raise


def search(state, config, old, new, old_verdict, session_lock):
    select = state / "select-tree"
    log_path = state / "bisect.log"
    term_old, term_new = ("passing", "failing") if old_verdict == "pass" else ("failing", "passing")
    with worktree(config["repo"], select, new):
        for revision, expected in ((old, old_verdict), (new, "fail" if old_verdict == "pass" else "pass")):
            actual = step(state, revision)
            if actual != expected:
                return {"status": "endpoint_mismatch", "endpoint": revision, "expected": expected, "actual": actual}
        git(select, "bisect", "start", f"--term-old={term_old}", f"--term-new={term_new}", new, old, "--")
        log = git(select, "bisect", "log").stdout
        first = rf"^# first '?{term_new}'? commit: \[([0-9a-f]+)\]"
        possible = []
        if not re.search(first, log, re.M):
            exit_code = git_probe(select, state, session_lock)
            log = git(select, "bisect", "log").stdout
            possible = re.findall(rf"^# possible first '?{term_new}'? commit: \[([0-9a-f]+)\]", log, re.M)
            if exit_code and not possible:
                log_path.write_text(log)
                raise ValueError(f"git bisect run exited {exit_code}; see git-run.log")
        log_path.write_text(log)
        found = re.search(first, log, re.M)
        if found:
            return {"status": "found", "first_changed_commit": found[1]}
        if possible:
            return {"status": "ambiguous", "candidates": possible}
        raise ValueError("git bisect produced no conclusion; see bisect.log")


def run_session(args):
    state = args.state_dir.resolve()
    config = configuration(args, state)
    old_verdict = "pass" if args.find == "regression" else "fail"
    old, new = (config["good"], config["bad"]) if old_verdict == "pass" else (config["bad"], config["good"])
    if old == new or git(config["repo"], "merge-base", "--is-ancestor", old, new, check=False).returncode:
        raise ValueError("expected distinct, ordered endpoints; check --find, --good and --bad")
    state.mkdir(parents=True, exist_ok=True)
    path = state / "report.json"
    with locked(state / "session.lock") as session_lock:
        if path.exists():
            report = read_json(path)
            if report.get("config") != config:
                raise ValueError("session inputs changed; use a new --state-dir")
        else:
            if any(p.name != "session.lock" for p in state.iterdir()):
                raise ValueError("new session requires an empty --state-dir")
            report = {"config": config, "old_verdict": old_verdict, "status": "running", "steps": []}
            save_json(path, report)
        if report["status"] == "running":
            outcome = search(state, config, old, new, old_verdict, session_lock)
            report = read_json(path)
            report.update(outcome)
            save_json(path, report)
    print(report.get("first_changed_commit", report["status"]), path)
    return 0 if report["status"] == "found" else 2


def interrupt(signum, frame):
    raise KeyboardInterrupt


def run(args):
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        return run_session(args)
    except KeyboardInterrupt:
        print("bisection interrupted; repeat the command to resume", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv):
    if len(argv) == 2 and argv[0] == "--step":
        signal.signal(signal.SIGTERM, interrupt)
        state = Path(argv[1])
        commit = git(Path.cwd(), "rev-parse", "HEAD").stdout.strip()
        try:
            return classify(state, commit)
        except KeyboardInterrupt:
            return 130
        except (ValueError, OSError) as exc:
            print(exc, file=sys.stderr)
            return 128
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    try:
        return run(parser.parse_args(argv))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
