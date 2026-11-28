"""Command line entry point for an installed Tardigrade distribution."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent
# Checkout scripts and Renode includes use the same relative layout as the wheel.
RUNTIME = PACKAGE / "runtime" if (PACKAGE / "runtime").is_dir() else PACKAGE.parent
SUPPORTED = {"1.16.1", "1.17.0"}


def probe(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def doctor(args):
    print(f"Python {sys.version.split()[0]} ({sys.executable})")
    runner = shutil.which(args.renode_test)
    binary = Path(runner).resolve().with_name("renode") if runner else None
    version = probe([str(binary), "--version"]) if binary else ""
    match = re.search(r"\bRenode(?:,? version)?\s+v?(\d+\.\d+\.\d+)\b", version, re.I)
    supported = bool(match and match[1] in SUPPORTED)
    if supported:
        print(f"Renode {match[1]} ({runner})")
    else:
        reason = f"unsupported {match[1]}" if match else "unavailable"
        print(f"Renode {reason}. Install Renode 1.17.0 or 1.16.1 and set RENODE_TEST to its renode-test.")
    client = shutil.which("docker")
    docker = probe([client, "version", "--format", "{{.Server.Version}}"]) if client else ""
    if docker:
        print(f"Docker {docker}")
    elif client:
        print("Docker server unavailable. Start the daemon and check access with docker version.")
    else:
        print("Docker unavailable. Install Docker Engine or Docker Desktop to use the Docker demo.")
    return 0 if supported or docker else 1


def _resolve_runner_arg(value: str) -> str:
    if not value or value.startswith("docker://"):
        return value
    if "/" in value or os.sep in value:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        return str(candidate.resolve())
    return value


def _audit_workdir(profile_path: Path) -> Path:
    parent = profile_path.parent
    if parent.name == "profiles" and (parent.parent / "profiles").is_dir():
        return parent.parent
    return Path.cwd()


def run_audit(profile: Path, output: Path, renode_test: str, timeout: int | None = None, extra_args=()):
    if timeout is not None and timeout <= 0:
        raise ValueError("--timeout must be positive")
    resolved_profile = profile.expanduser().resolve()
    resolved_output = output.expanduser().resolve()
    runner = _resolve_runner_arg(renode_test)
    command = [
        sys.executable,
        str(RUNTIME / "scripts/audit_bootloader.py"),
        "--profile",
        str(resolved_profile),
        "--output",
        str(resolved_output),
        "--renode-test",
        runner,
        *extra_args,
    ]
    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    if timeout is not None:
        env.setdefault("OTA_RENODE_POINT_TIMEOUT_S", str(timeout))
    workdir = _audit_workdir(resolved_profile)
    process = subprocess.Popen(command, cwd=str(workdir), env=env, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise ValueError(f"audit exceeded {timeout}s") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tardigrade")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("doctor", help="check the local execution environment")
    runner = os.environ.get("RENODE_TEST", "renode-test")
    check.add_argument("--renode-test", default=runner)
    init = commands.add_parser("init", help="derive a starter profile from build artifacts")
    init.add_argument("--bootloader", required=True, type=Path)
    init.add_argument("--primary", required=True, type=Path)
    init.add_argument("--update", required=True, type=Path)
    init.add_argument("--build-dir", type=Path, help="bootloader build containing zephyr/ or a NuttX .config")
    init.add_argument("--output", required=True, type=Path)
    init.add_argument("--control", action="store_true", help="boot the completed profile once")
    init.add_argument("--renode-test", default=runner)
    init.add_argument("--timeout", type=int, default=300, help="control wall-clock budget in seconds")
    audit = commands.add_parser("audit", help="run the profile-driven bootloader audit")
    audit.add_argument("--profile", required=True, type=Path)
    audit.add_argument("--output", required=True, type=Path)
    audit.add_argument("--renode-test", default=runner)
    audit.add_argument("--resume-state-search", type=Path, metavar="CHECKPOINT",
                       help="continue a recovery search from its checkpoint")
    audit.add_argument("--timeout", type=int, default=None, help="optional wall-clock budget in seconds")
    demo = commands.add_parser("demo", help="run the two-profile power-loss demo")
    demo.add_argument("--renode-test", default=runner)
    demo.add_argument("--timeout", type=int, default=600)
    demo.add_argument("--workers", type=int, default=1)
    demo.add_argument("--output-dir", type=Path, default=Path("results/demo"))
    bisect_parser = commands.add_parser("bisect", help="find a change in a repeated point verdict")
    from .verdict_bisect import add_arguments, run as run_bisect
    add_arguments(bisect_parser)
    report = commands.add_parser("report", help="render audit JSON as HTML")
    report.add_argument("--input", required=True, action="append")
    report.add_argument("--output", required=True)
    merge = commands.add_parser("merge-state-search", help="merge recovery state search shard reports")
    merge.add_argument("shards", nargs="+", type=Path, metavar="SHARD.json")
    merge.add_argument("--output", required=True, type=Path)
    debug = commands.add_parser("debug", help="open a failing point or state in a Renode GDB session")
    debug.add_argument("--report", "--input", "--sarif", dest="report", type=Path)
    debug.add_argument("--point")
    debug.add_argument("--state")
    debug.add_argument("--reproduction")
    debug.add_argument("--profile", type=Path)
    debug.add_argument("--elf", type=Path)
    debug.add_argument("--stop-at", "--at", "--stop", dest="stop_at", default="recovery-reset")
    debug.add_argument("--port", type=int, default=3333)
    debug.add_argument("--gdb")
    debug.add_argument("--renode-test", default=runner)
    debug.add_argument("--timeout", type=int, default=300)
    debug.add_argument("--output", type=Path)
    debug.add_argument("--ex", dest="gdb_ex", action="append")
    args, unknown = parser.parse_known_args(argv)
    if unknown and args.command != "audit":
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")
    if args.command == "doctor":
        return doctor(args)
    if args.command == "debug":
        sys.path.insert(0, str(RUNTIME / "scripts"))
        import debug_point

        debug_argv = [
            "--stop-at",
            str(args.stop_at),
            "--port",
            str(args.port),
            "--renode-test",
            _resolve_runner_arg(args.renode_test),
            "--timeout",
            str(args.timeout),
            "--repo-root",
            str(RUNTIME),
        ]
        if args.report is not None:
            debug_argv.extend(["--report", str(args.report.expanduser().resolve())])
        if args.point is not None:
            debug_argv.extend(["--point", str(args.point)])
        if args.state is not None:
            debug_argv.extend(["--state", str(args.state)])
        if args.reproduction is not None:
            debug_argv.extend(["--reproduction", str(args.reproduction)])
        if args.profile is not None:
            debug_argv.extend(["--profile", str(args.profile.expanduser().resolve())])
        if args.elf is not None:
            debug_argv.extend(["--elf", str(args.elf.expanduser().resolve())])
        if args.gdb is not None:
            debug_argv.extend(["--gdb", str(args.gdb)])
        if args.output is not None:
            debug_argv.extend(["--output", str(args.output.expanduser().resolve())])
        for ex_cmd in args.gdb_ex or ():
            debug_argv.extend(["--ex", str(ex_cmd)])
        return debug_point.main(debug_argv, prog="tardigrade debug")
    if args.command == "report":
        command = [sys.executable, str(RUNTIME / "scripts/render_results_html.py")]
        for item in args.input:
            command.extend(["--input", item])
        return subprocess.call([*command, "--output", args.output])
    if args.command == "demo":
        return subprocess.call([
            sys.executable,
            str(RUNTIME / "scripts/run_demo.py"),
            "--renode-test",
            _resolve_runner_arg(args.renode_test),
            "--timeout",
            str(args.timeout),
            "--workers",
            str(args.workers),
            "--output-dir",
            str(args.output_dir.expanduser().resolve()),
        ])
    try:
        if args.command == "bisect":
            return run_bisect(args)
        if args.command == "merge-state-search":
            sys.path.insert(0, str(RUNTIME / "scripts"))
            from merge_state_search import merge_files
            merge_files(args.shards, args.output)
            return 0
        if args.command == "init":
            if args.timeout is not None and args.timeout <= 0:
                raise ValueError("--timeout must be positive")
            sys.path.insert(0, str(RUNTIME / "scripts"))
            from .starter import generate
            generate(args)
            if not args.control:
                return 0
            return run_audit(
                args.output,
                args.output.with_suffix(".control.json"),
                args.renode_test,
                args.timeout,
            )
        if args.resume_state_search:
            unknown.extend(["--resume-state-search", str(args.resume_state_search.expanduser().resolve())])
        return run_audit(
            args.profile,
            args.output,
            args.renode_test,
            args.timeout,
            unknown,
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"tardigrade {args.command}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
