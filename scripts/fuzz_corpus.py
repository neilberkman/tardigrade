#!/usr/bin/env python3
"""Workflow helpers for fuzzer crash corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

import fuzz_crash_to_profile as fcp


def _crash_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_base_template(path: Path) -> Dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("base profile must be a YAML mapping")
    return raw


def _load_regions(address_map: Optional[str]) -> List[Dict[str, Any]]:
    return fcp.load_region_map(address_map or None)


def _write_signature(
    crash_data: bytes,
    regions: List[Dict[str, Any]],
    meta_base: Optional[int],
) -> Tuple[Tuple[str, str], ...]:
    base = int(meta_base) if meta_base is not None else 0
    writes = fcp.crash_bytes_to_writes(crash_data, regions, base_address=base)
    return tuple((entry["address"], entry["u32"]) for entry in writes)


def _profile_hashes(profile_dir: Path) -> Dict[str, List[Path]]:
    hashes: Dict[str, List[Path]] = {}
    if not profile_dir.exists():
        return hashes
    for path in sorted(profile_dir.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            continue
        fuzz_meta = raw.get("fuzz_metadata")
        if not isinstance(fuzz_meta, dict):
            continue
        crash_sha = str(fuzz_meta.get("crash_sha256", "")).strip()
        if not crash_sha:
            continue
        hashes.setdefault(crash_sha, []).append(path)
    return hashes


def minimize_corpus(
    crash_dir: Path,
    output_dir: Path,
    *,
    address_map: Optional[str] = None,
    meta_base: Optional[int] = None,
) -> Dict[str, Any]:
    crash_files = fcp.find_crash_files(crash_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    regions = _load_regions(address_map)
    seen_sha: Dict[str, Path] = {}
    seen_write_sigs: Dict[Tuple[Tuple[str, str], ...], Path] = {}
    kept: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for crash_path in crash_files:
        crash_data = crash_path.read_bytes()
        if not crash_data:
            skipped.append({"crash_file": crash_path.name, "reason": "empty"})
            continue
        sha = _crash_sha256(crash_data)
        if sha in seen_sha:
            skipped.append(
                {
                    "crash_file": crash_path.name,
                    "reason": "duplicate_sha256",
                    "duplicate_of": seen_sha[sha].name,
                }
            )
            continue
        write_sig = _write_signature(crash_data, regions, meta_base)
        if write_sig in seen_write_sigs:
            skipped.append(
                {
                    "crash_file": crash_path.name,
                    "reason": "duplicate_pre_boot_state",
                    "duplicate_of": seen_write_sigs[write_sig].name,
                }
            )
            continue

        seen_sha[sha] = crash_path
        seen_write_sigs[write_sig] = crash_path
        out_path = output_dir / crash_path.name
        shutil.copy2(crash_path, out_path)
        kept.append(
            {
                "crash_file": crash_path.name,
                "sha256": sha,
                "output_path": str(out_path),
            }
        )

    return {
        "crash_dir": str(crash_dir),
        "output_dir": str(output_dir),
        "kept": kept,
        "skipped": skipped,
        "kept_count": len(kept),
        "skipped_count": len(skipped),
    }


def corpus_status(crash_dir: Path, profile_dir: Path) -> Dict[str, Any]:
    crash_files = fcp.find_crash_files(crash_dir)
    hashes = _profile_hashes(profile_dir)
    converted: List[Dict[str, Any]] = []
    new: List[Dict[str, Any]] = []

    for crash_path in crash_files:
        crash_data = crash_path.read_bytes()
        if not crash_data:
            continue
        sha = _crash_sha256(crash_data)
        entry = {
            "crash_file": crash_path.name,
            "sha256": sha,
        }
        if sha in hashes:
            entry["profiles"] = [str(path) for path in hashes[sha]]
            converted.append(entry)
        else:
            new.append(entry)

    return {
        "crash_dir": str(crash_dir),
        "profile_dir": str(profile_dir),
        "converted": converted,
        "new": new,
        "converted_count": len(converted),
        "new_count": len(new),
    }


def convert_corpus(
    crash_dir: Path,
    base_profile: Path,
    output_dir: Path,
    *,
    address_map: Optional[str] = None,
    meta_base: Optional[int] = None,
    mode: str = "pre_boot_state",
    skip_existing: bool = False,
    fuzzer: Optional[str] = None,
    expect_rejection: bool = True,
    name_suffix: Optional[str] = None,
) -> Dict[str, Any]:
    crash_files = fcp.find_crash_files(crash_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    template = _load_base_template(base_profile)
    regions = _load_regions(address_map)
    existing = _profile_hashes(output_dir) if skip_existing else {}

    generated: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for crash_path in crash_files:
        crash_data = crash_path.read_bytes()
        if not crash_data:
            skipped.append({"crash_file": crash_path.name, "reason": "empty"})
            continue

        crash_sha = _crash_sha256(crash_data)
        if skip_existing and crash_sha in existing:
            skipped.append(
                {
                    "crash_file": crash_path.name,
                    "reason": "existing_profile",
                    "profiles": [str(path) for path in existing[crash_sha]],
                }
            )
            continue

        sha_short = crash_sha[:12]
        profile_path = output_dir / "fuzz_regression_{}.yaml".format(sha_short)
        staging_image_path = None
        if mode == "staging_image":
            staging_image_path = fcp.crash_as_staging_image(
                crash_data, crash_path, output_dir
            )

        try:
            profile = fcp.generate_profile(
                crash_data=crash_data,
                crash_path=crash_path,
                template=template,
                regions=regions,
                meta_base=meta_base,
                mode=mode,
                staging_image_path=staging_image_path,
                fuzzer=fuzzer,
                name_suffix=name_suffix,
                expect_rejection=expect_rejection,
            )
        except (ValueError, TypeError, KeyError, OSError) as exc:
            skipped.append(
                {
                    "crash_file": crash_path.name,
                    "reason": "conversion_error",
                    "detail": "{}: {}".format(type(exc).__name__, exc),
                }
            )
            continue

        profile_path.write_text(
            yaml.safe_dump(profile, sort_keys=False),
            encoding="utf-8",
        )
        generated.append(
            {
                "crash_file": crash_path.name,
                "sha256": crash_sha,
                "profile_path": str(profile_path),
            }
        )

    return {
        "crash_dir": str(crash_dir),
        "base_profile": str(base_profile),
        "output_dir": str(output_dir),
        "generated": generated,
        "skipped": skipped,
        "generated_count": len(generated),
        "skipped_count": len(skipped),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage fuzzer crash corpora.")
    sub = parser.add_subparsers(dest="command", required=True)

    minimize = sub.add_parser("minimize", help="Deduplicate crash inputs.")
    minimize.add_argument("--crash-dir", required=True)
    minimize.add_argument("--output", required=True)
    minimize.add_argument("--address-map", default=None)
    minimize.add_argument("--meta-base", type=lambda v: int(v, 0), default=None)
    minimize.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="Show crash/profile coverage.")
    status.add_argument("--crash-dir", required=True)
    status.add_argument("--profile-dir", required=True)
    status.add_argument("--json", action="store_true")

    convert = sub.add_parser("convert", help="Convert crash inputs to profiles.")
    convert.add_argument("--crash-dir", required=True)
    convert.add_argument("--base-profile", required=True)
    convert.add_argument("--output-dir", required=True)
    convert.add_argument("--address-map", default=None)
    convert.add_argument("--meta-base", type=lambda v: int(v, 0), default=None)
    convert.add_argument(
        "--mode",
        choices=["pre_boot_state", "staging_image"],
        default="pre_boot_state",
    )
    convert.add_argument("--skip-existing", action="store_true")
    convert.add_argument(
        "--fuzzer",
        choices=["libfuzzer", "afl", "honggfuzz", "other"],
        default=None,
    )
    convert.add_argument(
        "--no-expect-rejection",
        dest="expect_rejection",
        action="store_false",
        default=True,
    )
    convert.add_argument("--name-suffix", default=None)
    convert.add_argument("--json", action="store_true")

    return parser.parse_args(argv)


def _emit(payload: Dict[str, Any], json_mode: bool) -> int:
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(
        "{}: {} generated/kept, {} skipped".format(
            payload.get("output_dir") or payload.get("profile_dir") or payload.get("crash_dir"),
            payload.get("generated_count", payload.get("kept_count", 0)),
            payload.get("skipped_count", payload.get("new_count", 0)),
        )
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "minimize":
        payload = minimize_corpus(
            Path(args.crash_dir),
            Path(args.output),
            address_map=args.address_map,
            meta_base=args.meta_base,
        )
        return _emit(payload, args.json)
    if args.command == "status":
        payload = corpus_status(Path(args.crash_dir), Path(args.profile_dir))
        return _emit(payload, args.json)
    payload = convert_corpus(
        Path(args.crash_dir),
        Path(args.base_profile),
        Path(args.output_dir),
        address_map=args.address_map,
        meta_base=args.meta_base,
        mode=args.mode,
        skip_existing=args.skip_existing,
        fuzzer=args.fuzzer,
        expect_rejection=args.expect_rejection,
        name_suffix=args.name_suffix,
    )
    return _emit(payload, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
