#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Rebuild a failing audit point or state and open it in Renode's GDB server."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import unquote, urlparse
import zlib

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from fault_classification import (  # noqa: E402
    _effective_boot_result,
    classify_failure_class,
    result_has_initial_timeout,
    result_is_brick,
    result_is_infrastructure_error,
    result_is_skipped,
)
from fault_inject import decode_multi_fault_sequence, decode_multi_fault_stage_types  # noqa: E402
from fault_types import FAULT_TYPE_NAME_TO_CODE  # noqa: E402
from point_counts import classify_point_kind  # noqa: E402
from profile_loader import (  # noqa: E402
    ProfileConfig,
    _resolve_profile_input_path,
    load_profile,
)
from recovery_checkpoint import restore_snapshots  # noqa: E402
from recovery_explanation import explain_recovery_failures  # noqa: E402
from recovery_state import PersistentState  # noqa: E402
from renode_runner import (  # noqa: E402
    ensure_tool,
    merge_robot_vars,
    prepare_renode_command,
    prepare_run_environment,
)
from report_formats import saved_run  # noqa: E402
from report_points import Point, ReportRun, point_cuts, point_label, wire_point  # noqa: E402
from result_checks import annotate_result_checks  # noqa: E402
from sweep import (  # noqa: E402
    _cleanup_generated_robot_vars,
    build_control_robot_vars,
    build_fault_robot_vars,
)


DEFAULT_RENODE_TEST = os.environ.get("RENODE_TEST", "renode-test")
DEFAULT_ROBOT_SUITE = "tests/ota_fault_point.robot"
STOP_AT_ALIASES = {
    "recovery-reset": "recovery-reset",
    "recovery_reset": "recovery-reset",
    "reset-vector": "recovery-reset",
    "reset_vector": "recovery-reset",
    "recovery": "recovery-reset",
    "cut": "cut",
    "at-cut": "cut",
    "at_cut": "cut",
    "first-fault": "first-fault",
    "first_fault": "first-fault",
    "fault": "first-fault",
}
CODE_TO_FAULT_NAME = {code: name for name, code in FAULT_TYPE_NAME_TO_CODE.items()}
OPERATION_NAME_TO_CODE = {
    "write": "w",
    "erase": "e",
}
SINGLE_BOOT_NON_RESET_CODES = frozenset({
    "b",
    "s",
    "g",
    "x",
    "r",
    "d",
    "l",
    "k",
    "f",
    "i",
    "tb",
    "in",
    "it",
    "ib",
    "ic",
    "iw",
    "nv",
})
AUXILIARY_UNSUPPORTED_KINDS = {
    "partial_staging": "partial-staging truncation",
    "state_fuzz": "state-fuzz scenario",
    "fuzz_crash": "fuzz-crash regression",
    "authorization_review": "static authorization-review",
}


class DebugError(ValueError):
    """Raised when a debug request is malformed, ambiguous, or unsupported."""


@dataclass(frozen=True)
class DebugTarget:
    profile: ProfileConfig
    profile_path: Path
    elf_path: Path
    component: str | None
    point_name: str
    point_kind: str
    fault_at: int
    fault_type_code: str
    cuts: tuple[tuple[int, str], ...]
    is_control: bool
    state_identity: str | None
    state_search_gated: bool
    include_erase_fault_points: bool
    expected_outcome: str | None = None
    expected_fault_class: str | None = None
    row: dict[str, Any] | None = None
    pre_recovery_state: dict[str, Any] | None = None
    checkpoint_snapshot: dict[str, Any] | None = None
    expected_explanation: dict[str, Any] | None = None


def normalize_stop_at(value: str) -> str:
    token = str(value or "").strip().lower()
    canonical = STOP_AT_ALIASES.get(token)
    if canonical is None:
        raise DebugError(
            f"unsupported --stop-at value {value!r}; choose recovery-reset, cut, or first-fault"
        )
    return canonical


def select_gdb_binary(preferred: str | None = None) -> str:
    if preferred is not None:
        text = str(preferred).strip()
        if not text:
            raise DebugError("--gdb must not be empty")
        return text
    for candidate in ("arm-none-eabi-gdb", "gdb-multiarch", "gdb"):
        if shutil.which(candidate):
            return candidate
    return "arm-none-eabi-gdb"


def format_gdb_command(gdb_binary: str, elf_path: Path, port: int) -> str:
    quoted_gdb = shlex.quote(str(gdb_binary))
    quoted_elf = shlex.quote(str(elf_path))
    return f'{quoted_gdb} {quoted_elf} -ex "target remote :{int(port)}"'


def _allocate_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or port < 0 or port > 65535:
        raise DebugError(f"--port must be an integer between 0 and 65535, got {port!r}")
    if port == 0:
        return _allocate_ephemeral_port()
    return port


def _fault_type_to_code(value: Any) -> str:
    token = str(value or "").strip()
    if not token:
        raise DebugError("fault type must not be empty")
    lower = token.lower()
    if lower in FAULT_TYPE_NAME_TO_CODE:
        return FAULT_TYPE_NAME_TO_CODE[lower]
    if lower in CODE_TO_FAULT_NAME:
        return lower
    if lower in OPERATION_NAME_TO_CODE:
        return OPERATION_NAME_TO_CODE[lower]
    base, sep, rest = token.partition(":")
    if sep and base in {"p2", "pc", "mf", "c", "i", "tb", "b", "m", "h", "cc", "nv"} and rest:
        return token
    raise DebugError(f"unknown fault type {value!r}")


def _parse_non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise DebugError(f"{label} must be a non-negative integer, got {value!r}")
    try:
        parsed = int(str(value).strip(), 0)
    except (TypeError, ValueError) as exc:
        raise DebugError(f"{label} must be a non-negative integer, got {value!r}") from exc
    if parsed < 0:
        raise DebugError(f"{label} must be non-negative, got {parsed}")
    return parsed


def _cuts_from_wire_code(fault_at: int, code: str) -> tuple[tuple[int, str], ...]:
    if code == "control" or fault_at < 0:
        return ()
    parts = code.split(":")
    prefix = parts[0]
    if prefix == "p2":
        if len(parts) < 3:
            raise DebugError(f"malformed two-cut wire code {code!r}")
        p1_at = _parse_non_negative_int(parts[1], "p1_fault_at")
        p2_at = _parse_non_negative_int(parts[2], "p2_fault_at")
        p1_code = _fault_type_to_code(parts[3] if len(parts) > 3 else "w")
        p2_code = _fault_type_to_code(parts[4] if len(parts) > 4 else "w")
        return ((p1_at, p1_code), (p2_at, p2_code))
    if prefix == "pc":
        tail = parts[1:]
        if len(tail) < 6 or len(tail) % 2 != 0:
            raise DebugError(f"malformed phase2 fault chain wire code {code!r}")
        cuts = []
        for idx in range(0, len(tail), 2):
            cut_at = _parse_non_negative_int(tail[idx], f"chain cut {idx // 2 + 1} index")
            cut_code = _fault_type_to_code(tail[idx + 1])
            if cut_code not in ("w", "e"):
                raise DebugError(
                    f"phase2 fault chain supports only power_loss (w) and interrupted_erase (e), got {tail[idx + 1]!r}"
                )
            cuts.append((cut_at, cut_code))
        if not 3 <= len(cuts) <= 8:
            raise DebugError("phase2 fault chain requires 3 through 8 cuts")
        return tuple(cuts)
    if prefix == "c":
        if len(parts) != 3:
            raise DebugError(f"malformed cascade wire code {code!r}")
        w_at = _parse_non_negative_int(parts[1], "write_fault_at")
        e_at = _parse_non_negative_int(parts[2], "erase_fault_at")
        return ((w_at, "w"), (e_at, "e"))
    if prefix == "mf":
        seq = decode_multi_fault_sequence(code)
        stage_codes = decode_multi_fault_stage_types(code)
        if len(seq) < 2 or len(seq) != len(stage_codes):
            raise DebugError(f"malformed multi-fault wire code {code!r}")
        return tuple((int(pt), str(sc)) for pt, sc in zip(seq, stage_codes))
    return ((int(fault_at), code),)


def _parse_reproduction_dict(
    repro: dict[str, Any],
    *,
    point_name: str = "reproduction",
    point_kind: str = "reproduction",
) -> dict[str, Any]:
    if not isinstance(repro, dict) or not repro:
        raise DebugError("reproduction block must be a non-empty mapping")

    # Refuse auxiliary non-runtime reproductions explicitly.
    if "crash_file" in repro or ("generated_profile" in repro and "sha256" in repro):
        raise DebugError(
            "cannot debug fuzz_crash reproduction block: provide its generated profile to debug a runtime point"
        )
    if "scenario_index" in repro or "blob_sha256" in repro or "field_values" in repro:
        raise DebugError(
            "cannot debug state_fuzz reproduction block: only runtime fault-sweep points and states are supported"
        )
    if "sequence" in repro and ("model_digest" in repro or len(repro) <= 2):
        raise DebugError(
            "cannot debug authorization_review reproduction block: static findings have no runtime execution state"
        )
    fault_sweep = repro.get("fault_sweep")
    if isinstance(fault_sweep, dict) and "partial_staging" in fault_sweep:
        raise DebugError(
            "cannot debug partial_staging reproduction block: only runtime fault-sweep points and states are supported"
        )

    if str(repro.get("FAULT_AT", "")).strip() == "-1":
        return {
            "point_name": point_name if point_name != "reproduction" else "clean control",
            "point_kind": "control",
            "fault_at": -1,
            "fault_type_code": "control",
            "cuts": (),
            "is_control": True,
            "include_erase_fault_points": False,
        }

    if "FAULT_POINTS_CSV" in repro or "FAULT_TYPE_CSV" in repro:
        if "FAULT_POINTS_CSV" not in repro or "FAULT_TYPE_CSV" not in repro:
            raise DebugError(
                "single-point reproduction block requires both FAULT_POINTS_CSV and FAULT_TYPE_CSV"
            )
        raw_points = str(repro["FAULT_POINTS_CSV"]).strip()
        if not raw_points or "," in raw_points:
            raise DebugError(
                f"FAULT_POINTS_CSV must specify exactly one point index, got {repro['FAULT_POINTS_CSV']!r}"
            )
        fault_at = _parse_non_negative_int(raw_points, "FAULT_POINTS_CSV")
        raw_code = str(repro["FAULT_TYPE_CSV"]).strip()
        if not raw_code or "," in raw_code:
            raise DebugError(
                f"FAULT_TYPE_CSV must specify exactly one fault type code, got {repro['FAULT_TYPE_CSV']!r}"
            )
        code = _fault_type_to_code(raw_code)
        cuts = _cuts_from_wire_code(fault_at, code)
        include_erase = bool(cuts and cuts[0][1] in ("e", "a"))
        return {
            "point_name": point_name if point_name != "reproduction" else f"{code}[{fault_at}]",
            "point_kind": point_kind,
            "fault_at": fault_at,
            "fault_type_code": code,
            "cuts": cuts,
            "is_control": False,
            "include_erase_fault_points": include_erase,
        }

    phase2 = None
    include_erase = False
    if isinstance(fault_sweep, dict) and isinstance(fault_sweep.get("phase2_fault"), dict):
        phase2 = fault_sweep["phase2_fault"]
        include_erase = bool(fault_sweep.get("include_erase_fault_points", False))
    elif isinstance(repro.get("phase2_fault"), dict):
        phase2 = repro["phase2_fault"]
        include_erase = bool(repro.get("include_erase_fault_points", False))

    if isinstance(phase2, dict):
        if "pairs" in phase2 and "chains" in phase2:
            raise DebugError("phase2_fault reproduction cannot specify both pairs and chains")
        if "pairs" in phase2:
            pairs = phase2.get("pairs")
            if not isinstance(pairs, list) or len(pairs) != 1:
                raise DebugError("phase2_fault.pairs reproduction must contain exactly one [p1, p2] pair")
            pair = pairs[0]
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise DebugError("phase2_fault.pairs entry must be a two-element [p1, p2] list")
            p1_at = _parse_non_negative_int(pair[0], "pair[0]")
            p2_at = _parse_non_negative_int(pair[1], "pair[1]")
            first_types = phase2.get("first_fault_types") or ["power_loss"]
            second_types = phase2.get("fault_types") or ["power_loss"]
            if not isinstance(first_types, list) or len(first_types) != 1:
                raise DebugError("phase2_fault.first_fault_types must contain one fault type")
            if not isinstance(second_types, list) or len(second_types) != 1:
                raise DebugError("phase2_fault.fault_types must contain one fault type")
            p1_code = _fault_type_to_code(first_types[0])
            p2_code = _fault_type_to_code(second_types[0])
            code = f"p2:{p1_at}:{p2_at}:{p1_code}:{p2_code}"
            cuts = ((p1_at, p1_code), (p2_at, p2_code))
            label = (
                f"{CODE_TO_FAULT_NAME.get(p1_code, p1_code)}[{p1_at}] → "
                f"{CODE_TO_FAULT_NAME.get(p2_code, p2_code)}[{p2_at}]"
            )
            return {
                "point_name": point_name if point_name != "reproduction" else label,
                "point_kind": point_kind if point_kind != "reproduction" else "two_cut_pairs",
                "fault_at": p1_at,
                "fault_type_code": code,
                "cuts": cuts,
                "is_control": False,
                "include_erase_fault_points": include_erase or p1_code in ("e", "a"),
            }
        if "chains" in phase2:
            chains = phase2.get("chains")
            if not isinstance(chains, list) or len(chains) != 1:
                raise DebugError("phase2_fault.chains reproduction must contain exactly one chain")
            chain = chains[0]
            if not isinstance(chain, list) or len(chain) < 2:
                raise DebugError("phase2_fault.chains entry must contain at least two cuts")
            parsed_cuts: list[tuple[int, str]] = []
            for idx, item in enumerate(chain):
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise DebugError(f"chain cut {idx + 1} must be [operation_index, fault_type]")
                cut_at = _parse_non_negative_int(item[0], f"chain cut {idx + 1} index")
                cut_code = _fault_type_to_code(item[1])
                if cut_code not in ("w", "e"):
                    raise DebugError(
                        f"chain cut {idx + 1} fault type must be power_loss or interrupted_erase, got {item[1]!r}"
                    )
                parsed_cuts.append((cut_at, cut_code))
            if len(parsed_cuts) == 2:
                code = f"p2:{parsed_cuts[0][0]}:{parsed_cuts[1][0]}:{parsed_cuts[0][1]}:{parsed_cuts[1][1]}"
                inferred_kind = "two_cut_pairs"
            else:
                if len(parsed_cuts) > 8:
                    raise DebugError("phase2_fault.chains supports at most 8 cuts")
                code = "pc:" + ":".join(f"{c_at}:{c_code}" for c_at, c_code in parsed_cuts)
                inferred_kind = "n_cut_explicit"
            label = " → ".join(
                f"{CODE_TO_FAULT_NAME.get(c_code, c_code)}[{c_at}]"
                for c_at, c_code in parsed_cuts
            )
            return {
                "point_name": point_name if point_name != "reproduction" else label,
                "point_kind": point_kind if point_kind != "reproduction" else inferred_kind,
                "fault_at": parsed_cuts[0][0],
                "fault_type_code": code,
                "cuts": tuple(parsed_cuts),
                "is_control": False,
                "include_erase_fault_points": include_erase or parsed_cuts[0][1] in ("e", "a"),
            }

    raise DebugError(f"unrecognized reproduction block structure: {sorted(repro.keys())}")


def _normalize_arrow_text(text: str) -> str:
    return re.sub(r"\s*(?:->|→)\s*", " -> ", str(text or "").strip())


def _extract_row_cuts(row: dict[str, Any]) -> list[list[Any]]:
    cuts = point_cuts(row)
    if cuts:
        return cuts
    search = row.get("recovery_state_search") or {}
    raw_cuts = search.get("cuts")
    if isinstance(raw_cuts, list) and raw_cuts:
        out = []
        for cut in raw_cuts:
            if not isinstance(cut, dict):
                continue
            fault = cut.get("fault_type") or ("e" if cut.get("operation") == "erase" else "w")
            idx = cut.get("operation_index", cut.get("fault_at"))
            if idx is not None:
                out.append([idx, CODE_TO_FAULT_NAME.get(fault, fault)])
        if out:
            return out
    return []


def _row_to_execution_spec(row: dict[str, Any], point_name: str, point_kind: str) -> dict[str, Any]:
    if point_kind in AUXILIARY_UNSUPPORTED_KINDS:
        raise DebugError(
            f"cannot debug {AUXILIARY_UNSUPPORTED_KINDS[point_kind]} finding {point_name!r}: "
            "only runtime fault-sweep points and states are supported"
        )
    if result_is_infrastructure_error(row):
        detail = row.get("error") or row.get("error_kind") or "infrastructure error"
        raise DebugError(
            f"cannot debug point {point_name!r}: report recorded an infrastructure error ({detail})"
        )
    if result_has_initial_timeout(row):
        raise DebugError(
            f"cannot debug point {point_name!r}: initial boot timed out in report"
        )
    if result_is_skipped(row) or (not row.get("is_control") and row.get("fault_injected") is not True):
        reason = row.get("skip_reason") or "fault was not injected"
        raise DebugError(
            f"cannot debug point {point_name!r}: skipped in report ({reason})"
        )

    if row.get("is_control") or str(row.get("fault_type") or "") == "control" or int(row.get("fault_at", 0)) < 0:
        outcome, _ = _effective_boot_result(row)
        return {
            "point_name": point_name,
            "point_kind": "control",
            "fault_at": -1,
            "fault_type_code": "control",
            "cuts": (),
            "is_control": True,
            "state_identity": None,
            "state_search_gated": False,
            "include_erase_fault_points": False,
            "expected_outcome": str(outcome) if outcome else None,
            "expected_fault_class": str(row.get("fault_class") or "") or None,
            "row": row,
        }

    search = row.get("recovery_state_search") or {}
    state_identity = str(search.get("state_identity") or "").strip().lower() or None
    state_search_gated = bool(search) or str(row.get("fault_type") or "") == "rs"

    cuts_named = _extract_row_cuts(row)
    if cuts_named:
        parsed_cuts = tuple(
            (_parse_non_negative_int(idx, "cut index"), _fault_type_to_code(name))
            for idx, name in cuts_named
        )
        if len(parsed_cuts) == 1:
            fault_at, code = parsed_cuts[0]
        elif len(parsed_cuts) == 2:
            fault_at = parsed_cuts[0][0]
            code = f"p2:{parsed_cuts[0][0]}:{parsed_cuts[1][0]}:{parsed_cuts[0][1]}:{parsed_cuts[1][1]}"
        else:
            fault_at = parsed_cuts[0][0]
            code = "pc:" + ":".join(f"{c_at}:{c_code}" for c_at, c_code in parsed_cuts)
        include_erase = parsed_cuts[0][1] in ("e", "a")
    else:
        wp = wire_point(row)
        spec = _parse_reproduction_dict(wp, point_name=point_name, point_kind=point_kind)
        fault_at = spec["fault_at"]
        code = spec["fault_type_code"]
        parsed_cuts = spec["cuts"]
        include_erase = spec["include_erase_fault_points"]

    outcome, _ = _effective_boot_result(row)
    fault_class = row.get("fault_class") or classify_failure_class(row)
    if fault_class == "unrecoverable" and result_is_brick(row):
        fault_class = "brick"
    return {
        "point_name": point_name,
        "point_kind": point_kind,
        "fault_at": fault_at,
        "fault_type_code": code,
        "cuts": parsed_cuts,
        "is_control": False,
        "state_identity": state_identity,
        "state_search_gated": state_search_gated,
        "include_erase_fault_points": include_erase,
        "expected_outcome": str(outcome) if outcome else None,
        "expected_fault_class": str(fault_class) if fault_class else None,
        "row": row,
    }


def _parse_selector_cuts(selector: str) -> list[tuple[int, str | None]] | None:
    """Parse cut selector syntax such as '3,0', '3:0', '[3, 0]', 'w[2]->w[0]', 'write[2]@0x... -> write[0]@0x...'."""
    text = selector.strip()
    if not text:
        return None

    # JSON list form: [3, 0] or [[0, "power_loss"], [1, "interrupted_erase"]]
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = yaml.safe_load(text)
        except Exception:
            parsed = None
        if isinstance(parsed, list) and parsed:
            if all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in parsed):
                return [(int(x), None) for x in parsed]
            if all(
                isinstance(x, list)
                and len(x) == 2
                and isinstance(x[0], int)
                and not isinstance(x[0], bool)
                and x[0] >= 0
                for x in parsed
            ):
                try:
                    return [(int(x[0]), _fault_type_to_code(x[1])) for x in parsed]
                except DebugError:
                    return None

    # Wire code form: p2:3:0:w:w or pc:0:w:1:e:2:w
    if text.startswith("p2:") or text.startswith("pc:"):
        parts = text.split(":")
        try:
            if parts[0] == "p2" and len(parts) in (3, 5):
                p1 = _parse_non_negative_int(parts[1], "p1")
                p2 = _parse_non_negative_int(parts[2], "p2")
                c1 = _fault_type_to_code(parts[3]) if len(parts) == 5 else None
                c2 = _fault_type_to_code(parts[4]) if len(parts) == 5 else None
                return [(p1, c1), (p2, c2)]
            if parts[0] == "pc" and len(parts) >= 7 and len(parts) % 2 == 1:
                cuts = []
                for idx in range(1, len(parts), 2):
                    cuts.append((
                        _parse_non_negative_int(parts[idx], "cut"),
                        _fault_type_to_code(parts[idx + 1]),
                    ))
                return cuts
        except DebugError:
            return None

    # Arrow or comma/colon separated cut tokens:
    # e.g. "3,0", "3:0", "3 -> 0", "w[3] -> w[0]", "power_loss[3] → power_loss[0]", "write[2]@0x10100110 -> write[0]@0x10100100"
    norm = _normalize_arrow_text(text)
    if " -> " in norm:
        tokens = [t.strip() for t in norm.split(" -> ")]
    elif "," in norm:
        tokens = [t.strip() for t in norm.split(",")]
    elif ":" in norm and not norm.startswith(("i:", "tb:", "mf:", "c:", "b:", "m:", "h:", "cc:", "nv:")):
        tokens = [t.strip() for t in norm.split(":")]
    else:
        tokens = [norm]

    token_re = re.compile(
        r"^(?:(?P<ft>[A-Za-z_]+)\s*(?:\[\s*(?P<idx1>\d+)\s*\]|:\s*(?P<idx2>\d+))|(?P<idx3>\d+))(?:\s*@\s*0x[0-9A-Fa-f]+)?$"
    )
    cuts_out: list[tuple[int, str | None]] = []
    for tok in tokens:
        m = token_re.match(tok)
        if not m:
            return None
        idx_str = m.group("idx1") or m.group("idx2") or m.group("idx3")
        ft_str = m.group("ft")
        if idx_str is None:
            return None
        code = None
        if ft_str is not None:
            try:
                code = _fault_type_to_code(ft_str)
            except DebugError:
                return None
        cuts_out.append((int(idx_str), code))
    return cuts_out


def _candidate_cuts(point: Point) -> list[tuple[int, str]]:
    if point.row:
        raw_cuts = _extract_row_cuts(point.row)
        if raw_cuts:
            out = []
            for idx, name in raw_cuts:
                try:
                    out.append((int(idx), _fault_type_to_code(name)))
                except Exception:
                    return []
            return out
        if not point.row.get("is_control") and "fault_at" in point.row:
            ft = str(point.row.get("fault_requested_type") or point.row.get("fault_type") or "w")
            try:
                return list(_cuts_from_wire_code(int(point.row["fault_at"]), _fault_type_to_code(ft)))
            except Exception:
                return []
    if point.selector:
        try:
            spec = _parse_reproduction_dict(point.selector, point_name=point.name, point_kind=point.kind)
            return list(spec["cuts"])
        except Exception:
            return []
    return []


def _candidate_state_ids(point: Point) -> list[str]:
    search = (point.row or {}).get("recovery_state_search") or {}
    state_id = str(search.get("state_identity") or "").strip().lower()
    if state_id:
        return [state_id]
    m = re.search(r"\bstate\s+([0-9a-fA-F]{6,64})\b", point.name)
    if m:
        return [m.group(1).lower()]
    return []


def _select_point_from_candidates(
    candidates: list[Point],
    *,
    point_selector: str | None,
    state_selector: str | None,
) -> Point:
    if not candidates:
        raise DebugError("report contains no runtime points to debug")
    if not point_selector and not state_selector:
        raise DebugError("a point (--point) or state (--state) identifier is required when debugging from a report")

    if state_selector:
        query = state_selector.strip().lower()
        if query.startswith("state:"):
            query = query[6:].strip()
        if not query or not all(ch in "0123456789abcdef" for ch in query):
            raise DebugError(f"--state must be a hexadecimal state identity or prefix, got {state_selector!r}")
        matched_by_state: dict[str, Point] = {}
        for pt in candidates:
            if (pt.row or {}).get("recovery_state_search", {}).get("reused"):
                continue
            for sid in _candidate_state_ids(pt):
                if sid == query or sid.startswith(query):
                    matched_by_state.setdefault(sid, pt)
        if not matched_by_state:
            # Check reused entries as fallback
            for pt in candidates:
                for sid in _candidate_state_ids(pt):
                    if sid == query or sid.startswith(query):
                        matched_by_state.setdefault(sid, pt)
        if not matched_by_state:
            available = [sid for pt in candidates for sid in _candidate_state_ids(pt)]
            hint = f" (available states: {', '.join(available[:8])})" if available else " (report has no state_search records)"
            raise DebugError(f"state identifier {state_selector!r} not found in report{hint}")
        if len(matched_by_state) > 1:
            raise DebugError(
                f"ambiguous state identifier {state_selector!r} matches {len(matched_by_state)} states: "
                + ", ".join(sorted(matched_by_state))
            )
        selected = next(iter(matched_by_state.values()))
        if not point_selector:
            return selected
        candidates = [selected]

    assert point_selector is not None
    raw_query = point_selector.strip()
    if not raw_query:
        raise DebugError("--point must not be empty")
    norm_query = _normalize_arrow_text(raw_query)

    # 1. Exact match on point name, label, chain text, or wire code
    exact_matches: list[Point] = []
    for pt in candidates:
        labels = {_normalize_arrow_text(pt.name)}
        if pt.row:
            labels.add(_normalize_arrow_text(point_label(pt.row)))
            search_chain = ((pt.row.get("recovery_state_search") or {}).get("chain") or {}).get("text")
            if search_chain:
                labels.add(_normalize_arrow_text(search_chain))
            for eq in (pt.row.get("recovery_state_search") or {}).get("equivalent_chains") or []:
                if isinstance(eq, dict) and eq.get("text"):
                    labels.add(_normalize_arrow_text(eq["text"]))
            wp = wire_point(pt.row)
            labels.add(f"{wp['FAULT_TYPE_CSV']}[{wp['FAULT_POINTS_CSV']}]")
            labels.add(str(wp["FAULT_TYPE_CSV"]))
        if norm_query in labels:
            exact_matches.append(pt)
    if len(exact_matches) == 1:
        return exact_matches[0]
    if len(exact_matches) > 1:
        raise DebugError(
            f"ambiguous point selector {point_selector!r} matches {len(exact_matches)} points: "
            + ", ".join(p.name for p in exact_matches)
        )

    # 2. 1-based index selector: "#N" or "<campaign> #N"
    idx_match = re.match(r"^(?:(?P<camp>[a-z0-9_]+)\s*)?#(?P<num>\d+)$", raw_query, re.I)
    if idx_match:
        target_num = int(idx_match.group("num"))
        camp = (idx_match.group("camp") or "").lower()
        indexed = []
        for idx, pt in enumerate(candidates, start=1):
            if camp:
                if pt.name.lower().startswith(f"{camp} #{target_num} "):
                    indexed.append(pt)
            elif f"#{target_num} " in pt.name or idx == target_num:
                indexed.append(pt)
        if len(indexed) == 1:
            return indexed[0]
        if len(indexed) > 1:
            raise DebugError(
                f"ambiguous index selector {point_selector!r} matches: "
                + ", ".join(p.name for p in indexed)
            )

    # 3. Hex state identity or prefix passed via --point
    hex_query = raw_query.lower()
    if hex_query.startswith("state:"):
        hex_query = hex_query[6:].strip()
    if len(hex_query) >= 6 and all(ch in "0123456789abcdef" for ch in hex_query):
        state_matches: dict[str, Point] = {}
        for pt in candidates:
            if (pt.row or {}).get("recovery_state_search", {}).get("reused"):
                continue
            for sid in _candidate_state_ids(pt):
                if sid == hex_query or sid.startswith(hex_query):
                    state_matches.setdefault(sid, pt)
        if len(state_matches) == 1:
            return next(iter(state_matches.values()))
        if len(state_matches) > 1:
            raise DebugError(
                f"ambiguous state prefix {point_selector!r} matches {len(state_matches)} states: "
                + ", ".join(sorted(state_matches))
            )

    # 4. Control selector
    if raw_query.lower() in ("control", "clean control", "-1"):
        controls = [pt for pt in candidates if pt.kind == "control" or (pt.row or {}).get("is_control")]
        if len(controls) == 1:
            return controls[0]
        if len(controls) > 1:
            raise DebugError(
                f"ambiguous control selector matches {len(controls)} control points: "
                + ", ".join(p.name for p in controls)
            )

    # 5. Cut sequence / pair / single-cut index selector
    parsed_cuts = _parse_selector_cuts(raw_query)
    if parsed_cuts is not None:
        cut_matches: list[Point] = []
        for pt in candidates:
            if pt.kind == "control" or (pt.row or {}).get("is_control"):
                continue
            pt_cuts = _candidate_cuts(pt)
            if len(pt_cuts) == len(parsed_cuts) and all(
                c_at == q_at and (q_code is None or c_code == q_code)
                for (c_at, c_code), (q_at, q_code) in zip(pt_cuts, parsed_cuts)
            ):
                cut_matches.append(pt)
            elif not cut_matches and pt.row:
                # Also check equivalent_chains in state_search
                for eq in (pt.row.get("recovery_state_search") or {}).get("equivalent_chains") or []:
                    eq_cuts = eq.get("cuts") or []
                    if len(eq_cuts) == len(parsed_cuts):
                        norm_eq = [
                            (
                                int(c.get("operation_index", c.get("fault_at", -1))),
                                _fault_type_to_code(
                                    c.get("fault_type") or ("e" if c.get("operation") == "erase" else "w")
                                ),
                            )
                            for c in eq_cuts
                        ]
                        if all(
                            c_at == q_at and (q_code is None or c_code == q_code)
                            for (c_at, c_code), (q_at, q_code) in zip(norm_eq, parsed_cuts)
                        ):
                            cut_matches.append(pt)
                            break
        if len(cut_matches) == 1:
            return cut_matches[0]
        if len(cut_matches) > 1:
            raise DebugError(
                f"ambiguous point selector {point_selector!r} matches {len(cut_matches)} points: "
                + ", ".join(p.name for p in cut_matches)
            )
        # If plain integer e.g. "3" didn't match a 1-cut point, check if it matches fault_at on multi-cut points
        if len(parsed_cuts) == 1 and parsed_cuts[0][1] is None:
            target_fault_at = parsed_cuts[0][0]
            first_cut_matches = [
                pt for pt in candidates
                if not (pt.kind == "control" or (pt.row or {}).get("is_control"))
                and (
                    (pt.row and int(pt.row.get("fault_at", -999)) == target_fault_at)
                    or (_candidate_cuts(pt) and _candidate_cuts(pt)[0][0] == target_fault_at)
                )
            ]
            if len(first_cut_matches) == 1:
                return first_cut_matches[0]
            if len(first_cut_matches) > 1:
                raise DebugError(
                    f"ambiguous point selector {point_selector!r} matches {len(first_cut_matches)} points with first cut {target_fault_at}: "
                    + ", ".join(p.name for p in first_cut_matches)
                )

    # 6. Substring match on normalized label/name
    sub_matches: list[Point] = []
    for pt in candidates:
        haystacks = [_normalize_arrow_text(pt.name)]
        if pt.row:
            haystacks.append(_normalize_arrow_text(point_label(pt.row)))
            search_chain = ((pt.row.get("recovery_state_search") or {}).get("chain") or {}).get("text")
            if search_chain:
                haystacks.append(_normalize_arrow_text(search_chain))
        if any(norm_query in h for h in haystacks):
            sub_matches.append(pt)
    if len(sub_matches) == 1:
        return sub_matches[0]
    if len(sub_matches) > 1:
        raise DebugError(
            f"ambiguous point selector {point_selector!r} matches {len(sub_matches)} points: "
            + ", ".join(p.name for p in sub_matches)
        )

    available_names = ", ".join(p.name for p in candidates[:10])
    raise DebugError(
        f"point selector {point_selector!r} did not match any point in report (available: {available_names})"
    )


def _resolve_profile_path(
    *,
    explicit_profile: Path | None,
    report_profile_path: str | Path | None,
    report_profile_name: str | None,
    sarif_uri: str | None,
    repo_root: Path,
    report_dir: Path | None = None,
) -> Path:
    candidates: list[Path] = []
    if explicit_profile is not None:
        p = Path(explicit_profile).expanduser()
        candidates.append(p if p.is_absolute() else (Path.cwd() / p))
        if not p.is_absolute():
            candidates.append(repo_root / p)
    if report_profile_path:
        p = Path(str(report_profile_path)).expanduser()
        if p.is_absolute():
            candidates.append(p)
        else:
            candidates.append(repo_root / p)
            candidates.append(Path.cwd() / p)
            if report_dir is not None:
                candidates.append(report_dir / p)
    if sarif_uri:
        parsed = urlparse(str(sarif_uri))
        uri_path = unquote(parsed.path if parsed.scheme == "file" else str(sarif_uri))
        if uri_path.endswith((".yaml", ".yml")):
            p = Path(uri_path)
            if p.is_absolute():
                candidates.append(p)
            else:
                candidates.append(repo_root / p)
                candidates.append(Path.cwd() / p)
    if report_profile_name:
        clean_name = str(report_profile_name).strip().strip("/")
        if clean_name:
            candidates.append(repo_root / "profiles" / f"{clean_name}.yaml")
            for match in sorted((repo_root / "examples").glob(f"*/{clean_name}.yaml")):
                candidates.append(match)

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    if report_profile_name:
        clean_name = str(report_profile_name).strip().strip("/")
        if clean_name:
            name_re = re.compile(rf"^\s*name\s*:\s*['\"]?{re.escape(clean_name)}['\"]?\s*$", re.M)
            search_files = sorted(
                list((repo_root / "profiles").glob("*.yaml"))
                + list((repo_root / "examples").glob("*/*.yaml"))
            )
            for yaml_path in search_files:
                try:
                    if name_re.search(yaml_path.read_text(encoding="utf-8")):
                        return yaml_path.resolve()
                except Exception:
                    continue

    if explicit_profile is not None:
        raise DebugError(f"profile file not found: {explicit_profile}")
    raise DebugError(
        "profile path could not be resolved from report or reproduction; pass --profile FILE"
    )


def _load_profile_and_elf(
    profile_path: Path,
    *,
    explicit_elf: Path | None,
    component: str | None,
    repo_root: Path,
) -> tuple[ProfileConfig, Path]:
    try:
        profile = load_profile(profile_path, repo_root=repo_root)
    except Exception as exc:
        raise DebugError(f"failed to load profile {profile_path}: {exc}") from exc

    if getattr(profile, "initial_states", None):
        raise DebugError(
            f"profile {profile_path} is an initial-state matrix; select a concrete child profile"
        )

    if profile.is_multi_component:
        if not component:
            names = [c.name for c in profile.multi_component.components]
            raise DebugError(
                f"multi-component profile {profile.name!r} requires a component point selector "
                f"(components: {', '.join(names)})"
            )
        comp_map = {
            c.name: c.to_profile_config(profile)
            for c in profile.multi_component.components
        }
        if component not in comp_map:
            raise DebugError(
                f"unknown component {component!r} for profile {profile.name!r}"
            )
        profile = comp_map[component]

    if explicit_elf is not None:
        elf_candidate = Path(explicit_elf).expanduser()
        if not elf_candidate.is_absolute():
            elf_candidate = (Path.cwd() / elf_candidate).resolve()
        else:
            elf_candidate = elf_candidate.resolve()
        if not elf_candidate.is_file():
            raise DebugError(f"bootloader ELF not found: {explicit_elf}")
        return profile, elf_candidate

    if not profile.bootloader_elf:
        raise DebugError(
            f"profile {profile.name!r} has no bootloader.elf; pass --elf FILE"
        )
    resolved_elf = _resolve_profile_input_path(
        profile.bootloader_elf,
        repo_root=repo_root,
        profile_path=profile_path,
    )
    elf_path = Path(resolved_elf).resolve()
    if not elf_path.is_file():
        raise DebugError(f"bootloader ELF not found: {elf_path}")
    return profile, elf_path


def _validate_stop_at_compatibility(target: DebugTarget, stop_at: str) -> None:
    if target.is_control and stop_at == "cut":
        raise DebugError("cannot use --stop-at cut on a clean control point")
    eval_mode = str(getattr(target.profile.fault_sweep, "evaluation_mode", "execute") or "execute").strip().lower()
    if eval_mode == "state":
        raise DebugError(
            "cannot debug profile with fault_sweep.evaluation_mode 'state': "
            "state mode simulates copy operations without CPU execution"
        )
    if not target.is_control and not target.cuts:
        if stop_at == "cut":
            raise DebugError(
                "cannot use --stop-at cut on a state snapshot without a recorded cut sequence; "
                "use --stop-at recovery-reset or --stop-at first-fault"
            )
        if target.pre_recovery_state is None and target.checkpoint_snapshot is None:
            raise DebugError(
                "point has neither a cut sequence nor a pre-recovery persistent state snapshot"
            )
    if not target.is_control and stop_at == "recovery-reset":
        base_code = target.fault_type_code.split(":", 1)[0]
        if base_code in SINGLE_BOOT_NON_RESET_CODES:
            fault_label = CODE_TO_FAULT_NAME.get(base_code, target.fault_type_code)
            raise DebugError(
                f"fault type {fault_label!r} ({target.fault_type_code}) continues in the initial boot "
                "without a recovery reset; use --stop-at cut or --stop-at first-fault"
            )


def _load_json_or_yaml_input(raw: str | Path) -> tuple[Any, Path | None]:
    if isinstance(raw, Path):
        if not raw.is_file():
            raise DebugError(f"input file not found: {raw}")
        try:
            return yaml.safe_load(raw.read_text(encoding="utf-8")), raw.resolve()
        except Exception as exc:
            raise DebugError(f"failed to parse {raw}: {exc}") from exc

    text = str(raw).strip()
    if not text:
        raise DebugError("reproduction input must not be empty")
    if not text.startswith(("{", "[")):
        candidate = Path(text).expanduser()
        if candidate.is_file():
            try:
                return yaml.safe_load(candidate.read_text(encoding="utf-8")), candidate.resolve()
            except Exception as exc:
                raise DebugError(f"failed to parse {candidate}: {exc}") from exc
        if candidate.suffix in (".json", ".sarif", ".yaml", ".yml") or "/" in text:
            raise DebugError(f"reproduction file not found: {text}")
    try:
        return yaml.safe_load(text), None
    except Exception as exc:
        raise DebugError(f"failed to parse reproduction block: {exc}") from exc


def _extract_sarif_points(
    sarif_obj: dict[str, Any],
) -> list[tuple[Point, str | None, str | None]]:
    """Extract deduplicated (Point, profile_name, location_uri) tuples from a SARIF document or result."""
    extracted: list[tuple[Point, str | None, str | None]] = []
    seen_keys: set[tuple[str, str, str | None, str]] = set()

    def handle_result(res: dict[str, Any], run_profile: str | None = None) -> None:
        props = res.get("properties") or {}
        prof_name = props.get("profile") or run_profile
        comp_name = props.get("component")
        locs = res.get("locations") or []
        uri = None
        if locs and isinstance(locs[0], dict):
            uri = (
                ((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
            )
        pts = props.get("points")
        if not isinstance(pts, list):
            return
        for entry in pts:
            if not isinstance(entry, dict) or "reproduction" not in entry:
                continue
            kind_str = str(entry.get("kind") or "reproduction")
            name_str = str(entry.get("name") or "reproduction")
            try:
                repro_key = json.dumps(entry.get("reproduction"), sort_keys=True)
            except Exception:
                repro_key = str(entry.get("reproduction"))
            dedup_key = (name_str, kind_str, comp_name, repro_key)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            pt = Point(
                kind=kind_str,
                name=name_str,
                row={},
                status="failure",
                message=str((res.get("message") or {}).get("text") or ""),
                findings=[],
                selector=entry.get("reproduction"),
                component=comp_name,
            )
            extracted.append((pt, prof_name, uri))

    if sarif_obj.get("version") == "2.1.0" and isinstance(sarif_obj.get("runs"), list):
        for run in sarif_obj["runs"]:
            if not isinstance(run, dict):
                continue
            auto_id = str((run.get("automationDetails") or {}).get("id") or "").strip("/") or None
            for res in run.get("results") or []:
                if isinstance(res, dict):
                    handle_result(res, run_profile=auto_id)
    elif "ruleId" in sarif_obj or isinstance((sarif_obj.get("properties") or {}).get("points"), list):
        handle_result(sarif_obj)
    return extracted


def _extract_expected_explanation(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    payload: dict[str, Any] = {}
    fault_snap = row.get("fault_snapshot")
    if isinstance(fault_snap, dict):
        payload["fault_snapshot"] = fault_snap
    explanation = row.get("failure_explanation")
    if isinstance(explanation, dict):
        comparison = explanation.get("state_comparison")
        if isinstance(comparison, dict):
            payload["state_comparison"] = comparison
        cuts = explanation.get("cuts")
        if isinstance(cuts, list):
            payload["cuts"] = cuts
        sibling = explanation.get("passing_sibling")
        if isinstance(sibling, dict):
            payload["passing_sibling"] = sibling
    return payload or None


def _encode_persistent_state_for_debug(state: PersistentState) -> dict[str, Any]:
    region = state.region("nvm")
    raw = bytes(state.materialize()["nvm"])
    base = int(region.base_address)
    payload: dict[str, Any] = {
        "base_address": f"0x{base:08X}",
        "size": len(raw),
        "zlib_b64": base64.b64encode(zlib.compress(raw, 1)).decode("ascii"),
    }
    marks = [
        f"0x{base + int(off):08X}"
        for rname, off in sorted(state.uncorrectable_words)
        if rname == "nvm"
    ]
    if marks:
        payload["uncorrectable_words"] = marks
    if state.persistent_values:
        payload["persistent_values"] = {
            str(name): base64.b64encode(bytes(val)).decode("ascii")
            for name, val in dict(state.persistent_values).items()
        }
    return payload


def _preserve_pre_recovery_states(report_data: Any) -> dict[tuple[Any, ...], dict[str, Any]]:
    preserved: dict[tuple[Any, ...], dict[str, Any]] = {}

    def _visit_rows(rows: Any) -> None:
        if not isinstance(rows, list):
            return
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            pre = row.get("_pre_recovery_state")
            if isinstance(pre, dict) and pre.get("zlib_b64"):
                preserved[("id", id(row))] = dict(pre)
                sid = str((row.get("recovery_state_search") or {}).get("state_identity") or "").strip().lower()
                if sid:
                    preserved[("state", sid)] = dict(pre)
                preserved[("row", idx, row.get("fault_at"), row.get("fault_type"))] = dict(pre)

    if isinstance(report_data, list):
        _visit_rows(report_data)
    elif isinstance(report_data, dict):
        _visit_rows(report_data.get("runtime_sweep_results"))
        _visit_rows(report_data.get("results"))
        for comp in (report_data.get("components") or {}).values():
            if isinstance(comp, dict):
                _visit_rows(comp.get("runtime_sweep_results"))
    return preserved


def _lookup_preserved_pre_state(
    row: dict[str, Any] | None,
    preserved: dict[tuple[Any, ...], dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    direct = row.get("_pre_recovery_state")
    if isinstance(direct, dict) and direct.get("zlib_b64"):
        return dict(direct)
    if ("id", id(row)) in preserved:
        return preserved[("id", id(row))]
    sid = str((row.get("recovery_state_search") or {}).get("state_identity") or "").strip().lower()
    if sid and ("state", sid) in preserved:
        return preserved[("state", sid)]
    for key, val in preserved.items():
        if len(key) == 4 and key[0] == "row" and key[2] == row.get("fault_at") and key[3] == row.get("fault_type"):
            return val
    return None


def _extract_shard_edge_points(run_obj: ReportRun) -> list[Point]:
    """Synthesize candidate Points for generation-2 edges recorded in a single state-search shard."""
    existing_sids = {
        sid
        for pt in run_obj.points()
        for sid in _candidate_state_ids(pt)
    }
    extra_points: list[Point] = []
    seen_sids = set(existing_sids)

    def _add_edge(parent_cuts: list[dict[str, Any]], cut: dict[str, Any], child_id: str) -> None:
        sid = str(child_id or "").strip().lower()
        if not sid or sid in seen_sids or not isinstance(cut, dict):
            return
        seen_sids.add(sid)
        chain_cuts = [dict(c) for c in parent_cuts if isinstance(c, dict)] + [dict(cut)]
        text = " -> ".join(
            f"{c.get('operation', 'write')}[{c.get('operation_index', 0)}]"
            + (f"@{c['address']}" if c.get("address") else "")
            for c in chain_cuts
        )
        first_idx = int(chain_cuts[0].get("operation_index", 0))
        synth_row = {
            "fault_at": first_idx,
            "fault_requested": first_idx,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "pending_shard_merge",
            "boot_slot": None,
            "fault_class": "pending_shard_merge",
            "recovery_state_search": {
                "generation": len(chain_cuts),
                "state_identity": sid,
                "reused": False,
                "cut_count": len(chain_cuts),
                "cuts": chain_cuts,
                "chain": {
                    "cut_count": len(chain_cuts),
                    "text": text,
                },
            },
        }
        extra_points.append(
            Point(
                kind="state_search_multi",
                name=f"shard edge state {sid[:12]} ({text})",
                row=synth_row,
                status="pending",
                message="Unbooted shard edge candidate",
                findings=[],
                selector=wire_point(synth_row),
            )
        )

    for pt in run_obj.points():
        row = pt.row or {}
        parent_cuts = list((row.get("recovery_state_search") or {}).get("cuts") or [])
        expansion = row.get("shard_expansion")
        if isinstance(expansion, dict) and parent_cuts:
            for edge_list_key in ("edges", "peer_edges"):
                for edge in expansion.get(edge_list_key) or ():
                    if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                        _add_edge(parent_cuts, edge[0], edge[1])
        shard_meta = row.get("state_search_shard")
        if isinstance(shard_meta, dict):
            for root_entry in shard_meta.get("roots") or ():
                if not isinstance(root_entry, dict):
                    continue
                r_row = root_entry.get("result") or {}
                r_cuts = list((r_row.get("recovery_state_search") or {}).get("cuts") or [])
                if not r_cuts:
                    continue
                for edge_list_key in ("edges", "peer_edges"):
                    for edge in root_entry.get(edge_list_key) or ():
                        if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                            _add_edge(r_cuts, edge[0], edge[1])
    return extra_points


def _is_state_search_checkpoint(data: Any) -> bool:
    if not isinstance(data, dict) or "version" not in data:
        return False
    if data.get("final") is True and set(data.keys()) <= {"version", "final"}:
        return True
    return (
        "inputs" in data
        and "results" in data
        and "snapshots" in data
        and "chunks" in data
    )


def _operation_to_cut_dict(cut_number: int, operation: dict[str, Any], fault_type: str = "power_loss") -> dict[str, Any]:
    is_erase = operation.get("kind") == "erase" or fault_type == "interrupted_erase"
    raw_idx = operation.get("erase_index" if is_erase else "write_index")
    op_idx = max(0, int(raw_idx) - 1) if raw_idx is not None else int(operation.get("operation_index", 0))
    offset = int(operation.get("offset", 0))
    size = int(operation.get("erase_size" if is_erase else "width", operation.get("size", 4)))
    cut: dict[str, Any] = {
        "cut": int(cut_number),
        "operation": "erase" if is_erase else "write",
        "operation_index": op_idx,
        "fault_type": "interrupted_erase" if is_erase else str(fault_type or "power_loss"),
        "offset": offset,
        "size": size,
    }
    if operation.get("address"):
        cut["address"] = str(operation["address"])
    if operation.get("pc"):
        cut["pc"] = str(operation["pc"])
    if operation.get("call_context"):
        cut["call_context"] = str(operation["call_context"])
    return cut


def _resolve_target_from_checkpoint(
    checkpoint_data: dict[str, Any],
    checkpoint_path: Path,
    *,
    point: str | None,
    state: str | None,
    profile: Path | None,
    elf: Path | None,
    canonical_stop: str,
    repo_root: Path,
) -> DebugTarget:
    if checkpoint_data.get("final") is True:
        raise DebugError(
            f"state-search checkpoint {checkpoint_path} is final and contains no resumable state snapshots; "
            "debug from the audit report instead"
        )
    if checkpoint_data.get("version") != 1:
        raise DebugError(
            f"unsupported state-search checkpoint version {checkpoint_data.get('version')!r}"
        )
    try:
        restored_snapshots = restore_snapshots(checkpoint_data)
    except Exception as exc:
        raise DebugError(f"corrupt state-search checkpoint {checkpoint_path}: {exc}") from exc

    inputs = checkpoint_data.get("inputs") if isinstance(checkpoint_data.get("inputs"), dict) else {}
    prof_path = _resolve_profile_path(
        explicit_profile=profile,
        report_profile_path=inputs.get("profile_path") or checkpoint_data.get("profile_path"),
        report_profile_name=inputs.get("profile") or checkpoint_data.get("profile"),
        sarif_uri=None,
        repo_root=repo_root,
        report_dir=checkpoint_path.parent,
    )
    loaded_profile, elf_path = _load_profile_and_elf(
        prof_path,
        explicit_elf=elf,
        component=None,
        repo_root=repo_root,
    )

    raw_results = checkpoint_data.get("results")
    if not isinstance(raw_results, list):
        raise DebugError(f"state-search checkpoint {checkpoint_path} has no results list")
    recovery_traces = checkpoint_data.get("recovery_traces")
    if not isinstance(recovery_traces, list):
        recovery_traces = []

    booted_rows: list[dict[str, Any]] = []
    preserved_pre: dict[int, dict[str, Any]] = {}
    for raw_row in raw_results:
        if not isinstance(raw_row, dict):
            continue
        row_copy = dict(raw_row)
        if not row_copy.get("is_control") and "fault_injected" not in row_copy and not row_copy.get("skip_reason"):
            row_copy["fault_injected"] = True
        sid = str((row_copy.get("recovery_state_search") or {}).get("state_identity") or "").strip().lower()
        if sid and sid in restored_snapshots and "_pre_recovery_state" not in row_copy:
            row_copy["_pre_recovery_state"] = _encode_persistent_state_for_debug(restored_snapshots[sid])
        if isinstance(row_copy.get("_pre_recovery_state"), dict):
            preserved_pre[id(row_copy)] = dict(row_copy["_pre_recovery_state"])
        booted_rows.append(row_copy)

    if booted_rows:
        try:
            annotate_result_checks(booted_rows, loaded_profile, repo_root=repo_root)
            expected_slot = loaded_profile.success_criteria.vtor_in_slot or loaded_profile.success_criteria.pc_in_slot
            explain_recovery_failures(
                booted_rows,
                expected_slot,
                elf_path,
                repo_root,
                flash_base=loaded_profile.slots.exec_base,
                write_granularity=loaded_profile.memory.write_granularity,
                state_probe=loaded_profile.state_probe,
                slots={
                    "exec": (loaded_profile.slots.exec_base, loaded_profile.slots.exec_size),
                    "staging": (loaded_profile.slots.staging_base, loaded_profile.slots.staging_size),
                },
            )
        except Exception:
            pass
        for row_copy in booted_rows:
            if id(row_copy) in preserved_pre:
                row_copy["_pre_recovery_state"] = preserved_pre[id(row_copy)]

    candidates: list[Point] = []
    seen_sids: set[str] = set()
    for idx, row_copy in enumerate(booted_rows, start=1):
        sid = str((row_copy.get("recovery_state_search") or {}).get("state_identity") or "").strip().lower()
        if sid:
            seen_sids.add(sid)
        kind = classify_point_kind(row_copy)
        label = point_label(row_copy)
        name = f"{kind} #{idx} {label}" + (f" (state {sid[:12]})" if sid else "")
        candidates.append(
            Point(
                kind=kind,
                name=name,
                row=row_copy,
                status="info",
                message="",
                findings=[],
                selector=wire_point(row_copy) if not result_is_skipped(row_copy) else None,
            )
        )

    def _parent_chain_cuts(parent_idx: Any, op_idx: Any, target_sid: str) -> list[dict[str, Any]]:
        if parent_idx is None:
            return []
        p_i = int(parent_idx)
        if not (0 <= p_i < len(booted_rows)):
            return []
        parent_row = booted_rows[p_i]
        parent_search = parent_row.get("recovery_state_search") or {}
        base_cuts = [dict(c) for c in (parent_search.get("cuts") or ()) if isinstance(c, dict)]
        if not base_cuts:
            extracted = _extract_row_cuts(parent_row)
            base_cuts = [
                {
                    "cut": c_i + 1,
                    "operation": "erase" if _fault_type_to_code(c_ft) == "e" else "write",
                    "operation_index": int(c_at),
                    "fault_type": CODE_TO_FAULT_NAME.get(_fault_type_to_code(c_ft), str(c_ft)),
                }
                for c_i, (c_at, c_ft) in enumerate(extracted)
            ]
        if 0 <= p_i < len(recovery_traces):
            trace_ops = recovery_traces[p_i]
            if isinstance(trace_ops, list) and op_idx is not None and 0 <= int(op_idx) < len(trace_ops):
                op = trace_ops[int(op_idx)]
                if isinstance(op, dict):
                    next_cut = _operation_to_cut_dict(len(base_cuts) + 1, op)
                    if "address" not in next_cut and target_sid in restored_snapshots:
                        base_addr = int(restored_snapshots[target_sid].region("nvm").base_address)
                        next_cut["address"] = f"0x{base_addr + int(next_cut.get('offset', 0)):08X}"
                    return base_cuts + [next_cut]
        return []

    for queue_key in ("pending_visits", "computed_frontier", "trace_queue"):
        for item in checkpoint_data.get(queue_key) or ():
            if not isinstance(item, (list, tuple)) or len(item) < 3:
                continue
            parent_idx, op_idx, raw_sid = item[0], item[1], item[2]
            sid = str(raw_sid or "").strip().lower()
            if not sid or sid in seen_sids:
                continue
            seen_sids.add(sid)
            chain_cuts = _parent_chain_cuts(parent_idx, op_idx, sid)
            chain_text = " -> ".join(
                f"{c.get('operation', 'write')}[{c.get('operation_index', 0)}]"
                + (f"@{c['address']}" if c.get("address") else "")
                for c in chain_cuts
            )
            first_at = int(chain_cuts[0]["operation_index"]) if chain_cuts else 0
            synth_row: dict[str, Any] = {
                "fault_at": first_at,
                "fault_requested": first_at,
                "fault_type": "rs",
                "fault_injected": True,
                "boot_outcome": "checkpoint_pending",
                "boot_slot": None,
                "fault_class": "checkpoint_pending",
                "recovery_state_search": {
                    "generation": len(chain_cuts) if chain_cuts else 1,
                    "state_identity": sid,
                    "reused": False,
                    "cut_count": len(chain_cuts),
                    "cuts": chain_cuts,
                    "chain": {"cut_count": len(chain_cuts), "text": chain_text} if chain_text else {},
                },
            }
            if sid in restored_snapshots:
                synth_row["_pre_recovery_state"] = _encode_persistent_state_for_debug(
                    restored_snapshots[sid]
                )
            pt_kind = "state_search_multi" if len(chain_cuts) >= 2 else "state_search"
            pt_name = (
                f"{pt_kind} checkpoint state {sid[:12]} ({chain_text})"
                if chain_text
                else f"checkpoint state {sid[:12]}"
            )
            candidates.append(
                Point(
                    kind=pt_kind,
                    name=pt_name,
                    row=synth_row,
                    status="pending",
                    message=f"Queued in checkpoint {queue_key}",
                    findings=[],
                    selector=wire_point(synth_row) if chain_cuts else None,
                )
            )

    for sid, snap_state in restored_snapshots.items():
        sid_low = str(sid).strip().lower()
        if sid_low in seen_sids:
            continue
        seen_sids.add(sid_low)
        synth_row = {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "checkpoint_snapshot",
            "boot_slot": None,
            "fault_class": "checkpoint_snapshot",
            "recovery_state_search": {
                "state_identity": sid_low,
                "reused": False,
                "cuts": [],
            },
            "_pre_recovery_state": _encode_persistent_state_for_debug(snap_state),
        }
        candidates.append(
            Point(
                kind="state_search_snapshot",
                name=f"checkpoint state {sid_low[:12]}",
                row=synth_row,
                status="pending",
                message="Stored snapshot in state-search checkpoint",
                findings=[],
                selector=None,
            )
        )

    selected_pt = _select_point_from_candidates(
        candidates, point_selector=point, state_selector=state
    )
    row = selected_pt.row or {}
    sid = str((row.get("recovery_state_search") or {}).get("state_identity") or "").strip().lower() or None
    cuts_named = _extract_row_cuts(row)

    ckpt_single_snapshot: dict[str, Any] | None = None
    raw_snapshots_map = checkpoint_data.get("snapshots")
    if (
        sid
        and isinstance(raw_snapshots_map, dict)
        and sid in raw_snapshots_map
        and isinstance(checkpoint_data.get("chunks"), list)
    ):
        ckpt_single_snapshot = {
            "version": 1,
            "snapshots": {sid: raw_snapshots_map[sid]},
            "chunks": checkpoint_data["chunks"],
        }

    pre_state = row.get("_pre_recovery_state")
    if pre_state is None and sid and sid in restored_snapshots:
        pre_state = _encode_persistent_state_for_debug(restored_snapshots[sid])

    if cuts_named:
        exec_spec = _row_to_execution_spec(row, selected_pt.name, selected_pt.kind)
        fault_at = exec_spec["fault_at"]
        fault_type_code = exec_spec["fault_type_code"]
        parsed_cuts = exec_spec["cuts"]
        include_erase = exec_spec["include_erase_fault_points"]
        expected_outcome = exec_spec["expected_outcome"]
        expected_fault_class = exec_spec["expected_fault_class"]
    else:
        if result_is_skipped(row):
            reason = row.get("skip_reason") or "fault was not injected"
            raise DebugError(
                f"cannot debug point {selected_pt.name!r}: skipped in checkpoint ({reason})"
            )
        if canonical_stop == "cut":
            raise DebugError(
                f"cannot use --stop-at cut on checkpoint state {(sid or selected_pt.name)[:12]} "
                "because the checkpoint only stores its post-cut persistent snapshot; "
                "use --stop-at recovery-reset or --stop-at first-fault"
            )
        fault_at = 0
        fault_type_code = "rs"
        parsed_cuts = ()
        include_erase = False
        expected_outcome = None
        expected_fault_class = None

    target = DebugTarget(
        profile=loaded_profile,
        profile_path=prof_path,
        elf_path=elf_path,
        component=selected_pt.component,
        point_name=selected_pt.name,
        point_kind=selected_pt.kind,
        fault_at=fault_at,
        fault_type_code=fault_type_code,
        cuts=parsed_cuts,
        is_control=False,
        state_identity=sid,
        state_search_gated=True,
        include_erase_fault_points=include_erase,
        expected_outcome=expected_outcome,
        expected_fault_class=expected_fault_class,
        row=row,
        pre_recovery_state=pre_state,
        checkpoint_snapshot=ckpt_single_snapshot,
        expected_explanation=_extract_expected_explanation(row),
    )
    _validate_stop_at_compatibility(target, canonical_stop)
    return target


def resolve_debug_target(
    *,
    report: Path | None = None,
    point: str | None = None,
    state: str | None = None,
    reproduction: str | Path | None = None,
    profile: Path | None = None,
    elf: Path | None = None,
    stop_at: str = "recovery-reset",
    repo_root: Path = REPO_ROOT,
) -> DebugTarget:
    canonical_stop = normalize_stop_at(stop_at)
    repo_root = Path(repo_root).resolve()

    if report is None and reproduction is None:
        raise DebugError("either --report or --reproduction is required")

    # Case 1: Explicit --reproduction provided
    if reproduction is not None:
        repro_data, repro_path = _load_json_or_yaml_input(reproduction)
        if not isinstance(repro_data, dict):
            raise DebugError("reproduction block must be a JSON/YAML object")

        report_profile_path = None
        report_profile_name = repro_data.get("profile") if isinstance(repro_data.get("profile"), str) else None
        report_dir = repro_path.parent if repro_path else None
        if report is not None:
            rep_obj, rep_path = _load_json_or_yaml_input(report)
            report_dir = rep_path.parent if rep_path else report_dir
            if isinstance(rep_obj, dict):
                report_profile_path = rep_obj.get("profile_path")
                report_profile_name = report_profile_name or rep_obj.get("profile")

        sarif_entries = _extract_sarif_points(repro_data)
        if sarif_entries:
            pts = [entry[0] for entry in sarif_entries]
            if point or state:
                selected_pt = _select_point_from_candidates(
                    pts, point_selector=point, state_selector=state
                )
            elif len(pts) == 1:
                selected_pt = pts[0]
            else:
                raise DebugError(
                    f"SARIF result contains {len(pts)} points; pass --point to select one: "
                    + ", ".join(p.name for p in pts)
                )
            _, sarif_prof, sarif_uri = next(
                entry for entry in sarif_entries if entry[0] is selected_pt
            )
            if selected_pt.kind in AUXILIARY_UNSUPPORTED_KINDS:
                raise DebugError(
                    f"cannot debug {AUXILIARY_UNSUPPORTED_KINDS[selected_pt.kind]} finding {selected_pt.name!r}: "
                    "only runtime fault-sweep points and states are supported"
                )
            if not isinstance(selected_pt.selector, dict):
                raise DebugError(f"SARIF point {selected_pt.name!r} has no valid reproduction block")
            spec = _parse_reproduction_dict(
                selected_pt.selector,
                point_name=selected_pt.name,
                point_kind=selected_pt.kind,
            )
            prof_path = _resolve_profile_path(
                explicit_profile=profile,
                report_profile_path=report_profile_path,
                report_profile_name=report_profile_name or sarif_prof,
                sarif_uri=sarif_uri,
                repo_root=repo_root,
                report_dir=report_dir,
            )
            loaded_profile, elf_path = _load_profile_and_elf(
                prof_path,
                explicit_elf=elf,
                component=selected_pt.component,
                repo_root=repo_root,
            )
            state_ids = _candidate_state_ids(selected_pt)
            state_search_enabled = bool(
                getattr(
                    getattr(loaded_profile.fault_sweep, "phase2_fault", None),
                    "state_search",
                    None,
                )
                and loaded_profile.fault_sweep.phase2_fault.state_search.enabled
            )
            target = DebugTarget(
                profile=loaded_profile,
                profile_path=prof_path,
                elf_path=elf_path,
                component=selected_pt.component,
                point_name=spec["point_name"],
                point_kind=spec["point_kind"],
                fault_at=spec["fault_at"],
                fault_type_code=spec["fault_type_code"],
                cuts=spec["cuts"],
                is_control=spec["is_control"],
                state_identity=state_ids[0] if state_ids else None,
                state_search_gated=bool(
                    selected_pt.kind.startswith("state_search") or state_ids or state_search_enabled
                ),
                include_erase_fault_points=spec["include_erase_fault_points"],
            )
            _validate_stop_at_compatibility(target, canonical_stop)
            return target

        # Direct point wrapper {"name": ..., "kind": ..., "reproduction": {...}} or raw reproduction block
        inner_repro = repro_data.get("reproduction") if isinstance(repro_data.get("reproduction"), dict) else repro_data
        wrapper_name = str(repro_data.get("name") or "reproduction")
        wrapper_kind = str(repro_data.get("kind") or "reproduction")
        wrapper_comp = repro_data.get("component") if isinstance(repro_data.get("component"), str) else None
        if wrapper_kind in AUXILIARY_UNSUPPORTED_KINDS:
            raise DebugError(
                f"cannot debug {AUXILIARY_UNSUPPORTED_KINDS[wrapper_kind]} finding {wrapper_name!r}: "
                "only runtime fault-sweep points and states are supported"
            )
        spec = _parse_reproduction_dict(
            inner_repro,
            point_name=wrapper_name,
            point_kind=wrapper_kind,
        )
        prof_path = _resolve_profile_path(
            explicit_profile=profile,
            report_profile_path=report_profile_path,
            report_profile_name=report_profile_name,
            sarif_uri=None,
            repo_root=repo_root,
            report_dir=report_dir,
        )
        loaded_profile, elf_path = _load_profile_and_elf(
            prof_path,
            explicit_elf=elf,
            component=wrapper_comp,
            repo_root=repo_root,
        )
        state_search_enabled = bool(
            getattr(
                getattr(loaded_profile.fault_sweep, "phase2_fault", None),
                "state_search",
                None,
            )
            and loaded_profile.fault_sweep.phase2_fault.state_search.enabled
        )
        m_state = re.search(r"\bstate\s+([0-9a-fA-F]{6,64})\b", wrapper_name)
        state_id = m_state.group(1).lower() if m_state else None
        target = DebugTarget(
            profile=loaded_profile,
            profile_path=prof_path,
            elf_path=elf_path,
            component=wrapper_comp,
            point_name=spec["point_name"],
            point_kind=spec["point_kind"],
            fault_at=spec["fault_at"],
            fault_type_code=spec["fault_type_code"],
            cuts=spec["cuts"],
            is_control=spec["is_control"],
            state_identity=state_id,
            state_search_gated=bool(
                wrapper_kind.startswith("state_search") or state_id or state_search_enabled
            ),
            include_erase_fault_points=spec["include_erase_fault_points"],
        )
        _validate_stop_at_compatibility(target, canonical_stop)
        return target

    # Case 2: --report provided (audit JSON, raw batch JSON, or SARIF 2.1.0 report)
    assert report is not None
    report_data, report_path = _load_json_or_yaml_input(report)
    assert report_path is not None

    # Check if --report is a state-search checkpoint file (*.checkpoint.json)
    if _is_state_search_checkpoint(report_data):
        return _resolve_target_from_checkpoint(
            report_data,
            report_path,
            point=point,
            state=state,
            profile=profile,
            elf=elf,
            canonical_stop=canonical_stop,
            repo_root=repo_root,
        )

    # Check if --report is a SARIF document or SARIF result
    if isinstance(report_data, dict):
        sarif_entries = _extract_sarif_points(report_data)
        if sarif_entries or report_data.get("version") == "2.1.0":
            if not sarif_entries:
                raise DebugError(f"SARIF report {report} contains no findings with points")
            pts = [entry[0] for entry in sarif_entries]
            selected_pt = _select_point_from_candidates(
                pts, point_selector=point, state_selector=state
            )
            _, sarif_prof, sarif_uri = next(
                entry for entry in sarif_entries if entry[0] is selected_pt
            )
            if selected_pt.kind in AUXILIARY_UNSUPPORTED_KINDS:
                raise DebugError(
                    f"cannot debug {AUXILIARY_UNSUPPORTED_KINDS[selected_pt.kind]} finding {selected_pt.name!r}: "
                    "only runtime fault-sweep points and states are supported"
                )
            if not isinstance(selected_pt.selector, dict):
                raise DebugError(f"SARIF point {selected_pt.name!r} has no valid reproduction block")
            spec = _parse_reproduction_dict(
                selected_pt.selector,
                point_name=selected_pt.name,
                point_kind=selected_pt.kind,
            )
            prof_path = _resolve_profile_path(
                explicit_profile=profile,
                report_profile_path=None,
                report_profile_name=sarif_prof,
                sarif_uri=sarif_uri,
                repo_root=repo_root,
                report_dir=report_path.parent,
            )
            loaded_profile, elf_path = _load_profile_and_elf(
                prof_path,
                explicit_elf=elf,
                component=selected_pt.component,
                repo_root=repo_root,
            )
            state_ids = _candidate_state_ids(selected_pt)
            state_search_enabled = bool(
                getattr(
                    getattr(loaded_profile.fault_sweep, "phase2_fault", None),
                    "state_search",
                    None,
                )
                and loaded_profile.fault_sweep.phase2_fault.state_search.enabled
            )
            target = DebugTarget(
                profile=loaded_profile,
                profile_path=prof_path,
                elf_path=elf_path,
                component=selected_pt.component,
                point_name=spec["point_name"],
                point_kind=spec["point_kind"],
                fault_at=spec["fault_at"],
                fault_type_code=spec["fault_type_code"],
                cuts=spec["cuts"],
                is_control=spec["is_control"],
                state_identity=state_ids[0] if state_ids else None,
                state_search_gated=bool(
                    selected_pt.kind.startswith("state_search") or state_ids or state_search_enabled
                ),
                include_erase_fault_points=spec["include_erase_fault_points"],
            )
            _validate_stop_at_compatibility(target, canonical_stop)
            return target

    preserved_pre_states = _preserve_pre_recovery_states(report_data)
    try:
        run_obj: ReportRun = saved_run(
            report_data,
            report_path,
            repo_root,
            profile_path=profile,
            elf=elf,
        )
    except ValueError as exc:
        raise DebugError(str(exc)) from exc

    all_points = (
        list(run_obj.points())
        + _extract_shard_edge_points(run_obj)
        + [
            pt for pt in run_obj.additional_findings()
            if pt.kind in AUXILIARY_UNSUPPORTED_KINDS
        ]
    )
    if isinstance(report_data, dict) and isinstance(report_data.get("control_result"), dict):
        if not any(pt.kind == "control" or (pt.row or {}).get("is_control") for pt in all_points):
            ctrl_row = dict(report_data["control_result"])
            ctrl_row.setdefault("is_control", True)
            ctrl_row.setdefault("fault_at", -1)
            ctrl_row.setdefault("fault_type", "control")
            all_points.insert(
                0,
                Point(
                    kind="control",
                    name="clean control",
                    row=ctrl_row,
                    status="pass",
                    message="",
                    findings=[],
                    selector={"FAULT_AT": "-1"},
                ),
            )
    selected_pt = _select_point_from_candidates(
        all_points, point_selector=point, state_selector=state
    )
    row = selected_pt.row
    if selected_pt.component and isinstance((row.get("per_component") or {}).get(selected_pt.component), dict):
        row = row["per_component"][selected_pt.component]

    pre_recovery_state = _lookup_preserved_pre_state(row, preserved_pre_states)
    if pre_recovery_state is not None and isinstance(row, dict):
        row.setdefault("_pre_recovery_state", pre_recovery_state)

    exec_spec = _row_to_execution_spec(row, selected_pt.name, selected_pt.kind)
    prof_path = _resolve_profile_path(
        explicit_profile=profile,
        report_profile_path=run_obj.profile_path or (
            report_data.get("profile_path") if isinstance(report_data, dict) else None
        ),
        report_profile_name=run_obj.name,
        sarif_uri=None,
        repo_root=repo_root,
        report_dir=report_path.parent,
    )
    loaded_profile, elf_path = _load_profile_and_elf(
        prof_path,
        explicit_elf=elf,
        component=selected_pt.component,
        repo_root=repo_root,
    )
    state_search_enabled = bool(
        getattr(
            getattr(loaded_profile.fault_sweep, "phase2_fault", None),
            "state_search",
            None,
        )
        and loaded_profile.fault_sweep.phase2_fault.state_search.enabled
    )
    target = DebugTarget(
        profile=loaded_profile,
        profile_path=prof_path,
        elf_path=elf_path,
        component=selected_pt.component,
        point_name=exec_spec["point_name"],
        point_kind=exec_spec["point_kind"],
        fault_at=exec_spec["fault_at"],
        fault_type_code=exec_spec["fault_type_code"],
        cuts=exec_spec["cuts"],
        is_control=exec_spec["is_control"],
        state_identity=exec_spec["state_identity"],
        state_search_gated=bool(exec_spec["state_search_gated"] or state_search_enabled),
        include_erase_fault_points=exec_spec["include_erase_fault_points"],
        expected_outcome=exec_spec["expected_outcome"],
        expected_fault_class=exec_spec["expected_fault_class"],
        row=exec_spec["row"],
        pre_recovery_state=pre_recovery_state,
        expected_explanation=_extract_expected_explanation(exec_spec["row"]),
    )
    _validate_stop_at_compatibility(target, canonical_stop)
    return target


def _resolve_hash_bypass_addrs(elf_path: Path, symbols: list[str]) -> str:
    nm_bin = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
    if not nm_bin or not symbols or not elf_path.is_file():
        return ""
    try:
        res = subprocess.run(
            [nm_bin, str(elf_path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode != 0:
            return ""
    except Exception:
        return ""
    nm_entries: dict[str, list[int]] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16) & ~1
            except ValueError:
                continue
            nm_entries.setdefault(parts[2], []).append(addr)
    pairs = []
    for sym in symbols:
        for addr in sorted(nm_entries.get(sym, ())):
            pairs.append(f"{sym}=0x{addr:08x}")
    return ",".join(pairs)


def build_debug_robot_vars(
    target: DebugTarget,
    *,
    stop_at: str,
    port: int,
    ready_file: Path,
    timeout_s: int,
    repo_root: Path,
) -> tuple[list[str], list[str]]:
    """Return (merged_robot_vars, generated_base_robot_vars_for_cleanup)."""
    base_vars = target.profile.robot_vars(repo_root)
    if target.is_control:
        fault_vars = build_control_robot_vars(base_vars, target.profile)
    else:
        no_hash_bypass = target.fault_type_code.startswith("i:")
        fault_vars = build_fault_robot_vars(
            base_vars,
            target.profile,
            no_hash_bypass=no_hash_bypass,
        )
        bypass_syms = (
            []
            if no_hash_bypass
            else list(getattr(target.profile.fault_sweep, "sweep_hash_bypass_symbols", None) or [])
        )
        if bypass_syms:
            addrs = _resolve_hash_bypass_addrs(target.elf_path, bypass_syms)
            if addrs:
                fault_vars = merge_robot_vars(fault_vars, [f"HASH_BYPASS_ADDRS:{addrs}"])

    has_erase = any(code in ("e", "a") for _at, code in target.cuts)
    has_write = any(code not in ("e", "a") for _at, code in target.cuts)
    if has_erase and has_write:
        fault_types_mode = "both"
    elif has_erase:
        fault_types_mode = "erase"
    else:
        fault_types_mode = "write"

    overlay = [
        f"BOOTLOADER_ELF:{target.elf_path}",
        f"FAULT_AT:{-1 if target.is_control else target.fault_at}",
        f"FAULT_POINTS_CSV:{'' if target.is_control else target.fault_at}",
        f"FAULT_TYPE_CSV:{'control' if target.is_control else target.fault_type_code}",
        f"FAULT_TYPES:{fault_types_mode}",
        f"DEBUG_MODE:true",
        f"DEBUG_STOP_AT:{stop_at}",
        f"DEBUG_GDB_PORT:{port}",
        f"DEBUG_READY_FILE:{ready_file}",
        f"DEBUG_TIMEOUT_S:{timeout_s}",
        f"DEBUG_EXPECTED_STATE_ID:{target.state_identity or ''}",
        f"DEBUG_STATE_SEARCH_GATED:{'true' if target.state_search_gated else 'false'}",
    ]
    if (
        target.pre_recovery_state is not None
        or target.checkpoint_snapshot is not None
        or target.expected_explanation is not None
    ):
        expected_state_file = ready_file.parent / "debug_expected_state.json"
        expected_payload: dict[str, Any] = {
            "state_identity": target.state_identity,
        }
        if target.pre_recovery_state is not None:
            expected_payload["pre_recovery_state"] = target.pre_recovery_state
        if target.checkpoint_snapshot is not None:
            expected_payload["checkpoint_snapshot"] = target.checkpoint_snapshot
        if target.expected_explanation is not None:
            expected_payload["expected_explanation"] = target.expected_explanation
        ready_file.parent.mkdir(parents=True, exist_ok=True)
        expected_state_file.write_text(
            json.dumps(expected_payload, sort_keys=True),
            encoding="utf-8",
        )
        overlay.append(f"DEBUG_EXPECTED_STATE_FILE:{expected_state_file}")
    if target.include_erase_fault_points:
        overlay.append("INCLUDE_ERASE_FAULT_POINTS:true")
    return merge_robot_vars(fault_vars, overlay), base_vars


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        process.kill()
    except Exception:
        pass


def run_debug(
    target: DebugTarget,
    *,
    stop_at: str = "recovery-reset",
    port: int = 3333,
    gdb: str | None = None,
    renode_test: str = DEFAULT_RENODE_TEST,
    timeout: int = 300,
    output: Path | None = None,
    gdb_ex: list[str] | None = None,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    if timeout is None or isinstance(timeout, bool) or int(timeout) <= 0:
        raise DebugError("--timeout must be a positive integer")
    timeout_s = int(timeout)
    canonical_stop = normalize_stop_at(stop_at)
    resolved_port = validate_port(port)
    gdb_binary = select_gdb_binary(gdb)
    runner = ensure_tool(renode_test)
    repo_root = Path(repo_root).resolve()
    robot_suite = str((repo_root / DEFAULT_ROBOT_SUITE).resolve())

    gdb_cmd_str = format_gdb_command(gdb_binary, target.elf_path, resolved_port)

    with tempfile.TemporaryDirectory(prefix="tardigrade_debug_") as tmp_dir_raw:
        work_dir = Path(tmp_dir_raw).resolve()
        ready_file = work_dir / "debug_ready.json"
        result_file = work_dir / "result.json"
        rf_results = work_dir / "robot"
        temp_root = work_dir / ".tmp"
        bundle_dir = work_dir / ".dotnet_bundle"
        renode_config = work_dir / "renode.config"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        robot_timeout_m = max(5, (timeout_s + 180 + 59) // 60)
        robot_vars, base_vars_for_cleanup = build_debug_robot_vars(
            target,
            stop_at=canonical_stop,
            port=resolved_port,
            ready_file=ready_file,
            timeout_s=timeout_s,
            repo_root=repo_root,
        )
        env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)

        cmd = [
            runner,
            "--renode-config",
            str(renode_config),
            robot_suite,
            "--results-dir",
            str(rf_results),
            "--variable",
            f"RESULT_FILE:{result_file}",
            "--variable",
            "CALIBRATION_MODE:false",
            "--variable",
            f"TEST_TIMEOUT:{robot_timeout_m} minutes",
        ]
        for rv in robot_vars:
            cmd.extend(["--variable", rv])
        cmd = prepare_renode_command(runner, cmd, repo_root, env)

        process = subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        batch_proc: subprocess.Popen[str] | None = None
        try:
            setup_deadline = time.time() + max(120.0, float(timeout_s))
            ready_payload: dict[str, Any] | None = None
            while time.time() < setup_deadline:
                if ready_file.is_file():
                    try:
                        ready_payload = json.loads(ready_file.read_text(encoding="utf-8"))
                        break
                    except Exception:
                        pass
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise RuntimeError(
                        f"Renode exited before starting GDB server (code {process.returncode})\n"
                        f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
                    )
                time.sleep(0.05)

            if ready_payload is None:
                _kill_process_group(process)
                stdout, stderr = process.communicate()
                raise RuntimeError(
                    f"timed out waiting for Renode to rebuild state and start GDB server\n"
                    f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
                )

            if ready_payload.get("error"):
                _kill_process_group(process)
                process.communicate()
                raise RuntimeError(str(ready_payload["error"]))

            print(gdb_cmd_str, flush=True)
            sys.stderr.write(
                f"[debug] stop_at={ready_payload.get('stop_at', canonical_stop)} "
                f"port={resolved_port} pc={ready_payload.get('pc', '?')} "
                f"sp={ready_payload.get('sp', '?')}"
                + (
                    f" state_identity={ready_payload.get('state_identity')}"
                    if ready_payload.get("state_identity")
                    else ""
                )
                + "\n"
            )
            sys.stderr.flush()

            if gdb_ex:
                batch_cmd = [
                    gdb_binary,
                    "-nx",
                    "-nh",
                    "-batch",
                    str(target.elf_path),
                    "-ex",
                    f"target remote :{resolved_port}",
                ]
                for ex_cmd in gdb_ex:
                    batch_cmd.extend(["-ex", str(ex_cmd)])
                batch_cmd.extend(["-ex", "detach", "-ex", "quit"])
                batch_proc = subprocess.Popen(
                    batch_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

            try:
                stdout, stderr = process.communicate(timeout=float(timeout_s) + 30.0)
            except subprocess.TimeoutExpired as exc:
                _kill_process_group(process)
                process.communicate()
                raise RuntimeError(f"debug session exceeded {timeout_s}s timeout") from exc

            if batch_proc is not None:
                try:
                    batch_out, _ = batch_proc.communicate(timeout=15.0)
                except subprocess.TimeoutExpired:
                    batch_proc.kill()
                    batch_out, _ = batch_proc.communicate()
                if batch_out:
                    print(batch_out.rstrip(), flush=True)
                if batch_proc.returncode != 0:
                    raise RuntimeError(
                        f"gdb -batch exited with status {batch_proc.returncode}"
                    )

            if process.returncode != 0:
                raise RuntimeError(
                    f"debug session failed (exit {process.returncode})\n"
                    f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
                )
            if not result_file.is_file():
                raise RuntimeError("debug session did not produce a runtime result")

            result = json.loads(result_file.read_text(encoding="utf-8"))
            if isinstance(result, list):
                result = result[0]
            annotate_result_checks([result], target.profile, repo_root=repo_root)
            result["gdb_command"] = gdb_cmd_str
            if output is not None:
                out_path = Path(output).expanduser().resolve()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            outcome, slot = _effective_boot_result(result)
            fault_class = result.get("fault_class") or classify_failure_class(result)
            sys.stderr.write(
                f"[debug] verdict: boot_outcome={outcome} boot_slot={slot} fault_class={fault_class}\n"
            )
            sys.stderr.flush()
            return result
        except KeyboardInterrupt:
            _kill_process_group(process)
            process.wait()
            raise
        finally:
            if batch_proc is not None and batch_proc.poll() is None:
                batch_proc.kill()
                batch_proc.wait()
            _cleanup_generated_robot_vars(base_vars_for_cleanup)


def build_arg_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Rebuild a failing audit point or state and open it in Renode's GDB server.",
    )
    parser.add_argument(
        "--report",
        "--input",
        "--sarif",
        dest="report",
        type=Path,
        help="Audit JSON report or SARIF 2.1.0 report file.",
    )
    parser.add_argument(
        "--point",
        help="Point or state selector within --report (e.g. '3,0', 'w[2]', '#1', or state identity).",
    )
    parser.add_argument(
        "--state",
        help="State identity (full 64-character hex or unique prefix) from recovery_state_search.",
    )
    parser.add_argument(
        "--reproduction",
        help="SARIF reproduction block (or SARIF point/result JSON) as inline JSON or file path.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        help="Profile YAML path (optional when --report records profile_path).",
    )
    parser.add_argument(
        "--elf",
        type=Path,
        help="Override bootloader ELF path with debug symbols.",
    )
    parser.add_argument(
        "--stop-at",
        "--at",
        "--stop",
        dest="stop_at",
        default="recovery-reset",
        help="Where to stop before GDB attaches: recovery-reset (default), cut, or first-fault.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3333,
        help="TCP port for Renode's GDB server (default: 3333; use 0 for an ephemeral port).",
    )
    parser.add_argument(
        "--gdb",
        help="GDB executable to print (auto-detects arm-none-eabi-gdb, gdb-multiarch, or gdb).",
    )
    parser.add_argument(
        "--renode-test",
        default=DEFAULT_RENODE_TEST,
        help="Path to renode-test executable (default: $RENODE_TEST or renode-test).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Seconds to keep Renode running waiting for GDB to detach (default: 300).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the post-debug runtime result JSON.",
    )
    parser.add_argument(
        "--ex",
        dest="gdb_ex",
        action="append",
        help="Optional repeatable GDB command to run in an automated gdb -batch session.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository or runtime root directory.",
    )
    return parser


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    parser = build_arg_parser(prog=prog)
    args = parser.parse_args(argv)
    try:
        if args.timeout is not None and args.timeout <= 0:
            raise DebugError("--timeout must be positive")
        validate_port(args.port)
        canonical_stop = normalize_stop_at(args.stop_at)
        target = resolve_debug_target(
            report=args.report,
            point=args.point,
            state=args.state,
            reproduction=args.reproduction,
            profile=args.profile,
            elf=args.elf,
            stop_at=canonical_stop,
            repo_root=args.repo_root,
        )
        run_debug(
            target,
            stop_at=canonical_stop,
            port=args.port,
            gdb=args.gdb,
            renode_test=args.renode_test,
            timeout=args.timeout,
            output=args.output,
            gdb_ex=args.gdb_ex,
            repo_root=args.repo_root,
        )
        return 0
    except (DebugError, OSError, ValueError, RuntimeError) as exc:
        prefix = prog or parser.prog
        parser.exit(2, f"{prefix}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
