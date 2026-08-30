"""Binary-driven terminal-error escape campaign helpers.

The campaign is deliberately based on the emitted ELF, rather than source
annotations.  This module owns the small, deterministic part of the feature:
resolving function ranges and finding direct Thumb calls/tail branches to a
declared terminal handler.  Runtime orchestration can then inject the existing
instruction-skip fault at the returned callsite addresses.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TerminalErrorPathConfig:
    name: str
    handler_symbols: Tuple[str, ...]
    containing_symbols: Tuple[str, ...]
    forbidden_sink_symbols: Tuple[str, ...]
    expected_control: str = "terminal"
    required_failure_marker: Optional[Dict[str, int]] = None
    observation_window: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        value: Dict[str, Any] = {
            "name": self.name,
            "handler_symbols": list(self.handler_symbols),
            "containing_symbols": list(self.containing_symbols),
            "forbidden_sink_symbols": list(self.forbidden_sink_symbols),
            "expected_control": self.expected_control,
        }
        if self.required_failure_marker is not None:
            value["required_failure_marker"] = dict(self.required_failure_marker)
        if self.observation_window is not None:
            value["observation_window"] = self.observation_window
        return value


@dataclass(frozen=True)
class TerminalCallsite:
    campaign: str
    containing_symbol: str
    handler_symbol: str
    callsite_address: int
    instruction_bytes: bytes
    disassembly: str
    call_kind: str

    def to_dict(self) -> Dict[str, Any]:
        artifact_hash = hashlib.sha256(
            self.campaign.encode("utf-8")
            + self.callsite_address.to_bytes(4, "little")
            + self.instruction_bytes
        ).hexdigest()
        return {
            "campaign": self.campaign,
            "containing_symbol": self.containing_symbol,
            "handler_symbol": self.handler_symbol,
            "callsite_address": "0x{:08X}".format(self.callsite_address),
            "instruction_bytes": self.instruction_bytes.hex(),
            "disassembly": self.disassembly,
            "call_kind": self.call_kind,
            "artifact_hash": artifact_hash,
        }


@dataclass
class TerminalDiscovery:
    candidates: List[TerminalCallsite] = field(default_factory=list)
    unresolved_candidates: List[Dict[str, Any]] = field(default_factory=list)
    infrastructure_errors: List[Dict[str, Any]] = field(default_factory=list)
    symbols: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidates": [item.to_dict() for item in self.candidates],
            "unresolved_candidates": list(self.unresolved_candidates),
            "infrastructure_errors": list(self.infrastructure_errors),
            "symbols": {
                name: [
                    {"start": "0x{:08X}".format(start), "end": "0x{:08X}".format(end)}
                    for start, end in ranges
                ]
                for name, ranges in self.symbols.items()
            },
        }


def parse_terminal_error_paths(raw: Any) -> List[TerminalErrorPathConfig]:
    """Validate and normalize the top-level ``terminal_error_paths`` block."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("terminal_error_paths: expected list")
    result: List[TerminalErrorPathConfig] = []
    names = set()
    for index, entry in enumerate(raw):
        ctx = "terminal_error_paths[{}]".format(index)
        if not isinstance(entry, dict):
            raise ValueError("{}: expected mapping".format(ctx))
        name = str(entry.get("name") or "").strip()
        if not name:
            raise ValueError("{}.name: expected non-empty string".format(ctx))
        if name in names:
            raise ValueError("terminal_error_paths: duplicate name {!r}".format(name))
        names.add(name)

        def symbols(key: str) -> Tuple[str, ...]:
            value = entry.get(key)
            if not isinstance(value, list) or not value:
                raise ValueError("{}.{}: expected non-empty list".format(ctx, key))
            cleaned = tuple(str(item).strip() for item in value)
            if any(not item for item in cleaned):
                raise ValueError("{}.{}: symbols must be non-empty strings".format(ctx, key))
            if len(set(cleaned)) != len(cleaned):
                raise ValueError("{}.{}: symbols must be unique".format(ctx, key))
            return cleaned

        expected = str(entry.get("expected_control", "terminal") or "").strip().lower()
        if expected != "terminal":
            raise ValueError("{}.expected_control: expected 'terminal'".format(ctx))
        marker = entry.get("required_failure_marker")
        normalized_marker = None
        if marker is not None:
            if not isinstance(marker, dict):
                raise ValueError("{}.required_failure_marker: expected mapping".format(ctx))
            unknown = set(marker) - {"address", "expected_value", "mask", "op"}
            if unknown:
                raise ValueError("{}.required_failure_marker: unknown field(s): {}".format(ctx, ", ".join(sorted(unknown))))
            op = str(marker.get("op", "eq")).strip().lower()
            if op not in {"eq", "ne", "ge", "le", "nonzero"}:
                raise ValueError("{}.required_failure_marker.op: unsupported operator {!r}".format(ctx, op))
            if "address" not in marker:
                raise ValueError("{}.required_failure_marker.address is required".format(ctx))
            if op != "nonzero" and "expected_value" not in marker:
                raise ValueError("{}.required_failure_marker.expected_value is required".format(ctx))
            normalized_marker = {
                "address": int(marker["address"], 0) if isinstance(marker["address"], str) else int(marker["address"]),
                "expected_value": int(marker.get("expected_value", 0), 0) if isinstance(marker.get("expected_value", 0), str) else int(marker.get("expected_value", 0)),
                "mask": int(marker.get("mask", 0xFFFFFFFF), 0) if isinstance(marker.get("mask", 0xFFFFFFFF), str) else int(marker.get("mask", 0xFFFFFFFF)),
                "op": op,
            }
        window = entry.get("observation_window")
        if window is not None:
            try:
                window = float(window)
            except (TypeError, ValueError) as exc:
                raise ValueError("{}.observation_window: expected number".format(ctx)) from exc
            if window <= 0:
                raise ValueError("{}.observation_window: expected > 0".format(ctx))
        result.append(TerminalErrorPathConfig(
            name=name,
            handler_symbols=symbols("handler_symbols"),
            containing_symbols=symbols("containing_symbols"),
            forbidden_sink_symbols=symbols("forbidden_sink_symbols"),
            expected_control=expected,
            required_failure_marker=normalized_marker,
            observation_window=window,
        ))
    return result


@dataclass(frozen=True)
class _Symbol:
    name: str
    start: int
    size: int
    section_index: int


def _elf_symbols(elf_path: Path) -> List[_Symbol]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    except ImportError:
        tool = "arm-none-eabi-nm"
        output = subprocess.run([tool, "-S", "--defined-only", str(elf_path)], capture_output=True, text=True, check=False)
        if output.returncode != 0:
            raise RuntimeError("pyelftools and arm-none-eabi-nm are unavailable")
        result = []
        for line in output.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2].upper() in {"T", "W"}:
                try:
                    result.append(_Symbol(parts[3], int(parts[0], 16) & ~1, int(parts[1], 16), 1))
                except ValueError:
                    continue
        return result
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        result: List[_Symbol] = []
        for table_name in (".symtab", ".dynsym"):
            table = elf.get_section_by_name(table_name)
            if table is None:
                continue
            for symbol in table.iter_symbols():
                entry = symbol.entry
                typ = entry["st_info"]["type"]
                if typ != "STT_FUNC":
                    continue
                start = int(entry["st_value"] or 0) & ~1
                if not start:
                    continue
                result.append(_Symbol(symbol.name, start, int(entry["st_size"] or 0), int(entry["st_shndx"] or 0) if isinstance(entry["st_shndx"], int) else 0))
        return result


def _symbol_ranges(symbols: Sequence[_Symbol]) -> Dict[str, List[Tuple[int, int]]]:
    by_section: Dict[int, List[_Symbol]] = {}
    for symbol in symbols:
        by_section.setdefault(symbol.section_index, []).append(symbol)
    result: Dict[str, List[Tuple[int, int]]] = {}
    for section_symbols in by_section.values():
        ordered = sorted(section_symbols, key=lambda item: item.start)
        for index, symbol in enumerate(ordered):
            end = symbol.start + symbol.size
            if not symbol.size and index + 1 < len(ordered):
                end = ordered[index + 1].start
            if end <= symbol.start:
                continue
            result.setdefault(symbol.name, []).append((symbol.start, end))
    return result


def _load_bytes(elf_path: Path, address: int, end: int) -> bytes:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    except ImportError:
        # objcopy's binary output is not address-aware, so use objdump's
        # section bytes only as a last resort.  The normal project install
        # includes pyelftools; this branch primarily keeps preflight useful on
        # minimal CI images.
        raise RuntimeError("pyelftools is required to read ELF load segments")
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_LOAD":
                continue
            start = int(segment.header.p_vaddr)
            stop = start + int(segment.header.p_filesz)
            if start <= address and end <= stop:
                data = segment.data()
                offset = address - start
                return bytes(data[offset:offset + (end - address)])
    raise ValueError("ELF has no file-backed load segment for 0x{:X}-0x{:X}".format(address, end))


class _Instruction:
    def __init__(self, address: int, raw: bytes, mnemonic: str, op_str: str, target: Optional[int] = None):
        self.address = address
        self.bytes = raw
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.target = target


def _disassemble(code: bytes, start: int) -> List[Any]:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM  # type: ignore[import-untyped]
        disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        disassembler.detail = True
        result = []
        for instruction in disassembler.disasm(code, start):
            target = None
            if instruction.operands and instruction.operands[0].type == CS_OP_IMM:
                target = int(instruction.operands[0].imm) & ~1
            result.append(_Instruction(instruction.address, bytes(instruction.bytes), instruction.mnemonic, instruction.op_str, target))
        return result
    except ImportError:
        raise RuntimeError("capstone is required for Thumb disassembly")


def _branch_base_mnemonic(mnemonic: str) -> str:
    return str(mnemonic or "").strip().lower().split(".", 1)[0]


def _is_direct_branch_mnemonic(mnemonic: str) -> bool:
    # Capstone prints wide branches as ``b.w``/``beq.w``.  Conditional
    # branches are valid tail calls too: when taken they transfer control to
    # the terminal handler without a link register update.
    return _branch_base_mnemonic(mnemonic) in {
        "b", "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl",
        "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble", "bal",
    }


def _resolve_names(names: Iterable[str], ranges: Dict[str, List[Tuple[int, int]]]) -> Dict[str, List[Tuple[int, int]]]:
    selected: Dict[str, List[Tuple[int, int]]] = {}
    for query in names:
        matches = sorted((name, values) for name, values in ranges.items() if name == query or fnmatch.fnmatch(name, query))
        for name, values in matches:
            selected.setdefault(name, []).extend(values)
    return selected


def discover_terminal_error_paths(elf_path: str | Path, declarations: Sequence[TerminalErrorPathConfig | Dict[str, Any]]) -> TerminalDiscovery:
    """Find direct ``BL`` and tail ``B`` calls to each terminal handler."""
    path = Path(elf_path)
    normalized = [item if isinstance(item, TerminalErrorPathConfig) else TerminalErrorPathConfig(**parse_terminal_error_paths([item])[0].__dict__) for item in declarations]
    discovery = TerminalDiscovery()
    try:
        ranges = _symbol_ranges(_elf_symbols(path))
    except Exception as exc:
        discovery.infrastructure_errors.append({"kind": "elf_unreadable", "error": str(exc)})
        return discovery
    for declaration in normalized:
        containing = _resolve_names(declaration.containing_symbols, ranges)
        handlers = _resolve_names(declaration.handler_symbols, ranges)
        sinks = _resolve_names(declaration.forbidden_sink_symbols, ranges)
        discovery.symbols.update(containing)
        discovery.symbols.update(handlers)
        discovery.symbols.update(sinks)
        for requested, resolved in (("containing", containing), ("handler", handlers), ("forbidden_sink", sinks)):
            if not resolved:
                discovery.infrastructure_errors.append({"campaign": declaration.name, "kind": "missing_symbol", "role": requested, "symbols": list(getattr(declaration, requested + "_symbols"))})
        handler_addresses = {start for values in handlers.values() for start, _ in values}
        for containing_name, containing_ranges in containing.items():
            if len(containing_ranges) != 1:
                discovery.infrastructure_errors.append({"campaign": declaration.name, "kind": "ambiguous_range", "symbol": containing_name, "ranges": len(containing_ranges)})
                continue
            start, end = containing_ranges[0]
            try:
                code = _load_bytes(path, start, end)
                instructions = _disassemble(code, start)
            except Exception as exc:
                discovery.infrastructure_errors.append({"campaign": declaration.name, "kind": "disassembly_failed", "symbol": containing_name, "error": str(exc)})
                continue
            for instruction in instructions:
                mnemonic = instruction.mnemonic.lower()
                branch_base = _branch_base_mnemonic(mnemonic)
                if branch_base not in {"bl", "blx", "bx"} and not _is_direct_branch_mnemonic(mnemonic):
                    continue
                target = None
                target = getattr(instruction, "target", None)
                if target is None:
                    if branch_base in {"blx", "bx"} and instruction.op_str.strip().lower() not in {"lr", "r14", "pc"}:
                        discovery.unresolved_candidates.append({"campaign": declaration.name, "containing_symbol": containing_name, "callsite_address": "0x{:08X}".format(instruction.address), "disassembly": instruction.mnemonic + (" " + instruction.op_str if instruction.op_str else ""), "reason": "unsupported_indirect_call"})
                    continue
                handler_name = next((name for name, values in handlers.items() if any(start_addr == target for start_addr, _ in values)), None)
                if handler_name is None:
                    continue
                kind = "direct_call" if branch_base in {"bl", "blx"} else "tail_call"
                discovery.candidates.append(TerminalCallsite(declaration.name, containing_name, handler_name, int(instruction.address), bytes(instruction.bytes), instruction.mnemonic + (" " + instruction.op_str if instruction.op_str else ""), kind))
    campaigns_by_callsite: Dict[int, set[str]] = {}
    for candidate in discovery.candidates:
        campaigns_by_callsite.setdefault(candidate.callsite_address, set()).add(
            candidate.campaign
        )
    for address, campaigns_value in sorted(campaigns_by_callsite.items()):
        campaigns = sorted(campaigns_value)
        if len(campaigns) <= 1:
            continue
        # The runtime selects instruction-skip observations by address.  If
        # distinct declarations resolve to the same callsite, attributing the
        # resulting sink observation to only one campaign would be ambiguous.
        # Refuse to execute that campaign set instead of silently dropping one.
        for campaign in campaigns:
            discovery.infrastructure_errors.append({
                "campaign": campaign,
                "kind": "ambiguous_callsite_campaign",
                "callsite_address": "0x{:08X}".format(address),
                "campaigns": campaigns,
            })
    return discovery


def build_terminal_runtime_payload(discovery: TerminalDiscovery, declarations: Sequence[TerminalErrorPathConfig]) -> List[Dict[str, Any]]:
    """Build compact hook data consumed by the Renode runtime."""
    result = []
    for declaration in declarations:
        candidates = [item.to_dict() for item in discovery.candidates if item.campaign == declaration.name]
        sinks = []
        for symbol, ranges in discovery.symbols.items():
            if any(
                symbol == query or fnmatch.fnmatch(symbol, query)
                for query in declaration.forbidden_sink_symbols
            ):
                sinks.extend(start for start, _ in ranges)
        result.append({
            "config": declaration.to_dict(),
            "candidates": candidates,
            "forbidden_sink_addresses": ["0x{:08X}".format(addr) for addr in sorted(set(sinks))],
            "unresolved_candidates": [item for item in discovery.unresolved_candidates if item.get("campaign") == declaration.name],
            "infrastructure_errors": [item for item in discovery.infrastructure_errors if item.get("campaign") == declaration.name],
        })
    return result


def terminal_snapshot_identity(elf_path: str | Path, image_paths: Dict[str, str], pre_boot_state: Sequence[Any]) -> str:
    """Hash the immutable inputs shared by control and faulted runs."""
    digest = hashlib.sha256()
    digest.update(Path(elf_path).read_bytes())
    for name, image_path in sorted(image_paths.items()):
        digest.update(name.encode("utf-8"))
        digest.update(Path(image_path).read_bytes())
    for write in pre_boot_state:
        address = getattr(write, "address", write.get("address") if isinstance(write, dict) else 0)
        value = getattr(write, "u32", write.get("u32") if isinstance(write, dict) else 0)
        digest.update(int(address).to_bytes(4, "little"))
        digest.update(int(value).to_bytes(4, "little"))
    return digest.hexdigest()


def terminal_payload_identity(payload: bytes, expected_sha256: str) -> bool:
    """Verify the emitted terminal-campaign payload identity."""
    expected = str(expected_sha256 or "").strip().lower()
    return bool(_SHA256_RE.fullmatch(expected) and hashlib.sha256(payload).hexdigest() == expected)


def terminal_observation_window_open(started_at: float, now: float, window: Optional[float]) -> bool:
    """Return whether an observation is within the configured wall window."""
    if window is None:
        return True
    return float(now) - float(started_at) <= float(window)


def evaluate_terminal_error_differential(
    discovery: TerminalDiscovery,
    control_result: Dict[str, Any],
    fault_results: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluate control/fault telemetry with fail-closed finding semantics.

    A skipped instruction is not a finding by itself.  The selected patch must
    report successful application and the corresponding forbidden sink must be
    observed during the configured observation window.
    """
    control_signals = control_result.get("signals") if isinstance(control_result, dict) else {}
    control_paths = control_signals.get("terminal_error_paths") if isinstance(control_signals, dict) else {}
    infrastructure_errors = list(discovery.infrastructure_errors)
    control_identity = {
        "snapshot": control_signals.get("terminal_error_snapshot_hash") if isinstance(control_signals, dict) else None,
        "artifact": control_signals.get("terminal_error_artifact_hash") if isinstance(control_signals, dict) else None,
    }
    for label, value in control_identity.items():
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.lower()):
            infrastructure_errors.append({
                "campaign": None,
                "kind": "missing_terminal_identity",
                "identity": label,
                "role": "control",
            })

    campaigns = {item.campaign for item in discovery.candidates}
    for campaign in sorted(campaigns):
        evidence = control_paths.get(campaign) if isinstance(control_paths, dict) else None
        if not isinstance(evidence, dict) or not evidence.get("callsite_reached") or not evidence.get("control_terminal"):
            infrastructure_errors.append({
                "campaign": campaign,
                "kind": "control_not_terminal",
                "reason": "control did not reach a declared handler callsite and prove terminal control",
            })
    records = []
    for fault in fault_results:
        signals = fault.get("signals") if isinstance(fault, dict) else {}
        paths = signals.get("terminal_error_paths") if isinstance(signals, dict) else {}
        callsite = fault.get("fault_address") or fault.get("fault_at")
        try:
            callsite_int = int(str(callsite), 0)
        except (TypeError, ValueError):
            callsite_int = -1
        candidate = next((item for item in discovery.candidates if item.callsite_address == (callsite_int & ~1)), None)
        campaign_name = candidate.campaign if candidate is not None else None
        control = control_paths.get(campaign_name, {}) if isinstance(control_paths, dict) else {}
        observed = paths.get(campaign_name, {}) if isinstance(paths, dict) else {}
        fault_identity = {
            "snapshot": signals.get("terminal_error_snapshot_hash") if isinstance(signals, dict) else None,
            "artifact": signals.get("terminal_error_artifact_hash") if isinstance(signals, dict) else None,
        }
        identity_matches = True
        for label, value in fault_identity.items():
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.lower()):
                identity_matches = False
                infrastructure_errors.append({
                    "campaign": campaign_name,
                    "kind": "missing_terminal_identity",
                    "identity": label,
                    "role": "fault",
                })
            elif value.lower() != str(control_identity.get(label) or "").lower():
                identity_matches = False
                infrastructure_errors.append({
                    "campaign": campaign_name,
                    "kind": "terminal_identity_mismatch",
                    "identity": label,
                })
        control_valid = bool(
            isinstance(control, dict)
            and control.get("callsite_reached")
            and control.get("control_terminal")
        )
        patch_applied = bool(fault.get("fault_injected") is True and observed.get("fault_applied"))
        escaped = bool(identity_matches and control_valid and patch_applied and observed.get("forbidden_sink_reached"))
        record = {
            "campaign": campaign_name,
            "containing_symbol": candidate.containing_symbol if candidate else None,
            "handler_symbol": candidate.handler_symbol if candidate else None,
            "callsite_address": candidate.to_dict().get("callsite_address") if candidate else callsite,
            "instruction_bytes": candidate.to_dict().get("instruction_bytes") if candidate else None,
            "disassembly": candidate.disassembly if candidate else None,
            "control_evidence": control,
            "fault_applied_evidence": observed,
            "first_forbidden_sink": observed.get("first_forbidden_sink"),
            "finding": "TERMINAL_ERROR_PATH_ESCAPED" if escaped else None,
        }
        records.append(record)
    return {
        "candidates": len(discovery.candidates),
        "unresolved_candidates": list(discovery.unresolved_candidates),
        "infrastructure_errors": infrastructure_errors,
        "results": records,
        "findings": [item for item in records if item.get("finding")],
    }
