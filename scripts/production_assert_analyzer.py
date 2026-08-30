#!/usr/bin/env python3
"""Find Python assertions that disappear from optimized production builds.

This is a review-oriented Tardigrade analyzer.  It deliberately reports
security candidates, not confirmed vulnerabilities: callers must establish
that input can violate the asserted invariant and that execution reaches a
security-sensitive sink after the assertion is removed.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Optional, Sequence


SENSITIVE_PATH_TERMS = {
    "address",
    "authorization",
    "firmware",
    "keychain",
    "pairing",
    "payment",
    "recovery",
    "seed",
    "sign",
    "transaction",
    "webauthn",
}

SECURITY_SINK_TERMS = {
    "approve",
    "confirm",
    "derive",
    "hash",
    "serialize",
    "sign",
    "verify",
    "write",
}

NARROWING_COMMENT_TERMS = {
    "checked in",
    "type-check",
    "typechecker",
    "type checker",
}


@dataclass(frozen=True)
class AssertFinding:
    path: str
    line: int
    function: str
    condition: str
    confidence: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": "PRODUCTION_ASSERT_REVIEW",
            "path": self.path,
            "line": self.line,
            "function": self.function,
            "condition": self.condition,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
        }


def _iter_python_files(root: Path, includes: Sequence[str]) -> Iterator[Path]:
    include_roots = [root / value for value in includes] if includes else [root]
    seen: set[Path] = set()
    for include_root in include_roots:
        if include_root.is_file() and include_root.suffix == ".py":
            candidates: Iterable[Path] = (include_root,)
        elif include_root.is_dir():
            candidates = include_root.rglob("*.py")
        else:
            continue
        for candidate in candidates:
            candidate = candidate.resolve()
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        value = func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def _looks_like_narrowing(assert_node: ast.Assert, source_line: str) -> bool:
    lowered = source_line.lower()
    if any(term in lowered for term in NARROWING_COMMENT_TERMS):
        return True
    test = assert_node.test
    if isinstance(test, ast.Call) and _call_name(test).endswith("isinstance"):
        return True
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        comparator = test.comparators[0]
        if isinstance(test.ops[0], (ast.Is, ast.IsNot)) and isinstance(
            comparator, ast.Constant
        ) and comparator.value is None:
            return True
    return False


def _assert_references_arguments(node: ast.Assert, function: ast.AST) -> bool:
    args: set[str] = set()
    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        all_args = (
            list(function.args.posonlyargs)
            + list(function.args.args)
            + list(function.args.kwonlyargs)
        )
        args.update(arg.arg for arg in all_args if arg.arg not in {"self", "cls"})
        if function.args.vararg is not None:
            args.add(function.args.vararg.arg)
        if function.args.kwarg is not None:
            args.add(function.args.kwarg.arg)
    names = {child.id for child in ast.walk(node.test) if isinstance(child, ast.Name)}
    return bool(args & names)


def _has_security_sink_after(node: ast.Assert, function: ast.AST) -> bool:
    for child in ast.walk(function):
        if not isinstance(child, ast.Call) or getattr(child, "lineno", 0) <= node.lineno:
            continue
        call_name = _call_name(child).lower()
        if any(term in call_name for term in SECURITY_SINK_TERMS):
            return True
    return False


def _enclosing_functions(tree: ast.AST) -> Mapping[ast.Assert, ast.AST]:
    result: dict[ast.Assert, ast.AST] = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[ast.AST] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            self.stack.append(node)
            self.generic_visit(node)
            self.stack.pop()

        def visit_AsyncFunctionDef(  # noqa: N802
            self, node: ast.AsyncFunctionDef
        ) -> None:
            self.stack.append(node)
            self.generic_visit(node)
            self.stack.pop()

        def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802
            result[node] = self.stack[-1] if self.stack else tree

    Visitor().visit(tree)
    return result


def analyze_file(path: Path, root: Path) -> list[AssertFinding]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    lines = source.splitlines()
    owners = _enclosing_functions(tree)
    relative = path.relative_to(root).as_posix()
    path_terms = set(relative.lower().replace(".py", "").replace("_", "/").split("/"))
    sensitive_path = bool(path_terms & SENSITIVE_PATH_TERMS)
    findings: list[AssertFinding] = []

    for node, owner in owners.items():
        source_line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
        narrowing = _looks_like_narrowing(node, source_line)
        references_arguments = _assert_references_arguments(node, owner)
        sink_after = _has_security_sink_after(node, owner)
        reasons: list[str] = []
        if sensitive_path:
            reasons.append("security-sensitive source path")
        if references_arguments:
            reasons.append("condition references a function argument")
        if sink_after:
            reasons.append("security-relevant call follows in the same function")
        if narrowing:
            reasons.append("appears to narrow a previously validated value")

        if sensitive_path and references_arguments and sink_after and not narrowing:
            confidence = "high"
        elif sensitive_path and (references_arguments or sink_after) and not narrowing:
            confidence = "medium"
        else:
            confidence = "low"

        findings.append(
            AssertFinding(
                path=relative,
                line=node.lineno,
                function=getattr(owner, "name", "<module>"),
                condition=ast.unparse(node.test),
                confidence=confidence,
                reasons=tuple(reasons),
            )
        )

    return findings


def analyze_tree(root: Path, includes: Sequence[str]) -> dict[str, object]:
    root = root.resolve()
    findings: list[AssertFinding] = []
    parse_errors: list[dict[str, object]] = []
    files_analyzed = 0
    for path in _iter_python_files(root, includes):
        files_analyzed += 1
        try:
            findings.extend(analyze_file(path, root))
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            parse_errors.append({"path": str(path), "error": str(exc)})

    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (rank[item.confidence], item.path, item.line))
    counts = {
        confidence: sum(item.confidence == confidence for item in findings)
        for confidence in ("high", "medium", "low")
    }
    return {
        # A scan that could not parse/read every selected source is not a
        # clean pass: the missing assertions are unknown.  Keep REVIEW for
        # actionable findings and reserve INCONCLUSIVE for incomplete input.
        "verdict": (
            "INCONCLUSIVE"
            if parse_errors
            else ("REVIEW" if counts["high"] or counts["medium"] else "PASS")
        ),
        "files_analyzed": files_analyzed,
        "assertions_analyzed": len(findings),
        "counts": counts,
        "findings": [item.as_dict() for item in findings],
        "parse_errors": parse_errors,
        "limitation": (
            "Candidates are not confirmed vulnerabilities; validate reachability, "
            "attacker control, and security impact in an optimized production build."
        ),
    }


def _human_report(report: Mapping[str, object], max_findings: int) -> str:
    counts = report["counts"]
    assert isinstance(counts, dict)
    lines = [
        "Production assertion analysis",
        "Verdict: {} ({} files, {} assertions; {} high, {} medium, {} low)".format(
            report["verdict"],
            report["files_analyzed"],
            report["assertions_analyzed"],
            counts["high"],
            counts["medium"],
            counts["low"],
        ),
    ]
    if report.get("parse_errors"):
        lines.append(
            "- {} source parse/read error(s); scan is incomplete".format(
                len(report["parse_errors"])
            )
        )
    findings = report["findings"]
    assert isinstance(findings, list)
    review_findings = [
        item for item in findings if item["confidence"] in {"high", "medium"}
    ][:max_findings]
    for item in review_findings:
        lines.append(
            "- {} {}:{} {}: {}".format(
                str(item["confidence"]).upper(),
                item["path"],
                item["line"],
                item["function"],
                item["condition"],
            )
        )
    if len(review_findings) < counts["high"] + counts["medium"]:
        lines.append("- additional review findings omitted; use --json for all results")
    lines.append(str(report["limitation"]))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find assertions removed from optimized Python firmware builds"
    )
    parser.add_argument("--source-root", required=True, help="source tree root")
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="relative file or directory to scan; repeatable",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--max-findings", type=int, default=30)
    args = parser.parse_args(argv)

    root = Path(args.source_root)
    if not root.is_dir():
        print("ERROR: source root is not a directory: {}".format(root), file=sys.stderr)
        return 2
    report = analyze_tree(root, args.include)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_human_report(report, max(0, args.max_findings)))
    return 2 if report["verdict"] == "INCONCLUSIVE" else (1 if report["verdict"] == "REVIEW" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
