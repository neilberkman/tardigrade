#!/usr/bin/env python3
"""Compare heuristic vs exhaustive sweep results to measure recall.

Importable as a module or run as CLI:
    python3 scripts/compare_heuristic_vs_exhaustive.py exhaustive.json heuristic.json
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any, Dict, List, Set


# Outcomes that count as "no issue" (device recovered correctly).
SUCCESS_OUTCOMES: Set[str] = {"success", "complete_image_ok", "safe_fallback"}


def compare_results(
    exhaustive_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare two sweep result lists and compute recall metrics.

    Args:
        exhaustive_results: Full-sweep results, each with at least
            ``fault_point`` (int) and ``outcome`` (str).
        heuristic_results: Heuristic-sweep results, same schema.

    Returns:
        Dict with recall metrics, missed points, and per-fault-type breakdown.
    """
    heuristic_fps: Set[int] = {r["fault_point"] for r in heuristic_results}

    # Identify issue points in exhaustive.
    exhaustive_issue_fps: Dict[int, Dict[str, Any]] = {}
    for r in exhaustive_results:
        if r["outcome"] not in SUCCESS_OUTCOMES:
            exhaustive_issue_fps[r["fault_point"]] = r

    # Identify issue points in heuristic.
    heuristic_issue_count = sum(
        1 for r in heuristic_results if r["outcome"] not in SUCCESS_OUTCOMES
    )

    # Recall: fraction of exhaustive issue fault points that appear in
    # the heuristic fault point set (regardless of outcome).
    missed_fps: List[int] = sorted(
        fp for fp in exhaustive_issue_fps if fp not in heuristic_fps
    )
    covered = len(exhaustive_issue_fps) - len(missed_fps)
    issue_recall = (
        covered / len(exhaustive_issue_fps) if exhaustive_issue_fps else 1.0
    )

    missed_outcomes: Set[str] = {
        exhaustive_issue_fps[fp]["outcome"] for fp in missed_fps
    }

    # Per-fault_type recall (if fault_type present in results).
    recall_by_fault_type: Dict[str, float] = {}
    exhaustive_has_fault_type = any(
        "fault_type" in r for r in exhaustive_results
    )
    if exhaustive_has_fault_type:
        by_type: Dict[str, List[int]] = defaultdict(list)
        for fp, r in exhaustive_issue_fps.items():
            ft = r.get("fault_type", "unknown")
            by_type[ft].append(fp)
        for ft, fps in sorted(by_type.items()):
            type_covered = sum(1 for fp in fps if fp in heuristic_fps)
            recall_by_fault_type[ft] = (
                type_covered / len(fps) if fps else 1.0
            )

    result: Dict[str, Any] = {
        "total_exhaustive_points": len(exhaustive_results),
        "total_heuristic_points": len(heuristic_results),
        "exhaustive_issue_count": len(exhaustive_issue_fps),
        "heuristic_issue_count": heuristic_issue_count,
        "issue_recall": round(issue_recall, 4),
        "missed_issue_points": missed_fps,
        "missed_issue_classifications": sorted(missed_outcomes),
    }
    if recall_by_fault_type:
        result["recall_by_fault_type"] = recall_by_fault_type

    return result


def main() -> None:
    if len(sys.argv) != 3:
        print(
            "Usage: compare_heuristic_vs_exhaustive.py exhaustive.json heuristic.json",
            file=sys.stderr,
        )
        sys.exit(1)

    exhaustive_path, heuristic_path = sys.argv[1], sys.argv[2]

    with open(exhaustive_path, "r") as f:
        exhaustive_data = json.load(f)
    with open(heuristic_path, "r") as f:
        heuristic_data = json.load(f)

    exhaustive_results = exhaustive_data.get("results", exhaustive_data)
    heuristic_results = heuristic_data.get("results", heuristic_data)

    if isinstance(exhaustive_results, dict):
        exhaustive_results = exhaustive_results.get("results", [])
    if isinstance(heuristic_results, dict):
        heuristic_results = heuristic_results.get("results", [])

    comparison = compare_results(exhaustive_results, heuristic_results)
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
