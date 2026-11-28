# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""License policy and repository source notices used by export-repro."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


DEFAULT_LICENSE_DECISIONS: dict[str, str] = {
    "Apache-2.0": "allow",
    "BSD-2-Clause": "allow",
    "BSD-3-Clause": "allow",
    "ISC": "allow",
    "MIT": "allow",
    "PSF-2.0": "allow",
    "MPL-2.0": "prohibit",
    "LGPL-3.0-only": "prohibit",
    "GPL-3.0-only": "prohibit",
    "GPL-3.0-only WITH GCC-exception-3.1": "prohibit",
}

# Only the shipped reference texts are exempt from source notice detection.
REFERENCE_NOTICE_DIGESTS = {
    "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
    "73879138376be7ab8ccdb4eb116f11d215ff70210ca2ab5183b2b6a7276e52a5",
}
GPL_SPDX_HEADER_RE = re.compile(
    r"^\s*(?:#|//+|/\*+|\*+|;+|--+|\.\.|<!--|REM\b)?\s*"
    r"SPDX-License-Identifier\s*:\s*([^\r\n]+)",
    re.IGNORECASE | re.MULTILINE,
)
GPL_SPDX_TOKEN_RE = re.compile(
    r"\b(?:A|L)?GPL(?:-[0-9.]+(?:-(?:only|or-later)|\+)?)?\b",
    re.IGNORECASE,
)
GPL_GRANT_NOTICE_RE = re.compile(
    r"redistribute(?:\s|\*)+it(?:\s|\*)+and/or(?:\s|\*)+modify(?:\s|\*)+it"
    r"(?:\s|\*)+under(?:\s|\*)+the(?:\s|\*)+terms(?:\s|\*)+of(?:\s|\*)+the"
    r"(?:\s|\*)+GNU(?:\s|\*)+(?:(?:Affero|Lesser|Library)(?:\s|\*)+)?"
    r"General(?:\s|\*)+Public(?:\s|\*)+License",
    re.IGNORECASE,
)
GPL_LICENSE_TITLE_RE = re.compile(
    r"^\s*GNU\s+(?:(?:AFFERO|LESSER|LIBRARY)\s+)?GENERAL\s+PUBLIC\s+LICENSE\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def load_license_policy(repo_root: Path) -> dict[str, str]:
    decisions = dict(DEFAULT_LICENSE_DECISIONS)
    policy_path = repo_root / "scripts" / "export_repro_license_policy.json"
    if policy_path.is_file():
        try:
            data = json.loads(policy_path.read_text(encoding="utf-8"))
            for spdx, rule in (data.get("licenses") or {}).items():
                if isinstance(rule, dict) and isinstance(rule.get("decision"), str):
                    decisions[str(spdx)] = str(rule["decision"]).strip().lower()
        except Exception:
            pass
    return decisions


def detect_gpl_license_marker(root: Path, relative: Path) -> str | None:
    """Return a GPL-family marker in a repository file, if present."""
    try:
        data = (root / relative).read_bytes()
    except OSError as exc:
        raise ValueError(f"Could not inspect tracked file {relative}") from exc
    if relative.parent == Path("LICENSES") and hashlib.sha256(data).hexdigest() in REFERENCE_NOTICE_DIGESTS:
        return None
    text = data.decode("utf-8", errors="ignore")
    for match in GPL_SPDX_HEADER_RE.finditer(text):
        raw_expr = match.group(1).strip()
        spdx_expr = re.sub(r"\s*(?:\*/+|-->)\s*$", "", raw_expr).strip()
        if not GPL_SPDX_TOKEN_RE.search(spdx_expr):
            continue
        return f"SPDX-License-Identifier: {spdx_expr}"
    if GPL_GRANT_NOTICE_RE.search(text):
        return "GNU General Public License grant notice"
    if GPL_LICENSE_TITLE_RE.search(text):
        return "GNU General Public License text"
    return None
