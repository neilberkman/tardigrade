# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from export_repro_licenses import detect_gpl_license_marker  # noqa: E402


@pytest.mark.parametrize(
    ("source", "marker"),
    [
        (
            "/* " + "SPDX-License-Identifier" + ": GPL-3.0-only */\nint x = 0;\n",
            "SPDX-License-Identifier: GPL-3.0-only",
        ),
        (
            "/* Free software: you can redistribute it and/or\n"
            " * modify it under the terms of the GNU General Public License\n"
            " */\n",
            "GNU General Public License grant notice",
        ),
    ],
    ids=["spdx-header", "grant-notice"],
)
def test_detects_gpl_in_repository_source(tmp_path, source, marker):
    relative = Path("helper.c")
    (tmp_path / relative).write_text(source, encoding="utf-8")
    assert detect_gpl_license_marker(tmp_path, relative) == marker


def test_exempts_only_unchanged_gpl_reference_notice(tmp_path):
    relative = Path("LICENSES/reference.txt")
    reference = tmp_path / relative
    reference.parent.mkdir()
    reference.write_bytes((ROOT / "LICENSES/GPL-3.0-only.txt").read_bytes())
    assert detect_gpl_license_marker(tmp_path, relative) is None

    with reference.open("ab") as handle:
        handle.write(b"int added_source;\n")
    assert detect_gpl_license_marker(tmp_path, relative) is not None
