#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic harness that rejects expired metadata before a decision."""

from __future__ import annotations

import json
import sys
from pathlib import Path


scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
state = scenario["state"]
installed = state["installed"]
metadata = state["metadata"]
expired = state["now"] >= metadata["expires_at"]
accepted = not expired
print(json.dumps({
    "accepted": accepted,
    "committed": accepted,
    "rollback_outcome": "none" if accepted else "rejected-expired",
    "version": installed["version"] if accepted else None,
    "target": installed["target"] if accepted else None,
    "size": 1 if accepted else None,
    "installed_payload_digest": installed["payload_digest"],
    "metadata": {
        **metadata,
        "now": state["now"],
        "expired": expired,
        "refresh_failed": state["refresh_failed"],
    },
    "metadata_used": False,
    "security_state": {
        "installed_version": installed["version"],
        "selected_version": installed["version"] if accepted else None,
    },
}, sort_keys=True))
