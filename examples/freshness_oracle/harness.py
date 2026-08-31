#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic harness that incorrectly consumes expired metadata."""

from __future__ import annotations

import json
import sys
from pathlib import Path


scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
state = scenario["state"]
installed = state["installed"]
metadata = state["metadata"]
expired = state["now"] >= metadata["expires_at"]
# This is the intentional defect in the synthetic fixture: the old metadata
# remains an input to the decision after its expiry.
metadata_used = expired
accepted = True
print(json.dumps({
    "accepted": accepted,
    "committed": accepted,
    "rollback_outcome": "rollback-accepted" if metadata["version"] < installed["version"] else "none",
    "version": metadata["version"],
    "target": metadata["target"],
    "size": 1,
    "installed_payload_digest": metadata["payload_digest"],
    "metadata": {
        **metadata,
        "now": state["now"],
        "expired": expired,
        "refresh_failed": state["refresh_failed"],
    },
    "metadata_used": metadata_used,
    "security_state": {
        "installed_version": installed["version"],
        "selected_version": metadata["version"],
    },
}, sort_keys=True))
