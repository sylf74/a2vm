# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Exposure gaps of a client (`exposure_gaps.json` next to assets.json), read back by verdict run."""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA = "a2vm.exposure_gaps/1"


def write_gaps(path: str | Path, client_id: str, gaps: list[dict[str, str]]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"schema": SCHEMA, "client_id": client_id, "gaps": gaps}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def read_gaps(path: str | Path, client_id: str) -> list[dict[str, str]]:
    """The gaps of `client_id`; none when the file is absent (assets built before v0.11.4)."""
    path = Path(path)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or data.get("client_id") != client_id:
        raise ValueError(f"{path}: not the exposure gaps of {client_id!r}")
    return list(data.get("gaps", []))
