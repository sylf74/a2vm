# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Journal of the alerts: one JSON line per event, kept between runs.

GitLab keeps no history of the alerts: each watch is a job of its own whose artifacts expire. The
watch and the send job append their events to `.watch/alerts-log.jsonl` (the watch-state cache)
and publish a copy in their artifacts, so that the latest job shows every alert drafted, mailed to
the analysts and sent to the client, without opening each job.

Events: `drafted` (the watch drafted an alert), `analysts` (mail to the analysts: sent or failed),
`sent` / `send-failed` (mail to the client, by the send job). The history database replaces this
file later; until then it keeps the last MAX_LINES events.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

MAX_LINES = 5000


def event(kind: str, alert: dict, **extra) -> dict:
    """One journal entry for `alert` (an entry of the watch's index.json)."""
    entry = {
        "at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "event": kind,
        "alert": alert["id"],
        "level": alert.get("level", ""),
        "title": alert.get("title", ""),
        "pipeline": os.environ.get("CI_PIPELINE_URL", ""),
    }
    entry.update({k: v for k, v in extra.items() if v not in (None, "", [])})
    return entry


def append(path: str | Path, entries: list[dict]) -> None:
    """Add `entries` at the end of the journal, keeping the last MAX_LINES lines."""
    path = Path(path)
    if not entries:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    lines += [json.dumps(e, ensure_ascii=False) for e in entries]
    path.write_text("\n".join(lines[-MAX_LINES:]) + "\n", encoding="utf-8")


def read(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a truncated line never stops the watch
    return out


def publish(path: str | Path, out_dir: str | Path) -> None:
    """Copy the journal next to the job's other outputs (artifacts)."""
    path = Path(path)
    if path.exists():
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
