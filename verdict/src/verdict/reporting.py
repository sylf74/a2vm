# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The reporting dataset of a run (`a2vm.reporting/1`): the contract with the client portal.

The portal (Grafana) reads this file and nothing else, so that renaming a job or changing an
internal file never breaks it. Everything here is computed from the decisions of the run; the
portal recomputes no metric. One tenant per file; no licensed prose, no prompt, no secret.
Within `/1` fields are only added (LLD triage-prioritization §12).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from collections import Counter
from typing import Any

import a2vm
from a2vm.models import TriageRow, TriageRun

LEVELS = ("ACT", "ATTEND", "TRACK")
EXPOSURES = ("open", "controlled", "small")
SOON_DAYS = 7
TITLE_MAX = 140
RATIONALE_MAX = 400


def policy_hash(policy: dict[str, Any]) -> str:
    """Short hash of the decision policy in force, until policies carry a version."""
    return hashlib.sha256(json.dumps(policy, sort_keys=True, default=str).encode()).hexdigest()[:12]


def due_date(row: TriageRow) -> str | None:
    """First observation + the BOD 26-04 delay ('3 days', '14 days & …'); none for 'fix on system upgrade'."""
    m = re.match(r"(\d+) days", row.bod_timeline or "")
    if not m or not row.first_seen:
        return None
    start = dt.date.fromisoformat(row.first_seen[:10])
    return (start + dt.timedelta(days=int(m.group(1)))).isoformat()


def _counts(rows: list[TriageRow]) -> dict[str, int]:
    c = Counter(r.delivery_decision for r in rows)
    return {level: c.get(level, 0) for level in LEVELS}


def _short(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def build(run: TriageRun, policy: dict[str, Any] | None = None, today: dt.date | None = None) -> dict[str, Any]:
    """The dataset of `run`, as the schema `a2vm.reporting/1` describes it."""
    today = today or dt.date.fromisoformat(run.generated_at[:10])
    rows = sorted(run.rows, key=lambda r: (LEVELS.index(r.delivery_decision), r.cve_id, r.asset_id_full))
    sources: dict[str, dict[str, Any]] = {}
    for r in rows:
        for source, seen in r.seen_by.items():
            s = sources.setdefault(source, {"name": source, "findings": 0, "last_observation": ""})
            s["findings"] += 1
            s["last_observation"] = max(s["last_observation"], seen)

    decisions = []
    for r in rows:
        due = due_date(r)
        decisions.append(
            {
                "finding_id": r.finding_id,
                "asset": r.asset_id_full or r.asset_id,
                "asset_name": r.asset_id,
                "zone": r.zone,
                "exposure": r.exposure,
                "exposure_source": r.exposure_source,
                "cve": r.cve_id,
                "title": _short(r.description, TITLE_MAX),
                "level": r.delivery_decision,
                "ssvc": r.ssvc_decision,
                "bod_timeline": r.bod_timeline,
                "first_seen": r.first_seen[:10] or None,
                "due_date": due,
                "kev": r.in_kev,
                "epss": r.epss,
                "needs_review": r.needs_review,
                "rationale": _short(r.rationale, RATIONALE_MAX),
            }
        )

    deadlines = {"overdue": 0, "due_soon": 0, "by_timeline": {}}
    for d in decisions:
        if d["level"] not in ("ACT", "ATTEND"):
            continue
        deadlines["by_timeline"][d["bod_timeline"]] = deadlines["by_timeline"].get(d["bod_timeline"], 0) + 1
        if d["due_date"]:
            left = (dt.date.fromisoformat(d["due_date"]) - today).days
            deadlines["overdue"] += left < 0
            deadlines["due_soon"] += 0 <= left <= SOON_DAYS
    deadlines["by_timeline"] = dict(sorted(deadlines["by_timeline"].items()))

    by_asset: dict[str, list[TriageRow]] = {}
    for r in rows:
        by_asset.setdefault(r.asset_id_full or r.asset_id, []).append(r)
    assets = [
        {
            "id": asset_id,
            "name": rs[0].asset_id,
            "zone": rs[0].zone,
            "exposure": rs[0].exposure,
            "owner": rs[0].owner,
            "counts": _counts(rs),
        }
        for asset_id, rs in sorted(by_asset.items())
    ]

    zones = sorted({r.zone for r in rows if r.zone})
    return {
        "generated_at": run.generated_at,
        "run": {
            "tenant": {"id": run.client.id, "name": run.client.name},
            "a2vm_version": a2vm.__version__,
            "policy_hash": policy_hash(policy or {}),
            "pipeline": {
                "id": os.environ.get("CI_PIPELINE_ID", ""),
                "url": os.environ.get("CI_PIPELINE_URL", ""),
            },
            "sources": sorted(sources.values(), key=lambda s: s["name"]),
            "cve_count": run.cve_count,
        },
        "totals": {
            "findings": _counts(rows),
            "assets": {level: sum(a["counts"][level] > 0 for a in assets) for level in LEVELS},
            "needs_review": sum(r.needs_review for r in rows),
            "assumed_inputs": sum(bool(r.assumptions) for r in rows),
            "not_affected": len(run.not_affected),
            "errors": len(run.errors),
        },
        "by_exposure": {e: _counts([r for r in rows if r.exposure == e]) for e in EXPOSURES},
        "by_zone": {z: _counts([r for r in rows if r.zone == z]) for z in zones},
        "deadlines": deadlines,
        "decisions": decisions,
        "assets": assets,
    }
