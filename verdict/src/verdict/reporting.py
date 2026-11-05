# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The reporting dataset of a run (`a2vm.reporting/1`): the contract with the client portal.

The portal (Grafana) reads this file and nothing else, so that renaming a job or changing an
internal file never breaks it. Everything here is computed from the decisions of the run; the
portal recomputes no metric. One tenant per file; no licensed prose, no prompt, no secret.
Within `/1` fields are only added (LLD triage-prioritization §12); v0.11.6 added to each decision
the CVSS score and rating, the fix availability, the product and its kind, and the sources.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from collections import Counter
from typing import Any

import a2vm
from a2vm import sla
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
    return sla.bod_due(row.bod_timeline, row.first_seen)


def _sla(row: TriageRow, today: dt.date) -> dict[str, Any]:
    """The priority of the decision in the client's SLA (v0.21.0); empty values without one."""
    s = row.sla or {}
    if not s.get("priority"):
        return {"priority": "", "priority_rank": None, "sla_rule": None, "sla_since": None, "sla_due": None,
                "sla_since_source": "", "sla_status": None}  # fmt: skip
    return {
        "priority": s["priority"],
        "priority_rank": s.get("rank", 0),
        "sla_rule": s.get("rule"),
        "sla_since": s.get("since"),
        "sla_due": s["due"],
        "sla_since_source": s.get("since_source", ""),
        "sla_status": sla.status(s["due"], today),
    }


def _sla_summary(policy: dict[str, Any]) -> dict[str, Any]:
    keys = ("timezone", "calendar", "holidays", "priorities", "today", "history")
    return {k: policy[k] for k in keys if k in policy}


SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")


def severity(row: TriageRow) -> str:
    """CVSS qualitative rating of the metric the decision used (CNA first): Critical 9.0+, High 7.0+,
    Medium 4.0+, Low below (None counted as Low); Unknown without a score."""
    m = row.cvss
    if m is None or m.score is None:
        return "Unknown"
    s = m.score
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"


def _sources(row: TriageRow) -> list[str]:
    if row.seen_by:
        return sorted(row.seen_by)
    return sorted({s.strip() for s in (row.finding_source or "").split(",") if s.strip()}) or ["unknown"]


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
                "cvss_score": r.cvss.score if r.cvss else None,
                "cvss_version": r.cvss.version if r.cvss else "",
                "severity": severity(r),
                "fix_available": r.fix_available,
                "vendor": r.match.vendor,
                "product": r.match.product,
                "product_type": r.product_type or "unknown",
                "sources": _sources(r),
                "seen_by": dict(r.seen_by),
                **_sla(r, today),
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
    if run.sla:  # the client's SLA (v0.21.0): open decisions per priority, overdue, due within 7 days
        by: dict[str, dict[str, int]] = {}
        for d in decisions:
            if not d["priority"]:
                continue
            c = by.setdefault(d["priority"], {"rank": d["priority_rank"], "open": 0, "overdue": 0, "due_soon": 0})
            left = (dt.date.fromisoformat(d["sla_due"]) - today).days
            c["open"] += 1
            c["overdue"] += left < 0
            c["due_soon"] += 0 <= left <= SOON_DAYS
        deadlines["sla"] = {
            "overdue": sum(c["overdue"] for c in by.values()),
            "due_soon": sum(c["due_soon"] for c in by.values()),
            "unclassified": sum(1 for d in decisions if not d["priority"]),
            "by_priority": dict(sorted(by.items(), key=lambda kv: (kv[1]["rank"], kv[0]))),
        }

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
    # Every asset of the run, a finding or not, with its scans (v0.18.1): a fix is told from a scan
    # that did not run.
    listed = {a["id"]: a for a in assets}
    for entry in run.assets:
        a = listed.get(entry["id"])
        if a is None:
            a = listed[entry["id"]] = {
                "id": entry["id"],
                "name": entry["name"],
                "zone": entry.get("zone", ""),
                "exposure": entry.get("exposure", ""),
                "owner": entry.get("owner", ""),
                "counts": dict.fromkeys(LEVELS, 0),
            }
        a.update(kind=entry.get("kind", ""), scans=entry.get("scans") or {}, last_seen=entry.get("last_seen", ""))
        item = (entry.get("cmdb") or [{}])[0]  # its configuration item (v0.19.0)
        if item:
            a.update(cmdb_class=item.get("class", ""), cmdb_status=item.get("status", ""))
            a.update(criticality=item.get("criticality", ""))
    for entry in (run.coverage or {}).get("assets", []):
        if entry["asset"] in listed:
            listed[entry["asset"]]["coverage"] = entry["state"]
    assets = [listed[k] for k in sorted(listed)]

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
            **({"sla": _sla_summary(run.sla)} if run.sla else {}),
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
        "exposure_gaps": [
            {k: g.get(k, "") for k in ("kind", "asset", "name", "declared", "detail")} for g in run.exposure_gaps
        ],
        "coverage": run.coverage or {},
    }
