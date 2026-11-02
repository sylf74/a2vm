# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Scan coverage of a client (v0.19.0, LLD triage §14.6): what the CMDB says exists, what was
scanned, by which means and when. Written to `coverage.json` next to assets.json and carried by the
run into `triage.json` (`coverage`), the decision service and the reporting database.

State of each host asset, the first that applies:

  not-in-cmdb        scanned, and no configuration item of the CMDB is this asset (the run has one)
  retired-but-alive  its item is obsolete or in stock, and a scan still sees it
  not-expected       its item is obsolete, in stock or being implemented: no scan expected
  not-scannable      in production, with no address nor host name, and never scanned
  never-scanned      in production, never seen by a scan
  stale              in production, its last scan older than `stale_days`
  partial            in production, scanned lately, but a means of detection its class expects is missing
  covered            in production, every expected means saw it within `stale_days`

Without a CMDB in the run, every host is judged as an item in production of class `default`; the
state `not-in-cmdb` then never appears. Declared assets (product families) and images are left out.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from a2vm.models import Asset, CoveragePolicy

SCHEMA = "a2vm.coverage/1"
STATES = (
    "not-in-cmdb",
    "retired-but-alive",
    "not-expected",
    "not-scannable",
    "never-scanned",
    "stale",
    "partial",
    "covered",
)
GAPS = ("not-in-cmdb", "retired-but-alive", "not-scannable", "never-scanned", "stale", "partial")
IN_PRODUCTION = ("not-scannable", "never-scanned", "stale", "partial", "covered")
RETIRED = ("obsolete", "stock")
NOT_EXPECTED = (*RETIRED, "implementation")


def _when(value: str) -> datetime | None:
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def asset_coverage(asset: Asset, policy: CoveragePolicy, at: datetime, with_cmdb: bool) -> dict[str, Any]:
    items = asset.identifiers.get("cmdb") or []
    item = items[0] if items else {}
    cmdb_class = item.get("class") or None
    status = item.get("status") or ("production" if not with_cmdb else "")
    scans = dict(sorted((asset.scans or {}).items()))
    dates = [d for d in (_when(v) for v in scans.values()) if d]
    last = max(dates) if dates else None
    horizon = at - timedelta(days=policy.stale_days)
    recent = {source for source, value in scans.items() if (_when(value) or at) >= horizon}
    expected = policy.expected_for(cmdb_class)
    missing = [group for group in expected if not recent.intersection(group)]
    identified = any(asset.identifiers.get(k) for k in ("fqdns", "hostnames", "ips"))
    if with_cmdb and not items:
        state = "not-in-cmdb"
    elif status in RETIRED and last and last >= horizon:
        state = "retired-but-alive"
    elif status in NOT_EXPECTED:
        state = "not-expected"
    elif not scans and not identified:
        state = "not-scannable"
    elif not scans:
        state = "never-scanned"
    elif last < horizon:
        state = "stale"
    elif missing:
        state = "partial"
    else:
        state = "covered"
    return {
        "asset": asset.id,
        "name": asset.name,
        "state": state,
        "cmdb_class": cmdb_class or "",
        "cmdb_key": item.get("key", ""),
        "cmdb_status": item.get("status", ""),
        "criticality": item.get("criticality", ""),
        "cmdb_type": item.get("type", ""),
        "cmdb_items": len(items),
        "expected": ["|".join(group) for group in expected],
        "missing": ["|".join(group) for group in missing] if state in ("partial", "stale", "never-scanned") else [],
        "scans": scans,
        "last_scan": last.isoformat() if last else "",
        "owner": asset.attr("owner").value if "owner" in asset.attributes else "",
    }


def build_coverage(
    client_id: str, assets: list[Asset], policy: CoveragePolicy, at: datetime | None = None
) -> dict[str, Any]:
    """The coverage of every host asset of a client, at `at` (the run's time by default)."""
    at = at or datetime.now(UTC)
    hosts = [a for a in assets if a.kind == "host"]
    with_cmdb = any(a.identifiers.get("cmdb") for a in hosts)
    entries = sorted(
        (asset_coverage(a, policy, at, with_cmdb) for a in hosts),
        key=lambda e: (STATES.index(e["state"]), e["name"]),
    )
    counts = Counter(e["state"] for e in entries)
    # The share is over the items in production: those the CMDB expects to be scanned.
    expected = [e for e in entries if e["state"] in IN_PRODUCTION]
    covered = counts["covered"]
    return {
        "generated_at": at.replace(microsecond=0).isoformat(),
        "cmdb": with_cmdb,
        "stale_days": policy.stale_days,
        "counts": {state: counts.get(state, 0) for state in STATES},
        "expected_assets": len(expected),
        "covered_share": round(covered / len(expected), 4) if expected else None,
        "means": sorted({source for e in entries for source in e["scans"]}),
        "assets": entries,
    }


def write_coverage(path: str | Path, client_id: str, coverage: dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"schema": SCHEMA, "client_id": client_id, **coverage}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def read_coverage(path: str | Path, client_id: str) -> dict[str, Any]:
    """The coverage of `client_id`; empty when the file is absent (assets built before v0.19.0)."""
    path = Path(path)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or data.get("client_id") != client_id:
        raise ValueError(f"{path}: not the coverage of {client_id!r}")
    return {k: v for k, v in data.items() if k not in ("schema", "client_id")}
