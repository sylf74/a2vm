# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Read model of one run, built in memory from its triage document (LLD triage-prioritization §15).

Answers are short and paged, for people and for the tools of the conversational search (HLD §8):
a list carries a few fields per decision, one decision carries everything the run knows about it.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from typing import Any

LEVELS = ("ACT", "ATTEND", "TRACK")
EXPOSURES = ("open", "controlled", "small")
TITLE_MAX = 140
LIMIT_DEFAULT = 25
LIMIT_MAX = 200
SORTS = ("level", "epss", "cvss", "due_date", "cve", "asset")


class QueryError(ValueError):
    """A filter, a sort or a page the read model does not understand."""


def _short(text: str, limit: int = TITLE_MAX) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def row_id(row: dict[str, Any]) -> str:
    return row.get("finding_id") or f"{row['cve_id']}@{row.get('asset_id_full') or row['asset_id']}"


def due_date(row: dict[str, Any]) -> str | None:
    """First observation + the BOD 26-04 delay, as in the reporting dataset."""
    m = re.match(r"(\d+) days", row.get("bod_timeline") or "")
    first = (row.get("first_seen") or "")[:10]
    if not m or not first:
        return None
    try:
        return (dt.date.fromisoformat(first) + dt.timedelta(days=int(m.group(1)))).isoformat()
    except ValueError:
        return None


def _cvss(row: dict[str, Any]) -> float | None:
    c = row.get("cvss") or {}
    return c.get("score") if isinstance(c, dict) else None


def _asset(row: dict[str, Any]) -> str:
    return row.get("asset_id_full") or row["asset_id"]


def asset_names(row: dict[str, Any]) -> set[str]:
    """The ways people and models name an asset: its id (`host:web01.example.org`), the id without its
    kind (`web01.example.org`) and its short name (`web01`), any case."""
    full = _asset(row).lower()
    names = {full, row["asset_id"].lower()}
    if ":" in full:
        names.add(full.split(":", 1)[1])
    return names


def compact(row: dict[str, Any]) -> dict[str, Any]:
    match = row.get("match") or {}
    return {
        "id": row_id(row),
        "cve": row["cve_id"],
        "asset": _asset(row),
        "asset_name": row["asset_id"],
        "level": row["delivery_decision"],
        "ssvc": row["ssvc_decision"],
        "exposure": row.get("exposure", ""),
        "zone": row.get("zone", ""),
        "kev": bool(row.get("in_kev")),
        "epss": row.get("epss"),
        "cvss": _cvss(row),
        "due_date": due_date(row),
        "needs_review": bool(row.get("needs_review")),
        "product": " ".join(p for p in (match.get("vendor", ""), match.get("product", "")) if p),
        "title": _short(row.get("description", "")),
    }


def _bool(value: str, name: str) -> bool:
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    raise QueryError(f"{name}: true or false")


def _float(value: str, name: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise QueryError(f"{name}: a number") from exc


def page(query: dict[str, str]) -> tuple[int, int]:
    try:
        limit = int(query.get("limit", LIMIT_DEFAULT))
        offset = int(query.get("offset", 0))
    except ValueError as exc:
        raise QueryError("limit and offset: integers") from exc
    if not 1 <= limit <= LIMIT_MAX or offset < 0:
        raise QueryError(f"limit: 1 to {LIMIT_MAX}; offset: 0 or more")
    return limit, offset


def _paged(items: list[Any], limit: int, offset: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": items[offset : offset + limit],
    }
    if offset + limit < len(items):
        out["next_offset"] = offset + limit
    return out


def _sort_key(sort: str):  # noqa: ANN202
    level = {lv: i for i, lv in enumerate(LEVELS)}
    if sort == "level":
        return lambda r: (level[r["delivery_decision"]], not r.get("in_kev"), -(r.get("epss") or 0), r["cve_id"])
    if sort == "epss":
        return lambda r: (-(r.get("epss") or 0), r["cve_id"])
    if sort == "cvss":
        return lambda r: (-(_cvss(r) or 0), r["cve_id"])
    if sort == "due_date":
        return lambda r: (due_date(r) or "9999", level[r["delivery_decision"]], r["cve_id"])
    if sort == "cve":
        return lambda r: (r["cve_id"], _asset(r))
    return lambda r: (_asset(r), level[r["delivery_decision"]], r["cve_id"])


class RunIndex:
    def __init__(self, receipt: dict[str, Any], document: dict[str, Any]):
        self.receipt = receipt
        self.document = document
        self.rows: list[dict[str, Any]] = document["rows"]
        self.by_id = {row_id(r): r for r in self.rows}
        self.by_cve: dict[str, list[dict[str, Any]]] = {}
        self.by_asset: dict[str, list[dict[str, Any]]] = {}
        for r in self.rows:
            self.by_cve.setdefault(r["cve_id"], []).append(r)
            self.by_asset.setdefault(_asset(r), []).append(r)

    @property
    def run(self) -> dict[str, Any]:
        return {"id": self.receipt["id"], "generated_at": self.receipt["generated_at"]}

    def summary(self) -> dict[str, Any]:
        counts = Counter(r["delivery_decision"] for r in self.rows)
        act = [r for r in self.rows if r["delivery_decision"] == "ACT"]
        top_assets = Counter(_asset(r) for r in act).most_common(10)
        top_cves = Counter(r["cve_id"] for r in act).most_common(10)
        return {
            "run": self.run,
            "tenant": self.document["client"],
            "llm_model": self.document.get("llm_model"),
            "cve_count": self.document["cve_count"],
            "findings": {lv: counts.get(lv, 0) for lv in LEVELS},
            "assets": len(self.by_asset),
            "kev": {lv: sum(1 for r in self.rows if r["delivery_decision"] == lv and r.get("in_kev")) for lv in LEVELS},
            "by_exposure": {
                e: {
                    lv: sum(1 for r in self.rows if r.get("exposure") == e and r["delivery_decision"] == lv)
                    for lv in LEVELS
                }
                for e in EXPOSURES
            },
            "needs_review": sum(1 for r in self.rows if r.get("needs_review")),
            "top_act_assets": [{"asset": a, "act": n} for a, n in top_assets],
            "top_act_cves": [{"cve": c, "assets": n} for c, n in top_cves],
            "not_affected": len(self.document.get("not_affected") or []),
            "errors": len(self.document.get("errors") or []),
            "exposure_gaps": self.document.get("exposure_gaps") or [],
        }

    def decisions(self, query: dict[str, str]) -> dict[str, Any]:
        rows = self.rows
        if "level" in query:
            levels = {lv.strip().upper() for lv in query["level"].split(",") if lv.strip()}
            if not levels or not levels <= set(LEVELS):
                raise QueryError("level: ACT, ATTEND, TRACK, comma-separated")
            rows = [r for r in rows if r["delivery_decision"] in levels]
        if "cve" in query:
            rows = [r for r in rows if r["cve_id"] == query["cve"].upper()]
        if "asset" in query:
            a = query["asset"].strip().lower()
            rows = [r for r in rows if a in asset_names(r)]
        for name in ("exposure", "zone"):
            if name in query:
                rows = [r for r in rows if r.get(name, "") == query[name]]
        if "kev" in query:
            want = _bool(query["kev"], "kev")
            rows = [r for r in rows if bool(r.get("in_kev")) == want]
        if "needs_review" in query:
            want = _bool(query["needs_review"], "needs_review")
            rows = [r for r in rows if bool(r.get("needs_review")) == want]
        if "source" in query:
            rows = [r for r in rows if query["source"] in (r.get("seen_by") or {})]
        if "min_epss" in query:
            m = _float(query["min_epss"], "min_epss")
            rows = [r for r in rows if (r.get("epss") or 0) >= m]
        if "min_cvss" in query:
            m = _float(query["min_cvss"], "min_cvss")
            rows = [r for r in rows if (_cvss(r) or 0) >= m]
        if "product" in query:
            p = query["product"].lower()
            rows = [
                r
                for r in rows
                if p in " ".join((r.get("match") or {}).get(k, "") for k in ("vendor", "product")).lower()
            ]
        if "q" in query:
            q = query["q"].lower()
            rows = [
                r
                for r in rows
                if q in r["cve_id"].lower() or q in _asset(r).lower() or q in (r.get("description") or "").lower()
            ]
        sort = query.get("sort", "level")
        if sort not in SORTS:
            raise QueryError(f"sort: one of {', '.join(SORTS)}")
        limit, offset = page(query)
        ordered = sorted(rows, key=_sort_key(sort))
        out: dict[str, Any] = {
            "run": self.run,
            "total": len(ordered),
            "offset": offset,
            "limit": limit,
            "items": [compact(r) for r in ordered[offset : offset + limit]],
        }
        if offset + limit < len(ordered):
            out["next_offset"] = offset + limit
        return out

    def decision(self, rid: str) -> dict[str, Any] | None:
        row = self.by_id.get(rid)
        if row is None:
            return None
        return {"run": self.run, "id": rid, "due_date": due_date(row), **row}

    def cve(self, cve: str, query: dict[str, str]) -> dict[str, Any] | None:
        rows = self.by_cve.get(cve.upper())
        if not rows:
            return None
        first = rows[0]
        fixes = sorted({f for r in rows for f in r.get("fixes") or []})
        limit, offset = page(query)
        ordered = sorted(rows, key=_sort_key("level"))
        return {
            "run": self.run,
            "cve": first["cve_id"],
            "description": first.get("description", ""),
            "cvss": first.get("cvss"),
            "cwes": first.get("cwes") or [],
            "kev": bool(first.get("in_kev")),
            "epss": first.get("epss"),
            "epss_percentile": first.get("epss_percentile"),
            "exploitation": first.get("exploitation"),
            "automatable": first.get("automatable"),
            "technical_impact": first.get("technical_impact"),
            "fixes": fixes[:50],
            "levels": dict(Counter(r["delivery_decision"] for r in rows)),
            "assets": _paged([compact(r) for r in ordered], limit, offset),
        }

    def assets(self, query: dict[str, str]) -> dict[str, Any]:
        items = []
        for asset, rows in sorted(self.by_asset.items()):
            first = rows[0]
            counts = Counter(r["delivery_decision"] for r in rows)
            items.append(
                {
                    "asset": asset,
                    "name": first["asset_id"],
                    "owner": first.get("owner", ""),
                    "zone": first.get("zone", ""),
                    "exposure": first.get("exposure", ""),
                    "counts": {lv: counts.get(lv, 0) for lv in LEVELS},
                }
            )
        if "q" in query:
            q = query["q"].lower()
            items = [a for a in items if q in a["asset"].lower() or q in a["name"].lower()]
        for name in ("exposure", "zone"):
            if name in query:
                items = [a for a in items if a[name] == query[name]]
        items.sort(key=lambda a: (-a["counts"]["ACT"], -a["counts"]["ATTEND"], a["asset"]))
        limit, offset = page(query)
        return {"run": self.run, **_paged(items, limit, offset)}

    def asset(self, asset: str, query: dict[str, str]) -> dict[str, Any] | None:
        rows = self.by_asset.get(asset)
        if rows is None:
            name = asset.strip().lower()
            rows = next((rs for rs in self.by_asset.values() if name in asset_names(rs[0])), None)
        if not rows:
            return None
        first = rows[0]
        counts = Counter(r["delivery_decision"] for r in rows)
        limit, offset = page(query)
        ordered = sorted(rows, key=_sort_key("level"))
        return {
            "run": self.run,
            "asset": _asset(first),
            "name": first["asset_id"],
            "description": first.get("asset_description", ""),
            "owner": first.get("owner", ""),
            "zone": first.get("zone", ""),
            "exposure": first.get("exposure", ""),
            "exposure_source": first.get("exposure_source", ""),
            "counts": {lv: counts.get(lv, 0) for lv in LEVELS},
            "decisions": _paged([compact(r) for r in ordered], limit, offset),
        }
