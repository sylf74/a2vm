# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Read model of one run, built in memory from its triage document (LLD triage-prioritization §15).

Answers are short and paged, for people and for the tools of the conversational search (HLD §8):
a list carries a few fields per decision, one decision carries everything the run knows about it.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ngvm import sla

LEVELS = ("ACT", "ATTEND", "TRACK")
EXPOSURES = ("open", "controlled", "small")
TITLE_MAX = 140
LIMIT_DEFAULT = 25
LIMIT_MAX = 200
DECISIONS_MAX = 2000  # pages of GET decisions, for the services that read them all (v0.20.2, pillar 4)
SORTS = ("level", "epss", "cvss", "due_date", "cve", "asset", "priority", "sla_due")


class QueryError(ValueError):
    """A filter, a sort or a page the read model does not understand."""


# States of the scan coverage (verdict.assets.coverage, v0.19.0), and those that call for an action.
COVERAGE_STATES = (
    "not-in-cmdb",
    "retired-but-alive",
    "not-expected",
    "not-scannable",
    "never-scanned",
    "stale",
    "partial",
    "covered",
)
COVERAGE_GAPS = ("not-in-cmdb", "retired-but-alive", "not-scannable", "never-scanned", "stale", "partial")


def _short(text: str, limit: int = TITLE_MAX) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def row_id(row: dict[str, Any]) -> str:
    return row.get("finding_id") or f"{row['cve_id']}@{row.get('asset_id_full') or row['asset_id']}"


def due_date(row: dict[str, Any]) -> str | None:
    """First observation + the BOD 26-04 delay, as in the reporting dataset."""
    return sla.bod_due(row.get("bod_timeline") or "", row.get("first_seen") or "")


def priority(row: dict[str, Any]) -> dict[str, Any] | None:
    """The decision's priority in the client's SLA (v0.21.0), None in none or without an SLA."""
    s = row.get("sla") or {}
    return s if s.get("priority") and s.get("due") else None


def sla_due(row: dict[str, Any]) -> str | None:
    s = priority(row)
    return s["due"] if s else None


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
        "first_seen": (row.get("first_seen") or "")[:10] or None,
        "cve_updated": (row.get("cve_updated") or "")[:10] or None,
        "fixes": list(row.get("fixes") or []),  # the fixes the scanners reported (v0.20.0, pillar 4)
        # The client's SLA (v0.21.0): its priority, rank (0 the most urgent) and due date; due_date
        # stays the BOD 26-04 one.
        "priority": (priority(row) or {}).get("priority", ""),
        "priority_rank": (priority(row) or {}).get("rank"),
        "sla_due": sla_due(row),
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


def _day(value: str, name: str) -> str:
    try:
        return dt.date.fromisoformat(value[:10]).isoformat()
    except ValueError as exc:
        raise QueryError(f"{name}: a date, YYYY-MM-DD") from exc


def _level_rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


def page(query: dict[str, str], most: int = LIMIT_MAX) -> tuple[int, int]:
    try:
        limit = int(query.get("limit", LIMIT_DEFAULT))
        offset = int(query.get("offset", 0))
    except ValueError as exc:
        raise QueryError("limit and offset: integers") from exc
    if not 1 <= limit <= most or offset < 0:
        raise QueryError(f"limit: 1 to {most}; offset: 0 or more")
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
    if sort == "priority":  # no priority last, then the due date
        return lambda r: ((priority(r) or {}).get("rank", 9999), sla_due(r) or "9999", r["cve_id"], _asset(r))
    if sort == "sla_due":
        return lambda r: (sla_due(r) or "9999", (priority(r) or {}).get("rank", 9999), r["cve_id"], _asset(r))
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
        # Every asset of the run, a finding or not (v0.18.1; a triage of an earlier version lists
        # the assets of its findings only).
        self.inventory: dict[str, dict[str, Any]] = {a["id"]: a for a in document.get("assets") or []}
        # Scan coverage of each host asset (v0.19.0; empty for a triage of an earlier version).
        self.coverage_doc: dict[str, Any] = document.get("coverage") or {}
        self.coverage_by_asset = {c["asset"]: c for c in self.coverage_doc.get("assets") or []}

    def _card(self, asset: str) -> dict[str, Any]:
        """What the run knows of an asset: from its inventory entry, else from its first decision."""
        known = self.inventory.get(asset)
        rows = self.by_asset.get(asset, [])
        first = rows[0] if rows else {}
        counts = Counter(r["delivery_decision"] for r in rows)
        card = {
            "asset": asset,
            "name": (known or {}).get("name") or first.get("asset_id", asset),
            "owner": (known or {}).get("owner", first.get("owner", "")),
            "zone": (known or {}).get("zone", first.get("zone", "")),
            "exposure": (known or {}).get("exposure", first.get("exposure", "")),
            "counts": {lv: counts.get(lv, 0) for lv in LEVELS},
        }
        if known:
            if known.get("origins"):
                card["origins"] = known["origins"]  # where owner, exposure, zone come from (v0.23.13)
            if known.get("runs_on"):
                card["runs_on"] = known["runs_on"]  # an image: the host it runs on (v0.23.13)
            card["scans"] = known.get("scans") or {}
            card["last_seen"] = known.get("last_seen", "")
            if known.get("cmdb"):
                card["cmdb"] = known["cmdb"]  # its configuration items (v0.19.0)
        covered = self.coverage_by_asset.get(asset)
        if covered:
            card["coverage"] = covered["state"]
        return card

    def _find_asset(self, asset: str) -> str | None:
        if asset in self.by_asset or asset in self.inventory:
            return asset
        name = asset.strip().lower()
        for a, rows in self.by_asset.items():
            if name in asset_names(rows[0]):
                return a
        for a, entry in self.inventory.items():
            names = {a.lower(), a.split(":", 1)[-1].lower(), str(entry.get("name", "")).lower()}
            names.add(a.split(":", 1)[-1].split(".")[0].lower())
            if name in names:
                return a
        return None

    def today(self) -> str:
        """The day in the client's time zone (its SLA's, v0.21.0), else UTC."""
        tz = (self.document.get("sla") or {}).get("timezone")
        if tz:
            try:
                return dt.datetime.now(ZoneInfo(tz)).date().isoformat()
            except (ZoneInfoNotFoundError, ValueError):
                pass
        return dt.datetime.now(dt.UTC).date().isoformat()

    @property
    def run(self) -> dict[str, Any]:
        language = (self.document.get("client") or {}).get("language") or "en"
        return {"id": self.receipt["id"], "generated_at": self.receipt["generated_at"], "language": language}

    def summary(self) -> dict[str, Any]:
        counts = Counter(r["delivery_decision"] for r in self.rows)
        act = [r for r in self.rows if r["delivery_decision"] == "ACT"]
        top_assets = Counter(_asset(r) for r in act).most_common(10)
        top_cves = Counter(r["cve_id"] for r in act).most_common(10)
        return {
            "run": self.run,
            "tenant": self.document["client"],
            "llm_model": self.document.get("llm_model"),
            "ngvm_version": self.document.get("ngvm_version", "before v0.23.9"),
            **({"llm_usage": self.document["llm_usage"]} if self.document.get("llm_usage") else {}),
            **({"timing": self.document["timing"]} if self.document.get("timing") else {}),
            "cve_count": self.document["cve_count"],
            "findings": {lv: counts.get(lv, 0) for lv in LEVELS},
            "assets": len(set(self.by_asset) | set(self.inventory)),
            "assets_with_findings": len(self.by_asset),
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
            "coverage": {
                k: self.coverage_doc[k]
                for k in ("cmdb", "counts", "expected_assets", "covered_share", "stale_days")
                if k in self.coverage_doc
            },
            **({"sla": self.sla_summary()} if self.document.get("sla") else {}),
        }

    def sla_summary(self, today: str | None = None) -> dict[str, Any]:
        """The client's SLA (v0.21.0): per priority, the open decisions, the overdue and those due within
        7 days, on the day of the question."""
        today = today or self.today()
        soon = (dt.date.fromisoformat(today) + dt.timedelta(days=sla.SOON_DAYS)).isoformat()
        by: dict[str, dict[str, Any]] = {}
        for r in self.rows:
            s = priority(r)
            if s is None:
                continue
            c = by.setdefault(s["priority"], {"rank": s.get("rank", 0), "open": 0, "overdue": 0, "due_soon": 0})
            c["open"] += 1
            c["overdue"] += s["due"] < today
            c["due_soon"] += today <= s["due"] <= soon
        policy = self.document["sla"]
        return {
            "today": today,
            "timezone": policy.get("timezone"),
            "calendar": policy.get("calendar"),
            "priorities": policy.get("priorities") or [],
            "history": policy.get("history"),
            "by_priority": dict(sorted(by.items(), key=lambda kv: (kv[1]["rank"], kv[0]))),
            "unclassified": sum(1 for r in self.rows if priority(r) is None),
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
        if "due_before" in query:
            limit_day = _day(query["due_before"], "due_before")
            rows = [r for r in rows if (due_date(r) or "9999") <= limit_day]
        if "overdue" in query:
            want = _bool(query["overdue"], "overdue")
            today = query.get("today") or dt.date.today().isoformat()
            rows = [r for r in rows if (bool(due_date(r)) and due_date(r) < today) == want]
        if "priority" in query:
            wanted = {p.strip().casefold() for p in query["priority"].split(",") if p.strip()}
            rows = [r for r in rows if (priority(r) or {}).get("priority", "").casefold() in wanted]
        if "sla_overdue" in query:
            want = _bool(query["sla_overdue"], "sla_overdue")
            today = query.get("today") or self.today()
            rows = [r for r in rows if (bool(sla_due(r)) and sla_due(r) < today) == want]
        if "sla_due_before" in query:
            limit_day = _day(query["sla_due_before"], "sla_due_before")
            rows = [r for r in rows if (sla_due(r) or "9999") <= limit_day]
        sort = query.get("sort", "level")
        if sort not in SORTS:
            raise QueryError(f"sort: one of {', '.join(SORTS)}")
        limit, offset = page(query, DECISIONS_MAX)
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

    def not_affected(self, cve: str) -> list[dict[str, Any]]:
        return [
            {
                "asset": n.get("asset_id"),
                "deployed_versions": n.get("deployed_versions") or [],
                "source": n.get("source"),
            }
            for n in self.document.get("not_affected") or []
            if n.get("cve_id") == cve
        ]

    def cve(self, cve: str, query: dict[str, str]) -> dict[str, Any] | None:
        cve = cve.upper()
        rows = self.by_cve.get(cve)
        if not rows:
            spared = self.not_affected(cve)
            if not spared:
                return None
            return {
                "run": self.run,
                "cve": cve,
                "concerned": False,
                "why": "the tenant has the product, in versions outside the vulnerable range",
                "not_affected": spared[:50],
            }
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
            "concerned": True,
            "published": first.get("cve_published") or None,
            "updated": first.get("cve_updated") or None,
            "kev_date_added": first.get("kev_date_added") or None,
            "kev_due_date": first.get("kev_due_date") or None,
            "epss_date": first.get("epss_date") or None,
            "levels": dict(Counter(r["delivery_decision"] for r in rows)),
            "not_affected": self.not_affected(cve)[:50],
            "assets": _paged([compact(r) for r in ordered], limit, offset),
        }

    def assets(self, query: dict[str, str]) -> dict[str, Any]:
        items = [self._card(a) for a in sorted(set(self.by_asset) | set(self.inventory))]
        if "q" in query:
            q = query["q"].lower()
            items = [a for a in items if q in a["asset"].lower() or q in a["name"].lower()]
        for name in ("exposure", "zone"):
            if name in query:
                items = [a for a in items if a[name] == query[name]]
        items.sort(key=lambda a: (-a["counts"]["ACT"], -a["counts"]["ATTEND"], a["asset"]))
        limit, offset = page(query)
        return {"run": self.run, **_paged(items, limit, offset)}

    def components(self, query: dict[str, str]) -> dict[str, Any]:
        """The assets that carry a software component, vulnerable or not (v0.22.2), from the packages
        the collection listed on each host: `name` (part of the package name, or the whole with
        `exact=true`), `version` (its beginning). The counts are computed here, never by the model."""
        name = (query.get("name") or "").strip().lower()
        if not name:
            raise QueryError("name: part of a package name, e.g. openssl")
        exact = _bool(query["exact"], "exact") if "exact" in query else False
        version = (query.get("version") or "").strip()
        listed = {a: e for a, e in self.inventory.items() if e.get("components")}
        items, versions = [], Counter()
        for asset, entry in sorted(listed.items()):
            found = [
                c
                for c in entry["components"]
                if (c["name"].lower() == name if exact else name in c["name"].lower())
                and c["version"].startswith(version)
            ]
            if not found:
                continue
            versions.update(f"{c['name']} {c['version']}" for c in found)
            card = self._card(asset)
            items.append({
                "asset": asset, "name": card["name"], "zone": card["zone"], "exposure": card["exposure"],
                "components": [{k: c.get(k, "") for k in ("name", "version", "type")} for c in found],
                "components_seen": entry.get("components_seen", ""),
            })  # fmt: skip
        hosts = [a for a, e in self.inventory.items() if e.get("kind", "host") == "host"]
        limit, offset = page(query)
        return {
            "run": self.run,
            "query": {"name": name, "exact": exact, "version": version},
            "assets_with_it": len(items),
            "assets_listed": len(listed),
            "hosts_not_listed": sum(1 for a in hosts if a not in listed),
            "versions": dict(versions.most_common()),
            **_paged(items, limit, offset),
        }

    def coverage(self, query: dict[str, str]) -> dict[str, Any]:
        """Scan coverage of the run (v0.19.0): the state of each host asset, gaps first.

        Filters: `state` (comma-separated, or `gaps` for every state that needs an action), `class`
        (CMDB class), `q` (part of the asset or its name)."""
        items = list(self.coverage_doc.get("assets") or [])
        if "state" in query:
            wanted = {s.strip() for s in query["state"].split(",") if s.strip()}
            if "gaps" in wanted:
                wanted = (wanted - {"gaps"}) | set(COVERAGE_GAPS)
            unknown = wanted - set(COVERAGE_STATES)
            if unknown:
                raise ValueError(f"state: unknown {sorted(unknown)}; one of {', '.join(COVERAGE_STATES)} or gaps")
            items = [c for c in items if c["state"] in wanted]
        if "class" in query:
            items = [c for c in items if c.get("cmdb_class", "").lower() == query["class"].lower()]
        if "q" in query:
            q = query["q"].lower()
            items = [c for c in items if q in c["asset"].lower() or q in c["name"].lower()]
        limit, offset = page(query)
        head = {k: v for k, v in self.coverage_doc.items() if k != "assets"}
        return {"run": self.run, **head, **_paged(items, limit, offset)}

    def asset(self, asset: str, query: dict[str, str]) -> dict[str, Any] | None:
        """One asset and its decisions; an asset scanned without a finding has none (v0.18.1)."""
        found = self._find_asset(asset)
        if found is None:
            return None
        rows = self.by_asset.get(found, [])
        first = rows[0] if rows else {}
        known = self.inventory.get(found, {})
        limit, offset = page(query)
        ordered = sorted(rows, key=_sort_key("level"))
        return {
            "run": self.run,
            **self._card(found),
            "description": known.get("description") or first.get("asset_description", ""),
            "exposure_source": known.get("exposure_source") or first.get("exposure_source", ""),
            "decisions": _paged([compact(r) for r in ordered], limit, offset),
        }

    def exposure_path(self, asset: str) -> dict[str, Any] | None:
        """Why an asset has its exposure (v0.24.0): the value, where it comes from, and the path it rests
        on, step by step from the internet or a zone, with the source and date of each step; the
        services seen on it. An assumed exposure has no path: nothing proves it."""
        found = self._find_asset(asset)
        if found is None:
            return None
        known = self.inventory.get(found, {})
        card = self._card(found)
        path = list(known.get("exposure_path") or [])
        source = known.get("exposure_source", "")
        return {
            "run": self.run,
            "asset": found,
            "name": card["name"],
            "exposure": card["exposure"],
            "exposure_source": source,
            "origin": (known.get("origins") or {}).get("exposure", ""),
            "zone": card["zone"],
            "path": path,
            "path_text": " -> ".join(step.get("label") or step.get("node", "") for step in path),
            "assumed": source == "assumed",
            "services": list(known.get("services") or [])[:50],
        }

    def fix_plan(self, asset: str, query: dict[str, str]) -> dict[str, Any] | None:
        """The decisions of one asset grouped by the fix that clears them, the fix that clears most
        ACT first: what to apply, in which order."""
        found = self.asset(asset, {})
        if found is None:
            return None
        rows = self.by_asset.get(found["asset"]) or []
        groups: dict[str, list[dict[str, Any]]] = {}
        without: list[dict[str, Any]] = []
        for r in rows:
            fixes = r.get("fixes") or []
            if not fixes:
                without.append(r)
            for f in fixes:
                groups.setdefault(f, []).append(r)
        plan = []
        for fix, rs in groups.items():
            counts = Counter(r["delivery_decision"] for r in rs)
            dues = sorted(d for d in (due_date(r) for r in rs) if d)
            sla_dues = sorted(d for d in (sla_due(r) for r in rs) if d)
            plan.append(
                {
                    "fix": fix,
                    "clears": {lv: counts.get(lv, 0) for lv in LEVELS},
                    "kev": sum(1 for r in rs if r.get("in_kev")),
                    "earliest_due_date": dues[0] if dues else None,
                    "earliest_sla_due": sla_dues[0] if sla_dues else None,
                    "cves": sorted(
                        {r["cve_id"] for r in rs},
                        key=lambda c: min(_level_rank(r["delivery_decision"]) for r in rs if r["cve_id"] == c),
                    )[:20],
                }
            )
        plan.sort(key=lambda g: (-g["clears"]["ACT"], -g["clears"]["ATTEND"], -g["kev"], g["fix"]))
        limit, offset = page(query)
        nofix = Counter(r["delivery_decision"] for r in without)
        return {
            "run": self.run,
            "asset": found["asset"],
            "name": found["name"],
            "counts": found["counts"],
            "plan": _paged(plan, limit, offset),
            "without_known_fix": {
                "counts": {lv: nofix.get(lv, 0) for lv in LEVELS},
                "fix_in_cve_record": sum(1 for r in without if r.get("fix_available")),
            },
        }


def _reasons(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Why a decision moved, from the facts both runs recorded."""
    out = []
    if bool(old.get("in_kev")) != bool(new.get("in_kev")):
        out.append(
            "added to CISA KEV" + (f" on {new['kev_date_added']}" if new.get("kev_date_added") else "")
            if new.get("in_kev")
            else "removed from CISA KEV"
        )
    oe, ne = old.get("epss"), new.get("epss")
    if oe != ne and (oe is not None or ne is not None):
        out.append(f"EPSS {oe if oe is not None else '—'} -> {ne if ne is not None else '—'}")
    if old.get("exposure") != new.get("exposure"):
        out.append(f"exposure {old.get('exposure') or '—'} -> {new.get('exposure') or '—'}")
    for key in ("exploitation", "automatable", "technical_impact"):
        ov, nv = (old.get(key) or {}).get("value"), (new.get(key) or {}).get("value")
        if ov != nv:
            out.append(f"{key} {ov} -> {nv} (source {(new.get(key) or {}).get('source')})")
    if old.get("ssvc_decision") != new.get("ssvc_decision"):
        out.append(f"SSVC {old.get('ssvc_decision')} -> {new.get('ssvc_decision')}")
    if (old.get("cve_updated") or "") != (new.get("cve_updated") or "") and new.get("cve_updated"):
        out.append(f"CVE record updated on {new['cve_updated'][:10]}")
    return out


def _why_new(row: dict[str, Any], since: str) -> list[str]:
    out = []
    first = row.get("first_seen") or ""
    if first and first >= since:
        sources = ", ".join(sorted(row.get("seen_by") or {})) or row.get("finding_source") or "a source"
        out.append(f"first detected on {first[:10]} by {sources}")
    if (row.get("cve_published") or "") >= since and row.get("cve_published"):
        out.append(f"CVE published on {row['cve_published'][:10]}")
    elif (row.get("cve_updated") or "") >= since and row.get("cve_updated"):
        out.append(f"CVE record updated on {row['cve_updated'][:10]}")
    if (row.get("kev_date_added") or "") >= since[:10] and row.get("kev_date_added"):
        out.append(f"added to CISA KEV on {row['kev_date_added'][:10]}")
    return out or ["present in this run, not in the earlier one (asset, record or matching changed)"]


def changes(older: RunIndex, newer: RunIndex, query: dict[str, str]) -> dict[str, Any]:
    """What changed between two runs: decisions new, gone, or at another level, each with its reasons."""
    kinds = {k.strip() for k in query.get("kind", "new,gone,changed").split(",") if k.strip()}
    if not kinds or not kinds <= {"new", "gone", "changed"}:
        raise QueryError("kind: new, gone, changed, comma-separated")
    levels = {lv.strip().upper() for lv in query.get("level", ",".join(LEVELS)).split(",") if lv.strip()}
    if not levels or not levels <= set(LEVELS):
        raise QueryError("level: ACT, ATTEND, TRACK, comma-separated")
    asset = query.get("asset", "").strip().lower()
    since = older.receipt["generated_at"]
    items: list[dict[str, Any]] = []
    for rid, row in newer.by_id.items():
        if asset and asset not in asset_names(row):
            continue
        before = older.by_id.get(rid)
        if before is None:
            if "new" in kinds and row["delivery_decision"] in levels:
                items.append({"change": "new", **compact(row), "why": _why_new(row, since)})
        elif (
            "changed" in kinds
            and before["delivery_decision"] != row["delivery_decision"]
            and (row["delivery_decision"] in levels or before["delivery_decision"] in levels)
        ):
            items.append(
                {
                    "change": "changed",
                    **compact(row),
                    "from": before["delivery_decision"],
                    "why": _reasons(before, row) or ["policy or rule changed"],
                }
            )
    if "gone" in kinds:
        for rid, row in older.by_id.items():
            if (
                rid not in newer.by_id
                and row["delivery_decision"] in levels
                and (not asset or asset in asset_names(row))
            ):
                items.append(
                    {
                        "change": "gone",
                        **compact(row),
                        "why": ["not in this run: fixed, or the asset or its source missing from this run"],
                    }
                )
    order = {"changed": 0, "new": 1, "gone": 2}
    items.sort(key=lambda i: (_level_rank(i["level"]), order[i["change"]], i["cve"], i["asset"]))
    counts = Counter(i["change"] for i in items)
    limit, offset = page(query)
    return {
        "run": newer.run,
        "since": older.run,
        "counts": {k: counts.get(k, 0) for k in ("new", "gone", "changed")},
        **_paged(items, limit, offset),
    }
