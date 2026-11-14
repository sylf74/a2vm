# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The shared intelligence service (HLD D17, v0.22.0; contract ngvm/schemas/openapi/intel.v1.yaml).

One service for every tenant, in the namespace of the watch team (`ngvm-via`):

  POST /v1/records          the records of a set of CVEs, collected and enriched once (CVE record, KEV,
                            EPSS, GTI when enabled) and cached for every tenant
  POST /v1/technologies     the technologies a tenant watches (vendor, product, CPE); kept without who
                            sent them, dropped 48 hours after the last tenant sent them
  GET  /v1/feed?since=      what the tenants' watches read: the radar's validated events and, GTI
                            enabled, the vulnerabilities GTI knows on the technologies watched
  POST /v1/radar/events     the radar's sender publishes a validated event (role radar)
  GET  /v1/osv/<ecosystem>  the index of OSV for one language ecosystem (v0.23.12, ngvm.osvdb),
                            rebuilt every few hours from OSV's archive: the tenants match their
                            libraries against it at home, none of them is sent here

Roles: `read` (the tenants' jobs; one token per tenant, the service never records which one called),
`radar` (the watch team's sender). The service holds no asset, no address, no client name: it is no
path between tenants. GTI's prose never leaves it towards a tenant's feed: facts only.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ngvm import osvdb
from ngvm.config import Settings
from ngvm.service import JsonHandler, Problem, TokenSet, moment
from ngvm.service import serve as _serve

from .collect import collect_direct
from .gti import discovered
from .sources import CVE_ID, SourceError, Sources

log = logging.getLogger("via.intel")
ROLES = {"read", "radar"}
TECH_HOURS = 48  # a technology no tenant sent for this long is dropped (D17)
FEED_DAYS = 30
FEED_MAX = 5000
MAX_CVES = 5000
MAX_TECH = 5000
TEXT = 300  # characters of a technology field or a title
KINDS = ("radar", "gti")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso(moment: dt.datetime) -> str:
    return moment.isoformat(timespec="microseconds")


def _clean(value: Any, size: int = TEXT) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:size]


def tech_key(item: dict[str, str]) -> str:
    return "|".join(_clean(item.get(k)).lower() for k in ("vendor", "product", "cpe"))


class IntelStore:
    """The technologies and the feed, as two JSON files of a volume (one replica)."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def _read(self, name: str, default: Any) -> Any:
        path = self.root / name
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, name: str, data: Any) -> None:
        tmp = self.root / f".{name}.tmp"
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.root / name)

    def technologies(self, now: dt.datetime | None = None) -> list[dict[str, str]]:
        cutoff = _iso((now or _now()) - dt.timedelta(hours=TECH_HOURS))
        with self.lock:
            kept = {k: v for k, v in self._read("technologies.json", {}).items() if v["seen"] >= cutoff}
        return [{"vendor": v["vendor"], "product": v["product"], "cpe": v["cpe"]} for v in kept.values()]

    def add_technologies(self, items: list[dict[str, str]], now: dt.datetime | None = None) -> int:
        now = now or _now()
        cutoff = _iso(now - dt.timedelta(hours=TECH_HOURS))
        with self.lock:
            known = {k: v for k, v in self._read("technologies.json", {}).items() if v["seen"] >= cutoff}
            for it in items:
                entry = {k: _clean(it.get(k)) for k in ("vendor", "product", "cpe")}
                if entry["product"] or entry["cpe"]:
                    known[tech_key(entry)] = {**entry, "seen": _iso(now)}
            self._write("technologies.json", known)
            return len(known)

    def feed(self, since: str = "") -> list[dict[str, Any]]:
        with self.lock:
            items = self._read("feed.json", [])
        return [i for i in items if i["at"] > since] if since else items

    def add_to_feed(self, item: dict[str, Any], now: dt.datetime | None = None) -> dict[str, Any]:
        """Add (or replace, same id) an item; its `at` is after every other one, so a reader's mark
        never misses it."""
        now = now or _now()
        with self.lock:
            items = [i for i in self._read("feed.json", []) if i["id"] != item["id"]]
            at = _iso(now)
            if items and items[-1]["at"] >= at:
                at = _iso(dt.datetime.fromisoformat(items[-1]["at"]) + dt.timedelta(microseconds=1))
            item = {**item, "at": at}
            cutoff = _iso(now - dt.timedelta(days=FEED_DAYS))
            items = [i for i in items if i["at"] >= cutoff] + [item]
            self._write("feed.json", items[-FEED_MAX:])
        return item

    def known(self, item_id: str) -> bool:
        return any(i["id"] == item_id for i in self.feed())


class IntelService:
    """The service's logic, free of HTTP (tested directly)."""

    def __init__(self, tokens: TokenSet, store: IntelStore, settings: Settings, max_bytes: int = 8 * 1024 * 1024):
        self.tokens = tokens
        self.store = store
        self.settings = settings
        self.max_bytes = max_bytes
        self.collect_lock = threading.Lock()  # one collection at a time: one cache, one GTI quota
        self.transport = None  # tests
        self.fixtures: str | None = None  # tests: the sources read from files

    # -- OSV (v0.23.12) ------------------------------------------------------------------------
    def osv_mirror(self) -> osvdb.OsvMirror:
        return osvdb.OsvMirror(self.store.root / "osv")

    def sync_osv(self, ecosystems: list[str] | None = None) -> list[str]:
        """Rebuild the index of each ecosystem whose archive changed; one line per ecosystem."""
        lines = []
        mirror = self.osv_mirror()
        sources = self._sources()
        try:
            for eco in ecosystems or osvdb.DEFAULT_ECOSYSTEMS:
                try:
                    lines.append(mirror.refresh(eco, sources._client, _iso(_now())))
                except osvdb.OsvDbError as exc:
                    lines.append(f"WARN {exc}")
        finally:
            sources.close()
        return lines

    def osv_index(self, token: str | None, ecosystem: str, if_none_match: str = "") -> tuple[bytes, str]:
        """(the gzipped index, its ETag); empty bytes when the reader's copy is the same (304)."""
        self._require(token, "read")
        if ecosystem not in osvdb.DEFAULT_ECOSYSTEMS:
            raise Problem(HTTPStatus.NOT_FOUND, f"unknown ecosystem {ecosystem[:40]!r}")
        path = self.osv_mirror().path(ecosystem)
        if not path.exists():
            raise Problem(HTTPStatus.SERVICE_UNAVAILABLE, f"the index of {ecosystem} is not built yet")
        data = path.read_bytes()
        import hashlib

        etag = '"' + hashlib.sha256(data).hexdigest()[:32] + '"'
        return (b"" if if_none_match == etag else data), etag

    def _require(self, token: str | None, role: str) -> None:
        if self.tokens.role_of(token) != role:
            raise Problem(HTTPStatus.UNAUTHORIZED, f"missing or unknown {role} token")

    def _sources(self) -> Sources:
        self.settings.sources.intel_url = ""  # the service reads the sources itself
        return Sources(self.settings.sources, fixtures_dir=self.fixtures, transport=self.transport)

    def records(self, token: str | None, body: dict[str, Any]) -> dict[str, Any]:
        self._require(token, "read")
        wanted = []
        for c in body.get("cves") or []:
            c = str(c).strip().upper()
            if not CVE_ID.match(c):
                raise Problem(HTTPStatus.BAD_REQUEST, f"not a CVE id: {c[:40]!r}")
            if c not in wanted:
                wanted.append(c)
        if len(wanted) > MAX_CVES:
            raise Problem(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"at most {MAX_CVES} CVE ids per request")
        with self.collect_lock:
            sources = self._sources()
            try:
                out = collect_direct(sources, wanted, packages=body.get("packages") is True)
            finally:
                sources.close()
        return {"records": [r.to_dict() for r in out.records], "errors": out.errors, "notes": out.notes}

    def new_records(self, token: str | None, query: dict[str, str]) -> dict[str, Any]:
        """The CVE records published or updated in a period (v0.23.4, the chat's list_new_cves), from
        cvelistV5's deltaLog (about 30 days): `since`, `until` (moments, UTC), `change` (new, updated),
        `kev`, `min_cvss`, a page (`limit` 1 to 50, `offset`). Each item of the page with its record
        in short: CVSS, KEV, EPSS, title; `at` is when CVE.org published the change."""
        self._require(token, "read")
        try:
            since = _iso(moment(query.get("since") or "", "since")) if query.get("since") else ""
            until = _iso(moment(query["until"], "until", end=True)) if query.get("until") else ""
            limit, offset = int(query.get("limit") or 20), int(query.get("offset") or 0)
            min_cvss = float(query["min_cvss"]) if query.get("min_cvss") else None
        except ValueError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, f"since, until, limit, offset, min_cvss: {exc}") from exc
        if not 1 <= limit <= 50 or offset < 0:
            raise Problem(HTTPStatus.BAD_REQUEST, "limit: 1 to 50; offset: 0 or more")
        change = query.get("change", "")
        if change and change not in ("new", "updated"):
            raise Problem(HTTPStatus.BAD_REQUEST, "change: new or updated")
        with self.collect_lock:
            sources = self._sources()
            try:
                try:
                    entries = sources.delta_entries()
                except SourceError as exc:
                    raise Problem(HTTPStatus.BAD_GATEWAY, f"cvelistV5 not read: {exc}") from exc
                seen: dict[str, tuple[str, str]] = {}
                for cve, kind, at in entries:  # newest first: the latest change of each CVE
                    if (since and at < since) or (until and at > until) or (change and kind != change):
                        continue
                    seen.setdefault(cve, (kind, at))
                filtered = query.get("kev") == "true" or min_cvss is not None
                ids = list(seen)
                records: dict[str, Any] = {}
                if filtered:  # every record of the period is needed to filter on it
                    for start in range(0, len(ids), MAX_CVES):
                        part = collect_direct(sources, ids[start : start + MAX_CVES])
                        records.update({r.cve_id: r for r in part.records})
                    ids = [c for c in ids if c in records and _keep(records[c], query.get("kev") == "true", min_cvss)]
                page_ids = ids[offset : offset + limit]
                missing = [c for c in page_ids if c not in records]
                if missing:
                    records.update({r.cve_id: r for r in collect_direct(sources, missing).records})
            finally:
                sources.close()
        counts = {
            "new": sum(1 for c in ids if seen[c][0] == "new"),
            "updated": sum(1 for c in ids if seen[c][0] == "updated"),
        }
        items = [_brief(c, seen[c][0], seen[c][1], records.get(c)) for c in page_ids]
        out: dict[str, Any] = {"total": len(ids), "counts": counts, "offset": offset, "limit": limit, "items": items}
        if offset + limit < len(ids):
            out["next_offset"] = offset + limit
        if entries:
            out["oldest"] = entries[-1][2]  # the deltaLog reaches back to this moment, no further
        return out

    def technologies(self, token: str | None, body: dict[str, Any]) -> dict[str, Any]:
        self._require(token, "read")
        items = body.get("items") or []
        if not isinstance(items, list) or len(items) > MAX_TECH:
            raise Problem(HTTPStatus.BAD_REQUEST, f"items: a list of at most {MAX_TECH} technologies")
        kept = self.store.add_technologies([i for i in items if isinstance(i, dict)])
        return {"kept": kept}

    def feed(self, token: str | None, since: str = "", query: dict[str, str] | None = None) -> dict[str, Any]:
        """The items after a mark (`since`, the `next` of the last answer: a watch). Since v0.23.2 the
        analysts' chat also asks a period and a kind: `since` and `until` a day or a date and time,
        `kind` (radar, gti), `level`, `cve`; the mark stays the `at` of the last item."""
        self._require(token, "read")
        query = query or {}
        if since:  # a mark is an `at` (UTC): the same string back; a moment of the chat, made UTC
            since = _iso(moment(since, "since"))
        items = self.store.feed(since)
        if query.get("until"):
            until = _iso(moment(query["until"], "until", end=True))
            items = [i for i in items if i["at"] <= until]
        if query.get("kind"):
            if query["kind"] not in KINDS:
                raise Problem(HTTPStatus.BAD_REQUEST, f"kind: {' or '.join(KINDS)}")
            items = [i for i in items if i.get("kind") == query["kind"]]
        if query.get("level"):
            items = [i for i in items if i.get("level") == query["level"]]
        if query.get("cve"):
            items = [i for i in items if query["cve"].upper() in (i.get("cves") or [])]
        return {"items": items, "next": items[-1]["at"] if items else since}

    def publish(self, token: str | None, body: dict[str, Any]) -> dict[str, Any]:
        """A validated radar event: what a tenant's watch needs to match it, nothing more."""
        self._require(token, "radar")
        event_id = _clean(body.get("id"), 120)
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$", event_id):
            raise Problem(HTTPStatus.BAD_REQUEST, "id: letters, digits, . _ : -")
        cves = sorted({str(c).upper() for c in body.get("cves") or [] if CVE_ID.match(str(c).upper())})
        item = {
            "id": f"radar:{event_id}",
            "kind": "radar",
            "level": "urgent" if body.get("level") == "urgent" else "info",
            "title": _clean(body.get("title")),
            "summary": _clean(body.get("summary"), 2000),
            "cves": cves,
            "products": [
                {"vendor": _clean(p.get("vendor")), "product": _clean(p.get("product"))}
                for p in (body.get("products") or [])[:20]
                if isinstance(p, dict) and _clean(p.get("product"))
            ],
            "terms": [_clean(t, 60) for t in (body.get("terms") or [])[:20] if _clean(t, 60)],
            "links": [
                {"title": _clean(link.get("title")), "url": _clean(link.get("url"), 1000)}
                for link in (body.get("links") or [])[:12]
                if isinstance(link, dict) and str(link.get("url", "")).startswith(("https://", "http://"))
            ],
            "score": int(body.get("score") or 0),
        }
        if not item["title"] or not (item["cves"] or item["products"]):
            raise Problem(HTTPStatus.BAD_REQUEST, "an event needs a title and CVE ids or products")
        return {"id": self.store.add_to_feed(item)["id"]}

    # -- licensed sources on the technologies watched (GTI, optional) ------------------------------
    def search_technologies(self, now: dt.datetime | None = None) -> list[str]:
        """One pass: for each technology watched, the vulnerabilities GTI changed in the last two days;
        each new one goes to the feed, with GTI's facts only. Log lines."""
        src = self.settings.sources
        if not src.gti_enabled:
            return ["GTI: disabled, no search on the technologies"]
        now = now or _now()
        since = (now - dt.timedelta(days=2)).date().isoformat()
        notes, added, calls = [], 0, 0
        with self.collect_lock:
            sources = self._sources()
            try:
                for tech in self.store.technologies(now):
                    if calls >= src.gti_max_calls:
                        notes.append(f"GTI: budget of {src.gti_max_calls} searches reached")
                        break
                    product = tech["product"].replace('"', "")
                    if not product:
                        continue
                    query = f'collection_type:vulnerability AND vulnerable_product:"{product}"'
                    if tech["vendor"]:
                        query += f' AND vulnerable_vendor:"{tech["vendor"].replace(chr(34), "")}"'
                    query += f" AND last_modification_date:{since}+"
                    calls += 1
                    try:
                        found = discovered(sources, query)
                    except SourceError as exc:
                        notes.append(f"GTI {product}: {exc}")
                        if "credentials refused" in str(exc) or "API key missing" in str(exc):
                            break
                        continue
                    for view in found:
                        if not view["cve"] or self.store.known(f"gti:{view['cve']}"):
                            continue
                        self.store.add_to_feed(gti_item(view, tech), now)
                        added += 1
            finally:
                sources.close()
        notes.append(f"GTI: {calls} searches on the technologies watched, {added} new vulnerabilities in the feed")
        return notes


def _keep(record: Any, kev: bool, min_cvss: float | None) -> bool:
    if kev and not record.in_kev:
        return False
    if min_cvss is not None:
        best = record.best_cvss()
        return bool(best and best.score is not None and best.score >= min_cvss)
    return True


def _brief(cve: str, change: str, at: str, record: Any) -> dict[str, Any]:
    """One CVE of the period, in short: what an analyst asks first."""
    out: dict[str, Any] = {"cve": cve, "change": change, "at": at}
    if record is None:
        out["note"] = "record not read"
        return out
    best = record.best_cvss()
    out.update({
        "published": record.published, "updated": record.updated,
        "title": _clean(record.description, 300),
        "cvss": best.score if best else None, "severity": (best.severity or "").lower() if best else "",
        "kev": record.in_kev, "epss": record.epss,
        "products": sorted({f"{a.vendor} {a.product}".strip() for a in record.affected if a.product})[:5],
    })  # fmt: skip
    return out


def gti_item(view: dict[str, Any], tech: dict[str, str]) -> dict[str, Any]:
    """A feed item from a GTI vulnerability: its facts and the technology that matched; never its prose."""
    return {
        "id": f"gti:{view['cve']}",
        "kind": "gti",
        "level": "info",
        "title": view["cve"],
        "summary": "",
        "cves": [view["cve"]],
        "products": [{"vendor": tech["vendor"], "product": tech["product"]}],
        "terms": [],
        "links": [{"title": "Google Threat Intelligence", "url": view["url"]}],
        "score": 0,
        "facts": {k: view.get(k) for k in ("exploitation_state", "exploit_availability", "risk_rating")},
    }


def make_handler(service: IntelService) -> type[JsonHandler]:
    class Handler(JsonHandler):
        server_version = "ngvm-intel"
        logger = log

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            url = urlsplit(self.path)
            if url.path in ("/healthz", "/readyz"):
                self.send_json(HTTPStatus.OK, {"ready": True})
                return
            try:
                query = dict(parse_qsl(url.query))
                if url.path.startswith("/v1/osv/"):  # v0.23.12
                    data, etag = service.osv_index(self.bearer(), url.path.removeprefix("/v1/osv/"),
                                                   self.headers.get("If-None-Match", ""))  # fmt: skip
                    self.send_response(HTTPStatus.NOT_MODIFIED if not data else HTTPStatus.OK)
                    self.send_header("ETag", etag)
                    if data:
                        self.send_header("Content-Type", "application/gzip")
                        self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    if data:
                        self.wfile.write(data)
                    return
                if url.path == "/v1/records/new":  # v0.23.4
                    self.send_json(HTTPStatus.OK, service.new_records(self.bearer(), query))
                    return
                if url.path != "/v1/feed":
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                self.send_json(HTTPStatus.OK, service.feed(self.bearer(), query.pop("since", ""), query))
            except Problem as p:
                self.send_problem(p)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", url.path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            path = urlsplit(self.path).path
            try:
                routes = {"/v1/records": service.records, "/v1/technologies": service.technologies,
                          "/v1/radar/events": service.publish}  # fmt: skip
                if path not in routes:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                try:
                    body = json.loads(self.read_body(service.max_bytes) or b"{}")
                except ValueError as exc:
                    raise Problem(HTTPStatus.BAD_REQUEST, "body: JSON expected") from exc
                if not isinstance(body, dict):
                    raise Problem(HTTPStatus.BAD_REQUEST, "body: a JSON object expected")
                self.send_json(HTTPStatus.OK, routes[path](self.bearer(), body))
            except Problem as p:
                log.warning("POST %s refused status=%d: %s", path, int(p.status), p.detail)
                self.send_problem(p)
            except Exception:  # noqa: BLE001
                log.exception("POST %s failed", path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

    return Handler


def serve(service: IntelService, host: str = "0.0.0.0", port: int = 8080):  # noqa: S104, ANN201 - in a pod
    return _serve(make_handler(service), host, port)
