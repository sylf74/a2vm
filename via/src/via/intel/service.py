# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The shared intelligence service (HLD D17, v0.22.0; contract a2vm/schemas/openapi/intel.v1.yaml).

One service for every tenant, in the namespace of the watch team (`a2vm-via`):

  POST /v1/records          the records of a set of CVEs, collected and enriched once (CVE record, KEV,
                            EPSS, GTI when enabled) and cached for every tenant
  POST /v1/technologies     the technologies a tenant watches (vendor, product, CPE); kept without who
                            sent them, dropped 48 hours after the last tenant sent them
  GET  /v1/feed?since=      what the tenants' watches read: the radar's validated events and, GTI
                            enabled, the vulnerabilities GTI knows on the technologies watched
  POST /v1/radar/events     the radar's sender publishes a validated event (role radar)

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

from a2vm.config import Settings
from a2vm.service import JsonHandler, Problem, TokenSet
from a2vm.service import serve as _serve

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
                out = collect_direct(sources, wanted)
            finally:
                sources.close()
        return {"records": [r.to_dict() for r in out.records], "errors": out.errors, "notes": out.notes}

    def technologies(self, token: str | None, body: dict[str, Any]) -> dict[str, Any]:
        self._require(token, "read")
        items = body.get("items") or []
        if not isinstance(items, list) or len(items) > MAX_TECH:
            raise Problem(HTTPStatus.BAD_REQUEST, f"items: a list of at most {MAX_TECH} technologies")
        kept = self.store.add_technologies([i for i in items if isinstance(i, dict)])
        return {"kept": kept}

    def feed(self, token: str | None, since: str = "") -> dict[str, Any]:
        self._require(token, "read")
        items = self.store.feed(since)
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
        server_version = "a2vm-intel"
        logger = log

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            url = urlsplit(self.path)
            if url.path in ("/healthz", "/readyz"):
                self.send_json(HTTPStatus.OK, {"ready": True})
                return
            try:
                if url.path != "/v1/feed":
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                since = dict(parse_qsl(url.query)).get("since", "")
                self.send_json(HTTPStatus.OK, service.feed(self.bearer(), since))
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
