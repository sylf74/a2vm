# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""HTTP API of the watch service (contract: a2vm/schemas/openapi/via.v1.yaml).

Plain HTTP inside the cluster, one service per tenant namespace; every call names the tenant and
the service refuses another one. Roles:
  run    the tenant's own jobs: the daily run (inventory), the watch (state, runs), the sender
         (alerts, their files and corrected sheets, events)
  read   the analysts' tools: the alerts and their sheets, never the files to send nor the state
Nothing is sent from here: the service keeps, the jobs act. The analysts' review page is served on a
port of its own (`review.py`), behind oauth2-proxy.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import zlib
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from a2vm.io import ExchangeError, validate_assets, validate_findings
from a2vm.service import JsonHandler, Problem, TokenSet
from a2vm.service import serve as _serve

from .store import ALERT_ID, FILE_NAME, INVENTORY_FILES, STATUSES, WatchStore

log = logging.getLogger("via.serve")
ROLES = {"run", "read"}
ROUTE = re.compile(r"^/v1/tenants/(?P<tenant>[a-z0-9][a-z0-9-]{0,62})/(?P<rest>.*)$")
CLIENT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
EVENTS = {"drafted", "analysts", "sent", "send-failed"}
SHEET_MAX = 20000  # characters of a sheet given to a reader


class WatchService:
    """The service's logic, free of HTTP (tested directly)."""

    def __init__(self, tenant: str, tokens: TokenSet, store: WatchStore, max_bytes: int = 50 * 1024 * 1024):
        self.tenant = tenant
        self.tokens = tokens
        self.store = store
        self.max_bytes = max_bytes

    def _check(self, tenant: str, token: str | None, roles: tuple[str, ...]) -> str:
        if tenant != self.tenant:
            raise Problem(HTTPStatus.NOT_FOUND, "unknown tenant")
        role = self.tokens.role_of(token)
        if role not in roles:
            raise Problem(HTTPStatus.UNAUTHORIZED, f"missing or unknown {' or '.join(roles)} token")
        return role

    def _json(self, body: bytes, gzipped: bool) -> Any:
        if gzipped:
            try:
                d = zlib.decompressobj(wbits=31)
                body = d.decompress(body, self.max_bytes + 1)
            except zlib.error as exc:
                raise Problem(HTTPStatus.BAD_REQUEST, f"invalid gzip body: {exc}") from exc
            if len(body) <= self.max_bytes and (d.unused_data or not d.eof):
                raise Problem(HTTPStatus.BAD_REQUEST, "invalid gzip body: one complete gzip stream expected")
        if len(body) > self.max_bytes:
            raise Problem(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"body larger than {self.max_bytes} bytes")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, "body is not JSON") from exc

    @staticmethod
    def _events(events: Any) -> list[dict]:
        if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "events: a list of journal entries")
        for e in events:
            if e.get("event") not in EVENTS or not ALERT_ID.match(str(e.get("alert", ""))):
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, f"events: event one of {sorted(EVENTS)} and an alert id")
        return events

    # -- the tenant's jobs ---------------------------------------------------------------------
    def put_inventory(self, tenant: str, token: str | None, body: bytes, gzipped: bool) -> dict[str, Any]:
        self._check(tenant, token, ("run",))
        doc = self._json(body, gzipped)
        if not isinstance(doc, dict) or not {"assets", "findings"} <= set(doc):
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "expected {assets, findings}")
        try:
            validate_assets(doc["assets"], "assets")
            validate_findings(doc["findings"], "findings")
        except ExchangeError as exc:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)[:500]) from exc
        client = doc["assets"].get("client_id", "")
        if client != tenant or doc["findings"].get("client_id") != tenant:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "client id differs from the tenant")
        meta = self.store.put_inventory(
            tenant,
            client,
            {"assets.json": json.dumps(doc["assets"]).encode(), "findings.json": json.dumps(doc["findings"]).encode()},
        )
        log.info(
            "inventory tenant=%s assets=%d findings=%d",
            tenant,
            len(doc["assets"].get("assets", [])),
            len(doc["findings"].get("findings", [])),
        )
        return meta

    def get_inventory(self, tenant: str, token: str | None, name: str) -> bytes:
        self._check(tenant, token, ("run",))
        if name not in INVENTORY_FILES:
            raise Problem(HTTPStatus.NOT_FOUND, "no such inventory file")
        data = self.store.inventory(tenant, tenant, name)
        if data is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no inventory received yet")
        return data

    def get_state(self, tenant: str, token: str | None) -> bytes:
        self._check(tenant, token, ("run",))
        data = self.store.state(tenant)
        if data is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no state yet: the next watch records the baseline")
        return data

    def put_run(self, tenant: str, token: str | None, body: bytes, gzipped: bool) -> dict[str, Any]:
        self._check(tenant, token, ("run",))
        doc = self._json(body, gzipped)
        if not isinstance(doc, dict) or not isinstance(doc.get("state"), dict):
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "expected {state, events, files}")
        events = self._events(doc.get("events", []))
        files: dict[str, bytes] = {}
        for name, b64 in (doc.get("files") or {}).items():
            if not FILE_NAME.match(name) or name == "meta.json":
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, f"files: {name!r} is not a file name")
            try:
                files[name] = base64.b64decode(b64, validate=True)
            except (binascii.Error, TypeError) as exc:
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, f"files: {name} is not base64") from exc
        if files:
            try:
                index = json.loads(files.get("index.json", b"[]"))
            except ValueError as exc:
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "files: index.json is not JSON") from exc
            if not isinstance(index, list) or not all(
                isinstance(a, dict) and ALERT_ID.match(str(a.get("id", ""))) for a in index
            ):
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "files: index.json, a list of alerts with their id")
            missing = [n for a in index for n in WatchStore.files_of(a) if n not in files]
            if missing:
                raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, f"files: missing {', '.join(missing[:5])}")
        out = self.store.put_run(tenant, json.dumps(doc["state"]).encode(), events, files)
        log.info("watch tenant=%s run=%s alerts=%d events=%d", tenant, out["run"], out["alerts"], out["events"])
        return out

    def add_events(self, tenant: str, token: str | None, body: bytes, gzipped: bool) -> dict[str, Any]:
        self._check(tenant, token, ("run",))
        doc = self._json(body, gzipped)
        events = self._events((doc or {}).get("events") if isinstance(doc, dict) else None)
        n = self.store.add_events(tenant, events)
        log.info("events tenant=%s events=%d", tenant, n)
        return {"events": n}

    def get_file(self, tenant: str, token: str | None, alert_id: str, name: str) -> bytes:
        self._check(tenant, token, ("run",))
        alert = self.store.alert(tenant, alert_id)
        if alert is None or name not in WatchStore.files_of(alert):
            raise Problem(HTTPStatus.NOT_FOUND, "no such file of this alert")
        data = self.store.file(tenant, alert["run"], name)
        if data is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no such file of this alert")
        return data

    def get_edit(self, tenant: str, token: str | None, alert_id: str) -> bytes:
        """The sheet as a validator corrected it on the review page, for the sender."""
        self._check(tenant, token, ("run",))
        if self.store.alert(tenant, alert_id) is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no such alert kept")
        text = self.store.edit(tenant, alert_id)
        if text is None:
            raise Problem(HTTPStatus.NOT_FOUND, "the sheet was not corrected")
        return text.encode("utf-8")

    # -- readers -------------------------------------------------------------------------------
    def list_alerts(self, tenant: str, token: str | None, query: dict[str, str]) -> dict[str, Any]:
        self._check(tenant, token, ("read", "run"))
        status = query.get("status", "all")
        if status != "all" and status not in STATUSES:
            raise Problem(HTTPStatus.BAD_REQUEST, f"status: all or one of {', '.join(STATUSES)}")
        try:
            limit, offset = int(query.get("limit", 25)), int(query.get("offset", 0))
        except ValueError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, "limit and offset: integers") from exc
        if not 1 <= limit <= 200 or offset < 0:
            raise Problem(HTTPStatus.BAD_REQUEST, "limit: 1 to 200; offset: 0 or more")
        items = self.store.alerts(tenant)
        if status != "all":
            items = [a for a in items if a["status"] == status]
        if "cve" in query:
            items = [a for a in items if query["cve"].upper() in [c.upper() for c in a.get("cves") or []]]
        if "level" in query:
            items = [a for a in items if a.get("level", "").lower() == query["level"].lower()]
        if "since" in query:
            items = [a for a in items if a["run"] >= query["since"].replace("-", "")[:8]]
        page = [
            {k: a[k] for k in ("id", "level", "title", "cves", "status", "run", "prose") if k in a}
            for a in items[offset : offset + limit]
        ]
        out: dict[str, Any] = {"total": len(items), "offset": offset, "limit": limit, "items": page}
        if offset + limit < len(items):
            out["next_offset"] = offset + limit
        return out

    def get_alert(self, tenant: str, token: str | None, alert_id: str) -> dict[str, Any]:
        self._check(tenant, token, ("read", "run"))
        alert = self.store.alert(tenant, alert_id)
        if alert is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no such alert kept")
        edited = self.store.edit(tenant, alert_id)
        sheet = (
            edited
            if edited is not None
            else (self.store.file(tenant, alert["run"], f"{alert_id}.md") or b"").decode("utf-8", "replace")
        )
        return {**alert, "sheet": sheet[:SHEET_MAX]}


def make_handler(service: WatchService) -> type[JsonHandler]:
    class Handler(JsonHandler):
        server_version = "a2vm-via"
        logger = log

        def _route(self) -> tuple[str, str, dict[str, str]]:
            url = urlsplit(self.path)
            m = ROUTE.match(url.path)
            if not m:
                raise Problem(HTTPStatus.NOT_FOUND, "no such route")
            return m["tenant"], m["rest"], dict(parse_qsl(url.query))

        def _bytes(self, data: bytes, ctype: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = urlsplit(self.path).path
            if path in ("/healthz", "/readyz"):
                ready = path == "/healthz" or service.store.ready()
                self.send_json(HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE, {"ready": ready})
                return
            try:
                tenant, rest, query = self._route()
                token = self.bearer()
                parts = rest.split("/")
                if rest == "watch/state":
                    self._bytes(service.get_state(tenant, token), "application/json")
                elif len(parts) == 2 and parts[0] == "inventory":
                    self._bytes(service.get_inventory(tenant, token, parts[1]), "application/json")
                elif rest == "alerts":
                    self.send_json(HTTPStatus.OK, service.list_alerts(tenant, token, query))
                elif len(parts) == 2 and parts[0] == "alerts":
                    self.send_json(HTTPStatus.OK, service.get_alert(tenant, token, unquote(parts[1])))
                elif len(parts) == 3 and parts[0] == "alerts" and parts[2] == "edit":
                    self._bytes(service.get_edit(tenant, token, unquote(parts[1])), "text/markdown; charset=utf-8")
                elif len(parts) == 4 and parts[0] == "alerts" and parts[2] == "files":
                    self._bytes(
                        service.get_file(tenant, token, unquote(parts[1]), unquote(parts[3])),
                        "application/octet-stream",
                    )
                else:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
            except Problem as p:
                self.send_problem(p)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            try:
                tenant, rest, _ = self._route()
                body = self.read_body(service.max_bytes)
                gz = self.headers.get("Content-Encoding", "").lower() == "gzip"
                token = self.bearer()
                if rest == "inventory":
                    out = service.put_inventory(tenant, token, body, gz)
                elif rest == "watch/runs":
                    out = service.put_run(tenant, token, body, gz)
                elif rest == "events":
                    out = service.add_events(tenant, token, body, gz)
                else:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                self.send_json(HTTPStatus.ACCEPTED, out)
            except Problem as p:
                log.warning("POST refused status=%d: %s", int(p.status), p.detail)
                self.send_problem(p)
            except Exception:  # noqa: BLE001
                log.exception("POST %s failed", urlsplit(self.path).path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

    return Handler


def serve(service: WatchService, host: str = "0.0.0.0", port: int = 8080):  # noqa: S104, ANN201 - in a pod
    return _serve(make_handler(service), host, port)
