# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The dispatch service of a tenant (`dispatch serve`, LLD dispatch §6; contract
a2vm/schemas/openapi/dispatch.v1.yaml).

Plain HTTP inside the cluster, one service per tenant namespace. Roles: `run` (the daily run asks
it to process the newest run of the decision service) and `read` (tools: tickets and requests).
The page of the requests for remediation is on a second port, behind oauth2-proxy (`page.py`).
One run or request at a time (a lock): the tickets of a tenant move in one place.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import Counter
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit

from a2vm.service import JsonHandler, Problem, TokenSet

from .connectors import make
from .decisions import Decisions
from .engine import Dispatcher, DispatchError
from .page import Denied, RequestPage
from .page import _page as _html_page
from .rules import Rules
from .store import TicketStore
from .tickets import STATES, key_digest

log = logging.getLogger("dispatch.serve")
ROLES = {"run", "read"}
ROUTE = re.compile(r"^/v1/tenants/(?P<tenant>[a-z0-9][a-z0-9-]{0,62})/(?P<rest>.*)$")
FORM_MAX = 64 * 1024


class Service:
    """The service's logic, free of HTTP (tested directly)."""

    def __init__(
        self,
        tenant: str,
        tokens: TokenSet,
        store: TicketStore,
        rules: Rules,
        decisions: Callable[[], Decisions],
        secrets_dir: str | Path = "/secrets",
        connector_for: Callable[[str], Any] | None = None,
    ):
        self.tenant = tenant
        self.tokens = tokens
        self.store = store
        self.rules = rules
        self._decisions = decisions
        self.secrets_dir = Path(secrets_dir)
        self._connector_for = connector_for
        self.lock = threading.Lock()

    def dispatcher(self) -> Dispatcher:
        def connector_for(name: str) -> Any:
            if self._connector_for is not None:
                return self._connector_for(name)
            return make(self.rules.targets[name], self.secrets_dir)

        return Dispatcher(self.tenant, self.rules, self.store, self._decisions(), connector_for)

    def _check(self, tenant: str, token: str | None, role: str) -> None:
        if tenant != self.tenant:
            raise Problem(HTTPStatus.NOT_FOUND, "unknown tenant")
        self.tokens.require(token, role)

    def process(self, tenant: str, token: str | None) -> dict[str, Any]:
        self._check(tenant, token, "run")
        if not self.lock.acquire(timeout=600):
            raise Problem(HTTPStatus.CONFLICT, "another run or request is being processed")
        try:
            return self.dispatcher().process_run()
        except DispatchError as exc:
            raise Problem(HTTPStatus.BAD_GATEWAY, str(exc)) from exc
        finally:
            self.lock.release()

    def read(self, tenant: str, token: str | None, rest: str, query: dict[str, str]) -> Any:
        self._check(tenant, token, "read")
        if rest == "tickets":
            state = query.get("state")
            if state and state not in STATES and state != "open":
                raise Problem(HTTPStatus.BAD_REQUEST, f"state: one of open, {', '.join(STATES)}")
            items = self.store.tickets(open_only=state == "open", asset=query.get("asset") or None)
            if state and state != "open":
                items = [t for t in items if t.state == state]
            # v0.22.2: the tickets sent to the ITSM between two days (both included), newest first, with
            # their counts computed here; `limit` and `offset` page them.
            since, until = (_day(query, k) for k in ("since", "until"))
            if since or until:
                items = [t for t in items if t.created_at and since <= t.created_at[:10] <= (until or "9999")]
                items.sort(key=lambda t: (t.created_at, t.key), reverse=True)
            out: dict[str, Any] = {"mode": self.rules.mode, "total": len(items)}
            if since:
                out["since"] = since
            if until:
                out["until"] = until
            out["counts"] = {
                "by_state": dict(Counter(t.state for t in items)),
                "by_level": dict(Counter(t.level for t in items)),
                "with_itsm_ref": sum(1 for t in items if t.external.get("ref")),
            }
            limit, offset = _page(query, len(items))
            out["items"] = [_summary(t) for t in items[offset : offset + limit]]
            if offset + limit < len(items):
                out["next_offset"] = offset + limit
            return out
        if rest.startswith("tickets/"):
            ident = unquote(rest[len("tickets/") :])
            found = next((t for t in self.store.tickets() if key_digest(t.key) == ident or t.key == ident), None)
            if found is None:
                raise Problem(HTTPStatus.NOT_FOUND, "no such ticket")
            return {**found.to_dict(), "id": key_digest(found.key)}
        if rest == "fixes":
            # v0.22.2: the findings of the tickets the team declared fixed in the ITSM, with that date;
            # the reporting database checks each against the scans.
            items = [
                {"finding": f.id, "declared_at": t.declared_fixed_at, "ref": t.external.get("ref", ""), "ticket": t.key}
                for t in self.store.tickets()
                if t.declared_fixed_at
                for f in t.findings.values()
            ]
            return {"total": len(items), "items": items}
        if rest == "requests":
            return {"items": self.store.requests(int(query.get("limit") or 50))}
        raise Problem(HTTPStatus.NOT_FOUND, "no such resource")


def _day(query: dict[str, str], name: str) -> str:
    value = (query.get(name) or "").strip()
    if value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise Problem(HTTPStatus.BAD_REQUEST, f"{name}: a day YYYY-MM-DD")
    return value


def _page(query: dict[str, str], total: int) -> tuple[int, int]:
    try:
        limit = int(query.get("limit") or total or 1)
        offset = int(query.get("offset") or 0)
    except ValueError as exc:
        raise Problem(HTTPStatus.BAD_REQUEST, "limit, offset: integers") from exc
    if limit < 1 or offset < 0:
        raise Problem(HTTPStatus.BAD_REQUEST, "limit: 1 or more, offset: 0 or more")
    return limit, offset


def _summary(t: Any) -> dict[str, Any]:
    return {
        "id": key_digest(t.key),
        "key": t.key,
        "asset": t.asset,
        "fix": t.fix,
        "level": t.level,
        "priority": t.priority,  # v0.21.0: the most urgent priority of the client's SLA, "" without
        "due": t.due,
        "state": t.state,
        "origin": t.origin,
        "requested_by": t.requested_by,
        "target": t.target,
        "external": t.external,
        "findings": len(t.findings),
        "open_findings": len(t.open_findings),
        "updated_at": t.updated_at,
        "sent_at": t.created_at,  # v0.22.2: when the ticket was created in the ITSM ("" not sent)
        "error": t.error,
    }


def api_handler(service: Service) -> type[BaseHTTPRequestHandler]:
    class Handler(JsonHandler):
        def do_GET(self) -> None:  # noqa: N802
            u = urlsplit(self.path)
            if u.path == "/healthz":
                return self.send_json(HTTPStatus.OK, {"status": "ok"})
            if u.path == "/readyz":
                ok = service.store.ready()
                return self.send_json(HTTPStatus.OK if ok else HTTPStatus.SERVICE_UNAVAILABLE, {"ready": ok})
            m = ROUTE.match(u.path)
            try:
                if not m:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such resource")
                query = dict(parse_qsl(u.query))
                self.send_json(HTTPStatus.OK, service.read(m["tenant"], self.bearer(), m["rest"], query))
            except Problem as p:
                self.send_problem(p)

        def do_POST(self) -> None:  # noqa: N802
            m = ROUTE.match(urlsplit(self.path).path)
            try:
                if not m or m["rest"] != "runs":
                    raise Problem(HTTPStatus.NOT_FOUND, "no such resource")
                self.read_body(1024)
                self.send_json(HTTPStatus.OK, service.process(m["tenant"], self.bearer()))
            except Problem as p:
                self.send_problem(p)

    return Handler


def page_handler(service: Service, page: RequestPage) -> type[BaseHTTPRequestHandler]:
    class Handler(JsonHandler):
        def _html(self, status: HTTPStatus, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
            self.send_header("Content-Security-Policy", csp)
            self.send_header("Referrer-Policy", "same-origin")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                log.warning("page: the client left before the answer (proxy timeout?)")

        def do_GET(self) -> None:  # noqa: N802
            u = urlsplit(self.path)
            if u.path in ("/healthz", "/readyz"):
                return self.send_json(HTTPStatus.OK, {"status": "ok"})
            if u.path == "/":
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/remediate")
                self.send_header("Content-Length", "0")
                return self.end_headers()
            if u.path != "/remediate":
                return self._html(HTTPStatus.NOT_FOUND, _html_page("Not found", "<p>No such page.</p>"))
            try:
                self._html(HTTPStatus.OK, page.get(service.dispatcher(), self.headers, parse_qs(u.query)))
            except Denied as d:
                self._html(d.status, _html_page("Remediation", f"<p class='err'>{d.message}</p>"))

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/remediate":
                return self._html(HTTPStatus.NOT_FOUND, _html_page("Not found", "<p>No such page.</p>"))
            try:
                body = self.read_body(FORM_MAX).decode("utf-8", "replace")
                form = parse_qs(body, keep_blank_values=True)
                if not service.lock.acquire(timeout=120):
                    raise Denied(HTTPStatus.CONFLICT, "Another request is being processed: try again in a minute.")
                try:
                    self._html(HTTPStatus.OK, page.post(service.dispatcher(), self.headers, form))
                finally:
                    service.lock.release()
            except Denied as d:
                self._html(d.status, _html_page("Remediation", f"<p class='err'>{d.message}</p>"))
            except Problem as p:
                self._html(p.status, _html_page("Remediation", f"<p class='err'>{p.detail}</p>"))

    return Handler
