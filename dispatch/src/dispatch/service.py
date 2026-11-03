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
from .page import Denied, RequestPage, _page
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
            return {"mode": self.rules.mode, "total": len(items), "items": [_summary(t) for t in items]}
        if rest.startswith("tickets/"):
            ident = unquote(rest[len("tickets/") :])
            found = next((t for t in self.store.tickets() if key_digest(t.key) == ident or t.key == ident), None)
            if found is None:
                raise Problem(HTTPStatus.NOT_FOUND, "no such ticket")
            return {**found.to_dict(), "id": key_digest(found.key)}
        if rest == "requests":
            return {"items": self.store.requests(int(query.get("limit") or 50))}
        raise Problem(HTTPStatus.NOT_FOUND, "no such resource")


def _summary(t: Any) -> dict[str, Any]:
    return {
        "id": key_digest(t.key),
        "key": t.key,
        "asset": t.asset,
        "fix": t.fix,
        "level": t.level,
        "due": t.due,
        "state": t.state,
        "origin": t.origin,
        "requested_by": t.requested_by,
        "target": t.target,
        "external": t.external,
        "findings": len(t.findings),
        "open_findings": len(t.open_findings),
        "updated_at": t.updated_at,
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
            self.wfile.write(data)

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
                return self._html(HTTPStatus.NOT_FOUND, _page("Not found", "<p>No such page.</p>"))
            try:
                self._html(HTTPStatus.OK, page.get(service.dispatcher(), self.headers, parse_qs(u.query)))
            except Denied as d:
                self._html(d.status, _page("Remediation", f"<p class='err'>{d.message}</p>"))

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/remediate":
                return self._html(HTTPStatus.NOT_FOUND, _page("Not found", "<p>No such page.</p>"))
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
                self._html(d.status, _page("Remediation", f"<p class='err'>{d.message}</p>"))
            except Problem as p:
                self._html(p.status, _page("Remediation", f"<p class='err'>{p.detail}</p>"))

    return Handler
