# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""HTTP API of the decision service (contract: a2vm/schemas/openapi/verdict.v1.yaml).

Plain HTTP inside the cluster, one service per tenant namespace; every call names the tenant and
the service refuses another one. Roles: `publish` (the daily run pushes its triage) and `read`
(analysts' tools). Acceptance of a push, in order, nothing stored on failure:
  1. publish token, Idempotency-Key; a retry is answered from the key at once      401 / 400
  2. size limit, gzip (one complete stream), JSON, a2vm.triage/1                     413 / 400 / 422
  3. client id = tenant, generated_at not in the future                             422
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
import time
import zlib
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from a2vm.io import ExchangeError, validate_triage
from a2vm.service import JsonHandler, Problem, TokenSet
from a2vm.service import serve as _serve

from .index import QueryError, RunIndex, changes
from .store import RunStore, parse_time

log = logging.getLogger("verdict.serve")
ROLES = {"publish", "read"}
FUTURE_TOLERANCE = dt.timedelta(minutes=10)
ROUTE = re.compile(r"^/v1/tenants/(?P<tenant>[a-z0-9][a-z0-9-]{0,62})/(?P<rest>.*)$")
RUN_ID = re.compile(r"^(latest|[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12})$")


class Service:
    """The service's logic, free of HTTP (tested directly)."""

    def __init__(self, tenant: str, tokens: TokenSet, store: RunStore, max_bytes: int = 400 * 1024 * 1024):
        self.tenant = tenant
        self.tokens = tokens
        self.store = store
        self.max_bytes = max_bytes
        self._indexes: dict[str, RunIndex] = {}
        self._lock = threading.Lock()

    def _check_tenant(self, tenant: str) -> None:
        if tenant != self.tenant:
            raise Problem(HTTPStatus.NOT_FOUND, "unknown tenant")

    # -- publish ------------------------------------------------------------------------------
    def push(
        self,
        tenant: str,
        token: str | None,
        key: str | None,
        body: bytes,
        gzipped: bool,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        now = now or dt.datetime.now(dt.UTC)
        self._check_tenant(tenant)
        self.tokens.require(token, "publish")
        if not key or len(key) > 128:
            raise Problem(HTTPStatus.BAD_REQUEST, "Idempotency-Key header required (at most 128 characters)")
        known = self.store.known(tenant, key)
        if known is not None:
            log.info("push tenant=%s run=%s duplicate=True", tenant, known.id)
            return known.to_dict()
        started = time.monotonic()
        received = body
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
            document = json.loads(body)
        except ValueError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, "body is not JSON") from exc
        try:
            validate_triage(document, "body")
        except ExchangeError as exc:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)[:500]) from exc
        if document["client"]["id"] != tenant:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "client id differs from the tenant")
        try:
            generated = parse_time(document["generated_at"])
        except ValueError as exc:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "generated_at is not a date") from exc
        if generated > now + FUTURE_TOLERANCE:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "generated_at is in the future")
        receipt = self.store.put(tenant, body, document, key, now, received if gzipped else None)
        log.info(
            "push tenant=%s run=%s rows=%d received=%d bytes document=%d bytes seconds=%.1f",
            tenant,
            receipt.id,
            receipt.rows,
            len(received),
            len(body),
            time.monotonic() - started,
        )
        return receipt.to_dict()

    # -- read ---------------------------------------------------------------------------------
    def _reader(self, tenant: str, token: str | None) -> None:
        self._check_tenant(tenant)
        self.tokens.require(token, "read")

    def index(self, run: str = "latest") -> RunIndex:
        if not RUN_ID.match(run):
            raise Problem(HTTPStatus.BAD_REQUEST, "run: `latest` or a run id")
        receipt = self.store.latest(self.tenant) if run == "latest" else self.store.receipt(self.tenant, run)
        if receipt is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no run received yet" if run == "latest" else "no such run")
        with self._lock:
            idx = self._indexes.get(receipt.id)
            if idx is None:
                document = self.store.load(self.tenant, receipt.id)
                if document is None:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such run")
                idx = RunIndex(receipt.to_dict(), document)
                self._indexes = {receipt.id: idx, **dict(list(self._indexes.items())[:1])}  # this one and one more
        return idx

    def _before(self, idx: RunIndex, since: str) -> str:
        """The run to compare with: `previous` (the run kept just before) or a run id."""
        if since != "previous":
            return since
        this = parse_time(idx.receipt["generated_at"])
        earlier = [r for r in self.store.receipts(self.tenant) if parse_time(r.generated_at) < this]
        if not earlier:
            raise Problem(HTTPStatus.NOT_FOUND, "no earlier run kept: nothing to compare with yet")
        return earlier[-1].id  # receipts are oldest first

    def read(self, tenant: str, token: str | None, rest: str, query: dict[str, str]) -> Any:
        self._reader(tenant, token)
        if rest == "runs":
            return {"items": [r.to_dict() for r in reversed(self.store.receipts(tenant))]}
        idx = self.index(query.pop("run", "latest"))
        try:
            if rest == "changes":
                return changes(self.index(self._before(idx, query.pop("since", "previous"))), idx, query)
            if rest.startswith("assets/") and rest.endswith("/fixes") and len(rest) > len("assets//fixes"):
                found = idx.fix_plan(unquote(rest[len("assets/") : -len("/fixes")]), query)
                if found is None:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such asset in this run")
                return found
            if rest == "summary":
                return idx.summary()
            if rest == "decisions":
                return idx.decisions(query)
            if rest == "assets":
                return idx.assets(query)
            parts = rest.split("/", 1)
            if len(parts) == 2 and parts[1]:
                kind, ident = parts[0], unquote(parts[1])
                found = (
                    idx.decision(ident)
                    if kind == "decisions"
                    else idx.cve(ident, query)
                    if kind == "cves"
                    else idx.asset(ident, query)
                    if kind == "assets"
                    else False
                )
                if found is False:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                if found is None and kind == "cves":
                    raise Problem(
                        HTTPStatus.NOT_FOUND,
                        "no asset of the tenant is concerned by this CVE in this run: not detected on any asset, "
                        "and no asset has the product in a version outside the range",
                    )
                if found is None:
                    raise Problem(HTTPStatus.NOT_FOUND, f"no such {kind[:-1]} in this run")
                return found
        except QueryError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, str(exc)) from exc
        raise Problem(HTTPStatus.NOT_FOUND, "no such route")


def make_handler(service: Service) -> type[JsonHandler]:
    class Handler(JsonHandler):
        server_version = "a2vm-verdict"
        logger = log

        def _route(self) -> tuple[str, str, dict[str, str]]:
            url = urlsplit(self.path)
            m = ROUTE.match(url.path)
            if not m:
                raise Problem(HTTPStatus.NOT_FOUND, "no such route")
            return m["tenant"], m["rest"], dict(parse_qsl(url.query))

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = urlsplit(self.path).path
            if path in ("/healthz", "/readyz"):
                ready = path == "/healthz" or service.store.ready()
                self.send_json(HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE, {"ready": ready})
                return
            try:
                tenant, rest, query = self._route()
                self.send_json(HTTPStatus.OK, service.read(tenant, self.bearer(), rest, query))
            except Problem as p:
                self.send_problem(p)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            try:
                tenant, rest, _ = self._route()
                if rest != "runs":
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                body = self.read_body(service.max_bytes)
                gzipped = self.headers.get("Content-Encoding", "").lower() == "gzip"
                receipt = service.push(tenant, self.bearer(), self.headers.get("Idempotency-Key"), body, gzipped)
                self.send_json(HTTPStatus.ACCEPTED, receipt)
            except Problem as p:
                log.warning("push refused status=%d: %s", int(p.status), p.detail)
                self.send_problem(p)
            except Exception:  # noqa: BLE001 - a 5xx: the daily run warns and publishes again next time
                log.exception("POST %s failed", urlsplit(self.path).path)
                self.send_problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

    return Handler


def serve(service: Service, host: str = "0.0.0.0", port: int = 8080):  # noqa: S104, ANN201 - in a pod
    return _serve(make_handler(service), host, port)
