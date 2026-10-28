# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""HTTP API of the detection service (contract: a2vm/schemas/openapi/detect.v1.yaml).

Plain HTTP inside the cluster: TLS is ended by the ingress, which also restricts the push to the
collectors' addresses. One service per tenant namespace (D15, tenant isolation); every call still
names the tenant and the service refuses another one.

Acceptance of a push (LLD detection §8.2), in order, nothing stored on failure:
  1. token of a collector declared for this tenant           401 / 403
  2. size limit, gzip, JSON, vulnops.detection/1             413 / 400 / 422
  3. client_id = tenant, source declared for the collector     422 / 403
  4. generated_at not in the future nor older than max_age     422
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import time
import zlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from a2vm.io import ExchangeError, validate_detection

from .registry import SOURCE, Collector, Registry
from .store import FileStore, Receipt, age_hours, parse_time

log = logging.getLogger("detect.serve")
FUTURE_TOLERANCE = dt.timedelta(minutes=10)
ROUTE = re.compile(r"^/v1/tenants/(?P<tenant>[a-z0-9][a-z0-9-]{0,62})/(?P<rest>.*)$")


class Problem(Exception):
    def __init__(self, status: HTTPStatus, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class Service:
    """The service's logic, free of HTTP (tested directly)."""

    def __init__(self, registry: Registry, store: FileStore, max_bytes: int = 200 * 1024 * 1024):
        self.registry = registry
        self.store = store
        self.max_bytes = max_bytes
        # Last refusal per collector and source ("*" when the source is not known yet), cleared by an
        # accepted push of that source; in memory: a restart forgets them, the log keeps them.
        self.last_errors: dict[tuple[str, str], str] = {}

    def _tenant(self, tenant: str) -> None:
        if tenant != self.registry.tenant:
            raise Problem(HTTPStatus.NOT_FOUND, "unknown tenant")

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
        self._tenant(tenant)
        collector = self.registry.collector_for(token)
        if collector is None:
            log.warning("push refused tenant=%s: missing or unknown collector token", tenant)
            raise Problem(HTTPStatus.UNAUTHORIZED, "missing or unknown collector token")
        if collector.tenant != tenant:
            raise Problem(HTTPStatus.FORBIDDEN, "collector not declared for this tenant")
        if not key or len(key) > 128:
            raise Problem(HTTPStatus.BAD_REQUEST, "Idempotency-Key header required (at most 128 characters)")
        # A retry of a detection already stored is answered at once, before any decompression or
        # validation: the key is bound to this authenticated collector, the stored document was validated.
        known = self.store.known(tenant, collector.id, key)
        if known is not None:
            log.info(
                "push tenant=%s collector=%s source=%s id=%s duplicate=True",
                tenant,
                collector.id,
                known.source,
                known.id,
            )
            return known.to_dict()
        started = time.monotonic()
        state: dict[str, str] = {"source": "*"}
        try:
            receipt = self._accept(tenant, collector, key, body, gzipped, now, state)
        except Problem as p:
            self.last_errors[(collector.id, state["source"])] = f"{now.isoformat(timespec='seconds')} {p.detail[:300]}"
            log.warning(
                "push refused tenant=%s collector=%s source=%s status=%d: %s",
                tenant,
                collector.id,
                state["source"],
                int(p.status),
                p.detail,
            )
            raise
        self.last_errors.pop((collector.id, receipt.source), None)
        self.last_errors.pop((collector.id, "*"), None)
        log.info(
            "push tenant=%s collector=%s source=%s id=%s duplicate=%s received=%d bytes document=%d bytes seconds=%.1f",
            tenant,
            collector.id,
            receipt.source,
            receipt.id,
            receipt.duplicate,
            len(body),
            int(state.get("size", "0")),
            time.monotonic() - started,
        )
        return receipt.to_dict()

    def _accept(
        self,
        tenant: str,
        collector: Collector,
        key: str | None,
        body: bytes,
        gzipped: bool,
        now: dt.datetime,
        state: dict[str, str],
    ) -> Receipt:
        received = body
        if gzipped:
            try:
                d = zlib.decompressobj(wbits=31)
                body = d.decompress(body, self.max_bytes + 1)
            except zlib.error as exc:
                raise Problem(HTTPStatus.BAD_REQUEST, f"invalid gzip body: {exc}") from exc
            if len(body) <= self.max_bytes and (d.unused_data or not d.eof):
                # Stored as received: one complete gzip member, nothing after it.
                raise Problem(HTTPStatus.BAD_REQUEST, "invalid gzip body: one complete gzip stream expected")
        if len(body) > self.max_bytes:
            raise Problem(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"body larger than {self.max_bytes} bytes")
        state["size"] = str(len(body))
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise Problem(HTTPStatus.BAD_REQUEST, "body is not JSON") from exc
        try:
            validate_detection(document, "body")
        except ExchangeError as exc:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)) from exc
        if document["source"] in collector.sources:
            state["source"] = document["source"]  # where the status shows a refusal
        if document["client_id"] != tenant:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "client_id differs from the tenant")
        if document["source"] not in collector.sources:
            raise Problem(HTTPStatus.FORBIDDEN, f"source {document['source']!r} not declared for {collector.id}")
        try:
            generated = parse_time(document["generated_at"])
        except ValueError as exc:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "generated_at is not a date") from exc
        if generated > now + FUTURE_TOLERANCE:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, "generated_at is in the future")
        if (now - generated).total_seconds() / 3600 > collector.max_age_hours:
            raise Problem(HTTPStatus.UNPROCESSABLE_ENTITY, f"older than {collector.max_age_hours:g} hours")
        return self.store.put(tenant, collector.id, body, document, key, now, received if gzipped else None)

    def _reader(self, tenant: str, token: str | None) -> None:
        self._tenant(tenant)
        if not self.registry.may_read(token):
            raise Problem(HTTPStatus.UNAUTHORIZED, "missing or unknown read token")

    def latest(self, tenant: str, token: str | None, source: str | None = None) -> list[dict[str, Any]]:
        self._reader(tenant, token)
        if source is not None and not SOURCE.match(source):
            raise Problem(HTTPStatus.BAD_REQUEST, "invalid source")
        return [
            {"receipt": r.to_dict(), "age_hours": age_hours(r.generated_at), "detection": doc}
            for r, doc in self.store.latest(tenant, source)
        ]

    def one(self, tenant: str, token: str | None, rid: str) -> dict[str, Any]:
        self._reader(tenant, token)
        found = self.store.get(tenant, rid)
        if found is None:
            raise Problem(HTTPStatus.NOT_FOUND, "no such detection")
        r, doc = found
        return {"receipt": r.to_dict(), "age_hours": age_hours(r.generated_at), "detection": doc}

    def collectors(self, tenant: str, token: str | None) -> list[dict[str, Any]]:
        self._reader(tenant, token)
        latest = {(r.collector, r.source): r for r, _ in self.store.latest(tenant)}
        out = []
        for c in self.registry.collectors.values():
            sources = []
            for s in c.sources:
                entry: dict[str, Any] = {"source": s, "max_age_hours": c.max_age_hours}
                r = latest.get((c.id, s))
                if r is not None:
                    entry["last_received_at"] = r.received_at
                    entry["age_hours"] = age_hours(r.generated_at)
                entry["stale"] = entry.get("age_hours", c.max_age_hours + 1) > c.max_age_hours
                error = self.last_errors.get((c.id, s)) or self.last_errors.get((c.id, "*"))
                if error:
                    entry["last_error"] = error
                sources.append(entry)
            out.append({"id": c.id, "description": c.description, "sources": sources})
        return out


def make_handler(service: Service) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "a2vm-detect"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # access log without query strings
            log.info("%s %s %s", self.command, urlsplit(self.path).path, args[1] if len(args) > 1 else "")

        def _token(self) -> str | None:
            auth = self.headers.get("Authorization", "")
            return auth[7:].strip() if auth.lower().startswith("bearer ") else None

        def _send(self, status: HTTPStatus, payload: Any, ctype: str = "application/json") -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _problem(self, p: Problem) -> None:
            payload = {"title": p.status.phrase, "status": int(p.status), "detail": p.detail}
            self._send(p.status, payload, "application/problem+json")

        def _route(self) -> tuple[str, str, dict[str, list[str]]]:
            url = urlsplit(self.path)
            m = ROUTE.match(url.path)
            if not m:
                raise Problem(HTTPStatus.NOT_FOUND, "no such route")
            return m["tenant"], m["rest"], parse_qs(url.query)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = urlsplit(self.path).path
            if path in ("/healthz", "/readyz"):
                ready = path == "/healthz" or service.store.ready()
                self._send(
                    HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                    {"status": "ok" if ready else "not ready"},
                )
                return
            try:
                tenant, rest, query = self._route()
                if rest == "detections/latest":
                    source = (query.get("source") or [None])[0]
                    self._send(HTTPStatus.OK, service.latest(tenant, self._token(), source))
                elif rest == "collectors":
                    self._send(HTTPStatus.OK, service.collectors(tenant, self._token()))
                elif rest.startswith("detections/") and rest.count("/") == 1:
                    self._send(HTTPStatus.OK, service.one(tenant, self._token(), rest.split("/", 1)[1]))
                else:
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
            except Problem as p:
                self._problem(p)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", path)
                self._problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            try:
                tenant, rest, _ = self._route()
                if rest != "detections":
                    raise Problem(HTTPStatus.NOT_FOUND, "no such route")
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError as exc:
                    raise Problem(HTTPStatus.LENGTH_REQUIRED, "Content-Length required") from exc
                if length < 0:
                    raise Problem(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
                if length > service.max_bytes:
                    raise Problem(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"body larger than {service.max_bytes} bytes")
                body = self.rfile.read(length)
                gzipped = self.headers.get("Content-Encoding", "").lower() == "gzip"
                receipt = service.push(tenant, self._token(), self.headers.get("Idempotency-Key"), body, gzipped)
                self._send(HTTPStatus.ACCEPTED, receipt)
            except Problem as p:
                self._problem(p)
            except Exception:  # noqa: BLE001 - a 5xx: the collector keeps the detection and retries
                log.exception("POST %s failed", urlsplit(self.path).path)
                self._problem(Problem(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error"))

    return Handler


def serve(service: Service, host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:  # noqa: S104 - in a pod
    httpd = ThreadingHTTPServer((host, port), make_handler(service))
    httpd.daemon_threads = True
    return httpd


__all__ = ["Problem", "Service", "serve"]
