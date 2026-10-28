# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Building blocks of the pillars' HTTP services (HLD D15): token digests, problems (RFC 9457),
a JSON request handler on the standard library's server.

A pillar's service declares its roles (for instance `publish` and `read`), keeps only the
sha256 digests of their tokens, one `<role> <sha256>` per line in a file the deployment writes,
and answers JSON. Used by `verdict serve` since v0.14.0; `detect serve` predates it and keeps its
own copy until it moves here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DIGEST = re.compile(r"^[0-9a-f]{64}$")
PROBES = ("/healthz", "/readyz")


def digest(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


class Problem(Exception):
    """An answer other than success, with its HTTP status and a detail for the caller."""

    def __init__(self, status: HTTPStatus, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class TokenSet:
    """Digests of the tokens of each role; a token is matched in constant time."""

    def __init__(self, digests: dict[str, list[str]]):
        self.digests = digests

    @classmethod
    def load(cls, path: str | Path, roles: set[str]) -> TokenSet:
        found: dict[str, list[str]] = {}
        p = Path(path)
        if p.exists():
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 2 or parts[0] not in roles or not DIGEST.match(parts[1]):
                    raise ValueError(f"{path}:{n}: expected `<{'|'.join(sorted(roles))}> <sha256>`")
                found.setdefault(parts[0], []).append(parts[1])
        return cls(found)

    def role_of(self, token: str | None) -> str | None:
        if not token:
            return None
        d = digest(token)
        for role, known in self.digests.items():
            if any(hmac.compare_digest(d, k) for k in known):
                return role
        return None

    def require(self, token: str | None, role: str) -> None:
        if self.role_of(token) != role:
            raise Problem(HTTPStatus.UNAUTHORIZED, f"missing or unknown {role} token")


class JsonHandler(BaseHTTPRequestHandler):
    """Answers JSON and problems; the access log never carries a query string."""

    server_version = "a2vm"
    sys_version = ""
    logger = logging.getLogger("a2vm.service")

    def log_message(self, fmt: str, *args: Any) -> None:
        path = urlsplit(self.path).path
        status = str(args[1]) if len(args) > 1 else ""
        if path in PROBES and status == "200":
            return  # the kubelet's probes, every few seconds: only their failures are logged
        self.logger.info("%s %s %s", self.command, path, status)

    def bearer(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.lower().startswith("bearer ") else None

    def send_json(self, status: HTTPStatus, payload: Any, ctype: str = "application/json") -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_problem(self, p: Problem) -> None:
        payload = {"title": p.status.phrase, "status": int(p.status), "detail": p.detail}
        self.send_json(p.status, payload, "application/problem+json")

    def read_body(self, max_bytes: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as exc:
            raise Problem(HTTPStatus.LENGTH_REQUIRED, "Content-Length required") from exc
        if length < 0:
            raise Problem(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
        if length > max_bytes:
            raise Problem(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"body larger than {max_bytes} bytes")
        return self.rfile.read(length)


def serve(handler: type[BaseHTTPRequestHandler], host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd
