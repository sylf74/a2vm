# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The daily run's calls to the decision service: the push of its triage, and the SLA state it reads
before deciding (v0.21.0)."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import Any

import httpx

from ngvm import tls
from ngvm.io import legacy_schema

TIMEOUT = 600.0


class PushError(RuntimeError):
    def __init__(self, message: str, retry: bool):
        super().__init__(message)
        self.retry = retry


def push(
    base_url: str,
    tenant: str,
    token: str,
    triage_file: str | Path,
    ca_file: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """Push one triage.json as written; its digest is the idempotency key, so a retry is harmless."""
    body = Path(triage_file).read_bytes()
    key = hashlib.sha256(body).hexdigest()
    content = gzip.compress(body, 6)
    size = f"{len(body) / 1e6:.0f} MB, {len(content) / 1e6:.1f} MB compressed"
    del body
    try:
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "User-Agent": "ngvm-verdict"},
            verify=tls.verify(ca_file),
            timeout=httpx.Timeout(timeout, connect=15.0),
            transport=transport,
        ) as c:
            r = c.post(
                f"/v1/tenants/{tenant}/runs",
                content=content,
                headers={"Content-Encoding": "gzip", "Content-Type": "application/json", "Idempotency-Key": key},
            )
    except httpx.RemoteProtocolError as exc:
        # v0.23.18: the service closed the connection while it read the run, without answering: it
        # was most often stopped (memory limit, liveness probe), not unreachable.
        raise PushError(
            f"decision service closed the connection during the push of {size} ({exc}): look at its "
            "restarts and their reason (OOMKilled: NGVM_VERDICT_MEMORY, docs/kubernetes.md)",
            retry=True,
        ) from exc
    except httpx.HTTPError as exc:
        raise PushError(f"decision service unreachable: {exc}", retry=True) from exc
    if r.status_code == 202:
        return r.json()
    try:
        detail = r.json().get("detail") or r.text[:200]
    except ValueError:
        detail = r.text[:200]
    raise PushError(f"push refused ({r.status_code}): {detail}", retry=r.status_code >= 500 or r.status_code == 429)


def sla_state(
    base_url: str,
    tenant: str,
    token: str,
    ca_file: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """The state of the tenant's findings for the client's SLA (`ngvm.sla_state/1`)."""
    try:
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "User-Agent": "ngvm-verdict"},
            verify=tls.verify(ca_file),
            timeout=httpx.Timeout(timeout, connect=15.0),
            transport=transport,
        ) as c:
            r = c.get(f"/v1/tenants/{tenant}/sla-state")
    except httpx.HTTPError as exc:
        raise PushError(f"decision service unreachable: {exc}", retry=True) from exc
    if r.status_code == 200:
        data = legacy_schema(r.json())
        if data.get("schema") != "ngvm.sla_state/1" or data.get("tenant") != tenant:
            raise PushError("the decision service answered something else than the SLA state", retry=False)
        return data
    try:
        detail = r.json().get("detail") or r.text[:200]
    except ValueError:
        detail = r.text[:200]
    # 404: a service without the tenant's database; like a service down, the run goes on without history.
    retry = r.status_code >= 500 or r.status_code in (404, 429)
    raise PushError(f"SLA state refused ({r.status_code}): {detail}", retry=retry)
