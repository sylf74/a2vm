# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The daily run's push of its triage to the decision service."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import Any

import httpx

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
    try:
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-verdict"},
            verify=ca_file or True,
            timeout=httpx.Timeout(timeout, connect=15.0),
            transport=transport,
        ) as c:
            r = c.post(
                f"/v1/tenants/{tenant}/runs",
                content=gzip.compress(body, 6),
                headers={"Content-Encoding": "gzip", "Content-Type": "application/json", "Idempotency-Key": key},
            )
    except httpx.HTTPError as exc:
        raise PushError(f"decision service unreachable: {exc}", retry=True) from exc
    if r.status_code == 202:
        return r.json()
    try:
        detail = r.json().get("detail") or r.text[:200]
    except ValueError:
        detail = r.text[:200]
    raise PushError(f"push refused ({r.status_code}): {detail}", retry=r.status_code >= 500 or r.status_code == 429)
