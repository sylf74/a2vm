# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Clients of the detection service: the collector's push, the daily run's fetch."""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from a2vm.io import ExchangeError, validate_detection


class IntakeError(RuntimeError):
    pass


def _client(base_url: str, token: str, ca_file: str | None, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        base_url=base_url.rstrip("/"),
        headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-detect"},
        verify=ca_file or True,
        timeout=httpx.Timeout(60.0, connect=15.0),
        transport=transport,
    )


def _detail(response: httpx.Response) -> str:
    try:
        return response.json().get("detail") or response.text[:200]
    except ValueError:
        return response.text[:200]


def push(
    base_url: str,
    tenant: str,
    token: str,
    document: dict[str, Any],
    collector: str,
    ca_file: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Push one detection; the idempotency key is derived from the content, so a retry is harmless.
    Raises IntakeError with `retry` set when trying again later may succeed."""
    body = json.dumps(document, ensure_ascii=False).encode("utf-8")
    key = f"{collector}:{document['source']}:{hashlib.sha256(body).hexdigest()[:32]}"
    try:
        with _client(base_url, token, ca_file, transport) as c:
            r = c.post(
                f"/v1/tenants/{tenant}/detections",
                content=gzip.compress(body),
                headers={"Content-Encoding": "gzip", "Content-Type": "application/json", "Idempotency-Key": key},
            )
    except httpx.HTTPError as exc:
        err = IntakeError(f"detection service unreachable: {exc}")
        err.retry = True  # type: ignore[attr-defined]
        raise err from exc
    if r.status_code == 202:
        return r.json()
    err = IntakeError(f"push refused ({r.status_code}): {_detail(r)}")
    err.retry = r.status_code >= 500 or r.status_code == 429  # type: ignore[attr-defined]
    raise err


@dataclass
class FetchResult:
    written: list[Path] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def fetch(
    base_url: str,
    tenant: str,
    token: str,
    out: str | Path,
    sources: list[str],
    max_age_hours: float,
    ca_file: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> FetchResult:
    """Write the latest detection of each source to <out>/<tenant>/<source>.json; a source missing or
    older than max_age_hours is a problem (the run goes on without it, as with detect external)."""
    result = FetchResult()
    try:
        with _client(base_url, token, ca_file, transport) as c:
            r = c.get(f"/v1/tenants/{tenant}/detections/latest")
    except httpx.HTTPError as exc:
        raise IntakeError(f"detection service unreachable: {exc}") from exc
    if r.status_code != 200:
        raise IntakeError(f"read refused ({r.status_code}): {_detail(r)}")
    latest = {e["receipt"]["source"]: e for e in r.json()}
    for source in sources or sorted(latest):
        entry = latest.get(source)
        if entry is None:
            result.problems.append(f"{source}: nothing received yet")
            continue
        receipt, age = entry["receipt"], float(entry["age_hours"])
        if age > max_age_hours:
            result.problems.append(f"{source}: latest from {receipt['generated_at']} ({age:g} h old), left out")
            continue
        doc = entry["detection"]
        try:
            validate_detection(doc, source)
        except ExchangeError as exc:
            result.problems.append(f"{exc}, left out")
            continue
        if doc.get("client_id") != tenant or doc.get("source") != source:
            result.problems.append(f"{source}: document of another tenant or source, left out")
            continue
        path = Path(out) / tenant / f"{source}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        result.written.append(path)
    return result
