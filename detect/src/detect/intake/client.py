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

from a2vm.io import Detection, ExchangeError, validate_detection, write_detection
from a2vm.models import AssetObservation, Finding, NotAffected

from ..scanners import merge
from .registry import SOURCE


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
    max_age_hours: float | dict[str, float],
    ca_file: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> FetchResult:
    """Write the latest detection of each source to <out>/<tenant>/<source>.json.

    `sources` are the sources expected (default: every source received); `max_age_hours` is one
    limit or one per source (the declaration of the collectors). When several collectors push the
    same source (several networks), their latest detections are merged into one file. A source
    missing or too old is a problem: the run goes on without it, as with detect external."""
    result = FetchResult()
    try:
        with _client(base_url, token, ca_file, transport) as c:
            r = c.get(f"/v1/tenants/{tenant}/detections/latest")
    except httpx.HTTPError as exc:
        raise IntakeError(f"detection service unreachable: {exc}") from exc
    if r.status_code != 200:
        raise IntakeError(f"read refused ({r.status_code}): {_detail(r)}")
    try:
        entries = r.json()
        by_source: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            by_source.setdefault(str(e["receipt"]["source"]), []).append(e)
    except (ValueError, KeyError, TypeError) as exc:
        raise IntakeError(f"unexpected answer of the detection service: {exc}") from exc
    for source in sources or sorted(by_source):
        if not SOURCE.match(source):
            result.problems.append(f"{source[:64]!r}: not a source name, left out")
            continue
        limit = max_age_hours.get(source, 30.0) if isinstance(max_age_hours, dict) else float(max_age_hours)
        kept: list[Detection] = []
        for entry in by_source.get(source, []):
            receipt = entry["receipt"]
            who = f"{source} from {receipt.get('collector', '?')}"
            age = float(entry["age_hours"])
            if age > limit:
                result.problems.append(f"{who}: latest from {receipt['generated_at']} ({age:g} h old), left out")
                continue
            doc = entry["detection"]
            try:
                validate_detection(doc, who)
            except ExchangeError as exc:
                result.problems.append(f"{exc}, left out")
                continue
            if doc.get("client_id") != tenant or doc.get("source") != source:
                result.problems.append(f"{who}: document of another tenant or source, left out")
                continue
            kept.append(_as_detection(doc))
        if not kept:
            if source not in by_source:
                result.problems.append(f"{source}: nothing received yet")
            continue
        path = write_detection(Path(out) / tenant / f"{source}.json", kept[0] if len(kept) == 1 else merge(kept))
        result.written.append(path)
    return result


def _as_detection(doc: dict[str, Any]) -> Detection:
    return Detection(
        client_id=doc["client_id"],
        source=doc["source"],
        observations=[AssetObservation(**o) for o in doc["observations"]],
        findings=[Finding.from_dict(f) for f in doc["findings"]],
        not_affected=[NotAffected(**n) for n in doc["not_affected"]],
        skipped=dict(doc["skipped"]),
    )
