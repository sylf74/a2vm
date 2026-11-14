# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Client of the shared intelligence service (HLD D17, v0.22.0; contract ngvm/schemas/openapi/intel.v1.yaml).

A tenant's jobs ask it for the records of their CVEs (collected and enriched once for every tenant),
send it the technologies they watch (no identity: the service keeps them without who sent them), and
read its feed (the radar's validated events, the licensed sources' new vulnerabilities on the
technologies watched). The radar's sender publishes its validated events to it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from ngvm.config import env
from ngvm.models import VulnRecord

TIMEOUT = 120.0
BATCH = 2000  # CVE ids per request


class IntelError(RuntimeError):
    """The shared service cannot answer (down, refused, unexpected answer)."""


def token_from(path: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise IntelError(f"token of the shared intelligence service: {exc}") from exc
    if not value:
        raise IntelError(f"token of the shared intelligence service: {path} is empty")
    return value


class IntelClient:
    def __init__(self, url: str, token: str, transport: httpx.BaseTransport | None = None, timeout: float = TIMEOUT):
        self.url = url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": "ngvm-via"},
            timeout=httpx.Timeout(timeout, connect=15.0),
            transport=transport,
        )

    @classmethod
    def from_settings(cls, settings: Any, transport: httpx.BaseTransport | None = None) -> IntelClient | None:
        """None when no shared service is configured."""
        if not settings.intel_url:
            return None
        if settings.intel_token_file:
            return cls(settings.intel_url, token_from(settings.intel_token_file), transport)
        token = env("INTEL_TOKEN").strip()  # GitLab mode: a masked CI/CD variable
        if not token:
            raise IntelError("no token for the shared intelligence service (NGVM_INTEL_TOKEN_FILE or NGVM_INTEL_TOKEN)")
        return cls(settings.intel_url, token, transport)

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            r = self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise IntelError(f"shared intelligence service unreachable: {exc}") from exc
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail") or r.text[:200]
            except ValueError:
                detail = r.text[:200]
            raise IntelError(f"shared intelligence service: {method} {path} answered {r.status_code}: {detail}")
        try:
            return r.json()
        except ValueError as exc:
            raise IntelError(f"shared intelligence service: {method} {path}: not JSON") from exc

    def records(
        self, cve_ids: list[str], packages: bool = False
    ) -> tuple[list[VulnRecord], list[dict[str, str]], list[str]]:
        """(records, errors, notes) for `cve_ids`, in batches; with `packages`, the package advisories
        of the distributions too (v0.23.0; a service of an older version leaves them out)."""
        records: list[VulnRecord] = []
        errors: list[dict[str, str]] = []
        notes: list[str] = []
        for i in range(0, len(cve_ids), BATCH):
            body: dict[str, Any] = {"cves": cve_ids[i : i + BATCH]}
            if packages:
                body["packages"] = True
            data = self._call("POST", "/v1/records", json=body)
            try:
                records += [VulnRecord.from_dict(r) for r in data["records"]]
            except (KeyError, TypeError) as exc:
                raise IntelError(f"shared intelligence service: unreadable records ({exc})") from exc
            errors += list(data.get("errors") or [])
            notes += [str(n) for n in data.get("notes") or []]
        return records, errors, notes

    def technologies(self, items: list[dict[str, str]]) -> int:
        """Send the technologies a tenant watches; the number the service keeps in all."""
        return int(self._call("POST", "/v1/technologies", json={"items": items}).get("kept", 0))

    def feed(self, since: str = "") -> dict[str, Any]:
        """The feed since a mark (`next` of the previous answer): {"items": [...], "next": mark}."""
        return self._call("GET", "/v1/feed", params={"since": since} if since else None)

    def publish(self, event: dict[str, Any]) -> str:
        """Publish a validated radar event (radar token); its id in the feed."""
        return str(self._call("POST", "/v1/radar/events", json=event).get("id", ""))

    def close(self) -> None:
        self._client.close()
