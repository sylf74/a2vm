# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The decision service of pillar 3, read over its API (`verdict.v1`, role `read`): what pillar 4
knows of the decisions. Pillar 4 never imports pillar 3 (D12)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

PAGE = 200
MAX_PAGES = 500  # 100,000 decisions


class DecisionsError(RuntimeError):
    pass


class Decisions:
    def __init__(
        self,
        base_url: str,
        tenant: str,
        token: str,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 120.0,
    ):
        self.tenant = tenant
        self.http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-dispatch"},
            timeout=httpx.Timeout(timeout, connect=10.0),
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def _get(self, path: str, params: dict[str, Any] | None = None, missing_ok: bool = False) -> dict[str, Any] | None:
        try:
            r = self.http.get(f"/v1/tenants/{self.tenant}/{path}", params=params or {})
        except httpx.HTTPError as exc:
            raise DecisionsError(f"decision service unreachable: {exc}") from exc
        if r.status_code == 404 and missing_ok:
            return None
        if r.status_code != 200:
            try:
                detail = r.json().get("detail") or r.text[:200]
            except ValueError:
                detail = r.text[:200]
            raise DecisionsError(f"decision service answered {r.status_code}: {detail}")
        return r.json()

    def latest_run(self) -> dict[str, Any] | None:
        runs = self._get("runs", missing_ok=True) or {}
        items = runs.get("items") or runs.get("runs") or []
        return items[0] if items else None

    def decisions(self, filters: dict[str, str] | None = None, limit: int | None = None) -> tuple[dict, list[dict]]:
        """(the run, every decision matching `filters`), all pages; `limit`: stop after that many."""
        params = {k: v for k, v in (filters or {}).items() if v not in (None, "")}
        params["limit"] = PAGE
        out: list[dict[str, Any]] = []
        run: dict[str, Any] = {}
        offset = 0
        for _ in range(MAX_PAGES):
            params["offset"] = offset
            page = self._get("decisions", params) or {}
            run = page.get("run") or run
            out.extend(page.get("items") or [])
            if limit is not None and len(out) >= limit:
                return run, out[:limit]
            if "next_offset" not in page:
                break
            offset = page["next_offset"]
        return run, out

    def asset(self, asset: str) -> dict[str, Any] | None:
        """The asset's card (name, zone, owner, `cmdb` items), or None when the run does not know it."""
        return self._get(f"assets/{quote(asset, safe='')}", {"limit": 1}, missing_ok=True)

    def closed_since(self, since: str) -> list[dict[str, Any]]:
        """Findings closed (fixed, a scan confirmed) since a day; [] without the tenant's database."""
        out: list[dict[str, Any]] = []
        offset = 0
        for _ in range(MAX_PAGES):
            page = self._get("findings/closed", {"since": since, "limit": PAGE, "offset": offset}, missing_ok=True)
            if not page:
                break
            out.extend(page.get("items") or [])
            if "next_offset" not in page:
                break
            offset = page["next_offset"]
        return out
