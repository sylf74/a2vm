# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The tenant's jobs talking to the watch service: the daily run (inventory), the watch, the send job."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

import httpx

TIMEOUT = 120.0


class ServiceError(RuntimeError):
    def __init__(self, message: str, retry: bool):
        super().__init__(message)
        self.retry = retry


class WatchClient:
    def __init__(self, base_url: str, tenant: str, token: str, transport: httpx.BaseTransport | None = None):
        self.tenant = tenant
        self._c = httpx.Client(
            base_url=f"{base_url.rstrip('/')}/v1/tenants/{tenant}",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-via"},
            timeout=httpx.Timeout(TIMEOUT, connect=10.0),
            transport=transport,
        )

    def close(self) -> None:
        self._c.close()

    def _call(self, method: str, path: str, body: Any = None, missing_ok: bool = False) -> httpx.Response | None:
        try:
            if body is None:
                r = self._c.request(method, path)
            else:
                r = self._c.request(
                    method,
                    path,
                    content=gzip.compress(json.dumps(body).encode(), 6),
                    headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise ServiceError(f"watch service unreachable: {exc}", retry=True) from exc
        if r.status_code == 404 and missing_ok:
            return None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail") or r.text[:200]
            except ValueError:
                detail = r.text[:200]
            raise ServiceError(f"{method} {path} refused ({r.status_code}): {detail}", retry=r.status_code >= 500)
        return r

    # -- the watch -----------------------------------------------------------------------------
    def state(self) -> bytes | None:
        r = self._call("GET", "/watch/state", missing_ok=True)
        return r.content if r is not None else None

    def inventory(self, dest: Path) -> bool:
        """The last daily inventory into dest/<tenant>/: False when the service has none yet. Its
        findings compact (watch-findings.json, v0.23.19), else as before (findings.json)."""
        files = {}
        r = self._call("GET", "/inventory/assets.json", missing_ok=True)
        if r is None:
            return False
        files["assets.json"] = r.content
        for name in ("watch-findings.json", "findings.json"):
            r = self._call("GET", f"/inventory/{name}", missing_ok=True)
            if r is not None:
                files[name] = r.content
                break
        else:
            return False
        base = dest / self.tenant
        base.mkdir(parents=True, exist_ok=True)
        for name in ("watch-findings.json", "findings.json"):
            (base / name).unlink(missing_ok=True)
        for name, data in files.items():
            (base / name).write_bytes(data)
        return True

    def applications(self) -> dict[str, Any]:
        """The tenant's applications table (v0.23.3)."""
        return self._call("GET", "/applications").json()

    def put_proposals(self, proposals: list[dict[str, Any]]) -> dict[str, Any]:
        return self._call("POST", "/applications/proposals", {"proposals": proposals}).json()

    def put_run(self, state: dict, events: list[dict], alerts_dir: Path | None) -> dict[str, Any]:
        files: dict[str, str] = {}
        if alerts_dir and (alerts_dir / "index.json").exists():
            index = json.loads((alerts_dir / "index.json").read_text(encoding="utf-8"))
            if index:
                names = {"index.json"} | {n for a in index for n in _files_of(a)}
                files = {n: base64.b64encode((alerts_dir / n).read_bytes()).decode() for n in sorted(names)}
        return self._call("POST", "/watch/runs", {"state": state, "events": events, "files": files}).json()

    # -- the daily run -------------------------------------------------------------------------
    def put_inventory(self, assets: dict, findings: dict) -> dict[str, Any]:
        """`findings`: a2vm.watch_findings/1 (v0.23.19) or vulnops.findings/2."""
        key = "watch_findings" if findings.get("schema") == "a2vm.watch_findings/1" else "findings"
        return self._call("POST", "/inventory", {"assets": assets, key: findings}).json()

    def status(self) -> dict[str, Any]:
        return self._call("GET", "/status").json()

    # -- the send job --------------------------------------------------------------------------
    def alerts(self, status: str = "all") -> list[dict[str, Any]]:
        out, offset = [], 0
        while True:
            page = self._call("GET", f"/alerts?status={status}&limit=200&offset={offset}").json()
            out += page["items"]
            if "next_offset" not in page:
                return out
            offset = page["next_offset"]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        r = self._call("GET", f"/alerts/{alert_id}", missing_ok=True)
        return r.json() if r is not None else None

    def fetch(self, alert: dict[str, Any], dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for name in _files_of(alert):
            (dest / name).write_bytes(self._call("GET", f"/alerts/{alert['id']}/files/{name}").content)

    def edit(self, alert_id: str) -> str | None:
        """The sheet a validator corrected on the review page, or None."""
        r = self._call("GET", f"/alerts/{alert_id}/edit", missing_ok=True)
        return r.text if r is not None else None

    def translation(self, alert_id: str, lang: str) -> str | None:
        r = self._call("GET", f"/alerts/{alert_id}/translations/{lang}", missing_ok=True)
        return r.text if r is not None else None

    def put_translation(
        self, alert_id: str, lang: str, source_hash: str, source: str, text: str | None = None, error: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"language": lang, "source_hash": source_hash, "source": source}
        body.update({"text": text} if text is not None else {"error": error or "failed"})
        return self._call("POST", f"/alerts/{alert_id}/translations", body).json()

    def add_events(self, events: list[dict]) -> dict[str, Any]:
        return self._call("POST", "/events", {"events": events}).json()


def _files_of(entry: dict[str, Any]) -> list[str]:
    names = [f"{entry['id']}.md", f"{entry['id']}.html"]
    if entry.get("docx"):
        names.append(entry["docx"])
    names += [n for n in (entry.get("ctx") or {}).values() if isinstance(n, str)]
    return names
