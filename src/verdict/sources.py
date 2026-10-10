"""Data sources: CVE JSON 5 records, CISA KEV, FIRST EPSS, cvelistV5 delta log.

All network access goes through one httpx client (it honours HTTPS_PROXY / SSL_CERT_FILE) and a
small file cache, so a daily run does not refetch what it already has. With `fixtures_dir`, the
sources read local files only (tests, air-gapped demos).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

import httpx

from .config import SourceSettings

CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


class SourceError(RuntimeError):
    pass


def cve_bucket(cve_id: str) -> tuple[str, str]:
    m = CVE_ID.match(cve_id)
    if not m:
        raise SourceError(f"invalid CVE id: {cve_id!r}")
    return m.group(1), f"{int(m.group(2)) // 1000}xxx"


class Sources:
    def __init__(
        self,
        settings: SourceSettings,
        fixtures_dir: str | Path | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self.settings = settings
        self.fixtures = Path(fixtures_dir) if fixtures_dir else None
        self.cache = Path(settings.cache_dir)
        self._client = httpx.Client(
            timeout=settings.timeout_seconds,
            follow_redirects=True,
            transport=transport,
            headers={"User-Agent": "verdict/0.1"},
        )
        self._kev: dict[str, dict[str, Any]] | None = None

    # -- plumbing ---------------------------------------------------------------------------
    def _cache_path(self, url: str) -> Path:
        return self.cache / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def _get_json(self, url: str, max_age_hours: float, params: dict | None = None) -> Any:
        key = url + ("?" + json.dumps(params, sort_keys=True) if params else "")
        path = self._cache_path(key)
        if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
            return json.loads(path.read_text(encoding="utf-8"))
        try:
            resp = self._client.get(url, params=params)
        except httpx.HTTPError as exc:
            raise SourceError(f"GET {url}: {exc}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise SourceError(f"GET {url}: HTTP {resp.status_code}")
        data = resp.json()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def _fixture(self, name: str) -> Any:
        path = self.fixtures / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    # -- CVE records ------------------------------------------------------------------------
    def cve_record(self, cve_id: str) -> dict[str, Any] | None:
        year, bucket = cve_bucket(cve_id)
        if self.fixtures:
            return self._fixture(f"cves/{cve_id}.json")
        url = self.settings.cve_record_url.format(year=year, bucket=bucket, cve_id=cve_id)
        return self._get_json(url, self.settings.cve_cache_hours)

    def new_cve_ids(self, since: dt.datetime, include_updated: bool = False) -> list[str]:
        """CVE ids published (and optionally updated) since `since`, from cvelistV5's deltaLog."""
        if self.fixtures:
            log = self._fixture("deltaLog.json") or []
        else:
            log = self._get_json(self.settings.delta_log_url, 1) or []
        ids: list[str] = []
        for fetch in log:
            when = dt.datetime.fromisoformat(fetch["fetchTime"].replace("Z", "+00:00"))
            if when < since:
                continue
            kinds = ["new", "updated"] if include_updated else ["new"]
            for kind in kinds:
                for item in fetch.get(kind, []):
                    if item["cveId"] not in ids:
                        ids.append(item["cveId"])
        return ids

    # -- KEV --------------------------------------------------------------------------------
    def kev(self) -> dict[str, dict[str, Any]]:
        if self._kev is None:
            if self.fixtures:
                data = self._fixture("kev.json") or {"vulnerabilities": []}
            else:
                data = self._get_json(self.settings.kev_url, self.settings.feed_cache_hours)
                if data is None:
                    raise SourceError("KEV feed not found")
            self._kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        return self._kev

    def kev_added_since(self, since: dt.date) -> list[str]:
        return [cve for cve, v in self.kev().items() if dt.date.fromisoformat(v["dateAdded"]) >= since]

    # -- EPSS -------------------------------------------------------------------------------
    def epss(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """cve -> (score, percentile). Missing CVEs (too recent, rejected) are simply absent."""
        out: dict[str, tuple[float, float]] = {}
        if self.fixtures:
            rows = (self._fixture("epss.json") or {}).get("data", [])
            wanted = set(cve_ids)
            rows = [r for r in rows if r["cve"] in wanted]
        else:
            rows = []
            for i in range(0, len(cve_ids), 50):
                chunk = cve_ids[i : i + 50]
                data = self._get_json(self.settings.epss_url, self.settings.feed_cache_hours, {"cve": ",".join(chunk)})
                rows.extend((data or {}).get("data", []))
        for r in rows:
            out[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
        return out

    def close(self) -> None:
        self._client.close()
