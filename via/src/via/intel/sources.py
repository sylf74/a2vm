# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Data sources: CVE JSON 5 records, CISA KEV, FIRST EPSS, cvelistV5 delta log, CERT-FR feeds,
Google Threat Intelligence (optional, licensed).

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

from a2vm.config import SourceSettings

CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


class SourceError(RuntimeError):
    pass


class SourceAuthError(SourceError):
    """The source refused the credentials (HTTP 401 / 403): stop asking it for this run."""


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
        self.gti_calls = 0  # network lookups made to GTI in this run (cache hits excluded)

    # -- plumbing ---------------------------------------------------------------------------
    def _cache_path(self, url: str) -> Path:
        return self.cache / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def _cached(self, key: str, max_age_hours: float) -> Path | None:
        path = self._cache_path(key)
        if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
            return path
        return None

    def _get_json(
        self,
        url: str,
        max_age_hours: float,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        retries_429: int = 0,
    ) -> Any:
        key = url + ("?" + json.dumps(params, sort_keys=True) if params else "")
        path = self._cache_path(key)
        if self._cached(key, max_age_hours):
            return json.loads(path.read_text(encoding="utf-8"))
        for attempt in range(retries_429 + 1):
            try:
                resp = self._client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise SourceError(f"GET {url}: {exc}") from exc
            if resp.status_code != 429 or attempt == retries_429:
                break
            wait = resp.headers.get("Retry-After", "")
            time.sleep(min(float(wait), 60) if wait.isdigit() else 2 * (attempt + 1))
        if resp.status_code == 404:
            return None
        if resp.status_code in (401, 403) and headers:
            raise SourceAuthError(f"GET {url}: HTTP {resp.status_code} (credentials refused)")
        if resp.status_code >= 400:
            raise SourceError(f"GET {url}: HTTP {resp.status_code}")
        data = resp.json()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def get_text(self, url: str, max_age_hours: float) -> str:
        path = self._cache_path(url).with_suffix(".txt")
        if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
            return path.read_text(encoding="utf-8")
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            raise SourceError(f"GET {url}: {exc}") from exc
        if resp.status_code >= 400:
            raise SourceError(f"GET {url}: HTTP {resp.status_code}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(resp.text, encoding="utf-8")
        return resp.text

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

    def new_cve_ids(self, since: dt.datetime, include_updated: bool = False, max_age_hours: float = 1) -> list[str]:
        """CVE ids published (and optionally updated) since `since`, from cvelistV5's deltaLog."""
        if self.fixtures:
            log = self._fixture("deltaLog.json") or []
        else:
            log = self._get_json(self.settings.delta_log_url, max_age_hours) or []
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

    # -- CERT-FR -----------------------------------------------------------------------------
    def certfr_feed(self, kind: str, max_age_hours: float = 0.1) -> str:
        """RSS feed of CERT-FR publications: kind = "alerte" or "avis"."""
        if self.fixtures:
            path = self.fixtures / "certfr" / f"{kind}.xml"
            return path.read_text(encoding="utf-8") if path.exists() else ""
        return self.get_text(f"{self.settings.certfr_url}/{kind}/feed/", max_age_hours)

    def certfr_item(self, link: str) -> dict[str, Any] | None:
        """Structured view (JSON) of one CERT-FR publication, from its page link."""
        ref = link.rstrip("/").rsplit("/", 1)[-1]
        if self.fixtures:
            return self._fixture(f"certfr/{ref}.json")
        return self._get_json(link.rstrip("/") + "/json/", 24)

    # -- any feed (watch mode) -------------------------------------------------------------------
    @staticmethod
    def fixture_name(url: str) -> str:
        return re.sub(r"[^A-Za-z0-9.]+", "_", url.split("://", 1)[-1]).strip("_")

    def fetch_text(self, url: str, max_age_hours: float = 0.1) -> str:
        if self.fixtures:
            path = self.fixtures / "feeds" / self.fixture_name(url)
            return path.read_text(encoding="utf-8") if path.exists() else ""
        return self.get_text(url, max_age_hours)

    def fetch_json(self, url: str, max_age_hours: float = 0.1) -> Any:
        if self.fixtures:
            text = self.fetch_text(url)
            return json.loads(text) if text else None
        return self._get_json(url, max_age_hours)

    # -- Google Threat Intelligence ---------------------------------------------------------------
    def gti_url(self, cve_id: str) -> str:
        cve_bucket(cve_id)  # validates the id before it goes anywhere
        return f"{self.settings.gti_url.rstrip('/')}/collections/vulnerability--{cve_id.lower()}"

    def gti_cached(self, cve_id: str) -> bool:
        if self.fixtures is not None:
            return True
        return self._cached(self.gti_url(cve_id), self.settings.gti_cache_hours) is not None

    def gti_vulnerability(self, cve_id: str) -> dict[str, Any] | None:
        """Raw GTI vulnerability object (`data` envelope), None when GTI has none for this CVE."""
        if self.fixtures:
            return self._fixture(f"gti/{cve_id}.json")
        key = self.settings.gti_api_key
        if not key:
            raise SourceAuthError(f"GTI API key missing: set the variable {self.settings.gti_api_key_env}")
        url = self.gti_url(cve_id)
        if not self.gti_cached(cve_id):
            self.gti_calls += 1
        return self._get_json(url, self.settings.gti_cache_hours, headers={"x-apikey": key}, retries_429=3)

    def close(self) -> None:
        self._client.close()
