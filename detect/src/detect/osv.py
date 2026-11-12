# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""OSV: the libraries of the language ecosystems against the open vulnerability database (v0.23.11).

The images' libraries (Trivy) and the SBOMs carry each library with its `purl`. Every daily run,
`detect osv` asks OSV (api.osv.dev) which vulnerabilities concern each `purl@version`, keeps those
known by a CVE (an alias), and writes them as the findings of source `osv`: the triage decides on
them as on any finding. The hosts are not touched again: a new vulnerability of a library already
listed is found from the list.

Read only, two calls: `POST /v1/querybatch` (up to 1,000 libraries at once), then
`GET /v1/vulns/<id>` for the details of each vulnerability (kept in a cache directory, a
vulnerability's details read again after `cache_days`). Through the corporate proxy like every
public source (`HTTPS_PROXY`, `SSL_CERT_FILE`). A vulnerability known only by its GHSA or PYSEC id
is counted, not kept: the pipeline decides on CVEs.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from a2vm.io import Detection, now
from a2vm.models import AssetObservation, Finding, FindingObservation, Match

SOURCE = "osv"
API = "https://api.osv.dev"
BATCH = 1000
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


class OsvError(RuntimeError):
    pass


def libraries(detections: list[dict[str, Any]]) -> dict[str, list[tuple[dict[str, Any], dict[str, Any]]]]:
    """purl@version -> [(observation, component)] of every library with a purl in the detections."""
    out: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for d in detections:
        for o in d.get("observations") or []:
            for c in o.get("components") or []:
                if c.get("type") == "library" and c.get("purl"):
                    out.setdefault(c["purl"].split("?", 1)[0], []).append((o, c))
    return out


def _fixed(vuln: dict[str, Any], purl: str) -> str:
    """The first version that fixes it for this package, from the ranges of OSV."""
    base = purl.split("@", 1)[0]
    for a in vuln.get("affected") or []:
        pkg = (a.get("package") or {}).get("purl", "")
        if pkg and pkg.split("@", 1)[0] != base:
            continue
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if e.get("fixed"):
                    return str(e["fixed"])
    return ""


class Osv:
    def __init__(self, cache: str | Path | None = None, cache_days: int = 7, transport=None, timeout: float = 60):
        self.cache = Path(cache) if cache else None
        self.cache_days = cache_days
        self.client = httpx.Client(base_url=API, timeout=timeout, transport=transport, trust_env=True,
                                   headers={"User-Agent": "a2vm-detect"})  # fmt: skip

    def query(self, purls: list[str]) -> dict[str, list[str]]:
        """purl@version -> the ids of the vulnerabilities OSV knows for it."""
        out: dict[str, list[str]] = {}
        for i in range(0, len(purls), BATCH):
            chunk = purls[i : i + BATCH]
            try:
                r = self.client.post("/v1/querybatch", json={"queries": [{"package": {"purl": p}} for p in chunk]})
                r.raise_for_status()
                results = r.json().get("results") or []
            except (httpx.HTTPError, ValueError) as exc:
                raise OsvError(f"OSV query: {exc}") from exc
            for purl, res in zip(chunk, results, strict=False):
                ids = [v.get("id", "") for v in (res or {}).get("vulns") or [] if SAFE_ID.match(v.get("id", ""))]
                if ids:
                    out[purl] = ids
        return out

    def vuln(self, vid: str) -> dict[str, Any]:
        path = self.cache / f"{vid}.json" if self.cache else None
        if path and path.exists():
            age = dt.datetime.now(dt.UTC).timestamp() - path.stat().st_mtime
            if age < self.cache_days * 86400:
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except ValueError:
                    pass
        try:
            r = self.client.get(f"/v1/vulns/{vid}")
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OsvError(f"OSV {vid}: {exc}") from exc
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def close(self) -> None:
        self.client.close()


def match(detections: list[dict[str, Any]], tenant: str, osv: Osv, log=print) -> Detection:  # noqa: ANN001
    """The findings of source osv for the libraries of the detections."""
    libs = libraries(detections)
    known = osv.query(sorted(libs)) if libs else {}
    observed_at = now()
    observations: dict[str, AssetObservation] = {}
    findings: dict[str, Finding] = {}
    skipped: Counter[str] = Counter()
    for purl, ids in sorted(known.items()):
        for vid in ids:
            v = osv.vuln(vid)
            cves = sorted({a for a in [v.get("id", ""), *(v.get("aliases") or [])] if CVE.match(a)})
            if not cves:
                skipped[f"no CVE alias ({vid.split('-')[0]})"] += 1
                continue
            fixed = _fixed(v, purl)
            for o, c in libs[purl]:
                ref = o["ref"]
                observations.setdefault(ref, AssetObservation(
                    ref=ref, kind=o.get("kind", "image"), source=SOURCE, observed_at=observed_at,
                    name=o.get("name", ref), description="", identifiers=o.get("identifiers") or {}, attributes={},
                    os=None,
                ))  # fmt: skip
                for cve in cves:
                    fo = FindingObservation(
                        source=SOURCE, observed_at=observed_at,
                        match=Match("exact", "", c["name"], 1.0, f"OSV {vid} for {purl}"),
                        package=c["name"], installed_version=c.get("version", ""), fixed_version=fixed,
                        source_status="fixed" if fixed else "affected",
                    )  # fmt: skip
                    fid = Finding.make_id(tenant, ref, cve)
                    f = findings.get(fid)
                    if f is None:
                        findings[fid] = Finding(fid, tenant, ref, cve, "affected", [c.get("version", "")], [fo])
                    elif fo.package not in {x.package for x in f.observations}:
                        f.observations.append(fo)
    log(f"osv: {len(libs)} libraries, {len(known)} with vulnerabilities, {len(findings)} findings with a CVE")
    return Detection(tenant, SOURCE, list(observations.values()), list(findings.values()), [], dict(skipped))
