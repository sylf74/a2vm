# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""OSV: the libraries of the language ecosystems against the open vulnerability database (v0.23.11).

The images' libraries (Trivy) and the SBOMs carry each library with its `purl`. Every daily run,
`detect osv` says which vulnerabilities concern each `purl@version`, keeps those known by a CVE (an
alias), and writes them as the findings of source `osv`: the triage decides on them as on any
finding. The hosts are not touched again: a new vulnerability of a library already listed is found
from the list.

Three modes (`A2VM_OSV_MODE`, v0.23.12):

- `offline` (default): the libraries are matched here, against a copy of OSV (`a2vm.osvdb`): the
  index of each ecosystem from the shared intelligence service (`GET /v1/osv/<ecosystem>`) when the
  tenant has one, else built from OSV's archive (`<Ecosystem>/all.zip`). No library leaves the
  tenant: only the archive, the same for everyone, crosses the network.
- `api`: each `purl@version` is sent to api.osv.dev (`POST /v1/querybatch`, the pages of an answer
  followed, then `GET /v1/vulns/<id>`, cached): the tenant's inventory goes to Google. For a test, or
  a tenant that accepts it in writing.
- `off`: nothing (`A2VM_OSV_ENABLED=false`, v0.23.11, says the same).

Through the corporate proxy like every public source (`HTTPS_PROXY`, `SSL_CERT_FILE`). A
vulnerability known only by its GHSA or PYSEC id is counted, not kept: the pipeline decides on CVEs.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from a2vm import osvdb
from a2vm.io import Detection, now
from a2vm.models import AssetObservation, Finding, FindingObservation, Match

SOURCE = "osv"
API = "https://api.osv.dev"
BATCH = 1000
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MODES = ("offline", "api", "off")
MAX_PAGES = 20


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
        """purl@version -> the ids of the vulnerabilities OSV knows for it; an answer cut in pages
        (`next_page_token`, a package with many vulnerabilities) is followed (v0.23.12)."""
        out: dict[str, list[str]] = {}
        for i in range(0, len(purls), BATCH):
            pending = {p: "" for p in purls[i : i + BATCH]}
            for _ in range(MAX_PAGES):
                if not pending:
                    break
                queries = [{"package": {"purl": p}, **({"page_token": t} if t else {})} for p, t in pending.items()]
                try:
                    r = self.client.post("/v1/querybatch", json={"queries": queries})
                    r.raise_for_status()
                    results = r.json().get("results") or []
                except (httpx.HTTPError, ValueError) as exc:
                    raise OsvError(f"OSV query: {exc}") from exc
                following = {}
                for purl, res in zip(list(pending), results, strict=False):
                    res = res or {}
                    ids = [v.get("id", "") for v in res.get("vulns") or [] if SAFE_ID.match(v.get("id", ""))]
                    if ids:
                        out.setdefault(purl, []).extend(x for x in ids if x not in out.get(purl, []))
                    if res.get("next_page_token"):
                        following[purl] = str(res["next_page_token"])
                pending = following
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


class _Findings:
    """The observations and findings of source osv, as the matches come."""

    def __init__(self, tenant: str):
        self.tenant = tenant
        self.observed_at = now()
        self.observations: dict[str, AssetObservation] = {}
        self.findings: dict[str, Finding] = {}
        self.skipped: Counter[str] = Counter()

    def add(self, o: dict[str, Any], c: dict[str, Any], vid: str, purl: str, cves: list[str], fixed: str) -> None:
        ref = o["ref"]
        self.observations.setdefault(ref, AssetObservation(
            ref=ref, kind=o.get("kind", "image"), source=SOURCE, observed_at=self.observed_at,
            name=o.get("name", ref), description="", identifiers=o.get("identifiers") or {}, attributes={},
            os=None,
        ))  # fmt: skip
        for cve in cves:
            fo = FindingObservation(
                source=SOURCE, observed_at=self.observed_at,
                match=Match("exact", "", c["name"], 1.0, f"OSV {vid} for {purl}"),
                package=c["name"], installed_version=c.get("version", ""), fixed_version=fixed,
                source_status="fixed" if fixed else "affected",
            )  # fmt: skip
            fid = Finding.make_id(self.tenant, ref, cve)
            f = self.findings.get(fid)
            if f is None:
                self.findings[fid] = Finding(fid, self.tenant, ref, cve, "affected", [c.get("version", "")], [fo])
            elif fo.package not in {x.package for x in f.observations}:
                f.observations.append(fo)

    def detection(self) -> Detection:
        return Detection(self.tenant, SOURCE, list(self.observations.values()), list(self.findings.values()), [],
                         dict(self.skipped))  # fmt: skip


def match(detections: list[dict[str, Any]], tenant: str, osv: Osv, log=print) -> Detection:  # noqa: ANN001
    """Mode api: the findings of source osv for the libraries of the detections, from api.osv.dev."""
    libs = libraries(detections)
    known = osv.query(sorted(libs)) if libs else {}
    out = _Findings(tenant)
    for purl, ids in sorted(known.items()):
        for vid in ids:
            v = osv.vuln(vid)
            cves = sorted({a for a in [v.get("id", ""), *(v.get("aliases") or [])] if CVE.match(a)})
            if not cves:
                out.skipped[f"no CVE alias ({vid.split('-')[0]})"] += 1
                continue
            fixed = _fixed(v, purl)
            for o, c in libs[purl]:
                out.add(o, c, vid, purl, cves, fixed)
    log(f"osv: {len(libs)} libraries, {len(known)} with vulnerabilities, {len(out.findings)} findings with a CVE")
    return out.detection()


def ecosystems_of(detections: list[dict[str, Any]]) -> list[str]:
    """The ecosystems the libraries of the detections belong to (the indexes to read)."""
    found = {k[0] for p in libraries(detections) if (k := osvdb.from_purl(p))}
    return sorted(found)


def match_offline(
    detections: list[dict[str, Any]],
    tenant: str,
    indexes: dict[str, dict[str, Any]],
    log=print,  # noqa: ANN001
) -> Detection:
    """Mode offline: the libraries matched here against the indexes of OSV, by ecosystem."""
    libs = libraries(detections)
    out = _Findings(tenant)
    affected = 0
    for purl, uses in sorted(libs.items()):
        key = osvdb.from_purl(purl)
        if not key:
            out.skipped["ecosystem not in the copy of OSV"] += 1
            continue
        eco, name, version = key
        index = indexes.get(eco)
        if index is None:
            out.skipped[f"no index for {eco}"] += 1
            continue
        found, undecided = osvdb.match(index, name, version)
        if undecided:
            out.skipped["version undecided (GIT ranges only)"] += undecided
        affected += bool(found)
        for vid, cves, fixed in found:
            for o, c in uses:
                out.add(o, c, vid, purl, cves, fixed)
    log(f"osv: {len(libs)} libraries, {affected} affected, {len(out.findings)} findings with a CVE (offline)")
    return out.detection()


class IndexSource:
    """Where the indexes come from in mode offline: the shared intelligence service, else OSV's
    archives. Each index is kept in `cache`: the service answers 304 when it has not changed; when it
    cannot be reached, the index kept is used, with a warning."""

    def __init__(self, cache: str | Path, intel_url: str = "", intel_token: str = "", transport=None,
                 timeout: float = 300):  # fmt: skip
        self.mirror = osvdb.OsvMirror(cache)
        self.intel_url = intel_url.rstrip("/")
        headers = {"User-Agent": "a2vm-detect"}
        if self.intel_url and intel_token:
            headers["Authorization"] = f"Bearer {intel_token}"
        self.client = httpx.Client(timeout=httpx.Timeout(timeout, connect=15.0), transport=transport,
                                   trust_env=True, headers=headers, follow_redirects=True)  # fmt: skip
        self.warnings: list[str] = []

    def where(self) -> str:
        return f"the shared service {self.intel_url}" if self.intel_url else "OSV's archives"

    def get(self, ecosystem: str) -> dict[str, Any] | None:
        try:
            if self.intel_url:
                self._from_intel(ecosystem)
            else:
                self.mirror.refresh(ecosystem, self.client, now())
        except (osvdb.OsvDbError, httpx.HTTPError) as exc:
            self.warnings.append(str(exc))
        try:
            return self.mirror.load(ecosystem)
        except osvdb.OsvDbError as exc:
            self.warnings.append(str(exc))
            return None

    def _from_intel(self, ecosystem: str) -> None:
        meta = self.mirror.meta(ecosystem)
        headers = {"If-None-Match": meta["etag"]} if meta.get("etag") and self.mirror.path(ecosystem).exists() else {}
        r = self.client.get(f"{self.intel_url}/v1/osv/{ecosystem}", headers=headers)
        if r.status_code == 304:
            return
        if r.status_code >= 400:
            raise osvdb.OsvDbError(f"osv {ecosystem}: the shared service answered {r.status_code}")
        index = osvdb.load_index(r.content)
        meta = {"etag": r.headers.get("ETag", ""), **{k: index.get(k, "") for k in ("built", "records", "kept")}}
        self.mirror.save(ecosystem, r.content, meta)

    def close(self) -> None:
        self.client.close()
