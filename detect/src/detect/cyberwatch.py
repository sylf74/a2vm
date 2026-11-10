# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Cyberwatch as a scanner (`cyberwatch`, HLD D20, v0.23.5, LLD vulnerability-detection §3.8).

Cyberwatch scans the tenant's assets with its agents or without (SSH, WinRM, network). A2VM reads
what it found: one host observation per asset, with its identifiers, its OS, its components (the
packages Cyberwatch lists, else the current versions of its updates), and one finding per CVE still
open on the asset (active, not fixed, not ignored in Cyberwatch), with the version found and the
target version of the update that fixes it. Unlike the EDRs it is a scan: the asset counts as
scanned, and its findings are triaged like those of OpenVAS.

Read only: the client sends GET requests only, with the API keys of a Cyberwatch user (HTTP basic
access key and secret key, API v3). Two requests per asset at most: the list by pages, then each
asset's details. The paths are settings (`assets_path`, `asset_path`): they changed between versions
of Cyberwatch.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from a2vm.io import Detection, now
from a2vm.models import AssetObservation, Finding, FindingObservation, Match

from .collect import MAX_COMPONENTS, component

SOURCE = "cyberwatch"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")
RETRIES = 3


class CyberwatchError(RuntimeError):
    pass


@dataclass
class CyberwatchConfig:
    """Settings of a `cyberwatch` connector (collector.yaml) or of `detect cyberwatch fetch`."""

    url: str
    access_key_file: str
    secret_key_file: str
    ca_file: str | None = None
    timeout_seconds: float = 120.0
    page_size: int = 100
    assets_path: str = "/api/v3/vulnerabilities/servers"
    asset_path: str = "/api/v3/vulnerabilities/servers/{id}"
    groups: list[str] | None = None  # only the assets of these Cyberwatch groups (names)
    include_ignored: bool = False  # the CVEs an analyst ignored in Cyberwatch

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "cyberwatch") -> CyberwatchConfig:
        unknown = set(data) - set(cls.__dataclass_fields__) - {"name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("url", "access_key_file", "secret_key_file"):
            if not data.get(key):
                raise ValueError(f"{where}: `{key}` is required")
        if not str(data["url"]).startswith("https://"):
            raise ValueError(f"{where}: `url` must be the https URL of the Cyberwatch master")
        size = int(data.get("page_size", 100))
        if not 1 <= size <= 500:
            raise ValueError(f"{where}: `page_size` from 1 to 500")
        for key in ("assets_path", "asset_path"):
            if key in data and not str(data[key]).startswith("/api/"):
                raise ValueError(f"{where}: `{key}` is a path of the API, starting with /api/")
        if "asset_path" in data and "{id}" not in str(data["asset_path"]):
            raise ValueError(f"{where}: `asset_path` holds {{id}}")
        return cls(
            url=str(data["url"]).rstrip("/"),
            access_key_file=str(data["access_key_file"]),
            secret_key_file=str(data["secret_key_file"]),
            ca_file=data.get("ca_file"),
            timeout_seconds=float(data.get("timeout_seconds", 120)),
            page_size=size,
            assets_path=str(data.get("assets_path") or cls.assets_path),
            asset_path=str(data.get("asset_path") or cls.asset_path),
            groups=[str(g) for g in data["groups"]] if data.get("groups") else None,
            include_ignored=bool(data.get("include_ignored", False)),
        )

    def keys(self) -> tuple[str, str]:
        out = []
        for name in ("access_key_file", "secret_key_file"):
            path = getattr(self, name)
            try:
                value = Path(path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise CyberwatchError(f"{name} {path}: {exc}") from exc
            if not value:
                raise CyberwatchError(f"{name} {path} is empty")
            out.append(value)
        return out[0], out[1]


class CyberwatchClient:
    """HTTP client of the Cyberwatch master, read only."""

    def __init__(
        self,
        cfg: CyberwatchConfig,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.cfg = cfg
        verify: Any = cfg.ca_file or True
        self.http = httpx.Client(timeout=cfg.timeout_seconds, verify=verify, transport=transport)
        self._sleep = sleep
        self._auth: tuple[str, str] | None = None

    def close(self) -> None:
        self.http.close()

    def get(self, path: str, params: dict[str, Any] | None = None, method: str = "GET") -> Any:
        if method != "GET":  # A2VM never changes anything in Cyberwatch
            raise CyberwatchError(f"refused: {method} {path}, Cyberwatch is read only")
        if self._auth is None:
            self._auth = self.cfg.keys()
        headers = {"Accept": "application/json; charset=utf-8"}
        for attempt in range(RETRIES + 1):
            try:
                r = self.http.get(self.cfg.url + path, params=params, headers=headers, auth=self._auth)
            except httpx.HTTPError as exc:
                raise CyberwatchError(f"Cyberwatch not reached: {exc}") from exc
            if r.status_code == 429 and attempt < RETRIES:
                wait = r.headers.get("Retry-After", "")
                self._sleep(min(float(wait), 60.0) if wait.isdigit() else 2.0 * (attempt + 1))
                continue
            break
        if r.status_code in (401, 403):
            raise CyberwatchError(
                f"Cyberwatch refused the API keys ({r.status_code}): wrong keys, or a user without access to the assets"
            )
        if r.status_code == 404:
            raise CyberwatchError(f"Cyberwatch has no {path}: check assets_path and asset_path for this version")
        if r.status_code >= 400:
            raise CyberwatchError(f"Cyberwatch answered {r.status_code} to GET {path}")
        try:
            return r.json()
        except ValueError as exc:
            raise CyberwatchError("Cyberwatch answered something else than JSON (URL of the master?)") from exc

    def assets(self) -> Iterator[dict[str, Any]]:
        """Every asset of the list, page by page, until a short page."""
        page = 1
        while True:
            data = self.get(self.cfg.assets_path, {"page": page, "per_page": self.cfg.page_size})
            items = data if isinstance(data, list) else (data or {}).get("data") or []
            yield from items
            if len(items) < self.cfg.page_size:
                return
            page += 1

    def asset(self, asset_id: Any) -> dict[str, Any]:
        data = self.get(self.cfg.asset_path.replace("{id}", str(asset_id)))
        return data if isinstance(data, dict) else {}


# -- what Cyberwatch found, as a detection ------------------------------------------------------------
def _identifiers(asset: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    name = str(asset.get("hostname") or "").strip().lower()
    if DOMAIN.match(name):
        out["fqdn"], out["hostname"] = name, name.split(".")[0]
    elif HOSTNAME.match(name):
        out["hostname"] = name
    ips, names = [], []
    for value in asset.get("addresses") or []:
        text = str(value.get("value") if isinstance(value, dict) else value).strip()
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            if DOMAIN.match(text.lower()):
                names.append(text.lower())
            continue
        if not (address.is_loopback or address.is_unspecified or address.is_link_local):
            ips.append(str(address))
    if ips:
        out["ips"] = sorted(set(ips))
    if "fqdn" not in out and names:
        out["fqdn"] = sorted(names)[0]
        out.setdefault("hostname", out["fqdn"].split(".")[0])
    return out


def _kind(value: str) -> str:
    """Cyberwatch's type of a package (Packages::Rpm, deb, msi...) as a type of component."""
    text = value.lower()
    for kind in ("rpm", "deb", "apk"):
        if kind in text:
            return kind
    return "win" if any(k in text for k in ("msi", "windows", "kb")) else "application"


def _components(details: dict[str, Any]) -> list[dict[str, str]]:
    """The packages Cyberwatch lists, else the current versions of its updates."""
    rows = details.get("packages") or [u.get("current") or {} for u in details.get("updates") or []]
    comps: dict[tuple[str, str], dict[str, str]] = {}
    for p in rows:
        if not isinstance(p, dict) or p.get("active") is False:
            continue
        name, version = str(p.get("product") or "").strip(), str(p.get("version") or "").strip()
        if not name or not version:
            continue
        kind = _kind(str(p.get("type") or ""))
        comps[(name, version)] = component(name, version, "", kind, "", "", SOURCE, str(p.get("vendor") or "").strip())
    return [comps[k] for k in sorted(comps)][:MAX_COMPONENTS]


def _fixes(details: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    """CVE -> (package, version found, version that fixes it), from the updates of the asset."""
    out: dict[str, tuple[str, str, str]] = {}
    for u in details.get("updates") or []:
        current, target = u.get("current") or {}, u.get("target") or {}
        for cve in u.get("cve_announcements") or []:
            code = str(cve.get("cve_code") if isinstance(cve, dict) else cve).upper()
            out.setdefault(code, (str(current.get("product") or target.get("product") or ""),
                                  str(current.get("version") or ""), str(target.get("version") or "")))  # fmt: skip
    return out


def observation(
    asset: dict[str, Any], details: dict[str, Any], tenant: str, observed_at: str, include_ignored: bool
) -> tuple[AssetObservation | None, list[Finding]]:
    identifiers = _identifiers({**asset, **details})
    name = identifiers.get("hostname") or str(asset.get("hostname") or "").strip()
    if not name:
        return None, []
    ref = f"server:{asset.get('id')}"
    os_info = details.get("os") or asset.get("os") or {}
    groups = sorted(
        {g.get("name", "") for g in details.get("groups") or asset.get("groups") or [] if isinstance(g, dict)} - {""}
    )
    seen = str(
        details.get("analyzed_at") or asset.get("analyzed_at") or details.get("last_communication") or observed_at
    )
    obs = AssetObservation(
        ref=ref,
        kind="host",
        source=SOURCE,
        observed_at=seen,
        name=name,
        description=str(asset.get("description") or "")[:500],
        identifiers=identifiers,
        attributes={"cyberwatch_groups": ", ".join(groups)} if groups else {},
        os=str(os_info.get("name") or "") or None if isinstance(os_info, dict) else str(os_info) or None,
        components=_components(details),
    )
    fixes = _fixes(details)
    findings: dict[str, Finding] = {}
    for c in details.get("cve_announcements") or []:
        code = str(c.get("cve_code") or "").upper()
        if not CVE.match(code) or c.get("active") is False or c.get("fixed_at"):
            continue
        if c.get("ignored") and not include_ignored:
            continue
        package, found, fixed = fixes.get(code, ("", "", ""))
        level = str(c.get("level") or "").removeprefix("level_")
        fo = FindingObservation(
            source=SOURCE,
            observed_at=seen,
            match=Match("scanner", "", package, 1.0, "cyberwatch: CVE open on the asset"),
            package=package,
            installed_version=found,
            fixed_version=fixed,
            source_status="fixed" if fixed else "affected",
            source_severity=level,
        )
        findings[code] = Finding(
            id=Finding.make_id(tenant, ref, code), client_id=tenant, asset_ref=ref, cve_id=code,
            status="affected", affected_versions=[found] if found else [], observations=[fo],
        )  # fmt: skip
    return obs, [findings[k] for k in sorted(findings)]


def fetch(
    cfg: CyberwatchConfig,
    tenant: str,
    client: CyberwatchClient | None = None,
    log: Callable[[str], None] = print,
) -> Detection:
    """Every asset of Cyberwatch with its components and open CVEs, as one detection of source cyberwatch."""
    own = client is None
    client = client or CyberwatchClient(cfg)
    observed_at = now()
    observations: list[AssetObservation] = []
    findings: list[Finding] = []
    skipped: dict[str, int] = {}
    try:
        for asset in client.assets():
            if cfg.groups is not None:
                names = {g.get("name") for g in asset.get("groups") or [] if isinstance(g, dict)}
                if not names & set(cfg.groups):
                    skipped["asset outside the groups"] = skipped.get("asset outside the groups", 0) + 1
                    continue
            details = client.asset(asset.get("id"))
            obs, found = observation(asset, details, tenant, observed_at, cfg.include_ignored)
            if obs is None:
                skipped["asset without a name"] = skipped.get("asset without a name", 0) + 1
                continue
            observations.append(obs)
            findings += found
    finally:
        if own:
            client.close()
    log(f"cyberwatch: {len(observations)} assets, {len(findings)} open CVEs, components on "
        f"{sum(1 for o in observations if o.components)}")  # fmt: skip
    return Detection(tenant, SOURCE, sorted(observations, key=lambda o: o.ref), findings, skipped=skipped)
