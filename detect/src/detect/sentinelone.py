# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""SentinelOne as a source of components (`sentinelone`, HLD D20, v0.23.3, LLD vulnerability-detection
§3.7).

The application inventory SentinelOne's agents collect becomes one host observation per agent: its
name and addresses, its operating system, and every application installed as components
(`source: sentinelone`), each with its publisher. The applications of SentinelOne are not packages
of a distribution: the watch matches them against the CVE records through the tenant's applications
table, where an analyst validates the CPE of each application name (`ngvm.applications`, D11). A
SentinelOne observation carries no finding: its own vulnerability data (Application Risk) is not
read.

Two ways to read it, both read only, with the API token of a service user of role Viewer:

  agents                  `GET /web/api/v2.1/agents`, then `GET /web/api/v2.1/agents/applications`
                          agent by agent (every console)
  installed-applications  `GET /web/api/v2.1/agents`, then `GET /web/api/v2.1/installed-applications`
                          by pages (consoles with Application Risk): fewer requests on a large fleet

The client sends only GET requests: any other is refused before it leaves.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ngvm import tls
from ngvm.io import Detection, now
from ngvm.models import AssetObservation

from .collect import MAX_COMPONENTS, component

SOURCE = "sentinelone"
API = "/web/api/v2.1"
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")
ID = re.compile(r"^[0-9]{1,30}$")
# osType of SentinelOne -> the type of the components, as Wazuh names them (win, pkg).
TYPES = {"windows": "win", "macos": "pkg", "linux": "application"}
RETRIES = 3  # answers 429 (rate limit) waited for, then an error


class SentinelOneError(RuntimeError):
    pass


@dataclass
class SentinelOneConfig:
    """Settings of a `sentinelone` connector (collector.yaml) or of `detect sentinelone fetch`."""

    url: str
    token_file: str
    api: str = "agents"  # agents | installed-applications
    ca_file: str | None = None
    timeout_seconds: float = 120.0
    page_size: int = 500
    site_ids: list[str] = field(default_factory=list)
    account_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "sentinelone") -> SentinelOneConfig:
        unknown = set(data) - set(cls.__dataclass_fields__) - {"name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("url", "token_file"):
            if not data.get(key):
                raise ValueError(f"{where}: `{key}` is required")
        if not str(data["url"]).startswith("https://"):
            raise ValueError(f"{where}: `url` must be the https URL of the console")
        api = str(data.get("api") or "agents")
        if api not in ("agents", "installed-applications"):
            raise ValueError(f"{where}: `api` is agents or installed-applications")
        size = int(data.get("page_size", 500))
        if not 1 <= size <= 1000:
            raise ValueError(f"{where}: `page_size` from 1 to 1000")
        ids: dict[str, list[str]] = {}
        for key in ("site_ids", "account_ids"):
            values = [str(v) for v in (data.get(key) or [])]
            bad = [v for v in values if not ID.match(v)]
            if bad:
                raise ValueError(f"{where}: `{key}` holds numeric ids only, not {bad[0]!r}")
            ids[key] = values
        return cls(
            url=str(data["url"]).rstrip("/"),
            token_file=str(data["token_file"]),
            api=api,
            ca_file=data.get("ca_file"),
            timeout_seconds=float(data.get("timeout_seconds", 120)),
            page_size=size,
            **ids,
        )

    def token(self) -> str:
        try:
            value = Path(self.token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SentinelOneError(f"token_file {self.token_file}: {exc}") from exc
        if not value:
            raise SentinelOneError(f"token_file {self.token_file} is empty")
        return value

    def scope(self) -> dict[str, str]:
        """The filters of the console's scope: sites and accounts, when given."""
        out = {}
        if self.site_ids:
            out["siteIds"] = ",".join(self.site_ids)
        if self.account_ids:
            out["accountIds"] = ",".join(self.account_ids)
        return out


class SentinelOneClient:
    """HTTP client of the management console, read only."""

    def __init__(
        self,
        cfg: SentinelOneConfig,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.cfg = cfg
        self.http = httpx.Client(timeout=cfg.timeout_seconds, verify=tls.verify(cfg.ca_file), transport=transport)
        self._sleep = sleep
        self._headers: dict[str, str] = {}

    def close(self) -> None:
        self.http.close()

    def get(self, path: str, params: dict[str, Any] | None = None, method: str = "GET") -> dict[str, Any]:
        if method != "GET":  # NGVM never changes anything in SentinelOne
            raise SentinelOneError(f"refused: {method} {path}, SentinelOne is read only")
        if not self._headers:
            self._headers = {"Authorization": f"ApiToken {self.cfg.token()}", "Accept": "application/json"}
        for attempt in range(RETRIES + 1):
            try:
                r = self.http.get(self.cfg.url + API + path, params=params, headers=self._headers)
            except httpx.HTTPError as exc:
                raise SentinelOneError(f"SentinelOne not reached: {exc}") from exc
            if r.status_code == 429 and attempt < RETRIES:
                wait = r.headers.get("Retry-After", "")
                self._sleep(min(float(wait), 60.0) if wait.isdigit() else 2.0 * (attempt + 1))
                continue
            break
        if r.status_code in (401, 403):
            raise SentinelOneError(
                f"SentinelOne refused the token ({r.status_code}): expired, or its user lacks the Viewer role"
            )
        if r.status_code >= 400:
            raise SentinelOneError(f"SentinelOne answered {r.status_code} to GET {path}")
        try:
            return r.json()
        except ValueError as exc:
            raise SentinelOneError("SentinelOne answered something else than JSON (URL of the console?)") from exc

    def pages(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Every item of a list of the API, page by page (`pagination.nextCursor`)."""
        query = {**(params or {}), "limit": self.cfg.page_size}
        while True:
            data = self.get(path, query)
            yield from data.get("data") or []
            cursor = (data.get("pagination") or {}).get("nextCursor")
            if not cursor:
                return
            query = {**query, "cursor": cursor}


# -- the inventory as observations ------------------------------------------------------------------
def _identifiers(agent: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    name = str(agent.get("computerName") or "").strip().lower()
    domain = str(agent.get("domain") or "").strip().lower()
    if HOSTNAME.match(name):
        out["hostname"] = name
        if DOMAIN.match(domain):  # a DNS domain, not a NetBIOS one (EXAMPLE, WORKGROUP)
            out["fqdn"] = f"{name}.{domain}"
    elif DOMAIN.match(name):
        out["fqdn"], out["hostname"] = name, name.split(".")[0]
    ips: list[str] = []
    for nic in agent.get("networkInterfaces") or []:
        for value in (nic or {}).get("inet") or []:
            try:
                address = ipaddress.ip_address(str(value).strip())
            except ValueError:
                continue
            if not (address.is_loopback or address.is_unspecified or address.is_link_local):
                ips.append(str(address))
    if ips:
        out["ips"] = sorted(set(ips))
    return out


def _application(app: dict[str, Any], kind: str) -> dict[str, str] | None:
    name, version = str(app.get("name") or "").strip(), str(app.get("version") or "").strip()
    if not name or not version:
        return None
    return component(name, version, "", kind, "", "", SOURCE, str(app.get("publisher") or "").strip())


def observation(agent: dict[str, Any], apps: list[dict[str, Any]], observed_at: str) -> AssetObservation | None:
    """One agent -> one host observation with its applications; None for an agent without a name."""
    identifiers = _identifiers(agent)
    name = identifiers.get("hostname") or str(agent.get("computerName") or "").strip()
    if not name:
        return None
    kind = TYPES.get(str(agent.get("osType") or "").lower(), "application")
    comps: dict[tuple[str, str, str], dict[str, str]] = {}
    for a in apps:
        c = _application(a, kind)
        if c is not None:
            comps[(c["name"], c["version"], c.get("vendor", ""))] = c
    parts = (str(agent.get("osName") or "").strip(), str(agent.get("osRevision") or "").strip())
    os_name = " ".join(x for x in parts if x)
    seen = observed_at if agent.get("isActive", True) else str(agent.get("lastActiveDate") or observed_at)
    return AssetObservation(
        ref=f"agent:{agent.get('id')}",
        kind="host",
        source=SOURCE,
        observed_at=seen,
        name=name,
        description="",
        identifiers=identifiers,
        attributes={},
        os=os_name or None,
        components=[comps[k] for k in sorted(comps)][:MAX_COMPONENTS],
    )


def read_agents(client: SentinelOneClient) -> list[dict[str, Any]]:
    """The agents of the scope, decommissioned ones left out."""
    params = {**client.cfg.scope(), "isDecommissioned": "false"}
    return [a for a in client.pages("/agents", params) if a.get("id")]


def read_per_agent(client: SentinelOneClient, agents: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """The applications of each agent, one request per agent."""
    return {str(a["id"]): client.get("/agents/applications", {"ids": str(a["id"])}).get("data") or [] for a in agents}


def read_installed(client: SentinelOneClient) -> dict[str, list[dict[str, Any]]]:
    """The applications of every agent, by pages of the Application Risk inventory."""
    out: dict[str, list[dict[str, Any]]] = {}
    for app in client.pages("/installed-applications", client.cfg.scope()):
        aid = str(app.get("agentId") or "")
        if aid:
            out.setdefault(aid, []).append(app)
    return out


def fetch(
    cfg: SentinelOneConfig,
    tenant: str,
    client: SentinelOneClient | None = None,
    log: Callable[[str], None] = print,
) -> Detection:
    """Every agent with its applications, as one detection of source `sentinelone` (no finding)."""
    own = client is None
    client = client or SentinelOneClient(cfg)
    observed_at = now()
    try:
        agents = read_agents(client)
        apps = read_installed(client) if cfg.api == "installed-applications" else read_per_agent(client, agents)
    finally:
        if own:
            client.close()
    observations: dict[str, AssetObservation] = {}
    skipped: dict[str, int] = {}
    for agent in agents:
        obs = observation(agent, apps.get(str(agent["id"]), []), observed_at)
        if obs is None:
            skipped["agent without a name"] = skipped.get("agent without a name", 0) + 1
            continue
        if not obs.components:
            skipped["agent without applications"] = skipped.get("agent without applications", 0) + 1
        observations[obs.ref] = obs
    listed = sum(1 for o in observations.values() if o.components)
    log(f"sentinelone: {len(observations)} agents, applications listed on {listed} ({cfg.api})")
    return Detection(tenant, SOURCE, sorted(observations.values(), key=lambda o: o.ref), [], skipped=skipped)
