# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Wazuh as a source of components (`wazuh`, HLD D20, v0.23.1, LLD vulnerability-detection §3.6).

The software inventory Wazuh's agents collect (syscollector) becomes one host observation per
agent: its name and address, its operating system, and every package installed as components
(`source: wazuh`), with the distribution of the agent and the source package of each, so that
pillar 3 keeps them beside those listed over SSH and the watch matches them against the package
advisories of the distributions (`a2vm.packages`). A Wazuh observation carries no finding: Wazuh's
own vulnerability detection is not read.

Two ways to read it, both read only:

  indexer  the Wazuh indexer (OpenSearch, port 9200): the global state indices of recent versions,
           `wazuh-states-inventory-system-*` and `wazuh-states-inventory-packages-*`, read with
           `_search` and scrolls; a user with the read permissions on those indices
  manager  the API of the Wazuh manager (port 55000), every 4.x version: `GET /agents` and
           `GET /syscollector/<agent>/packages`, agent by agent; a user with a read-only role

The client sends only searches (indexer) or GET requests after the authentication (manager): any
other request is refused before it leaves.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from a2vm.io import Detection, now
from a2vm.models import AssetObservation

from .collect import MAX_COMPONENTS, component

SOURCE = "wazuh"
SYSTEM_INDEX = "wazuh-states-inventory-system-*"
PACKAGES_INDEX = "wazuh-states-inventory-packages-*"
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
FQDN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")
# The name of an operating system as Wazuh gives it -> the ID of /etc/os-release.
PLATFORMS = {
    "rocky linux": "rocky", "almalinux": "almalinux", "red hat enterprise linux": "rhel",
    "centos stream": "centos", "centos linux": "centos", "ubuntu": "ubuntu", "debian gnu/linux": "debian",
    "debian": "debian", "oracle linux server": "ol", "fedora linux": "fedora",
}  # fmt: skip
# Package types of Wazuh that are packages of a distribution (the others: win, pkg, pypi, npm...).
DISTRIBUTION_TYPES = {"rpm", "deb"}


class WazuhError(RuntimeError):
    pass


@dataclass
class WazuhConfig:
    """Settings of a `wazuh` connector (collector.yaml) or of `detect wazuh fetch`."""

    url: str
    user: str
    password_file: str
    api: str = "indexer"  # indexer | manager
    ca_file: str | None = None
    timeout_seconds: float = 120.0
    page_size: int = 2000

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "wazuh") -> WazuhConfig:
        unknown = set(data) - set(cls.__dataclass_fields__) - {"name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("url", "user", "password_file"):
            if not data.get(key):
                raise ValueError(f"{where}: `{key}` is required")
        if not str(data["url"]).startswith(("https://", "http://")):
            raise ValueError(f"{where}: `url` must be an http(s) URL")
        api = str(data.get("api") or "indexer")
        if api not in ("indexer", "manager"):
            raise ValueError(f"{where}: `api` is indexer (port 9200) or manager (port 55000)")
        size = int(data.get("page_size", 2000))
        if not 1 <= size <= 10000:
            raise ValueError(f"{where}: `page_size` from 1 to 10000")
        return cls(
            url=str(data["url"]).rstrip("/"),
            user=str(data["user"]),
            password_file=str(data["password_file"]),
            api=api,
            ca_file=data.get("ca_file"),
            timeout_seconds=float(data.get("timeout_seconds", 120)),
            page_size=size,
        )

    def password(self) -> str:
        try:
            value = Path(self.password_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise WazuhError(f"password_file {self.password_file}: {exc}") from exc
        if not value:
            raise WazuhError(f"password_file {self.password_file} is empty")
        return value


class WazuhClient:
    """HTTP client of the indexer or the manager, read only."""

    def __init__(self, cfg: WazuhConfig, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        verify: Any = cfg.ca_file or True
        self.http = httpx.Client(timeout=cfg.timeout_seconds, verify=verify, transport=transport)
        self._token = ""

    def close(self) -> None:
        self.http.close()

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        allowed = (
            (method == "POST" and (path.endswith("/_search") or path == "/_search/scroll"))
            or (method == "DELETE" and path == "/_search/scroll")
            if self.cfg.api == "indexer"
            else method == "GET" or (method == "POST" and path == "/security/user/authenticate")
        )
        if not allowed:  # A2VM never changes anything in Wazuh
            raise WazuhError(f"refused: {method} {path}, Wazuh is read only")
        try:
            response = self.http.request(method, self.cfg.url + path, **kw)
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh {self.cfg.api} not reached: {exc}") from exc
        if response.status_code in (401, 403):
            raise WazuhError(f"Wazuh {self.cfg.api} refused the user {self.cfg.user!r} ({response.status_code})")
        if response.status_code == 404 and self.cfg.api == "indexer":
            raise WazuhError(
                f"no index {path.split('/')[1]!r} on the indexer: a Wazuh version without the inventory "
                "indices, or no agent yet (api: manager reads every 4.x version)"
            )
        if response.status_code >= 400:
            raise WazuhError(f"Wazuh {self.cfg.api} answered {response.status_code} to {method} {path}")
        try:
            return response.json()
        except ValueError as exc:
            raise WazuhError(f"Wazuh {self.cfg.api} answered something else than JSON") from exc

    # -- indexer ---------------------------------------------------------------------------------------
    def search_all(self, index: str, fields: list[str]) -> Iterator[dict[str, Any]]:
        """Every document of an index pattern (its `_source`), by scrolls of `page_size`."""
        auth = (self.cfg.user, self.cfg.password())
        body = {"size": self.cfg.page_size, "_source": fields, "query": {"match_all": {}}, "sort": ["_doc"]}
        data = self._request("POST", f"/{index}/_search", params={"scroll": "2m"}, json=body, auth=auth)
        scroll = data.get("_scroll_id")
        try:
            while True:
                hits = (data.get("hits") or {}).get("hits") or []
                if not hits:
                    return
                for hit in hits:
                    yield hit.get("_source") or {}
                if not scroll:
                    return
                data = self._request("POST", "/_search/scroll", json={"scroll": "2m", "scroll_id": scroll}, auth=auth)
                scroll = data.get("_scroll_id") or scroll
        finally:
            if scroll:  # a scroll not cleared expires by itself
                with contextlib.suppress(WazuhError):
                    self._request("DELETE", "/_search/scroll", json={"scroll_id": [scroll]}, auth=auth)

    # -- manager ---------------------------------------------------------------------------------------
    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._token:
            data = self._request(
                "POST",
                "/security/user/authenticate",
                auth=(self.cfg.user, self.cfg.password()),
                params={"raw": "false"},
            )
            self._token = str(((data.get("data") or {}).get("token")) or "")
            if not self._token:
                raise WazuhError("Wazuh manager: no token in the answer to the authentication")
        return self._request("GET", path, params=params, headers={"Authorization": f"Bearer {self._token}"})

    def items(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Every item of a paged list of the manager's API."""
        offset, limit = 0, min(self.cfg.page_size, 500)
        while True:
            data = (self._get(path, {**(params or {}), "limit": limit, "offset": offset}).get("data")) or {}
            batch = data.get("affected_items") or []
            yield from batch
            offset += len(batch)
            if not batch or offset >= int(data.get("total_affected_items") or 0):
                return


# -- the inventory as observations -----------------------------------------------------------------------
def platform(name: str, given: str = "") -> str:
    """The ID of /etc/os-release for a Wazuh OS name (`Rocky Linux` -> rocky), or the platform
    Wazuh gives when it is one of them."""
    given = given.strip().lower()
    if given in PLATFORMS.values():
        return given
    lowered = name.strip().lower()
    return next((v for k, v in PLATFORMS.items() if lowered.startswith(k)), "")


def distro_of(os_info: dict[str, Any]) -> str:
    """`<platform>-<major>[.<minor>]` (`rocky-9.4`, `ubuntu-22.04`), as the SSH collection names it."""
    plat = platform(str(os_info.get("name") or ""), str(os_info.get("platform") or ""))
    major = str(os_info.get("major") or "").strip()
    minor = str(os_info.get("minor") or "").strip()
    if not plat or not major.isdigit():
        return ""
    return f"{plat}-{major}.{minor}" if minor.isdigit() else f"{plat}-{major}"


def _identifiers(name: str, ip: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    lowered = name.strip().lower()
    if FQDN.match(lowered):
        out["fqdn"] = lowered
        out["hostname"] = lowered.split(".")[0]
    elif HOSTNAME.match(lowered):
        out["hostname"] = lowered
    try:
        address = ipaddress.ip_address(ip.strip())
        if not (address.is_loopback or address.is_unspecified or address.is_link_local):
            out["ips"] = [str(address)]
    except ValueError:
        pass
    return out


def _package(p: dict[str, Any], distro: str) -> dict[str, str] | None:
    name, version = str(p.get("name") or "").strip(), str(p.get("version") or "").strip()
    if not name or not version or name == "gpg-pubkey":
        return None
    kind = str(p.get("type") or p.get("format") or "").strip().lower()
    arch = str(p.get("architecture") or "").strip()
    src = str(p.get("source") or "").strip()
    if kind not in DISTRIBUTION_TYPES:  # a Windows or macOS application: its publisher (v0.23.3)
        return component(name, version, arch, kind, "", "", SOURCE, str(p.get("vendor") or "").strip())
    return component(name, version, arch, kind, src, distro, SOURCE)


def observation(agent: dict[str, Any], packages: list[dict[str, Any]], observed_at: str) -> AssetObservation | None:
    """One agent -> one host observation with its components; None for an agent without a name."""
    name = str(agent.get("hostname") or agent.get("name") or "").strip()
    if not name:
        return None
    os_info = agent.get("os") or {}
    distro = distro_of(os_info)
    comps: dict[tuple[str, str, str], dict[str, str]] = {}
    for p in packages:
        c = _package(p, distro)
        if c is not None:
            comps[(c["name"], c["version"], c["arch"])] = c
    identifiers = _identifiers(name, str(agent.get("ip") or ""))
    os_name = " ".join(x for x in (distro.rsplit("-", 1)[0] if distro else "", str(os_info.get("version") or "")) if x)
    return AssetObservation(
        ref=f"agent:{agent.get('id')}",
        kind="host",
        source=SOURCE,
        observed_at=str(agent.get("seen") or observed_at),
        name=identifiers.get("hostname") or name,
        description="",
        identifiers=identifiers,
        attributes={},
        os=os_name or str(os_info.get("name") or "") or None,
        components=[comps[k] for k in sorted(comps)][:MAX_COMPONENTS],
    )


def _get(doc: dict[str, Any], dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(doc, dict):
            return None
        doc = doc.get(part)
    return doc


def read_indexer(client: WazuhClient) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """(agents, packages by agent id) from the global state indices."""
    agents: dict[str, dict[str, Any]] = {}
    for doc in client.search_all(SYSTEM_INDEX, ["agent", "host"]):
        aid = str(_get(doc, "agent.id") or "")
        if aid:
            agents[aid] = {
                "id": aid,
                "name": _get(doc, "agent.name") or "",
                "hostname": _get(doc, "host.hostname") or "",
                "ip": _get(doc, "agent.host.ip") or "",
                "os": dict(_get(doc, "host.os") or {}),
            }
    packages: dict[str, list[dict[str, Any]]] = {}
    for doc in client.search_all(PACKAGES_INDEX, ["agent.id", "agent.name", "agent.host.ip", "package"]):
        aid = str(_get(doc, "agent.id") or "")
        if not aid:
            continue
        agents.setdefault(
            aid, {"id": aid, "name": _get(doc, "agent.name") or "", "ip": _get(doc, "agent.host.ip") or "", "os": {}}
        )
        packages.setdefault(aid, []).append(dict(doc.get("package") or {}))
    return list(agents.values()), packages


def read_manager(client: WazuhClient) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """(agents, packages by agent id) from the manager's API, agent by agent. An agent never
    connected has no inventory; a disconnected one keeps its last, dated by its last keep-alive."""
    agents, packages = [], {}
    select = "id,name,ip,status,lastKeepAlive,os.name,os.platform,os.version,os.major,os.minor"
    for a in client.items("/agents", {"select": select}):
        if a.get("status") == "never_connected":
            continue
        agent = {"id": str(a.get("id")), "name": a.get("name") or "", "ip": a.get("ip") or "", "os": a.get("os") or {}}
        if a.get("status") == "disconnected" and a.get("lastKeepAlive"):
            agent["seen"] = _iso(str(a["lastKeepAlive"]))
        agents.append(agent)
        select_p = "name,version,architecture,format,source,vendor"
        packages[agent["id"]] = [
            {**p, "type": p.get("format")}
            for p in client.items(f"/syscollector/{agent['id']}/packages", {"select": select_p})
        ]
    return agents, packages


def _iso(value: str) -> str:
    """A date of the manager (`2026-11-06T21:04:12+00:00` or `2026-11-06 21:04:12`) as ISO 8601 UTC."""
    value = value.strip().replace(" ", "T")
    return value if re.search(r"(Z|[+-]\d{2}:?\d{2})$", value) else value + "+00:00"


def fetch(
    cfg: WazuhConfig, tenant: str, client: WazuhClient | None = None, log: Callable[[str], None] = print
) -> Detection:
    """Every agent with its packages, as one detection of source `wazuh` (no finding)."""
    own = client is None
    client = client or WazuhClient(cfg)
    observed_at = now()
    try:
        agents, packages = (read_indexer if cfg.api == "indexer" else read_manager)(client)
    finally:
        if own:
            client.close()
    observations: dict[str, AssetObservation] = {}
    skipped: dict[str, int] = {}
    for agent in agents:
        obs = observation(agent, packages.get(str(agent["id"]), []), observed_at)
        if obs is None:
            skipped["agent without a name"] = skipped.get("agent without a name", 0) + 1
            continue
        if not obs.components:
            skipped["agent without packages"] = skipped.get("agent without packages", 0) + 1
        observations[obs.ref] = obs
    listed = sum(1 for o in observations.values() if o.components)
    log(f"wazuh: {len(observations)} agents, packages listed on {listed} ({cfg.api})")
    return Detection(tenant, SOURCE, sorted(observations.values(), key=lambda o: o.ref), [], skipped=skipped)
