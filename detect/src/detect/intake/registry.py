# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Who may push and read: the collectors a tenant declares, and the digests of their tokens.

The tenant project declares its collectors in collectors.yaml (LLD detection §8.3):

  collectors:
    - id: homelab-lan
      description: LAN collector
      sources: [trivy, dnf-updateinfo, openvas]
      max_age_hours: 30

The deployment adds a digests file, one line per token: `<collector id> <sha256 of the token>`
(several lines for one collector during a rotation), and `read <sha256>` for the token of the
daily run. The service never sees a token in clear outside a request.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
SOURCE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
READ = "read"


class RegistryError(ValueError):
    pass


def digest(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Collector:
    id: str
    tenant: str
    sources: tuple[str, ...]
    max_age_hours: float
    description: str = ""


@dataclass
class Registry:
    tenant: str
    collectors: dict[str, Collector]
    tokens: dict[str, list[str]] = field(default_factory=dict)  # owner (collector id or "read") -> digests

    def _match(self, token: str | None) -> str | None:
        if not token:
            return None
        d = digest(token)
        for owner, digests in self.tokens.items():
            if any(hmac.compare_digest(d, known) for known in digests):
                return owner
        return None

    def collector_for(self, token: str | None) -> Collector | None:
        owner = self._match(token)
        return self.collectors.get(owner) if owner and owner != READ else None

    def may_read(self, token: str | None) -> bool:
        return self._match(token) == READ

    def max_age(self, source: str) -> float | None:
        ages = [c.max_age_hours for c in self.collectors.values() if source in c.sources]
        return max(ages) if ages else None


def load_collectors(tenant: str, collectors_file: str | Path) -> dict[str, Collector]:
    """The declaration of the tenant project, checked (also run by the pipeline's validate job)."""
    if not ID.match(tenant):
        raise RegistryError(f"invalid tenant id {tenant!r}")
    try:
        data = yaml.safe_load(Path(collectors_file).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RegistryError(f"{collectors_file}: not YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("collectors") or [], list):
        raise RegistryError(f"{collectors_file}: expected `collectors:` and a list")
    collectors: dict[str, Collector] = {}
    for i, entry in enumerate(data.get("collectors") or []):
        where = f"{collectors_file}: collectors[{i}]"
        if not isinstance(entry, dict):
            raise RegistryError(f"{where}: expected a mapping")
        cid = str(entry.get("id", ""))
        if not ID.match(cid) or cid == READ:
            raise RegistryError(f"{where}: invalid id {cid!r}")
        if cid in collectors:
            raise RegistryError(f"{where}: duplicate id {cid!r}")
        raw_sources = entry.get("sources") or []
        if not isinstance(raw_sources, list):
            raise RegistryError(f"{where}: `sources` must be a list")
        sources = tuple(str(s) for s in raw_sources)
        if not sources or not all(SOURCE.match(s) for s in sources):
            raise RegistryError(f"{where}: `sources` must list the sources this collector pushes")
        try:
            max_age = float(entry.get("max_age_hours", 30))
        except (TypeError, ValueError) as exc:
            raise RegistryError(f"{where}: max_age_hours: {exc}") from exc
        if max_age <= 0:
            raise RegistryError(f"{where}: max_age_hours must be positive")
        collectors[cid] = Collector(cid, tenant, sources, max_age, str(entry.get("description", "")))
    return collectors


def load_registry(tenant: str, collectors_file: str | Path, digests_file: str | Path) -> Registry:
    collectors = load_collectors(tenant, collectors_file)
    tokens: dict[str, list[str]] = {}
    path = Path(digests_file)
    if path.exists():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
                raise RegistryError(f"{digests_file}:{n}: expected `<collector id or read> <sha256>`")
            owner, d = parts
            if owner != READ and owner not in collectors:
                raise RegistryError(f"{digests_file}:{n}: unknown collector {owner!r}")
            tokens.setdefault(owner, []).append(d)
    return Registry(tenant, collectors, tokens)
