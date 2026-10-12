# SPDX-License-Identifier: AGPL-3.0-only
"""Consolidate the asset observations of one client into an inventory, and re-key its findings.

Reconciliation (minimal first scope): two host observations are the same asset when they share an
FQDN, a short host name or an address; image observations merge on the image reference; declared
assets stay as declared (they may describe a product family rather than a machine).

Attributes (exposure, mission_prevalence, public_wellbeing_impact, owner), first source wins:
  1. declared   the client profile declares it for this asset
  2. rule       a profile rule matches the host name, FQDN or address
  3. <scanner>  a source reported it (e.g. a scanner tag)
  4. default    the client's default assumption, or the built-in worst case — flagged in reports
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field

from vulnops.core.io import Detection
from vulnops.core.models import (
    ATTRIBUTES,
    Asset,
    AssetObservation,
    Attribute,
    AttributeRule,
    ClientProfile,
    Finding,
    NotAffected,
)

WORST_CASE = {
    "exposure": "internet",
    "mission_prevalence": "essential",
    "public_wellbeing_impact": "minimal",
    "owner": "inconnu",
}


@dataclass
class Inventory:
    client_id: str
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    not_affected: list[NotAffected] = field(default_factory=list)


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def _keys(o: AssetObservation) -> list[tuple[str, str]]:
    ids = o.identifiers
    if o.kind == "declared":
        return [("declared", o.ref)]
    if o.kind == "image":
        return [("image", str(ids.get("image") or o.ref))]
    keys = []
    if ids.get("fqdn"):
        keys.append(("fqdn", str(ids["fqdn"]).lower()))
    if ids.get("hostname"):
        keys.append(("hostname", str(ids["hostname"]).lower()))
    keys += [("ip", ip) for ip in ids.get("ips", [])]
    return keys or [("ref", o.ref)]


def _rule_matches(rule: AttributeRule, ids: dict) -> bool:
    checks = []
    if rule.hostname:
        checks.append(any(fnmatch.fnmatch(h, rule.hostname.lower()) for h in ids.get("hostnames", [])))
    if rule.fqdn:
        checks.append(any(fnmatch.fnmatch(f, rule.fqdn.lower()) for f in ids.get("fqdns", [])))
    if rule.ip:
        net = ipaddress.ip_network(rule.ip, strict=False)
        checks.append(any(ipaddress.ip_address(ip) in net for ip in ids.get("ips", [])))
    return bool(checks) and all(checks)


def _merge_identifiers(group: list[AssetObservation]) -> dict:
    fqdns = sorted({str(o.identifiers["fqdn"]).lower() for o in group if o.identifiers.get("fqdn")})
    hostnames = sorted({str(o.identifiers["hostname"]).lower() for o in group if o.identifiers.get("hostname")})
    ips = sorted({ip for o in group for ip in o.identifiers.get("ips", [])})
    images = sorted({str(o.identifiers["image"]) for o in group if o.identifiers.get("image")})
    out: dict = {}
    if fqdns:
        out["fqdns"] = fqdns
    if hostnames:
        out["hostnames"] = hostnames
    if ips:
        out["ips"] = ips
    if images:
        out["images"] = images
    return out


def _asset_id(kind: str, group: list[AssetObservation], ids: dict) -> str:
    if kind == "declared":
        return f"declared:{group[0].ref}"
    if kind == "image":
        return f"image:{ids.get('images', [group[0].ref])[0]}"
    key = (ids.get("fqdns") or ids.get("hostnames") or ids.get("ips") or [group[0].ref])[0]
    return f"host:{key}"


def _attributes(profile: ClientProfile, group: list[AssetObservation], ids: dict, kind: str) -> dict[str, Attribute]:
    out: dict[str, Attribute] = {}
    defaults = {**WORST_CASE, **profile.defaults}
    for name in ATTRIBUTES:
        declared = next((o for o in group if o.kind == "declared" and name in o.attributes), None)
        if declared:
            out[name] = Attribute(declared.attributes[name], "declared")
            continue
        rule = None
        if kind != "declared":
            rule = next((r for r in profile.rules if name in r.set and _rule_matches(r, ids)), None)
        if rule:
            where = rule.hostname or rule.fqdn or rule.ip or ""
            out[name] = Attribute(rule.set[name], "rule", rule.description or where)
            continue
        seen = next((o for o in group if name in o.attributes), None)
        if seen:
            out[name] = Attribute(seen.attributes[name], seen.source)
            continue
        origin = "client default" if name in profile.defaults else "worst case"
        out[name] = Attribute(defaults[name], "default", origin)
    return out


def build_inventory(profile: ClientProfile, detections: list[Detection]) -> Inventory:
    observations: list[AssetObservation] = []
    for d in detections:
        if d.client_id != profile.id:
            raise ValueError(f"detection of {d.client_id!r} given for client {profile.id!r}")
        observations.extend(d.observations)

    uf = _UnionFind(len(observations))
    first_by_key: dict[tuple[str, str], int] = {}
    for i, o in enumerate(observations):
        for key in _keys(o):
            if key in first_by_key:
                uf.union(i, first_by_key[key])
            else:
                first_by_key[key] = i
    groups: dict[int, list[int]] = {}
    for i in range(len(observations)):
        groups.setdefault(uf.find(i), []).append(i)

    inv = Inventory(profile.id)
    asset_of: dict[tuple[str, str], Asset] = {}  # (source, observation ref) -> asset
    for members in groups.values():
        group = [observations[i] for i in members]
        kind = group[0].kind
        ids = _merge_identifiers(group)
        seen = sorted(o.observed_at for o in group)
        name = group[0].name if kind == "declared" else (ids.get("hostnames") or [group[0].name])[0]
        os_name = next((o.os for o in group if o.os), None)
        description = next((o.description for o in group if o.description), "")
        if not description:
            description = f"{name} ({os_name})" if os_name else name
        asset = Asset(
            id=_asset_id(kind, group, ids),
            client_id=profile.id,
            kind=kind,
            name=name,
            description=description,
            identifiers=ids,
            attributes=_attributes(profile, group, ids, kind),
            sources=sorted({o.source for o in group}),
            first_seen=seen[0],
            last_seen=seen[-1],
            os=os_name,
        )
        inv.assets.append(asset)
        for o in group:
            asset_of[(o.source, o.ref)] = asset
    inv.assets.sort(key=lambda a: a.id)

    merged: dict[tuple[str, str], Finding] = {}
    for d in detections:
        for f in d.findings:
            asset = asset_of.get((d.source, f.asset_ref))
            if asset is None:
                raise ValueError(f"{d.source}: finding {f.id} refers to an unknown asset {f.asset_ref!r}")
            key = (asset.id, f.cve_id)
            if key not in merged:
                merged[key] = Finding(
                    id=Finding.make_id(profile.id, asset.id, f.cve_id),
                    client_id=profile.id,
                    asset_ref=asset.id,
                    cve_id=f.cve_id,
                    status=f.status,
                    affected_versions=list(f.affected_versions),
                    observations=list(f.observations),
                    review_reasons=list(f.review_reasons),
                )
                continue
            m = merged[key]
            m.observations.extend(f.observations)
            m.affected_versions += [v for v in f.affected_versions if v not in m.affected_versions]
            m.review_reasons += [r for r in f.review_reasons if r not in m.review_reasons]
            if f.status == "affected":
                m.status = "affected"
        for n in d.not_affected:
            asset = asset_of.get((d.source, n.asset_id))
            inv.not_affected.append(
                NotAffected(n.client_id, n.cve_id, asset.name if asset else n.asset_id, n.deployed_versions, n.source)
            )
    inv.findings = list(merged.values())
    return inv
