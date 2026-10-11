"""Watch mode: what is new since the last check, and which of it concerns this client.

New items come from three sources, read every few minutes:

  CERT-FR      alerts and advisories (RSS, then the JSON view of each publication)
  CISA KEV     vulnerabilities newly known to be exploited
  cvelistV5    new CVE records that are critical (CVSS >= 9) or exploited according to CISA ADP

An item concerns the client when one of its CVEs matches a declared asset (same matching as the
detection stage), or when a product it names matches a declared asset or the client's watchlist.
The state file remembers what was already seen; the first run only records the current state.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnops.core.config import Settings
from vulnops.core.models import ClientProfile, DeclaredAsset, Finding, VulnRecord
from vulnops.detect.inventory import InventoryScanner
from vulnops.intel.collect import collect
from vulnops.intel.sources import SourceError, Sources

from .certfr import Publication, parse_feed, parse_publication

STATE_VERSION = 1


@dataclass
class State:
    kev: set[str] = field(default_factory=set)
    certfr: set[str] = field(default_factory=set)
    delta_since: str = ""
    path: Path | None = None
    new: bool = False  # no previous state: this run only records the baseline

    @classmethod
    def load(cls, path: str | Path) -> State:
        path = Path(path)
        if not path.exists():
            return cls(path=path, new=True)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(set(data.get("kev", [])), set(data.get("certfr", [])), data.get("delta_since", ""), path)

    def save(self) -> None:
        assert self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": STATE_VERSION, "kev": sorted(self.kev), "certfr": sorted(self.certfr)}
        data["delta_since"] = self.delta_since
        self.path.write_text(json.dumps(data, indent=1), encoding="utf-8")


@dataclass
class Item:
    """One new piece of news: a CERT-FR publication, a KEV addition or a critical new CVE."""

    key: str  # CERTFR-2026-ALE-012 | KEV:CVE-... | CVE:CVE-...
    origin: str  # certfr-alerte | certfr-avis | kev | cve
    title: str
    cves: list[str]
    published: str
    publication: Publication | None = None
    kev: dict[str, Any] | None = None


@dataclass
class Alert:
    """An item that concerns a client, with what is needed to write the fiche."""

    id: str
    client_id: str
    level: str  # urgent | info
    item: Item
    records: list[VulnRecord]
    findings: list[Finding]  # declared assets matched through the CVE records
    product_matches: list[str]  # assets or watchlist entries matched by product name
    assets: dict[str, DeclaredAsset]
    reasons: list[str] = field(default_factory=list)


# -- discovery --------------------------------------------------------------------------------
def discover(sources: Sources, state: State, now: dt.datetime | None = None) -> tuple[list[Item], list[str]]:
    """New items since the state, and the errors met (a failing source does not stop the others)."""
    now = now or dt.datetime.now(dt.UTC)
    items: list[Item] = []
    errors: list[str] = []

    for kind in ("alerte", "avis"):
        try:
            feed = parse_feed(sources.certfr_feed(kind), kind)
        except (SourceError, ValueError) as exc:  # ValueError: XML parse errors
            errors.append(f"CERT-FR {kind}: {exc}")
            continue
        for fi in feed:
            if fi.ref in state.certfr:
                continue
            state.certfr.add(fi.ref)
            if state.new:
                continue
            try:
                data = sources.certfr_item(fi.link)
            except SourceError as exc:
                errors.append(f"{fi.ref}: {exc}")
                data = None
            pub = parse_publication(fi, data)
            items.append(Item(pub.ref, f"certfr-{kind}", pub.title, pub.cves, pub.published, publication=pub))

    try:
        kev = sources.kev()
        in_certfr = {c for it in items for c in it.cves}  # the CERT-FR alert already says it is exploited
        for cve, entry in kev.items():
            if cve in state.kev:
                continue
            state.kev.add(cve)
            if not state.new and cve not in in_certfr:
                title = entry.get("vulnerabilityName") or f"{cve} ajoutée au catalogue KEV"
                items.append(Item(f"KEV:{cve}", "kev", title, [cve], entry.get("dateAdded", ""), kev=entry))
    except SourceError as exc:
        errors.append(f"KEV: {exc}")

    since = dt.datetime.fromisoformat(state.delta_since) if state.delta_since else now - dt.timedelta(hours=1)
    if not state.new:
        try:
            covered = {c for it in items for c in it.cves}
            for cve in sources.new_cve_ids(since, include_updated=False, max_age_hours=0.1):
                if cve not in covered:
                    items.append(Item(f"CVE:{cve}", "cve", cve, [cve], ""))
        except SourceError as exc:
            errors.append(f"cvelistV5: {exc}")
    state.delta_since = now.isoformat()
    return items, errors


# -- relevance ----------------------------------------------------------------------------------
def _specific(name: str, vendor: str = "") -> bool:
    """Names precise enough to look for in free text: several words, or one long word ('core' is not)."""
    name = name.strip()
    return len(name.split()) >= 2 or len(name) >= 5 or (len(name) >= 4 and name.lower() == vendor.lower())


def _phrases(asset: DeclaredAsset) -> set[str]:
    out = {f"{asset.vendor} {asset.product}".strip()}
    out |= {p for p in [asset.product, *asset.product_aliases] if _specific(p, asset.vendor)}
    return {p.lower() for p in out if p}


def _found(phrase: str, texts: list[str]) -> bool:
    pattern = re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])")
    return any(pattern.search(t) for t in texts)


def product_matches(pub: Publication | None, profile: ClientProfile) -> list[str]:
    """Assets and watchlist entries named by a CERT-FR publication's affected systems or title."""
    if not pub:
        return []
    texts = [f"{s['vendor']} {s['product']} {s['description']}".lower() for s in pub.systems] + [pub.title.lower()]
    out = [a.id for a in profile.assets if any(_found(p, texts) for p in _phrases(a))]
    for entry in profile.alerts.get("watchlist", []):
        product = entry.split(" ", 1)[-1]
        phrases = {entry.lower()} | ({product.lower()} if _specific(product) else set())
        if any(_found(p, texts) for p in phrases):
            out.append(f"watchlist: {entry}")
    return out


def exposure(profile: ClientProfile, asset: DeclaredAsset | None) -> str:
    """Declared exposure, else the client's default, else the worst case (as the assets stage does)."""
    return (asset and asset.exposure) or profile.defaults.get("exposure") or "internet"


def _critical(record: VulnRecord) -> bool:
    metric = record.best_cvss()
    exploited = (record.adp_ssvc or {}).get("exploitation") in {"poc", "active"}
    return record.in_kev or exploited or bool(metric and metric.score and metric.score >= 9.0)


def relevant(
    items: list[Item], profile: ClientProfile, sources: Sources, settings: Settings, scanner: InventoryScanner
) -> list[Alert]:
    wanted = sorted({c for it in items for c in it.cves})
    records = {r.cve_id: r for r in collect(sources, wanted).records} if wanted else {}
    assets = {a.id: a for a in profile.assets}
    level_wanted = profile.alerts.get("level", "urgent")
    alerts = []
    for it in items:
        recs = [records[c] for c in it.cves if c in records]
        if it.origin == "cve" and not any(_critical(r) for r in recs):
            continue
        detection = scanner.scan(profile, recs) if recs else None
        findings = list(detection.findings) if detection else []
        by_name = product_matches(it.publication, profile)
        if not findings and not by_name:
            continue
        reasons = []
        if it.origin == "kev" or any(r.in_kev for r in recs):
            reasons.append("exploitation active (catalogue KEV de la CISA)")
        if it.origin == "certfr-alerte":
            reasons.append("alerte CERT-FR")
        if any((r.adp_ssvc or {}).get("exploitation") in {"poc", "active"} for r in recs):
            reasons.append("exploitation ou preuve de concept signalée par la CISA")
        exposed = [f.asset_ref for f in findings if exposure(profile, assets.get(f.asset_ref)) == "internet"]
        if exposed and any(_critical(r) for r in recs):
            reasons.append("vulnérabilité critique sur un actif exposé à Internet")
        level = "urgent" if reasons else "info"
        if level == "info" and level_wanted != "all":
            continue
        alerts.append(
            Alert(
                id=f"{profile.id}-{it.key.replace(':', '-')}",
                client_id=profile.id,
                level=level,
                item=it,
                records=recs,
                findings=findings,
                product_matches=by_name,
                assets=assets,
                reasons=reasons,
            )
        )
    return alerts
