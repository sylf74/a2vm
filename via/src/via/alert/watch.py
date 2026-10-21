# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Watch mode: what is new since the last check, and which of it concerns this client.

New items come from the sources of the catalogue (config/watch-sources.yaml), read every few
minutes and labelled institutional, vendor or research:

  certfr    CERT-FR alerts and advisories (RSS, then the JSON view of each publication)
  kev       CISA KEV: vulnerabilities newly known to be exploited
  cvelist   new CVE records (cvelistV5); "cna" entries name the vendors whose records are labelled
            with the vendor (Dell, Lenovo, Supermicro... publish their CVEs as CNAs, without a feed)
  rss       any RSS / Atom / RDF feed (CISA, CERT-EU, Microsoft, Fortinet, Palo Alto, HPE...)
  csaf      CSAF providers (Cisco, Siemens...): structured advisories with products and fixes

An item concerns the client when one of its CVEs matches a declared asset (same matching as the
detection stage), or when a product it names matches a declared asset or the client's watchlist.
The state file remembers what was already seen; the first run of each source only records its
current state. A CVE already alerted in the last 14 days is not alerted again from another source,
except when it becomes known as exploited (KEV).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from a2vm.config import Settings
from a2vm.extensions import AssetMatcher
from a2vm.gti import ssvc_exploitation
from a2vm.models import Asset, ClientProfile, DeclaredAsset, Finding, VulnRecord, exposure_value
from via.intel.collect import collect
from via.intel.sources import SourceError, Sources

from .certfr import Publication, parse_feed, parse_publication
from .feeds import MAX_NEW_PER_RUN, Source, parse_generic_feed, read_csaf
from .inventory import Inventory

STATE_VERSION = 2
SEEN_KEEP = 3000  # ids remembered per source
REALERT_DAYS = 14


@dataclass
class State:
    kev: set[str] = field(default_factory=set)
    certfr: set[str] = field(default_factory=set)
    delta_since: str = ""
    path: Path | None = None
    new: bool = False  # no previous state at all: this run only records the baseline
    seen: dict[str, list[str]] = field(default_factory=dict)  # rss sources: ids already seen
    marks: dict[str, str] = field(default_factory=dict)  # csaf sources: newest timestamp seen
    alerted: dict[str, str] = field(default_factory=dict)  # CVE -> date of the last alert

    @classmethod
    def load(cls, path: str | Path) -> State:
        path = Path(path)
        if not path.exists():
            return cls(path=path, new=True)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            set(data.get("kev", [])),
            set(data.get("certfr", [])),
            data.get("delta_since", ""),
            path,
            seen=data.get("seen", {}),
            marks=data.get("marks", {}),
            alerted=data.get("alerted", {}),
        )

    def save(self) -> None:
        assert self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cutoff = (dt.date.today() - dt.timedelta(days=60)).isoformat()
        data = {
            "version": STATE_VERSION,
            "kev": sorted(self.kev),
            "certfr": sorted(self.certfr),
            "delta_since": self.delta_since,
            "seen": {k: v[-SEEN_KEEP:] for k, v in self.seen.items()},
            "marks": self.marks,
            "alerted": {c: d for c, d in self.alerted.items() if d >= cutoff},
        }
        self.path.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def recently_alerted(self, cve: str, today: dt.date | None = None) -> bool:
        when = self.alerted.get(cve)
        today = today or dt.date.today()
        return bool(when) and (today - dt.date.fromisoformat(when)).days < REALERT_DAYS


@dataclass
class Item:
    """One new piece of news: a CERT-FR publication, a KEV addition or a critical new CVE."""

    key: str  # CERTFR-2026-ALE-012 | KEV:CVE-... | CVE:CVE-... | <source id>:<ref>
    origin: str  # certfr-alerte | certfr-avis | kev | cve | <source id>
    title: str
    cves: list[str]
    published: str
    publication: Publication | None = None
    kev: dict[str, Any] | None = None
    source: str = ""  # source name, e.g. "CERT-FR — alertes"
    category: str = "institutional"  # institutional | vendor | research
    urgent_source: bool = False  # every publication of the source is urgent


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
    detected: list[tuple[Asset, Finding]] = field(default_factory=list)  # from the last daily inventory
    inventory_as_of: str = ""


# -- discovery --------------------------------------------------------------------------------
def default_catalogue() -> list[Source]:
    """CERT-FR, KEV and cvelistV5 only: what the watch mode reads without a catalogue file."""
    return [
        Source("certfr-alerte", "CERT-FR — alertes", "institutional", "certfr", feed="alerte", urgent=True),
        Source("certfr-avis", "CERT-FR — avis", "institutional", "certfr", feed="avis"),
        Source("cisa-kev", "CISA — KEV", "institutional", "kev", urgent=True),
        Source("cvelist", "CVE (cvelistV5)", "institutional", "cvelist"),
    ]


def discover(
    sources: Sources, state: State, now: dt.datetime | None = None, catalogue: list[Source] | None = None
) -> tuple[list[Item], list[str]]:
    """New items since the state, and the errors met (a failing source does not stop the others)."""
    now = now or dt.datetime.now(dt.UTC)
    catalogue = [s for s in (catalogue or default_catalogue()) if s.enabled]
    items: list[Item] = []
    errors: list[str] = []

    for src in [s for s in catalogue if s.kind == "certfr"]:
        try:
            feed = parse_feed(sources.certfr_feed(src.feed), src.feed)
        except (SourceError, ValueError) as exc:  # ValueError: XML parse errors
            errors.append(f"{src.name}: {exc}")
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
            items.append(
                Item(pub.ref, f"certfr-{src.feed}", pub.title, pub.cves, pub.published, publication=pub,
                     source=src.name, category=src.category, urgent_source=src.urgent)
            )  # fmt: skip

    for src in [s for s in catalogue if s.kind in ("rss", "csaf")]:
        baseline = state.new or src.id not in (state.seen if src.kind == "rss" else state.marks)
        try:
            if src.kind == "rss":
                pubs = parse_generic_feed(sources.fetch_text(src.url), src)
                known = set(state.seen.get(src.id, []))
                fresh = [p for p in pubs if p.ref not in known]
                state.seen[src.id] = state.seen.get(src.id, []) + [p.ref for p in fresh]
                fresh = [] if baseline else fresh[:MAX_NEW_PER_RUN]
            else:
                fresh, newest = read_csaf(sources, src, "" if baseline else state.marks.get(src.id, ""))
                state.marks[src.id] = newest
        except (SourceError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{src.name}: {exc}")
            continue
        for pub in fresh:
            items.append(
                Item(f"{src.id}:{pub.ref}", src.id, pub.title, pub.cves, pub.published, publication=pub,
                     source=src.name, category=src.category, urgent_source=src.urgent)
            )  # fmt: skip

    kev_src = next((s for s in catalogue if s.kind == "kev"), None)
    if kev_src:
        try:
            kev = sources.kev()
            # a publication of this run already covers the CVE: it will say it is exploited
            in_items = {c for it in items for c in it.cves}
            for cve, entry in kev.items():
                if cve in state.kev:
                    continue
                state.kev.add(cve)
                if not state.new and cve not in in_items:
                    title = entry.get("vulnerabilityName") or f"{cve} ajoutée au catalogue KEV"
                    items.append(
                        Item(f"KEV:{cve}", "kev", title, [cve], entry.get("dateAdded", ""), kev=entry,
                             source=kev_src.name, category=kev_src.category, urgent_source=True)
                    )  # fmt: skip
        except SourceError as exc:
            errors.append(f"{kev_src.name}: {exc}")

    cve_src = next((s for s in catalogue if s.kind == "cvelist"), None)
    if cve_src:
        since = dt.datetime.fromisoformat(state.delta_since) if state.delta_since else now - dt.timedelta(hours=1)
        if not state.new:
            try:
                covered = {c for it in items for c in it.cves}
                for cve in sources.new_cve_ids(since, include_updated=False, max_age_hours=0.1):
                    if cve not in covered:
                        items.append(Item(f"CVE:{cve}", "cve", cve, [cve], "", source=cve_src.name))
            except SourceError as exc:
                errors.append(f"{cve_src.name}: {exc}")
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


def item_texts(item: Item, records: list[VulnRecord]) -> list[str]:
    """Where to look for product names: affected systems and title of a publication (and its summary
    when it lists no systems), else the vendor / product of the CVE records."""
    pub = item.publication
    texts = []
    if pub:
        texts += [f"{s['vendor']} {s['product']} {s['description']}".lower() for s in pub.systems]
        texts.append(pub.title.lower())
        if not pub.systems and pub.summary:
            texts.append(pub.summary.lower())
    texts += [f"{e.vendor} {e.product}".lower() for r in records for e in r.affected]
    return texts


def product_matches(texts: list[str], profile: ClientProfile) -> list[str]:
    """Assets and watchlist entries named in `texts`."""
    if not texts:
        return []
    out = [a.id for a in profile.assets if any(_found(p, texts) for p in _phrases(a))]
    for entry in profile.alerts.get("watchlist", []):
        product = entry.split(" ", 1)[-1]
        phrases = {entry.lower()} | ({product.lower()} if _specific(product) else set())
        if any(_found(p, texts) for p in phrases):
            out.append(f"watchlist: {entry}")
    return out


def cna_label(records: list[VulnRecord], catalogue: list[Source]) -> str:
    """Name of the catalogue's CNA entry whose vendors appear in the records, if any."""
    vendors = {e.vendor.lower() for r in records for e in r.affected}
    for src in catalogue:
        if src.kind == "cna" and src.enabled and vendors & {v.lower() for v in src.vendors}:
            return src.name
    return ""


def exposure(profile: ClientProfile, asset: DeclaredAsset | None) -> str:
    """Declared exposure, else the client's default, else the worst case (as the assets stage does)."""
    return exposure_value((asset and asset.exposure) or profile.defaults.get("exposure") or "open")


def _critical(record: VulnRecord) -> bool:
    metric = record.best_cvss()
    exploited = (record.adp_ssvc or {}).get("exploitation") in {"poc", "active"}
    exploited = exploited or ssvc_exploitation(record.gti)[0] in {"poc", "active"}
    return record.in_kev or exploited or bool(metric and metric.score and metric.score >= 9.0)


def _open(asset: Asset) -> bool:
    return exposure_value(asset.attributes["exposure"].value) == "open"


def relevant(
    items: list[Item],
    profile: ClientProfile,
    sources: Sources,
    settings: Settings,
    scanner: AssetMatcher,
    state: State | None = None,
    catalogue: list[Source] | None = None,
    inventory: Inventory | None = None,
) -> list[Alert]:
    wanted = sorted({c for it in items for c in it.cves})
    records: dict[str, VulnRecord] = {}
    if wanted:
        collection = collect(sources, wanted)
        records = {r.cve_id: r for r in collection.records}
        for note in collection.notes:
            print(note)
    assets = {a.id: a for a in profile.assets}
    level_wanted = profile.alerts.get("level", "urgent")
    alerts = []
    for it in items:
        recs = [records[c] for c in it.cves if c in records]
        if state and it.origin != "kev" and it.cves and all(state.recently_alerted(c) for c in it.cves):
            continue  # already alerted from another source; KEV (now exploited) is the exception
        detection = scanner.scan(profile, recs) if recs else None
        findings = list(detection.findings) if detection else []
        by_name = product_matches(item_texts(it, recs), profile)
        detected = []
        if inventory is not None:
            for cve in it.cves:
                for f in inventory.findings_by_cve.get(cve, []):
                    asset = inventory.assets.get(f.asset_ref)
                    if asset is not None:
                        detected.append((asset, f))
        if not findings and not by_name and not detected:
            continue
        if it.origin == "cve":
            label = cna_label(recs, catalogue or [])
            if label:
                it.source, it.category = label, "vendor"
        reasons = []
        if it.origin == "kev" or any(r.in_kev for r in recs):
            reasons.append("exploitation active (catalogue KEV de la CISA)")
        elif any(ssvc_exploitation(r.gti)[0] == "active" for r in recs):  # often before KEV
            reasons.append("exploitation confirmée par Google Threat Intelligence")
        if it.urgent_source and it.origin != "kev":
            reasons.append(f"publication {it.source}")
        if any((r.adp_ssvc or {}).get("exploitation") in {"poc", "active"} for r in recs):
            reasons.append("exploitation ou preuve de concept signalée par la CISA")
        exposed = [f.asset_ref for f in findings if exposure(profile, assets.get(f.asset_ref)) == "open"]
        exposed += [a.id for a, _ in detected if "exposure" in a.attributes and _open(a)]
        if exposed and any(_critical(r) for r in recs):
            reasons.append("vulnérabilité critique sur un actif exposé à Internet")
        level = "urgent" if reasons else "info"
        if level == "info" and level_wanted != "all":
            continue
        alerts.append(
            Alert(
                id=f"{profile.id}-{re.sub(r'[^A-Za-z0-9._-]+', '-', it.key)[:120]}",
                client_id=profile.id,
                level=level,
                item=it,
                records=recs,
                findings=findings,
                product_matches=by_name,
                assets=assets,
                reasons=reasons,
                detected=detected,
                inventory_as_of=inventory.as_of if inventory else "",
            )
        )
    if state:
        today = dt.date.today().isoformat()
        for a in alerts:
            for c in a.item.cves:
                state.alerted[c] = today
    return alerts
