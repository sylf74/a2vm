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
  intel     the feed of the shared intelligence service (D17, v0.22.0): the radar's validated events,
            and GTI's vulnerabilities on the technologies watched
  gti       a GTI search (licensed, optional): for the radar, the vulnerabilities exploited, tagged
            zero-day or rated critical, whoever they concern (v0.22.0)

An item concerns the client when one of its CVEs matches a declared asset (same matching as the
detection stage), or when a product it names matches a declared asset or the client's watchlist.
Since v0.23.0 (D20) it also concerns the client when the packages listed on its hosts by the last
daily run hold an affected version (the package advisories of the distributions, `a2vm.packages`):
the alert names those hosts within minutes, with no scan. Each asset named carries a level of proof:

  confirmed  a scan or an authenticated check of the last daily run sees the flaw
  exposed    the inventory holds an affected version (packages listed, with their date), or a
             version declared in the profile is in the affected range
  possible   the product is there, its version against the record unknown: a package named like the
             product on a distribution the advisories do not cover yet, a declared asset without a
             version, a product named by the publication, a distribution still investigating

The level is evidence for the analyst; it changes no decision (D4).

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

from a2vm import applications
from a2vm.config import Settings
from a2vm.declared import DeclaredMatcher
from a2vm.gti import ssvc_exploitation
from a2vm.models import Asset, ClientProfile, DeclaredAsset, Finding, VulnRecord, exposure_value
from a2vm.packages import INVESTIGATING, Exposure, covered, exposures, present
from via.intel.collect import collect
from via.intel.gti import RADAR_FILTER, discovered
from via.intel.remote import IntelClient, IntelError
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
    failures: dict[str, int] = field(default_factory=dict)  # source -> consecutive failed runs
    radar: dict[str, Any] = field(default_factory=dict)  # the radar's events (v0.22.0, alert.radar)

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
            failures=data.get("failures", {}),
            radar=data.get("radar", {}),
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
            "failures": self.failures,
            "radar": self.radar,
        }
        self.path.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def count_failures(self, errors: list[str], threshold: int) -> tuple[list[str], list[str]]:
        """Split this run's source errors into (errors, warnings): a source is in error only after
        `threshold` failed runs in a row; one success resets its count. A feed down for a few
        minutes, common on vendor sites, then never turns the job orange."""
        counts: dict[str, int] = {}
        for e in errors:
            name = e.split(": ", 1)[0]
            counts[name] = self.failures.get(name, 0) + 1
        self.failures = counts  # sources without an error this run are reset
        hard, soft = [], []
        for e in errors:
            n = counts[e.split(": ", 1)[0]]
            if n >= threshold:
                hard.append(f"{e} ({n} runs in a row)")
            else:
                soft.append(f"{e} (failure {n}/{threshold}, error from {threshold} in a row)")
        return hard, soft

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
    source: str = ""  # source name, e.g. "CERT-FR — alerts"
    category: str = "institutional"  # institutional | vendor | research | radar
    urgent_source: bool = False  # every publication of the source is urgent
    facts: dict[str, Any] = field(default_factory=dict)  # gti: the licensed source's facts (never its prose)


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
    reasons: list[str] = field(default_factory=list)  # codes, worded by i18n.reason
    detected: list[tuple[Asset, Finding]] = field(default_factory=list)  # from the last daily inventory
    inventory_as_of: str = ""
    radar: dict[str, Any] = field(default_factory=dict)  # the radar's event (v0.22.0), empty otherwise
    # D20 (v0.23.0): hosts whose listed packages hold an affected version (level exposed), and hosts
    # carrying a package named like the product, its version unknown against the record (possible).
    exposed: list[tuple[Asset, Exposure]] = field(default_factory=list)
    possible: list[tuple[Asset, str]] = field(default_factory=list)


# Levels of proof of an asset named by an alert (D20), strongest first.
CONFIRMED, EXPOSED, POSSIBLE = "confirmed", "exposed", "possible"


# -- discovery --------------------------------------------------------------------------------
def default_catalogue() -> list[Source]:
    """CERT-FR, KEV and cvelistV5 only: what the watch mode reads without a catalogue file."""
    return [
        Source("certfr-alerte", "CERT-FR — alerts", "institutional", "certfr", feed="alerte", urgent=True),
        Source("certfr-avis", "CERT-FR — advisories", "institutional", "certfr", feed="avis"),
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

    for src in [s for s in catalogue if s.kind in ("intel", "gti")]:
        try:
            fresh = _read_intel(sources, src, state) if src.kind == "intel" else _read_gti(sources, src, state, now)
        except (SourceError, IntelError, KeyError, TypeError, ValueError) as exc:
            errors.append(f"{src.name}: {exc}")
            continue
        items += fresh

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
                    title = entry.get("vulnerabilityName") or f"{cve} added to the KEV catalog"
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


def _read_intel(sources: Sources, src: Source, state: State) -> list[Item]:
    """The feed of the shared intelligence service since the last mark; nothing without one configured."""
    client = IntelClient.from_settings(sources.settings)
    if client is None:
        return []
    try:
        mark = state.marks.get(src.id)
        data = client.feed(mark or "")
    finally:
        client.close()
    state.marks[src.id] = data.get("next") or mark or ""
    if state.new or mark is None:
        return []  # baseline: what the feed held before this tenant read it is not news
    out = []
    for it in data.get("items") or []:
        links = [link for link in it.get("links") or [] if link.get("url")]
        pub = Publication(
            ref=it["id"], kind=it.get("kind", "radar"), title=it.get("title", ""),
            link=links[0]["url"] if links else "", published=it.get("at", ""), cves=list(it.get("cves") or []),
            systems=[{"vendor": p.get("vendor", ""), "product": p.get("product", ""),
                      "description": f"{p.get('vendor', '')} {p.get('product', '')}".strip()}
                     for p in it.get("products") or []],
            summary=it.get("summary", ""), vendor_advisories=links[1:], source=src.name,
        )  # fmt: skip
        out.append(
            Item(f"{src.id}:{it['id']}", src.id, pub.title, pub.cves, pub.published, publication=pub,
                 source=src.name, category="radar" if it.get("kind") == "radar" else "research",
                 urgent_source=it.get("kind") == "radar" and it.get("level") == "urgent",
                 facts=dict(it.get("facts") or {}))
        )  # fmt: skip
    return out


def _read_gti(sources: Sources, src: Source, state: State, now: dt.datetime) -> list[Item]:
    """A GTI search (the radar's, by default): the vulnerabilities changed since the last mark, each
    one once per exploitation state. Nothing when GTI is not enabled."""
    if not sources.settings.gti_enabled:
        return []
    mark = state.marks.get(src.id)
    state.marks[src.id] = now.date().isoformat()
    if state.new or mark is None:
        return []
    query = f"{src.query or RADAR_FILTER} AND last_modification_date:{mark}+"
    seen = set(state.seen.get(src.id, []))
    out = []
    for view in discovered(sources, query):
        key = f"{view['id']}:{view.get('exploitation_state', '')}"
        if key in seen:
            continue
        state.seen[src.id] = state.seen.get(src.id, []) + [key]
        cves = [view["cve"]] if view.get("cve") else []
        pub = Publication(ref=view["id"], kind="gti", title=view["title"], link=view["url"],
                          published=view.get("last_modification_date", ""), cves=cves, source=src.name)  # fmt: skip
        facts = {k: view.get(k) for k in ("exploitation_state", "exploit_availability", "risk_rating")}
        out.append(
            Item(f"{src.id}:{view['id']}", src.id, view["title"], cves, pub.published, publication=pub,
                 source=src.name, category=src.category, facts=facts)
        )  # fmt: skip
    return out[:MAX_NEW_PER_RUN]


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


def inventory_matches(
    records: list[VulnRecord],
    inventory: Inventory,
    confirmed: set[tuple[str, str]],
    table: dict[str, applications.Row] | None = None,
) -> tuple[list[tuple[Asset, Exposure]], list[tuple[Asset, str]]]:
    """The hosts of the inventory exposed by their listed packages (D20), and those where the product
    is possibly there; an asset already confirmed by a scan for the CVE is left to that proof. The
    applications of an EDR (v0.23.3) are matched through the tenant's applications table."""
    exposed: list[tuple[Asset, Exposure]] = []
    possible: list[tuple[Asset, str]] = []
    for record in records:
        products = sorted({e.product for e in record.affected if e.product and e.product.lower() != "n/a"})
        for asset in sorted(inventory.assets.values(), key=lambda a: a.id):
            if not asset.components or (asset.id, record.cve_id) in confirmed:
                continue
            app_hits = applications.matches(record, asset.components, table) if table else []
            sure_apps = [h.exposure for h in app_hits if h.proof == "exposed"]
            if sure_apps:
                exposed += [(asset, h) for h in sure_apps]
                continue
            if app_hits:
                named = {f"{h.exposure.component} {h.exposure.version} ({h.reason})" for h in app_hits}
                possible.append((asset, ", ".join(sorted(named))))
                continue
            hits = exposures(record.cve_id, asset.components, record.packages, asset.os)
            sure = [h for h in hits if h.state != INVESTIGATING]
            if sure:
                exposed += [(asset, h) for h in sure]
                continue
            if hits:  # the distribution has not decided yet
                possible.append((asset, ", ".join(sorted({f"{h.component} {h.version}" for h in hits}))))
                continue
            if covered(asset.components, record.packages, asset.os):
                continue  # the distribution says which versions are affected: none of these
            named = sorted({f"{c['name']} {c['version']}" for p in products for c in present(p, asset.components)})
            if named:
                possible.append((asset, ", ".join(named)))
    return exposed, possible


def relevant(
    items: list[Item],
    profile: ClientProfile,
    sources: Sources,
    settings: Settings,
    scanner: DeclaredMatcher,
    state: State | None = None,
    catalogue: list[Source] | None = None,
    inventory: Inventory | None = None,
) -> list[Alert]:
    wanted = sorted({c for it in items for c in it.cves})
    records: dict[str, VulnRecord] = {}
    listed = inventory is not None and any(a.components for a in inventory.assets.values())
    if wanted:
        collection = collect(sources, wanted, packages=listed)
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
        exposed_by_packages: list[tuple[Asset, Exposure]] = []
        possible: list[tuple[Asset, str]] = []
        if listed:
            confirmed = {(a.id, f.cve_id) for a, f in detected}
            exposed_by_packages, possible = inventory_matches(recs, inventory, confirmed, inventory.applications)
        if not findings and not by_name and not detected and not exposed_by_packages and not possible:
            continue
        if it.origin == "cve":
            label = cna_label(recs, catalogue or [])
            if label:
                it.source, it.category = label, "vendor"
        reasons = []
        if it.origin == "kev" or any(r.in_kev for r in recs):
            reasons.append("kev")
        elif any(ssvc_exploitation(r.gti)[0] == "active" for r in recs):  # often before KEV
            reasons.append("gti_active")
        if it.urgent_source and it.origin != "kev":
            reasons.append(f"source:{it.source}")
        if any((r.adp_ssvc or {}).get("exploitation") in {"poc", "active"} for r in recs):
            reasons.append("cisa_poc")
        exposed = [f.asset_ref for f in findings if exposure(profile, assets.get(f.asset_ref)) == "open"]
        exposed += [a.id for a, _ in detected if "exposure" in a.attributes and _open(a)]
        exposed += [a.id for a, _ in exposed_by_packages if "exposure" in a.attributes and _open(a)]
        if exposed and any(_critical(r) for r in recs):
            reasons.append("exposed_critical")
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
                exposed=exposed_by_packages,
                possible=possible,
            )
        )
    if state:
        today = dt.date.today().isoformat()
        for a in alerts:
            for c in a.item.cves:
                state.alerted[c] = today
    return alerts
