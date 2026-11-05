# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The radar of the watch team (HLD D17, v0.22.0): the major vulnerabilities, whoever they concern.

A tenant whose profile says `alerts.mode: radar` (the watch team's own, `via`) does not match the
news against assets: it gathers the publications of every source into events and alerts the team
on the events whose magnitude passes a threshold, zero-days before their CVE included.

- An event gathers the items that share a CVE, or, without one, whose titles share most of their
  words, or that name the same product while the event has no CVE yet; within `window_hours`.
- Its magnitude is deterministic (D11): the weight of its strongest source (an institutional alert,
  KEV, exploitation confirmed by GTI: 3; any other source: 1; a CVSS of 9 or more: +1), the markers
  found in the texts, English or French (exploited in the wild 3, also when KEV or GTI says so;
  zero-day 2; unauthenticated 1; remote code execution 1; proof of concept 1), and 2 per other
  independent source (6 at most).
- An event is alerted when its score reaches `info` (4) or `urgent` (7), again when it moves up a
  level, and once more when it gets its first CVE ids.

A validated radar alert is published to the shared intelligence service, whose feed the tenants'
watches read: each matches it with its own assets, the radar never knows who has what.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any

from a2vm.gti import ssvc_exploitation
from a2vm.models import ClientProfile, VulnRecord

from .certfr import Publication

MARKERS = {  # English and French (CERT-FR)
    "in_the_wild": (re.compile(
        r"in the wild|actively exploited|exploited in attacks|under active exploitation|exploitation "
        r"(?:is )?(?:confirmed|observed|ongoing)|activement exploitée|exploitée? dans (?:la nature|le cadre)"
        r"|exploitation active|cas d'exploitation", re.I), 3),
    "zero_day": (re.compile(r"zero[- ]day|\b0[- ]?day\b|jour z[ée]ro", re.I), 2),
    "unauthenticated": (re.compile(
        r"pre[- ]?auth|unauthenticated|without authentication|no authentication|sans authentification"
        r"|non authentifié", re.I), 1),
    "rce": (re.compile(r"remote code execution|\bRCE\b|arbitrary code execution|exécution de code"
                       r"(?: arbitraire)? à distance", re.I), 1),
    "poc": (re.compile(r"proof[- ]of[- ]concept|\bPoC\b|exploit (?:code )?(?:is )?(?:now )?(?:publicly )?"
                       r"(?:released|available|published)|preuve de concept", re.I), 1),
}  # fmt: skip
STOP = frozenset(
    re.findall(
        r"\w+",
        "about after against allows also and are being both but can cause could critical cve days each fixed "
        "fixes flaw flaws for from has have high how important impact into issue issues its latest list low "
        "medium more multiple new not now patch patched patches products release released releases remote "
        "security several some than that the their them these this those through under update updates using "
        "version versions via vulnerabilities vulnerability vulnerable warns what when which while with "
        "without ",
    )
)
LEVELS = ("", "info", "urgent")


@dataclass
class RadarConfig:
    info: int = 4
    urgent: int = 7
    window_hours: int = 72
    keep_days: int = 14

    @classmethod
    def of(cls, profile: ClientProfile) -> RadarConfig:
        raw = profile.alerts.get("radar") or {}
        return cls(**{k: int(v) for k, v in raw.items() if k in cls.__dataclass_fields__})


def is_radar(profile: ClientProfile) -> bool:
    return profile.alerts.get("mode") == "radar"


def markers(texts: list[str]) -> list[str]:
    return [name for name, (pattern, _) in MARKERS.items() if any(pattern.search(t) for t in texts)]


def words(text: str) -> list[str]:
    found = re.findall(r"[a-z0-9][a-z0-9._+-]{3,}", text.lower())
    return sorted({w.strip("._-") for w in found if w not in STOP and not re.fullmatch(r"cve-\d{4}-\d+|\d+", w)})


def _similar(a: list[str], b: list[str]) -> bool:
    """Two titles on the same news: at least two words in common, and most of the shorter title."""
    sa, sb = set(a), set(b)
    common = sa & sb
    return len(common) >= 2 and len(common) / min(len(sa), len(sb)) >= 0.6


def products(item: Any, records: list[VulnRecord]) -> list[dict[str, str]]:
    pub = item.publication
    if pub and pub.systems:
        out = [{"vendor": s.get("vendor", ""), "product": s.get("product", "")} for s in pub.systems]
    else:
        out = [{"vendor": e.vendor, "product": e.product} for r in records for e in r.affected[:3]]
    seen, unique = set(), []
    for p in out:
        key = (p["vendor"].lower(), p["product"].lower())
        if p["product"] and key not in seen and p["product"].lower() not in ("n/a", "*", "-"):
            seen.add(key)
            unique.append(p)
    return unique[:10]


def weight(item: Any, records: list[VulnRecord]) -> tuple[int, list[str]]:
    """The weight of one item and its signals: an institutional alert, KEV or exploitation confirmed by
    GTI weigh 3, any other source 1; a CVSS of 9 or more adds 1."""
    signals = []
    if item.origin == "kev" or any(r.in_kev for r in records):
        signals.append("kev")
    if any(ssvc_exploitation(r.gti)[0] == "active" for r in records) or (item.facts or {}).get(
        "exploitation_state"
    ) in ("confirmed", "wide"):
        signals.append("gti_active")
    if item.urgent_source and item.origin != "kev":
        signals.append("urgent_source")
    base = 3 if signals else 1
    if any((r.best_cvss() and (r.best_cvss().score or 0) >= 9.0) for r in records):
        signals.append("critical")
        base += 1
    return base, signals


def _texts(item: Any, records: list[VulnRecord]) -> list[str]:
    pub = item.publication
    texts = [item.title]
    if pub:
        texts += [pub.title, pub.summary or ""]
    texts += [r.description or "" for r in records[:3]]
    return [t for t in texts if t]


def _score(event: dict[str, Any]) -> int:
    base = max((s["base"] for s in event["sources"]), default=0)
    marks = sum(MARKERS[m][1] for m in event["markers"])
    others = len({s["source"] for s in event["sources"]}) - 1
    return base + marks + min(2 * max(others, 0), 6)


def _level(score: int, cfg: RadarConfig) -> str:
    return "urgent" if score >= cfg.urgent else "info" if score >= cfg.info else ""


def _find(events: dict[str, dict], cves: list[str], wds: list[str], prods: list[dict], since: str) -> dict | None:
    recent = [e for e in events.values() if e["last"] >= since]
    for e in recent:
        if set(cves) & set(e["cves"]):
            return e
    for e in recent:
        if wds and _similar(wds, e["words"]):
            return e
    if not cves:
        return None
    # A CVE published for an event without one yet: the same product, named by the event's sources or
    # found among the words of their titles.
    keys = {(p["vendor"].lower(), p["product"].lower()) for p in prods}
    named = [set(words(f"{p['vendor']} {p['product']}")) for p in prods]
    for e in recent:
        if e["cves"]:
            continue
        if keys & {(p["vendor"].lower(), p["product"].lower()) for p in e["products"]}:
            return e
        if any(len(n) >= 2 and n <= set(e["words"]) for n in named):
            return e
    return None


def assess(
    items: list[Any],
    records: dict[str, VulnRecord],
    radar_state: dict[str, Any],
    cfg: RadarConfig,
    now: dt.datetime | None = None,
) -> list[tuple[dict[str, Any], str]]:
    """Fold the new items into the events of `radar_state` (changed in place); the events to alert,
    with why: `new`, `raised` (a higher level), `cve` (its first CVE ids after an alert without)."""
    now = now or dt.datetime.now(dt.UTC)
    at = now.isoformat(timespec="seconds")
    events: dict[str, dict] = radar_state.setdefault("events", {})
    since = (now - dt.timedelta(hours=cfg.window_hours)).isoformat(timespec="seconds")
    touched: list[str] = []
    for it in items:
        recs = [records[c] for c in it.cves if c in records]
        prods = products(it, recs)
        wds = words(it.title if it.origin not in ("cve", "kev") else "")
        event = _find(events, list(it.cves), wds, prods, since)
        if event is None:
            radar_state["seq"] = int(radar_state.get("seq", 0)) + 1
            eid = f"R{now:%Y%m%d}-{radar_state['seq']:04d}"
            event = events[eid] = {"id": eid, "first": at, "last": at, "title": "", "cves": [], "words": wds,
                                   "products": [], "sources": [], "markers": [], "score": 0, "alerted": "",
                                   "alerted_cves": [], "alerts": 0}  # fmt: skip
        base, signals = weight(it, recs)
        pub = it.publication
        event["sources"].append({
            "source": it.source or it.origin, "category": it.category, "title": it.title[:300],
            "link": (pub.link if pub else "") or "", "at": at, "base": base, "signals": signals,
            "summary": ((pub.summary if pub else "") or "")[:1500],
        })  # fmt: skip
        event["sources"] = event["sources"][-30:]
        event["cves"] = sorted(set(event["cves"]) | set(it.cves))
        found = set(markers(_texts(it, recs)))
        if {"kev", "gti_active"} & set(signals):  # KEV or GTI: exploitation known, whatever the texts say
            found.add("in_the_wild")
        event["markers"] = sorted(set(event["markers"]) | found)
        known = {(p["vendor"].lower(), p["product"].lower()) for p in event["products"]}
        event["products"] += [p for p in prods if (p["vendor"].lower(), p["product"].lower()) not in known]
        event["products"] = event["products"][:10]
        if not event["words"]:
            event["words"] = wds
        best = max(event["sources"], key=lambda s: (s["base"], s["category"] == "institutional"))
        event["title"] = best["title"]
        event["last"] = at
        event["score"] = _score(event)
        if event["id"] not in touched:
            touched.append(event["id"])
    out = []
    for eid in touched:
        e = events[eid]
        level = _level(e["score"], cfg)
        if LEVELS.index(level) > LEVELS.index(e["alerted"]):
            out.append((e, "new" if not e["alerted"] else "raised"))
            e["alerted"], e["alerted_cves"] = level, list(e["cves"])
        elif e["alerted"] and e["cves"] and not e["alerted_cves"]:
            out.append((e, "cve"))
            e["alerted_cves"] = list(e["cves"])
        else:
            continue
        e["alerts"] += 1
    cutoff = (now - dt.timedelta(days=cfg.keep_days)).isoformat(timespec="seconds")
    for eid in [k for k, v in events.items() if v["last"] < cutoff]:
        del events[eid]
    return out


def item_of(event: dict[str, Any]) -> Any:
    """The item the sheet of an event is written from: its strongest source, the others as links."""
    from .watch import Item

    best = max(event["sources"], key=lambda s: (s["base"], s["category"] == "institutional"))
    others = [s for s in event["sources"] if s is not best and s["link"]]
    seen, links = {best["link"]}, []
    for s in others:
        if s["link"] not in seen:
            seen.add(s["link"])
            links.append({"title": f"{s['source']}: {s['title']}", "url": s["link"]})
    pub = Publication(
        ref=event["id"], kind="radar", title=event["title"], link=best["link"], published=event["first"],
        cves=list(event["cves"]),
        systems=[{"vendor": p["vendor"], "product": p["product"],
                  "description": f"{p['vendor']} {p['product']}".strip()} for p in event["products"]],
        summary=best["summary"] or next((s["summary"] for s in event["sources"] if s["summary"]), ""),
        vendor_advisories=links[:10], source=best["source"],
    )  # fmt: skip
    return Item(f"RADAR:{event['id']}", "radar", event["title"], list(event["cves"]), event["first"],
                publication=pub, source=best["source"], category=best["category"])  # fmt: skip


def payload(event: dict[str, Any], level: str) -> dict[str, Any]:
    """What the shared service publishes to the tenants' watches once the alert is validated."""
    item = item_of(event)
    pub = item.publication
    links = ([{"title": pub.source, "url": pub.link}] if pub.link else []) + list(pub.vendor_advisories)
    return {
        "id": event["id"],
        "level": level,
        "title": event["title"],
        "summary": pub.summary,
        "cves": list(event["cves"]),
        "products": list(event["products"]),
        "terms": list(event["markers"]),
        "links": links[:12],
        "score": event["score"],
    }


def alerts(items: list[Any], profile: ClientProfile, sources: Any, state: Any, now: dt.datetime | None = None) -> list:
    """The radar's alerts of this passage (`via watch` for a profile in radar mode)."""
    from via.intel.collect import collect

    from .watch import Alert

    wanted = sorted({c for it in items for c in it.cves})
    records: dict[str, VulnRecord] = {}
    if wanted:
        collection = collect(sources, wanted)
        records = {r.cve_id: r for r in collection.records}
        for note in collection.notes:
            print(note)
    out = []
    for event, why in assess(items, records, state.radar, RadarConfig.of(profile), now):
        suffix = f"-{event['alerts']}" if event["alerts"] > 1 else ""
        reasons = sorted({s for src in event["sources"] for s in src["signals"] if s in ("kev", "gti_active")})
        out.append(
            Alert(
                id=f"{profile.id}-RADAR-{event['id']}{suffix}",
                client_id=profile.id,
                level=event["alerted"],
                item=item_of(event),
                records=[records[c] for c in event["cves"] if c in records],
                findings=[],
                product_matches=[],
                assets={},
                reasons=reasons,
                radar={
                    **{k: event[k] for k in ("id", "score", "markers", "cves", "products")},
                    "why": why,
                    "sources": [
                        {"source": s["source"], "title": s["title"], "link": s["link"]} for s in event["sources"]
                    ],
                },
            )  # fmt: skip
        )
    return out


def publish(entry: dict[str, Any], transport: Any = None) -> str:
    """Publish the event of a validated radar alert to the shared intelligence service (A2VM_INTEL_URL,
    the radar token in the file A2VM_INTEL_RADAR_TOKEN_FILE); a log line, "" for another alert."""
    from a2vm.config import env
    from via.intel.remote import IntelClient, IntelError, token_from

    event = entry.get("radar")
    if not event:
        return ""
    url = env("INTEL_URL")
    if not url:
        return f"radar: {event['id']} not published (no shared service: A2VM_INTEL_URL)"
    try:
        client = IntelClient(url, token_from(env("INTEL_RADAR_TOKEN_FILE")), transport)
        try:
            published = client.publish(event)
        finally:
            client.close()
    except IntelError as exc:
        return f"radar: {event['id']} NOT published: {exc}"
    return f"radar: {published} published to the tenants' watches"
