# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Watch sources other than CERT-FR, KEV and cvelistV5: generic feeds (RSS 2.0, Atom, RDF) and CSAF
providers. The catalogue (config/watch-sources.yaml) says which ones are read and how they are
labelled: institutional bodies, vendors and manufacturers, research.

Everything is read defensively: a source that changes its format produces an error line in the
job log and is skipped; the other sources go on.
"""

from __future__ import annotations

import email.utils
import html
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from via.intel.sources import SourceError, Sources

from .certfr import CVE_RE, Publication

KINDS = ("certfr", "kev", "cvelist", "rss", "csaf", "cna")
CATEGORIES = ("institutional", "vendor", "research")
MAX_NEW_PER_RUN = 40  # per source: a feed that resets itself must not flood the analysts


@dataclass
class Source:
    id: str
    name: str
    category: str
    kind: str
    url: str = ""
    feed: str = ""  # certfr: alerte | avis
    vendors: list[str] = field(default_factory=list)  # cna: vendor names as written in CVE records
    urgent: bool = False  # every publication of this source is urgent (e.g. CERT-FR alerts)
    enabled: bool = True
    notes: str = ""


def load_catalogue(path: str | Path) -> list[Source]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out = []
    for raw in data.get("sources", []):
        src = Source(**raw)
        if src.kind not in KINDS or src.category not in CATEGORIES:
            raise ValueError(f"{path}: {src.id}: kind must be one of {KINDS}, category one of {CATEGORIES}")
        out.append(src)
    ids = [s.id for s in out]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate source ids")
    return out


# -- RSS 2.0 / Atom / RDF ------------------------------------------------------------------------
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el: ET.Element, *names: str) -> str:
    for child in el:
        if _local(child.tag) in names:
            if _local(child.tag) == "link" and child.get("href"):
                return child.get("href", "")
            return (child.text or "").strip()
    return ""


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()


def _date(value: str) -> str:
    if not value:
        return ""
    try:
        return email.utils.parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError):
        return value  # Atom / RDF dates are already ISO 8601


def parse_generic_feed(xml_text: str, source: Source) -> list[Publication]:
    """Items of an RSS 2.0, Atom or RSS 1.0 (RDF) feed, as publications of `source`."""
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        title = _strip_html(_child_text(el, "title"))
        link = _child_text(el, "link")
        guid = _child_text(el, "guid", "id") or link or title
        summary = _strip_html(_child_text(el, "description", "summary", "content", "encoded"))
        published = _date(_child_text(el, "pubDate", "published", "updated", "date"))
        cves = sorted(set(CVE_RE.findall(f"{title} {summary}")))
        pub = Publication(
            ref=guid,
            kind=source.id,
            title=title or guid,
            link=link,
            published=published,
            cves=cves,
            summary=summary[:2000],
            source=source.name,
        )
        if link:
            pub.vendor_advisories = [{"title": f"{source.name} — {title}"[:160], "url": link}]
        out.append(pub)
    return out


# -- CSAF ----------------------------------------------------------------------------------------
def csaf_index_url(metadata: dict[str, Any]) -> tuple[str, str]:
    """('changes', url) for a directory distribution, ('rolie', url) for a ROLIE feed."""
    for dist in metadata.get("distributions") or []:
        if dist.get("directory_url"):
            return "changes", dist["directory_url"].rstrip("/") + "/changes.csv"
    for dist in metadata.get("distributions") or []:
        for feed in (dist.get("rolie") or {}).get("feeds") or []:
            if feed.get("url"):
                return "rolie", feed["url"]
    raise SourceError("no CSAF distribution in provider metadata")


def csaf_entries(kind: str, url: str, text: str) -> list[tuple[str, str]]:
    """(document URL, timestamp) of an index, newest first."""
    out = []
    if kind == "changes":
        base = url.rsplit("/", 1)[0]
        for line in text.splitlines():
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) >= 2 and parts[0].endswith(".json"):
                out.append((f"{base}/{parts[0]}", parts[1]))
    else:
        import json

        feed = json.loads(text).get("feed", {})
        for entry in feed.get("entry") or []:
            href = next((lk.get("href") for lk in entry.get("link") or [] if lk.get("rel") == "self"), None)
            href = href or (entry.get("content") or {}).get("src")
            if href:
                out.append((href, entry.get("updated", "")))
    out.sort(key=lambda e: e[1], reverse=True)
    return out


def _walk_products(branches: list[dict[str, Any]], vendor: str = "") -> list[dict[str, str]]:
    out = []
    for b in branches or []:
        cat, name = b.get("category"), b.get("name", "")
        v = name if cat == "vendor" else vendor
        if cat in ("product_name", "product_family"):
            out.append({"vendor": v, "product": name, "description": f"{v} {name}".strip()})
        out += _walk_products(b.get("branches") or [], v)
    return out


def parse_csaf(doc: dict[str, Any], url: str, source: Source) -> Publication:
    d = doc.get("document") or {}
    tracking = d.get("tracking") or {}
    vulns = doc.get("vulnerabilities") or []
    cves = sorted({v["cve"] for v in vulns if CVE_RE.fullmatch(v.get("cve") or "")})
    notes = [n.get("text", "") for n in d.get("notes") or [] if n.get("category") in ("summary", "description")]
    fixes = []
    for v in vulns:
        for r in v.get("remediations") or []:
            if r.get("category") == "vendor_fix" and (r.get("details") or r.get("url")):
                fixes.append(_strip_html(r.get("details") or r["url"])[:200])
    systems = _walk_products((doc.get("product_tree") or {}).get("branches") or [])
    # one line per product family, not per version
    seen, products = set(), []
    for s in systems:
        if (s["vendor"], s["product"]) not in seen:
            seen.add((s["vendor"], s["product"]))
            products.append(s)
    pub = Publication(
        ref=tracking.get("id") or url,
        kind=source.id,
        title=d.get("title") or tracking.get("id") or url,
        link=next((r.get("url") for r in d.get("references") or [] if r.get("category") == "self"), url),
        published=tracking.get("current_release_date") or tracking.get("initial_release_date") or "",
        cves=cves,
        systems=products[:30],
        summary=_strip_html(" ".join(notes))[:2000],
        source=source.name,
        fixes=list(dict.fromkeys(fixes))[:10],
    )
    severity = ((d.get("aggregate_severity") or {}).get("text") or "").lower()
    if severity:
        pub.risks.append(f"sévérité éditeur : {severity}")
    pub.vendor_advisories = [{"title": f"{source.name} — {pub.ref}", "url": pub.link}]
    return pub


def read_csaf(sources: Sources, source: Source, since: str) -> tuple[list[Publication], str]:
    """Documents changed after `since` (empty: none, baseline), and the newest timestamp seen."""
    metadata = sources.fetch_json(source.url)
    kind, index_url = csaf_index_url(metadata or {})
    entries = csaf_entries(kind, index_url, sources.fetch_text(index_url))
    newest = entries[0][1] if entries else since
    if not since:
        return [], newest
    pubs = []
    for doc_url, ts in entries:
        if ts <= since or len(pubs) >= MAX_NEW_PER_RUN:
            break
        doc = sources.fetch_json(doc_url)
        if doc:
            pubs.append(parse_csaf(doc, doc_url, source))
    return pubs, newest
