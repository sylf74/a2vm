"""CERT-FR publications: RSS feeds for discovery, the JSON view of each publication for details.

Every field is read defensively: an unexpected or missing field degrades the alert (fewer details),
it never stops the watch.
"""

from __future__ import annotations

import email.utils
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

REF_RE = re.compile(r"CERTFR-\d{4}-(?:ALE|AVI)-\d+")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


@dataclass
class FeedItem:
    ref: str
    kind: str  # alerte | avis
    title: str
    link: str
    published: str  # ISO 8601


@dataclass
class Publication:
    ref: str
    kind: str
    title: str
    link: str
    published: str
    cves: list[str] = field(default_factory=list)
    systems: list[dict[str, str]] = field(default_factory=list)  # vendor, product, description
    risks: list[str] = field(default_factory=list)
    summary: str = ""
    vendor_advisories: list[dict[str, str]] = field(default_factory=list)  # title, url


def parse_feed(xml_text: str, kind: str) -> list[FeedItem]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    items = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        m = REF_RE.search(link) or REF_RE.search(title) or REF_RE.search(it.findtext("guid") or "")
        if not m:
            continue
        published = ""
        if it.findtext("pubDate"):
            try:
                published = email.utils.parsedate_to_datetime(it.findtext("pubDate")).isoformat()
            except (TypeError, ValueError):
                published = ""
        items.append(FeedItem(m.group(0), kind, title, link, published))
    return items


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def parse_publication(item: FeedItem, data: dict[str, Any] | None) -> Publication:
    pub = Publication(item.ref, item.kind, item.title, item.link, item.published)
    if not data:
        pub.cves = sorted(set(CVE_RE.findall(item.title)))
        return pub
    pub.title = _text(data.get("title")) or item.title
    cves = [c.get("name", "") if isinstance(c, dict) else str(c) for c in data.get("cves") or []]
    pub.cves = sorted({c for c in cves if CVE_RE.fullmatch(c or "")})
    for s in data.get("affected_systems") or []:
        if not isinstance(s, dict):
            continue
        product = s.get("product") or {}
        vendor = product.get("vendor") or {} if isinstance(product, dict) else {}
        pub.systems.append(
            {
                "vendor": _text(vendor.get("name") if isinstance(vendor, dict) else ""),
                "product": _text(product.get("name") if isinstance(product, dict) else ""),
                "description": _text(s.get("description")),
            }
        )
    pub.risks = [_text(r.get("description")) for r in data.get("risks") or [] if isinstance(r, dict)]
    pub.risks = [r for r in pub.risks if r]
    pub.summary = _text(data.get("summary"))
    for a in data.get("vendor_advisories") or []:
        if isinstance(a, dict) and _text(a.get("url")):
            pub.vendor_advisories.append({"title": _text(a.get("title")), "url": _text(a.get("url"))})
    return pub
