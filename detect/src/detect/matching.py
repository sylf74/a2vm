# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Match the products named in a CVE record against a client's asset profile."""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from vulnops.models import AffectedEntry, CveFacts, DeclaredAsset, Match


def norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def cpe_vendor_product(cpe: str) -> tuple[str, str] | None:
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return norm(parts[3]), norm(parts[4])
    return None


@dataclass
class AssetMatch:
    asset: DeclaredAsset
    match: Match
    entries: list[AffectedEntry]  # affected blocks that refer to this asset's product


def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio() if a and b else 0.0


def _asset_keys(asset: DeclaredAsset) -> tuple[set[str], set[str], tuple[str, str] | None]:
    vendors = {norm(asset.vendor), *(norm(v) for v in asset.vendor_aliases)}
    products = {norm(asset.product), *(norm(p) for p in asset.product_aliases)}
    return vendors - {""}, products - {""}, cpe_vendor_product(asset.cpe) if asset.cpe else None


def _entry_match(asset: DeclaredAsset, entry: AffectedEntry, fuzzy_threshold: float) -> Match | None:
    vendors, products, asset_cpe = _asset_keys(asset)
    ev, ep = norm(entry.vendor), norm(entry.product)

    if asset_cpe:
        for cpe in entry.cpes:
            if cpe_vendor_product(cpe) == asset_cpe:
                return Match("cpe", entry.vendor, entry.product, 1.0, cpe)
    if ev in vendors and ep in products:
        exact = ev == norm(asset.vendor) and ep == norm(asset.product)
        return Match("exact" if exact else "alias", entry.vendor, entry.product, 1.0)

    # Fuzzy candidates: never conclusive on their own, they go to the LLM or to human review.
    vendor_score = max((_sim(ev, v) for v in vendors), default=0.0)
    product_score = max((_sim(ep, p) for p in products), default=0.0)
    if ep and any(p and (p in ep or ep in p) for p in products):
        product_score = max(product_score, fuzzy_threshold)
    if vendor_score >= 0.85 and product_score >= fuzzy_threshold:
        score = round(min(vendor_score, product_score), 2)
        return Match("fuzzy", entry.vendor, entry.product, score, "name similarity only")
    return None


def match_assets(facts: CveFacts, assets: list[DeclaredAsset], fuzzy_threshold: float = 0.75) -> list[AssetMatch]:
    results: list[AssetMatch] = []
    rank = {"cpe": 0, "exact": 1, "alias": 2, "fuzzy": 3}
    for asset in assets:
        best: Match | None = None
        entries: list[AffectedEntry] = []
        for entry in facts.affected:
            m = _entry_match(asset, entry, fuzzy_threshold)
            if not m:
                continue
            entries.append(entry)
            if best is None or rank[m.method] < rank[best.method]:
                best = m
        if best:
            # Keep only the blocks matched at the best level (a fuzzy block must not
            # contribute version ranges to a CPE-level match).
            if best.method != "fuzzy":
                entries = [e for e in entries if _entry_match(asset, e, fuzzy_threshold).method != "fuzzy"]
            results.append(AssetMatch(asset, best, entries))
    return results
