# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Declared assets matched against vulnerability records: findings computed from the products and
versions a client declared in its profile. Shared by pillar 2 (`detect inventory`, the declared
inventory of clients without a scanner and of products scanners do not see: appliances, network
devices, SaaS) and pillar 1 (the watch, to tell whether a new CVE concerns the client). Owned by
pillar 2 (LLD vulnerability-detection §1.1, §3.3); in a2vm so that every pillar runs it alone.

Each declared asset becomes an asset observation (kind "declared"), carrying the attributes the
profile declares; the assets stage completes the missing ones from rules and default assumptions.
A fuzzy (name-similarity) candidate may go to the LLM, whose answer is a proposal: the candidate is
kept either way and flagged for review with it, so the analyst decides. Vendor text is untrusted
and passed as data.
"""

from __future__ import annotations

import json
from typing import Any

from .config import Settings
from .io import Detection, now
from .llm import UNTRUSTED, LlmClient, LlmError
from .matching import AssetMatch, match_assets
from .models import (
    ATTRIBUTES,
    AffectedEntry,
    AssetObservation,
    ClientProfile,
    DeclaredAsset,
    Finding,
    FindingObservation,
    Match,
    NotAffected,
    VulnRecord,
)
from .versions import evaluate

SOURCE = "inventory"

MATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["same_product", "justification"],
    "properties": {
        "same_product": {"type": "boolean"},
        "justification": {"type": "string", "maxLength": 400},
    },
}

_MATCH_SYSTEM = f"""You decide whether the product named in a vulnerability record is the same software
product as an asset in a client's inventory. Different products from the same vendor, different
editions with separate code bases, or plugins/clients of a product are NOT the same product.
Ignore version numbers: only the product identity matters.
{UNTRUSTED}
Answer in English, justification in at most 2 sentences."""


def adjudicate_match(llm: LlmClient, facts: VulnRecord, entry: AffectedEntry, asset: DeclaredAsset) -> dict[str, Any]:
    inventory = {
        "vendor": asset.vendor,
        "product": asset.product,
        "aliases": asset.product_aliases,
        "description": asset.description,
    }
    user = (
        f"Client asset: {json.dumps(inventory, ensure_ascii=False)}\n"
        f"Vulnerability {facts.cve_id}, product as named in the record:\n"
        f"<untrusted>\nvendor: {entry.vendor}\nproduct: {entry.product}\n"
        f"description: {facts.description[:1500]}\n</untrusted>"
    )
    return llm.structured(_MATCH_SYSTEM, user, "product_match", MATCH_SCHEMA)


def declared_observations(profile: ClientProfile, observed_at: str) -> list[AssetObservation]:
    out = []
    for a in profile.assets:
        attributes = {k: getattr(a, k) for k in (*ATTRIBUTES, "zone") if getattr(a, k)}
        out.append(
            AssetObservation(
                ref=a.id,
                kind="declared",
                source=SOURCE,
                observed_at=observed_at,
                name=a.id,
                description=a.description,
                identifiers={},
                attributes=attributes,
                os=None,
            )
        )
    return out


class DeclaredMatcher:
    def __init__(self, settings: Settings, llm: LlmClient | None = None):
        self.settings = settings
        self.llm = llm if (llm and settings.llm.enabled and settings.llm.match_adjudication) else None
        self.fuzzy_without_llm = settings.policy.get("fuzzy_match_without_llm", "review")
        if self.fuzzy_without_llm not in {"review", "drop"}:
            raise ValueError("policy.fuzzy_match_without_llm must be 'review' or 'drop'")

    def _confirm_fuzzy(self, record: VulnRecord, am: AssetMatch) -> tuple[Match | None, list[str]]:
        if self.llm:
            try:
                out = adjudicate_match(self.llm, record, am.entries[0], am.asset)
            except LlmError as exc:
                return am.match, [f"approximate product match, LLM unavailable: {exc}"]
            # The LLM proposes, it never decides: the candidate is kept either way and goes to review
            # with the proposal, so that a wrong "no" cannot hide a vulnerability.
            m = am.match
            if not out["same_product"]:
                return m, [f"approximate product match; LLM proposal: unlikely — {out['justification']}"]
            return Match("llm", m.vendor, m.product, m.score, out["justification"]), [
                "approximate product match; LLM proposal: likely — to confirm"
            ]
        if self.fuzzy_without_llm == "drop":
            return None, []
        return am.match, ["approximate product match (name similarity)"]

    def scan(self, profile: ClientProfile, records: list[VulnRecord]) -> Detection:
        observed_at = now()
        result = Detection(profile.id, SOURCE, declared_observations(profile, observed_at), [])
        for record in records:
            for am in match_assets(record, profile.assets, self.settings.fuzzy_threshold):
                review: list[str] = []
                match = am.match
                if match.method == "fuzzy":
                    match, extra = self._confirm_fuzzy(record, am)
                    if match is None:
                        continue
                    review.extend(extra)

                asset = am.asset
                if asset.versions:
                    statuses = {v: evaluate(v, am.entries) for v in asset.versions}
                    affected = [v for v, s in statuses.items() if s == "affected"]
                    if not affected and all(s == "unaffected" for s in statuses.values()):
                        result.not_affected.append(
                            NotAffected(profile.id, record.cve_id, asset.id, asset.versions, SOURCE)
                        )
                        continue
                    status = "affected" if affected else "under_investigation"
                    if not affected:
                        review.append("status of the deployed version undetermined")
                else:
                    affected, status = [], "under_investigation"
                    review.append("deployed versions not given in the client profile")

                result.findings.append(
                    Finding(
                        id=Finding.make_id(profile.id, asset.id, record.cve_id),
                        client_id=profile.id,
                        asset_ref=asset.id,
                        cve_id=record.cve_id,
                        status=status,
                        affected_versions=affected,
                        observations=[
                            FindingObservation(
                                source=SOURCE,
                                observed_at=observed_at,
                                match=match,
                                package=asset.product,
                                installed_version=", ".join(asset.versions),
                            )
                        ],
                        review_reasons=review,
                    )
                )
        return result
