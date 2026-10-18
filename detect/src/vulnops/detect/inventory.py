# SPDX-License-Identifier: AGPL-3.0-only
"""The inventory scanner: findings computed by matching vulnerability records against the assets a
client declared in its profile (products, versions). Used for clients without a scanner, and for
products scanners do not see (appliances, network devices, SaaS).

Each declared asset becomes an asset observation (kind "declared"), carrying the attributes the
profile declares; the assets stage completes the missing ones from rules and default assumptions.
"""

from __future__ import annotations

from vulnops.core.config import Settings
from vulnops.core.io import Detection, now
from vulnops.core.llm import LlmClient, LlmError
from vulnops.core.models import (
    ATTRIBUTES,
    AssetObservation,
    ClientProfile,
    Finding,
    FindingObservation,
    Match,
    NotAffected,
    VulnRecord,
)

from .llm_tasks import adjudicate_match
from .matching import AssetMatch, match_assets
from .versions import evaluate

SOURCE = "inventory"


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


class InventoryScanner:
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
                return am.match, [f"correspondance produit approximative, LLM indisponible : {exc}"]
            if not out["same_product"]:
                return None, []
            m = am.match
            return Match("llm", m.vendor, m.product, m.score, out["justification"]), [
                "correspondance produit confirmée par LLM uniquement"
            ]
        if self.fuzzy_without_llm == "drop":
            return None, []
        return am.match, ["correspondance produit approximative (similarité de noms)"]

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
                        review.append("statut de la version déployée indéterminé")
                else:
                    affected, status = [], "under_investigation"
                    review.append("versions déployées non renseignées dans le profil client")

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
