"""The inventory scanner: findings computed by matching vulnerability records against the assets a
client declared in its profile (products, versions). Used for clients without a scanner, and for
products scanners do not see.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnops.core.config import Settings
from vulnops.core.llm import LlmClient, LlmError
from vulnops.core.models import ClientProfile, Finding, Match, NotAffected, VulnRecord

from .llm_tasks import adjudicate_match
from .matching import AssetMatch, match_assets
from .versions import evaluate

SOURCE = "inventory"


@dataclass
class InventoryResult:
    client_id: str
    findings: list[Finding] = field(default_factory=list)
    not_affected: list[NotAffected] = field(default_factory=list)


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

    def scan(self, profile: ClientProfile, records: list[VulnRecord]) -> InventoryResult:
        result = InventoryResult(profile.id)
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
                        result.not_affected.append(NotAffected(profile.id, record.cve_id, asset.id, asset.versions))
                        continue
                    version_status = "affected" if affected else "unknown"
                    if not affected:
                        review.append("statut de la version déployée indéterminé")
                else:
                    affected, version_status = [], "unknown"
                    review.append("versions déployées non renseignées dans le profil client")

                result.findings.append(
                    Finding(
                        id=Finding.make_id(profile.id, asset.id, record.cve_id),
                        client_id=profile.id,
                        asset_id=asset.id,
                        cve_id=record.cve_id,
                        source=SOURCE,
                        match=match,
                        version_status=version_status,
                        affected_versions=affected,
                        review_reasons=review,
                    )
                )
        return result
