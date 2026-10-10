"""Triage: findings + vulnerability records + client profile -> one decision per finding.

verdict collects nothing itself: records come from the intel stage, findings from the detect
stage. Decision inputs and their precedence:

  Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference tag -> "none" (review)
  Automatable        CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
  Technical Impact   CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
  Mission/Well-being client profile (asset)
  Publicly exposed   client profile (asset.exposure == internet)

The SSVC tables and the policy make the decision; the LLM never does.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnops.core.config import Settings
from vulnops.core.io import now
from vulnops.core.llm import LlmClient, LlmError
from vulnops.core.models import (
    Assessed,
    ClientProfile,
    CvssMetric,
    Finding,
    NotAffected,
    TriageRow,
    TriageRun,
    VulnRecord,
)

from . import ssvc
from .llm_tasks import assess_ssvc_inputs
from .policy import Policy, delivery_decision
from .rationale import llm_rationale, template_rationale


def _cvss_fields(metric: CvssMetric) -> dict[str, str]:
    fields = {}
    for part in metric.vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            fields[k] = v
    return fields


def cvss_heuristic(metric: CvssMetric) -> tuple[str, str]:
    """(automatable, technical_impact) derived from a CVSS v3.x / v4.0 vector."""
    f = _cvss_fields(metric)
    if metric.version == "4.0":
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N"}.items())
        total = f.get("VC") == "H" and f.get("VI") == "H"
    else:
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}.items())
        total = f.get("C") == "H" and f.get("I") == "H"
    return ("yes" if auto else "no"), ("total" if total else "partial")


@dataclass
class CveInputs:
    record: VulnRecord
    exploitation: Assessed
    automatable: Assessed
    technical_impact: Assessed
    review_reasons: list[str] = field(default_factory=list)


class Triage:
    def __init__(self, settings: Settings, llm: LlmClient | None = None):
        self.settings = settings
        self.policy = Policy.from_dict(settings.policy)
        self.llm = llm if (llm and settings.llm.enabled) else None
        self._inputs: dict[str, CveInputs] = {}

    # -- per-CVE inputs (shared by all clients) ---------------------------------------------
    def cve_inputs(self, record: VulnRecord) -> CveInputs:
        if record.cve_id not in self._inputs:
            self._inputs[record.cve_id] = self._assess(record)
        return self._inputs[record.cve_id]

    def _assess(self, record: VulnRecord) -> CveInputs:
        review: list[str] = []
        adp = record.adp_ssvc or {}

        if record.in_kev:
            exploitation = Assessed("active", "kev")
        elif "exploitation" in adp:
            exploitation = Assessed(adp["exploitation"], "cisa-adp", adp.get("timestamp", ""))
        elif any("exploit" in (t or "").lower() for r in record.references for t in r.get("tags", []) or []):
            exploitation = Assessed("poc", "references")
            review.append("exploitation déduite d'une référence taguée « exploit »")
        else:
            exploitation = Assessed("none", "default")
            review.append("pas d'évaluation CISA de l'exploitation")

        automatable = technical_impact = None
        if "automatable" in adp and "technical_impact" in adp:
            automatable = Assessed(adp["automatable"], "cisa-adp", adp.get("timestamp", ""))
            technical_impact = Assessed(adp["technical_impact"], "cisa-adp", adp.get("timestamp", ""))
        else:
            metric = record.best_cvss()
            if metric:
                a, t = cvss_heuristic(metric)
                note = f"CVSS {metric.version} {metric.vector}"
                automatable = Assessed(a, "cvss-heuristic", note)
                technical_impact = Assessed(t, "cvss-heuristic", note)
                review.append("automatisable / impact technique déduits du vecteur CVSS")
            elif self.llm and self.settings.llm.ssvc_inputs and record.description:
                try:
                    out = assess_ssvc_inputs(self.llm, record)
                    automatable = Assessed(out["automatable"], "llm", out["justification"])
                    technical_impact = Assessed(out["technical_impact"], "llm", out["justification"])
                    review.append("automatisable / impact technique estimés par LLM")
                except LlmError as exc:
                    review.append(f"LLM indisponible pour l'évaluation SSVC : {exc}")
            if automatable is None:
                worst = self.policy.unknown_inputs == "conservative"
                automatable = Assessed("yes" if worst else "no", "default")
                technical_impact = Assessed("total" if worst else "partial", "default")
                review.append(f"automatisable / impact technique inconnus (politique {self.policy.unknown_inputs})")

        return CveInputs(record, exploitation, automatable, technical_impact, review)

    # -- run --------------------------------------------------------------------------------
    def run(
        self,
        profile: ClientProfile,
        records: dict[str, VulnRecord],
        findings: list[Finding],
        not_affected: list[NotAffected] | None = None,
        cve_count: int | None = None,
        errors: list[dict[str, str]] | None = None,
    ) -> TriageRun:
        run = TriageRun(
            client=profile,
            generated_at=now(),
            cve_count=len(records) if cve_count is None else cve_count,
            not_affected=list(not_affected or []),
            errors=list(errors or []),
            llm_model=self.llm.model if self.llm else None,
        )
        for finding in findings:
            record = records.get(finding.cve_id)
            if record is None:
                run.errors.append({"cve": finding.cve_id, "error": "finding without a vulnerability record"})
                continue
            run.rows.append(self._row(profile, self.cve_inputs(record), finding))

        order = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
        run.rows.sort(key=lambda r: (order[r.delivery_decision], -(r.epss or 0), r.cve_id, r.asset_id))
        return run

    def _row(self, profile: ClientProfile, inputs: CveInputs, finding: Finding) -> TriageRow:
        asset = profile.asset(finding.asset_id)
        record = inputs.record
        mwi = ssvc.mission_wellbeing(asset.mission_prevalence, asset.public_wellbeing_impact)
        exposed = asset.exposure == "internet"
        decision = ssvc.coordinator_decision(
            inputs.exploitation.value, inputs.automatable.value, inputs.technical_impact.value, mwi
        )
        bod = ssvc.bod_timeline(record.in_kev, exposed, inputs.automatable.value, inputs.technical_impact.value)
        delivery, reasons = delivery_decision(decision, bod, record.epss, self.policy)
        review = list(inputs.review_reasons) + list(finding.review_reasons)
        row = TriageRow(
            client_id=profile.id,
            cve_id=record.cve_id,
            asset_id=asset.id,
            asset_description=asset.description,
            owner=asset.owner,
            match=finding.match,
            version_status=finding.version_status,
            affected_versions=finding.affected_versions,
            exploitation=inputs.exploitation,
            automatable=inputs.automatable,
            technical_impact=inputs.technical_impact,
            mission_wellbeing=Assessed(
                mwi, "asset-profile", f"{asset.mission_prevalence}/{asset.public_wellbeing_impact}"
            ),
            publicly_exposed=exposed,
            in_kev=record.in_kev,
            epss=record.epss,
            epss_percentile=record.epss_percentile,
            cvss=record.best_cvss(),
            cwes=record.cwes,
            ssvc_decision=decision,
            bod_timeline=bod,
            delivery_decision=delivery,
            reasons=reasons,
            needs_review=bool(review),
            review_reasons=review,
            description=record.description,
            finding_id=finding.id,
            finding_source=finding.source,
        )
        if self.llm and self.settings.llm.rationale:
            row.rationale, row.rationale_source = llm_rationale(self.llm, row)
        else:
            row.rationale = template_rationale(row)
        return row
