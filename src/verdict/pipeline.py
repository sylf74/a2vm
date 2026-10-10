"""Triage pipeline: CVE ids x client profile -> one row per (CVE, affected asset).

Decision inputs and their precedence:

  Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference tag -> "none" (review)
  Automatable        CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
  Technical Impact   CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
  Mission/Well-being client profile (asset)
  Publicly exposed   client profile (asset.exposure == internet)

The SSVC tables and the policy make the decision; the LLM never does.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from . import ssvc
from .config import Settings
from .llm import LlmClient, LlmError
from .llm.tasks import adjudicate_match, assess_ssvc_inputs
from .matching import AssetMatch, match_assets
from .models import Assessed, ClientProfile, CveFacts, CvssMetric, Match, NotAffected, TriageRow, TriageRun
from .policy import delivery_decision
from .rationale import llm_rationale, template_rationale
from .record import parse_record
from .sources import SourceError, Sources
from .versions import evaluate


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
    facts: CveFacts
    exploitation: Assessed
    automatable: Assessed
    technical_impact: Assessed
    in_kev: bool
    review_reasons: list[str] = field(default_factory=list)


class Triage:
    def __init__(self, settings: Settings, sources: Sources, llm: LlmClient | None = None):
        self.settings = settings
        self.policy = settings.policy
        self.sources = sources
        self.llm = llm if (llm and settings.llm.enabled) else None
        self._inputs: dict[str, CveInputs | None] = {}
        self._errors: dict[str, str] = {}

    # -- per-CVE inputs (shared by all clients) ---------------------------------------------
    def cve_inputs(self, cve_id: str) -> CveInputs | None:
        if cve_id in self._inputs:
            return self._inputs[cve_id]
        result = None
        try:
            record = self.sources.cve_record(cve_id)
            if record is None:
                self._errors[cve_id] = "CVE record not found"
            else:
                facts = parse_record(record)
                if facts.state.upper() == "REJECTED":
                    self._errors[cve_id] = "CVE rejected"
                else:
                    result = self._assess(facts)
        except (SourceError, ValueError) as exc:
            self._errors[cve_id] = str(exc)
        self._inputs[cve_id] = result
        return result

    def _assess(self, facts: CveFacts) -> CveInputs:
        review: list[str] = []
        kev = self.sources.kev()
        in_kev = facts.cve_id in kev or facts.adp_kev is not None
        adp = facts.adp_ssvc or {}

        if in_kev:
            exploitation = Assessed("active", "kev")
        elif "exploitation" in adp:
            exploitation = Assessed(adp["exploitation"], "cisa-adp", adp.get("timestamp", ""))
        elif any("exploit" in (t or "").lower() for r in facts.references for t in r.get("tags", []) or []):
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
            metric = facts.best_cvss()
            if metric:
                a, t = cvss_heuristic(metric)
                note = f"CVSS {metric.version} {metric.vector}"
                automatable = Assessed(a, "cvss-heuristic", note)
                technical_impact = Assessed(t, "cvss-heuristic", note)
                review.append("automatisable / impact technique déduits du vecteur CVSS")
            elif self.llm and self.settings.llm.ssvc_inputs and facts.description:
                try:
                    out = assess_ssvc_inputs(self.llm, facts)
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

        return CveInputs(facts, exploitation, automatable, technical_impact, in_kev, review)

    # -- matching ---------------------------------------------------------------------------
    def _confirm_fuzzy(self, inputs: CveInputs, am: AssetMatch) -> tuple[Match | None, list[str]]:
        if self.llm and self.settings.llm.match_adjudication:
            try:
                out = adjudicate_match(self.llm, inputs.facts, am.entries[0], am.asset)
            except LlmError as exc:
                return am.match, [f"correspondance produit approximative, LLM indisponible : {exc}"]
            if not out["same_product"]:
                return None, []
            m = am.match
            confirmed = Match("llm", m.vendor, m.product, m.score, out["justification"])
            return confirmed, ["correspondance produit confirmée par LLM uniquement"]
        if self.policy.fuzzy_match_without_llm == "drop":
            return None, []
        return am.match, ["correspondance produit approximative (similarité de noms)"]

    # -- run --------------------------------------------------------------------------------
    def run(self, profile: ClientProfile, cve_ids: list[str], epss: dict[str, tuple[float, float]]) -> TriageRun:
        run = TriageRun(
            client=profile,
            generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            cve_count=len(cve_ids),
            llm_model=self.llm.model if self.llm else None,
        )
        for cve_id in cve_ids:
            inputs = self.cve_inputs(cve_id)
            if inputs is None:
                run.errors.append({"cve": cve_id, "error": self._errors.get(cve_id, "unknown error")})
                continue
            for am in match_assets(inputs.facts, profile.assets, self.settings.fuzzy_threshold):
                review = list(inputs.review_reasons)
                match = am.match
                if match.method == "fuzzy":
                    match, extra = self._confirm_fuzzy(inputs, am)
                    if match is None:
                        continue
                    review.extend(extra)

                asset = am.asset
                if asset.versions:
                    statuses = {v: evaluate(v, am.entries) for v in asset.versions}
                    affected = [v for v, s in statuses.items() if s == "affected"]
                    if not affected and all(s == "unaffected" for s in statuses.values()):
                        run.not_affected.append(NotAffected(profile.id, cve_id, asset.id, asset.versions))
                        continue
                    version_status = "affected" if affected else "unknown"
                    if not affected:
                        review.append("statut de la version déployée indéterminé")
                else:
                    affected, version_status = [], "unknown"
                    review.append("versions déployées non renseignées dans le profil client")

                row = self._row(profile, inputs, am, match, version_status, affected, epss.get(cve_id), review)
                run.rows.append(row)

        order = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
        run.rows.sort(key=lambda r: (order[r.delivery_decision], -(r.epss or 0), r.cve_id, r.asset_id))
        return run

    def _row(self, profile, inputs, am, match, version_status, affected, epss, review) -> TriageRow:
        asset = am.asset
        mwi = ssvc.mission_wellbeing(asset.mission_prevalence, asset.public_wellbeing_impact)
        exposed = asset.exposure == "internet"
        decision = ssvc.coordinator_decision(
            inputs.exploitation.value, inputs.automatable.value, inputs.technical_impact.value, mwi
        )
        bod = ssvc.bod_timeline(inputs.in_kev, exposed, inputs.automatable.value, inputs.technical_impact.value)
        score, percentile = epss if epss else (None, None)
        delivery, reasons = delivery_decision(decision, bod, score, self.policy)
        row = TriageRow(
            client_id=profile.id,
            cve_id=inputs.facts.cve_id,
            asset_id=asset.id,
            asset_description=asset.description,
            owner=asset.owner,
            match=match,
            version_status=version_status,
            affected_versions=affected,
            exploitation=inputs.exploitation,
            automatable=inputs.automatable,
            technical_impact=inputs.technical_impact,
            mission_wellbeing=Assessed(
                mwi, "asset-profile", f"{asset.mission_prevalence}/{asset.public_wellbeing_impact}"
            ),
            publicly_exposed=exposed,
            in_kev=inputs.in_kev,
            epss=score,
            epss_percentile=percentile,
            cvss=inputs.facts.best_cvss(),
            cwes=inputs.facts.cwes,
            ssvc_decision=decision,
            bod_timeline=bod,
            delivery_decision=delivery,
            reasons=reasons,
            needs_review=bool(review),
            review_reasons=review,
            description=inputs.facts.description,
        )
        if self.llm and self.settings.llm.rationale:
            row.rationale, row.rationale_source = llm_rationale(self.llm, row)
        else:
            row.rationale = template_rationale(row)
        return row


def collect_cve_ids(
    sources: Sources,
    explicit: list[str],
    since: dt.datetime | None = None,
    include_updated: bool = False,
) -> list[str]:
    ids: list[str] = []
    for cve in explicit:
        cve = cve.strip().upper()
        if cve and cve not in ids:
            ids.append(cve)
    if since:
        for cve in sources.new_cve_ids(since, include_updated) + sources.kev_added_since(since.date()):
            if cve not in ids:
                ids.append(cve)
    return ids
