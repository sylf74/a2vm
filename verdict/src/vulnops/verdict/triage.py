# SPDX-License-Identifier: AGPL-3.0-only
"""Triage: findings + vulnerability records + consolidated assets -> one decision per finding.

verdict collects nothing itself: records come from the intel stage, assets and findings from the
assets stage. Decision inputs and their precedence:

  Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference tag -> "none" (review)
  Automatable        CISA ADP -> CVSS heuristic (CVE record, else scanner) -> LLM -> policy default (review)
  Technical Impact   CISA ADP -> CVSS heuristic (CVE record, else scanner) -> LLM -> policy default (review)
  Mission/Well-being asset attributes (declared, rule, source, or the client's default assumption)
  Publicly exposed   asset attribute exposure == internet

An attribute that comes from a default assumption is named in the row and flags it for review.

The SSVC tables and the policy make the decision; the LLM never does.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from vulnops.core.config import Settings
from vulnops.core.gti import RANK, gti_unconfirmed, ssvc_exploitation
from vulnops.core.io import now
from vulnops.core.llm import LlmClient, LlmError
from vulnops.core.models import (
    REJECTED,
    Assessed,
    Asset,
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
    """(automatable, technical_impact) derived from a CVSS v2 / v3.x / v4.0 vector."""
    f = _cvss_fields(metric)
    if metric.version == "2.0":  # no user-interaction metric in v2; complete loss of C and I = total
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "Au": "N"}.items())
        total = f.get("C") == "C" and f.get("I") == "C"
    elif metric.version == "4.0":
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N"}.items())
        total = f.get("VC") == "H" and f.get("VI") == "H"
    else:
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}.items())
        total = f.get("C") == "H" and f.get("I") == "H"
    return ("yes" if auto else "no"), ("total" if total else "partial")


def scanner_metrics(findings: list[Finding]) -> dict[str, CvssMetric]:
    """CVE -> CVSS vector reported by a scanner, for CVE records that carry none (no NVD here).

    A v3 or v4 vector is preferred to a v2 one (old CVEs often have only v2)."""
    out: dict[str, CvssMetric] = {}
    for finding in findings:
        for obs in finding.observations:
            vector = obs.cvss_vector
            if vector.startswith("CVSS:"):
                version = vector.split("/", 1)[0].split(":", 1)[1]
            elif vector.startswith("AV:") and "/Au:" in vector:
                version = "2.0"
            else:
                continue
            current = out.get(finding.cve_id)
            if current is None or (current.version == "2.0" and version != "2.0"):
                out[finding.cve_id] = CvssMetric(version, vector, None, None, obs.cvss_source)
    return out


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
        self.llm_calls = 0
        self.llm_errors_in_row = 0
        self.llm_stopped: str | None = None  # why the LLM is no longer used in this run
        self._inputs: dict[str, CveInputs] = {}

    # -- per-CVE inputs (shared by all clients) ---------------------------------------------
    def cve_inputs(self, record: VulnRecord, scanner_cvss: CvssMetric | None = None) -> CveInputs:
        if record.cve_id not in self._inputs:
            self._inputs[record.cve_id] = self._assess(record, scanner_cvss)
        return self._inputs[record.cve_id]

    def _assess(self, record: VulnRecord, scanner_cvss: CvssMetric | None = None) -> CveInputs:
        review: list[str] = []
        adp = record.adp_ssvc or {}

        # Every source that has an opinion; the highest value wins (a source never lowers another),
        # ties go to the first listed: KEV, GTI, CISA ADP, exploit-tagged references.
        gti_value, gti_note = ssvc_exploitation(record.gti)
        candidates: list[Assessed] = []
        if record.in_kev:
            candidates.append(Assessed("active", "kev"))
        if gti_value:
            candidates.append(Assessed(gti_value, "gti", gti_note))
        if "exploitation" in adp:
            candidates.append(Assessed(adp["exploitation"], "cisa-adp", adp.get("timestamp", "")))
        if any("exploit" in (t or "").lower() for r in record.references for t in r.get("tags", []) or []):
            candidates.append(Assessed("poc", "references"))
        if candidates:
            exploitation = max(candidates, key=lambda c: RANK[c.value])  # max() keeps the first of equals
            if exploitation.source == "references":
                review.append("exploitation déduite d'une référence taguée « exploit »")
        else:
            exploitation = Assessed("none", "default")
            review.append("pas d'évaluation CISA de l'exploitation")
        if gti_unconfirmed(record.gti) and exploitation.value != "active":
            review.append(f"exploitation signalée ou suspectée par GTI, non confirmée ({gti_note})")

        automatable = technical_impact = None
        if "automatable" in adp and "technical_impact" in adp:
            automatable = Assessed(adp["automatable"], "cisa-adp", adp.get("timestamp", ""))
            technical_impact = Assessed(adp["technical_impact"], "cisa-adp", adp.get("timestamp", ""))
        else:
            metric = record.best_cvss() or scanner_cvss
            if metric:
                a, t = cvss_heuristic(metric)
                note = f"CVSS {metric.version} {metric.vector}"
                if metric is scanner_cvss:
                    note += f" ({metric.source})"
                automatable = Assessed(a, "cvss-heuristic", note)
                technical_impact = Assessed(t, "cvss-heuristic", note)
                review.append("automatisable / impact technique déduits du vecteur CVSS")
            elif self.settings.llm.ssvc_inputs and record.description and self._llm_ready():
                try:
                    self.llm_calls += 1
                    out = assess_ssvc_inputs(self.llm, record)
                    self._llm_ok()
                    automatable = Assessed(out["automatable"], "llm", out["justification"])
                    technical_impact = Assessed(out["technical_impact"], "llm", out["justification"])
                    review.append("automatisable / impact technique estimés par LLM")
                except LlmError as exc:
                    self._llm_failed(exc)
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
        assets: dict[str, Asset],
        findings: list[Finding],
        not_affected: list[NotAffected] | None = None,
        cve_count: int | None = None,
        errors: list[dict[str, str]] | None = None,
    ) -> TriageRun:
        self.llm_calls, self.llm_errors_in_row, self.llm_stopped = 0, 0, None  # budget per client run
        run = TriageRun(
            client=profile,
            generated_at=now(),
            cve_count=len(records) if cve_count is None else cve_count,
            not_affected=list(not_affected or []),
            errors=list(errors or []),
            llm_model=self.llm.model if self.llm else None,
        )
        scanner_cvss = scanner_metrics(findings)
        missing: dict[str, int] = {}
        for finding in findings:
            record = records.get(finding.cve_id)
            if record is None:
                missing[finding.cve_id] = missing.get(finding.cve_id, 0) + 1
                continue
            asset = assets.get(finding.asset_ref)
            if asset is None:
                raise ValueError(f"finding {finding.id} refers to an unknown asset {finding.asset_ref!r}")
            inputs = self.cve_inputs(record, scanner_cvss.get(finding.cve_id))
            run.rows.append(self._row(profile, inputs, asset, finding))
        run.ignored = [e for e in run.errors if e.get("error") == REJECTED]
        run.errors = [e for e in run.errors if e.get("error") != REJECTED]
        known = {e["cve"] for e in run.errors} | {e["cve"] for e in run.ignored}
        for cve, n in sorted(missing.items()):
            if cve not in known:
                run.errors.append({"cve": cve, "error": f"no vulnerability record for {n} finding(s)"})

        self._llm_rationales(run.rows)
        order = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
        run.rows.sort(key=lambda r: (order[r.delivery_decision], -(r.epss or 0), r.cve_id, r.asset_id))
        return run

    def _row(self, profile: ClientProfile, inputs: CveInputs, asset: Asset, finding: Finding) -> TriageRow:
        record = inputs.record
        exposure = asset.attr("exposure")
        mission = asset.attr("mission_prevalence")
        wellbeing = asset.attr("public_wellbeing_impact")
        owner = asset.attr("owner")
        mwi = ssvc.mission_wellbeing(mission.value, wellbeing.value)
        exposed = exposure.value == "internet"
        decision = ssvc.coordinator_decision(
            inputs.exploitation.value, inputs.automatable.value, inputs.technical_impact.value, mwi
        )
        bod = ssvc.bod_timeline(record.in_kev, exposed, inputs.automatable.value, inputs.technical_impact.value)
        delivery, reasons = delivery_decision(decision, bod, record.epss, self.policy)
        origin = {"worst case": "pire cas", "client default": "hypothèse par défaut du client"}
        assumptions = [
            f"{label} : {attr.value} ({origin.get(attr.note, attr.note)})"
            for label, attr in (
                ("exposition supposée", exposure),
                ("criticité mission supposée", mission),
                ("impact bien-être supposé", wellbeing),
                ("propriétaire supposé", owner),
            )
            if attr.assumed
        ]
        review = list(inputs.review_reasons) + list(finding.review_reasons) + assumptions[:3]
        mission_source = "asset-profile" if {mission.source, wellbeing.source} <= {"declared"} else "asset-inventory"
        row = TriageRow(
            client_id=profile.id,
            cve_id=record.cve_id,
            asset_id=asset.name,
            asset_description=asset.description,
            owner=owner.value,
            match=finding.match,
            version_status="affected" if finding.status == "affected" else "unknown",
            affected_versions=finding.affected_versions,
            exploitation=inputs.exploitation,
            automatable=inputs.automatable,
            technical_impact=inputs.technical_impact,
            mission_wellbeing=Assessed(mwi, mission_source, f"{mission.value}/{wellbeing.value}"),
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
            finding_source=", ".join(finding.sources),
            asset_id_full=asset.id,
            assumptions=assumptions,
            fixes=sorted({f"{o.package} {o.fixed_version}" for o in finding.observations if o.fixed_version}),
        )
        row.rationale = template_rationale(row)
        return row

    # -- LLM rationales: one per CVE and decision, most urgent first, in parallel -------------
    def _llm_rationales(self, rows: list[TriageRow]) -> None:
        if not (self.llm and self.settings.llm.rationale):
            return
        groups: dict[tuple[str, str], list[TriageRow]] = {}
        for r in rows:
            if r.delivery_decision in self.settings.llm.rationale_for:
                groups.setdefault((r.cve_id, r.delivery_decision), []).append(r)
        order = {"ACT": 0, "ATTEND": 1, "TRACK": 2}

        def urgency(item: tuple[tuple[str, str], list[TriageRow]]) -> tuple:
            (cve, decision), rs = item
            return (order[decision], not any(r.publicly_exposed for r in rs), not rs[0].in_kev, -(rs[0].epss or 0), cve)

        pending = sorted(groups.items(), key=urgency)
        width = max(1, self.settings.llm.parallel)
        with ThreadPoolExecutor(max_workers=width) as pool:
            while pending:
                batch = []
                while pending and len(batch) < width and self._llm_ready():
                    self.llm_calls += 1
                    batch.append(pending.pop(0))
                if not batch:
                    break
                for (_key, rs), (text, source) in zip(batch, pool.map(self._group_rationale, batch), strict=True):
                    if source.startswith("template (LLM error"):
                        self._llm_failed(source)
                    else:
                        self._llm_ok()
                    for r in rs:
                        if source.startswith("llm"):
                            r.rationale = text
                            r.rationale_source = source + (f", {len(rs)} actifs" if len(rs) > 1 else "")
                        else:
                            r.rationale_source = source
        for _key, rs in pending:  # left over: budget reached or LLM down
            for r in rs:
                r.rationale_source = f"template ({self.llm_stopped})"

    def _group_rationale(self, item: tuple[tuple[str, str], list[TriageRow]]) -> tuple[str, str]:
        _key, rs = item
        lead = sorted(rs, key=lambda r: (not r.publicly_exposed, r.asset_id))[0]
        return llm_rationale(self.llm, lead, [r.asset_description for r in rs])

    # -- LLM budget and circuit breaker ------------------------------------------------------
    def _llm_ready(self) -> bool:
        if not self.llm or self.llm_stopped:
            return False
        if self.llm_calls >= self.settings.llm.max_calls:
            self.llm_stopped = f"LLM budget of {self.settings.llm.max_calls} calls reached"
            return False
        return True

    def _llm_ok(self) -> None:
        self.llm_errors_in_row = 0

    def _llm_failed(self, exc: object) -> None:
        self.llm_errors_in_row += 1
        if self.llm_errors_in_row >= self.settings.llm.max_consecutive_errors:
            self.llm_stopped = f"LLM down after {self.llm_errors_in_row} errors: {exc}"
