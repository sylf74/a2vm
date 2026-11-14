# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Triage: findings + vulnerability records + consolidated assets -> one decision per finding.

verdict collects nothing itself: records come from the intel stage, assets and findings from the
assets stage. Decision inputs and their precedence:

  Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference tag -> "none" (review)
  Automatable        CISA ADP -> CVSS heuristic (CVE record, else scanner) -> LLM -> policy default (review)
  Technical Impact   CISA ADP -> CVSS heuristic (CVE record, else scanner) -> LLM -> policy default (review)
  Mission/Well-being asset attributes (declared, rule, source, or the client's default assumption)
  Publicly exposed   asset attribute exposure == open (SSVC System Exposure; the former "internet"
                     is read as open)

An attribute that comes from a default assumption is named in the row and flags it for review.

The SSVC tables and the policy make the decision; the LLM never does.

Review (v0.23.7, policy `review: decisive`): a row asks an analyst only when its uncertain inputs
could change its decision. The decision is computed again with every value such an input could
take (an estimated automatable or technical impact, an exploitation without assessment, an assumed
exposure, mission or well-being); when all give the same decision, the reasons stay in the row as
notes and the row does not ask for a review. A doubt on the finding itself (version not confirmed,
a product matched by name) always asks.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ngvm import ssvc
from ngvm.config import Settings
from ngvm.gti import RANK, gti_unconfirmed, ssvc_exploitation
from ngvm.io import now
from ngvm.llm import LlmClient, LlmError
from ngvm.models import (
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
    attribute_origin,
    exposure_source,
    exposure_value,
)

from .llm_tasks import assess_ssvc_inputs
from .policy import Policy, delivery_decision
from .rationale import llm_rationale, template_rationale


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


def run_asset(asset: Asset) -> dict[str, Any]:
    """An asset as the triage document lists it (v0.18.1): with or without a finding."""
    zone = asset.attributes.get("zone")
    exposure = asset.attr("exposure")
    return {
        "id": asset.id,
        "name": asset.name,
        "kind": asset.kind,
        "description": asset.description,
        "owner": asset.attr("owner").value,
        "exposure": exposure_value(exposure.value),
        "exposure_source": exposure_source(exposure),
        "zone": zone.value if zone else "",
        # Where each attribute comes from (v0.23.13): cmdb (CI), rule, host (inherited), default
        "origins": {
            name: attribute_origin(a)
            for name in ("owner", "exposure", "mission_prevalence", "public_wellbeing_impact", "zone")
            if (a := asset.attributes.get(name)) is not None
        },
        **({"runs_on": asset.identifiers["runs_on"]} if asset.identifiers.get("runs_on") else {}),
        "os": asset.os,
        "ips": list(asset.identifiers.get("ips") or []),
        "cmdb": [dict(item) for item in asset.identifiers.get("cmdb") or []],
        "scans": dict(sorted((asset.scans or {s: asset.last_seen for s in asset.sources}).items())),
        "last_seen": asset.last_seen,
        **(
            {"components": list(asset.components), "components_seen": asset.components_seen} if asset.components else {}
        ),
        # v0.24.0: the services seen on it (at most 50: the triage is pushed whole) and the path its
        # exposure rests on, from the asset graph
        **({"services": list(asset.services[:50])} if asset.services else {}),
        **({"exposure_path": list(asset.exposure_path)} if asset.exposure_path else {}),
    }


class Triage:
    def __init__(self, settings: Settings, llm: LlmClient | None = None):
        self.settings = settings
        self.policy = Policy.from_dict(settings.policy)
        self.llm = llm if (llm and settings.llm.enabled) else None
        self.llm_calls = 0
        self.llm_errors_in_row = 0
        self.llm_stopped: str | None = None  # why the LLM is no longer used in this run
        self._inputs: dict[str, CveInputs] = {}
        self._decisions: dict[tuple, str] = {}

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
                review.append("exploitation inferred from a reference tagged \u201cexploit\u201d")
        else:
            exploitation = Assessed("none", "default")
            review.append("no CISA assessment of the exploitation")
        if gti_unconfirmed(record.gti) and exploitation.value != "active":
            review.append(f"exploitation reported or suspected by GTI, not confirmed ({gti_note})")

        automatable = technical_impact = None
        if "automatable" in adp and "technical_impact" in adp:
            automatable = Assessed(adp["automatable"], "cisa-adp", adp.get("timestamp", ""))
            technical_impact = Assessed(adp["technical_impact"], "cisa-adp", adp.get("timestamp", ""))
        else:
            metric = record.best_cvss() or scanner_cvss
            if metric:
                a, t = ssvc.cvss_heuristic(metric)
                note = f"CVSS {metric.version} {metric.vector}"
                if metric is scanner_cvss:
                    note += f" ({metric.source})"
                automatable = Assessed(a, "cvss-heuristic", note)
                technical_impact = Assessed(t, "cvss-heuristic", note)
                review.append("automatable / technical impact derived from the CVSS vector")
            elif self.settings.llm.ssvc_inputs and record.description and self._llm_ready():
                try:
                    self.llm_calls += 1
                    out = assess_ssvc_inputs(self.llm, record)
                    self._llm_ok()
                    automatable = Assessed(out["automatable"], "llm", out["justification"])
                    technical_impact = Assessed(out["technical_impact"], "llm", out["justification"])
                    review.append("automatable / technical impact estimated by the LLM")
                except LlmError as exc:
                    self._llm_failed(exc)
                    review.append(f"LLM unavailable for the SSVC assessment: {exc}")
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
        started, clock = now(), time.monotonic()
        before = self.llm.usage_summary() if self.llm else None
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

        run.assets = [run_asset(a) for a in sorted(assets.values(), key=lambda a: a.id)]
        self._llm_rationales(run.rows)
        order = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
        run.rows.sort(key=lambda r: (order[r.delivery_decision], -(r.epss or 0), r.cve_id, r.asset_id))
        if self.llm and before is not None:
            after = self.llm.usage_summary()
            run.llm_usage = {
                k: (round(after[k] - before[k], 1) if k == "seconds" else after[k] - before[k])
                for k in ("questions", "from_cache", "prompt_tokens", "completion_tokens", "seconds")
            }
            run.llm_usage.update({k: after[k] for k in ("thinking", "family", "reasoning")})
            if self.llm_stopped:
                run.llm_usage["stopped"] = self.llm_stopped
        run.timing = {
            "started_at": started,
            "ended_at": now(),
            "seconds": round(time.monotonic() - clock, 1),
            "findings": len(findings),
            "decided": len(run.rows),
            "without_record": sum(missing.values()),
            "not_affected": len(run.not_affected),
        }
        return run

    def _row(self, profile: ClientProfile, inputs: CveInputs, asset: Asset, finding: Finding) -> TriageRow:
        record = inputs.record
        exposure = asset.attr("exposure")
        mission = asset.attr("mission_prevalence")
        wellbeing = asset.attr("public_wellbeing_impact")
        owner = asset.attr("owner")
        mwi = ssvc.mission_wellbeing(mission.value, wellbeing.value)
        exposure_ssvc = exposure_value(exposure.value)
        exposed = exposure_ssvc == "open"
        zone = asset.attributes.get("zone")
        decision = ssvc.coordinator_decision(
            inputs.exploitation.value, inputs.automatable.value, inputs.technical_impact.value, mwi
        )
        bod = ssvc.bod_timeline(record.in_kev, exposed, inputs.automatable.value, inputs.technical_impact.value)
        delivery, reasons = delivery_decision(decision, bod, record.epss, self.policy)
        origin = {"worst case": "worst case", "client default": "client's default assumption"}
        assumptions = [
            f"{label}: {attr.value} ({origin.get(attr.note, attr.note)})"
            for label, attr in (
                ("assumed exposure", exposure),
                ("assumed mission criticality", mission),
                ("assumed well-being impact", wellbeing),
                ("assumed owner", owner),
            )
            if attr.assumed
        ]
        review = list(inputs.review_reasons) + list(finding.review_reasons) + assumptions[:3]
        if finding.review_reasons or self.policy.review == "all":
            asks = bool(review)
        else:
            asks = bool(review) and self._decisive(inputs, record, exposure, mission, wellbeing, mwi, exposed)
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
            needs_review=asks,
            review_reasons=review,
            description=record.description,
            finding_id=finding.id,
            finding_source=", ".join(finding.sources),
            asset_id_full=asset.id,
            assumptions=assumptions,
            exposure=exposure_ssvc,
            exposure_source=exposure_source(exposure),
            zone=zone.value if zone else "",
            fixes=sorted({f"{o.package} {o.fixed_version}" for o in finding.observations if o.fixed_version}),
            first_seen=min((o.observed_at for o in finding.observations), default=""),
            seen_by=_seen_by(finding),
            product_type=product_type(record, finding.match.vendor, finding.match.product, asset),
            fix_available=fix_available(record, finding),
            cve_published=record.published or "",
            cve_updated=record.updated or "",
            kev_date_added=str((record.kev or record.adp_kev or {}).get("dateAdded") or ""),
            kev_due_date=str((record.kev or {}).get("dueDate") or ""),
            epss_date=record.epss_date or "",
        )
        row.rationale = template_rationale(row)
        return row

    def _delivery(self, exploitation: str, automatable: str, impact: str, mwi: str, kev: bool, exposed: bool,
                  epss: float | None) -> str:  # fmt: skip
        key = (exploitation, automatable, impact, mwi, kev, exposed, epss)
        if key not in self._decisions:
            decision = ssvc.coordinator_decision(exploitation, automatable, impact, mwi)
            bod = ssvc.bod_timeline(kev, exposed, automatable, impact)
            self._decisions[key] = delivery_decision(decision, bod, epss, self.policy)[0]
        return self._decisions[key]

    def _decisive(self, inputs: CveInputs, record: VulnRecord, exposure, mission, wellbeing, mwi: str,
                  exposed: bool) -> bool:  # fmt: skip
        """True when a value the uncertain inputs could take gives another delivery decision."""
        estimated = ("cvss-heuristic", "llm", "default")
        exploitation = {inputs.exploitation.value}
        if inputs.exploitation.source in ("default", "references"):
            exploitation |= {"none", "poc"}
        if gti_unconfirmed(record.gti):
            exploitation.add("active")
        automatable = {"yes", "no"} if inputs.automatable.source in estimated else {inputs.automatable.value}
        impact = (
            {"partial", "total"} if inputs.technical_impact.source in estimated else {inputs.technical_impact.value}
        )
        exposures = {True, False} if exposure.assumed else {exposed}
        mwis = {"low", "medium", "high"} if (mission.assumed or wellbeing.assumed) else {mwi}
        seen = {
            self._delivery(e, a, t, m, record.in_kev, x, record.epss)
            for e in exploitation for a in automatable for t in impact for m in mwis for x in exposures
        }  # fmt: skip
        return len(seen) > 1

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
                            r.rationale_source = source + (f", {len(rs)} assets" if len(rs) > 1 else "")
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


CPE_PARTS = {"a": "application", "o": "os", "h": "hardware"}


def _norm(text: str) -> str:
    return "".join(ch for ch in (text or "").lower() if ch.isalnum())


def product_type(record: VulnRecord, vendor: str, product: str, asset: Asset) -> str:
    """Kind of the vulnerable product, from the CPE part of the record's entries for that product
    (all entries when none names it); else `os` for the asset's own OS or a product named "… OS",
    `application` for a container image; "" when nothing tells."""
    want = _norm(product)
    entries = [e for e in record.affected if want and _norm(e.product) == want] or record.affected
    parts = [c.split(":")[2] for e in entries for c in e.cpes if c.startswith("cpe:2.3:") and c.count(":") >= 4]
    if parts:
        part = max(sorted(set(parts)), key=parts.count)
        if part in CPE_PARTS:
            return CPE_PARTS[part]
    if want and asset.os and want in _norm(asset.os):
        return "os"
    if "os" in re.split(r"[^a-z0-9]+", (product or "").lower()):  # PAN-OS, SecureGate OS
        return "os"
    if asset.kind == "image":
        return "application"
    return ""


def fix_available(record: VulnRecord, finding: Finding) -> bool:
    """A fix is known: a fixed version reported by a scanner, a fixed version in the CVE record
    (an affected range closed by `lessThan`), or a reference tagged as a patch."""
    if any(o.fixed_version for o in finding.observations):
        return True
    for e in record.affected:
        for v in e.versions:
            if v.get("status", "affected") == "affected" and v.get("lessThan") not in (None, "", "*"):
                return True
    return any("patch" in (r.get("tags") or []) for r in record.references)


def _seen_by(finding) -> dict[str, str]:
    """Latest observation of the finding per source."""
    out: dict[str, str] = {}
    for o in finding.observations:
        if o.observed_at > out.get(o.source, ""):
            out[o.source] = o.observed_at
    return dict(sorted(out.items()))
