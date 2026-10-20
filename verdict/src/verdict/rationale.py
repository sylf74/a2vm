# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""French explanation of each triage row: a deterministic template, optionally rephrased by the LLM."""

from __future__ import annotations

import json

from a2vm.llm import LlmClient, LlmError
from a2vm.llm.guard import unsupported_tokens
from a2vm.models import TriageRow

from .llm_tasks import write_rationale

EXPLOITATION_FR = {
    "none": "aucune exploitation connue",
    "poc": "preuve de concept publique",
    "active": "exploitation active",
}
AUTOMATABLE_FR = {"yes": "exploitation automatisable", "no": "exploitation non automatisable"}
IMPACT_FR = {"partial": "impact technique partiel", "total": "impact technique total"}
MWI_FR = {"low": "faible", "medium": "moyen", "high": "élevé"}
BOD_FR = {
    "fix on system upgrade": "à la prochaine mise à niveau majeure",
    "60 days": "60 jours",
    "14 days": "14 jours",
    "3 days": "3 jours",
    "3 days & forensic investigation": "3 jours, avec investigation forensique",
}
SOURCE_FR = {
    "kev": "catalogue KEV de la CISA",
    "gti": "Google Threat Intelligence",
    "cisa-adp": "évaluation CISA Vulnrichment",
    "references": "lien d'exploit dans les références",
    "cvss-heuristic": "déduit du vecteur CVSS",
    "llm": "estimé par LLM",
    "default": "valeur par défaut",
    "asset-profile": "profil client",
    "asset-inventory": "inventaire des actifs",
}


def template_rationale(row: TriageRow) -> str:
    exposure = "exposé à Internet" if row.publicly_exposed else "non exposé à Internet"
    parts = [
        f"{row.delivery_decision} — {row.asset_description} : actif {exposure}, "
        f"impact mission {MWI_FR[row.mission_wellbeing.value]}.",
        f"{EXPLOITATION_FR[row.exploitation.value].capitalize()} ({SOURCE_FR[row.exploitation.source]}), "
        f"{AUTOMATABLE_FR[row.automatable.value]} ({SOURCE_FR[row.automatable.source]}), "
        f"{IMPACT_FR[row.technical_impact.value]} ({SOURCE_FR[row.technical_impact.source]}).",
        f"Décision SSVC CISA : {row.ssvc_decision} ; délai de remédiation BOD 26-04 : {BOD_FR[row.bod_timeline]}.",
    ]
    if len(row.reasons) > 1:
        parts.append("Politique : " + " ; ".join(row.reasons[1:]) + ".")
    if row.fixes:
        more = f" (+{len(row.fixes) - 4} autres)" if len(row.fixes) > 4 else ""
        parts.append("Correctif disponible : " + ", ".join(row.fixes[:4]) + more + ".")
    if row.assumptions:
        parts.append("Hypothèses : " + " ; ".join(row.assumptions) + ".")
    if row.version_status == "unknown":
        parts.append("Version déployée non confirmée comme vulnérable : à vérifier.")
    return " ".join(parts)


def rationale_facts(row: TriageRow, affected_assets: list[str] | None = None) -> str:
    facts = {
        "cve": row.cve_id,
        "decision": row.delivery_decision,
        "ssvc_decision": row.ssvc_decision,
        "bod_timeline": BOD_FR[row.bod_timeline],
        "asset": row.asset_description,
        "owner": row.owner,
        "internet_exposed": row.publicly_exposed,
        "deployed_versions_affected": row.affected_versions,
        "version_status": row.version_status,
        "exploitation": EXPLOITATION_FR[row.exploitation.value],
        "in_kev": row.in_kev,
        "automatable": row.automatable.value,
        "technical_impact": row.technical_impact.value,
        "mission_impact": MWI_FR[row.mission_wellbeing.value],
        "epss": None if row.epss is None else round(row.epss, 3),
        "cvss": None if not row.cvss else {"score": row.cvss.score, "vector": row.cvss.vector},
        "cwe": row.cwes,
        "policy_reasons": row.reasons,
        "fixed_packages": row.fixes[:10],
        "assumptions": row.assumptions,
    }
    if affected_assets and len(affected_assets) > 1:
        facts["affected_assets"] = affected_assets[:20]
        facts["affected_assets_count"] = len(affected_assets)
    return json.dumps(facts, ensure_ascii=False, indent=1)


def llm_rationale(llm: LlmClient, row: TriageRow, affected_assets: list[str] | None = None) -> tuple[str, str]:
    """(text, source). Falls back to the template when the LLM fails or the guard rejects it.

    With `affected_assets`, the text covers every asset of the same CVE and decision (`row` is the
    most exposed of them)."""
    facts = rationale_facts(row, affected_assets)
    try:
        out = write_rationale(llm, facts, row.description)
    except LlmError as exc:
        return template_rationale(row), f"template (LLM error: {exc})"
    text = f"{out['summary'].strip()} {out['action'].strip()}".strip()
    bad = unsupported_tokens(text, facts + "\n" + row.description, row.delivery_decision)
    if bad:
        return template_rationale(row), f"template (LLM output rejected: {', '.join(sorted(set(bad)))})"
    return text, f"llm ({llm.model})"
