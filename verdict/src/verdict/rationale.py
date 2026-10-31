# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""English explanation of each triage row: a deterministic template, optionally rephrased by the LLM
(v0.17.3, HLD D16: A2VM writes in English; deliverables in another language translate their labels,
not these texts)."""

from __future__ import annotations

import json

from a2vm.llm import LlmClient, LlmError
from a2vm.llm.guard import unsupported_tokens
from a2vm.models import TriageRow
from a2vm.ssvc import BOD_EN

from .llm_tasks import write_rationale

EXPLOITATION_EN = {
    "none": "no known exploitation",
    "poc": "public proof of concept",
    "active": "active exploitation",
}
AUTOMATABLE_EN = {"yes": "automatable exploitation", "no": "exploitation not automatable"}
IMPACT_EN = {"partial": "partial technical impact", "total": "total technical impact"}
MWI_EN = {"low": "low", "medium": "medium", "high": "high"}
SOURCE_EN = {
    "kev": "CISA KEV catalog",
    "gti": "Google Threat Intelligence",
    "cisa-adp": "CISA Vulnrichment assessment",
    "references": "exploit link in the references",
    "cvss-heuristic": "derived from the CVSS vector",
    "llm": "estimated by the LLM",
    "default": "default value",
    "asset-profile": "client profile",
    "asset-inventory": "asset inventory",
}


def template_rationale(row: TriageRow) -> str:
    exposure = "internet-facing" if row.publicly_exposed else "not internet-facing"
    parts = [
        f"{row.delivery_decision} — {row.asset_description}: {exposure} asset, "
        f"{MWI_EN[row.mission_wellbeing.value]} mission impact.",
        f"{EXPLOITATION_EN[row.exploitation.value].capitalize()} ({SOURCE_EN[row.exploitation.source]}), "
        f"{AUTOMATABLE_EN[row.automatable.value]} ({SOURCE_EN[row.automatable.source]}), "
        f"{IMPACT_EN[row.technical_impact.value]} ({SOURCE_EN[row.technical_impact.source]}).",
        f"CISA SSVC decision: {row.ssvc_decision}; BOD 26-04 remediation delay: {BOD_EN[row.bod_timeline]}.",
    ]
    if len(row.reasons) > 1:
        parts.append("Policy: " + "; ".join(row.reasons[1:]) + ".")
    if row.fixes:
        more = f" (+{len(row.fixes) - 4} more)" if len(row.fixes) > 4 else ""
        parts.append("Fix available: " + ", ".join(row.fixes[:4]) + more + ".")
    if row.assumptions:
        parts.append("Assumptions: " + "; ".join(row.assumptions) + ".")
    if row.version_status == "unknown":
        parts.append("Deployed version not confirmed as vulnerable: to check.")
    return " ".join(parts)


def rationale_facts(row: TriageRow, affected_assets: list[str] | None = None) -> str:
    facts = {
        "cve": row.cve_id,
        "decision": row.delivery_decision,
        "ssvc_decision": row.ssvc_decision,
        "bod_timeline": BOD_EN[row.bod_timeline],
        "asset": row.asset_description,
        "owner": row.owner,
        "internet_exposed": row.publicly_exposed,
        "deployed_versions_affected": row.affected_versions,
        "version_status": row.version_status,
        "exploitation": EXPLOITATION_EN[row.exploitation.value],
        "in_kev": row.in_kev,
        "automatable": row.automatable.value,
        "technical_impact": row.technical_impact.value,
        "mission_impact": MWI_EN[row.mission_wellbeing.value],
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
