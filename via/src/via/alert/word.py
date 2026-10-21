# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The alert sheet as a Word file, from a template with tags (docxtpl).

The client's template lives in its project (`templates/alert.docx`, built from the client's own
sheet); without one, the neutral template shipped here is used. The context is computed from the
same facts as the mail (`Fiche.facts`, the CVE records), so the Word sheet and the mail never say
different things. Tags: `docs/alert-word.md`.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

from a2vm.models import CvssMetric, VulnRecord

from .fiche import Fiche, _versions

AV = {"N": "Réseau", "A": "Réseau adjacent", "L": "Local", "P": "Physique"}
AC = {"L": "Faible", "H": "Élevée"}
PR = {"N": "Aucun", "L": "Authentification utilisateur simple", "H": "Privilèges élevés"}
UI = {"N": "Non", "R": "Oui", "P": "Oui (passive)", "A": "Oui (active)"}
IMPACT_RISKS = (
    (("C", "VC"), "Atteinte à la confidentialité des données"),
    (("I", "VI"), "Atteinte à l'intégrité des données"),
    (("A", "VA"), "Déni de service"),
)
# Every tag A2VM fills; `via check-template` refuses a template naming another one.
KNOWN = {
    "titre", "niveau", "date", "source", "pourquoi", "produit_description", "poc", "risques",
    "cvss_version", "cvss_score", "exploitee", "correctif_existe", "contournement_existe", "cwes",
    "cves", "correctifs", "contournements", "references", "actifs", "impact", "description", "delai",
}  # fmt: skip


def default_template() -> Path:
    return Path(str(resources.files("via.alert").joinpath("templates", "alert.docx")))


def _vector(m: CvssMetric | None) -> dict[str, str]:
    if not m or not m.vector:
        return {}
    return dict(p.split(":", 1) for p in m.vector.split("/")[1:] if ":" in p)


def calculator_url(m: CvssMetric | None) -> str:
    """FIRST calculator of the vector's own version."""
    if not m or not m.vector:
        return ""
    if m.version == "4.0":
        return f"https://www.first.org/cvss/calculator/4-0#{m.vector}"
    if m.version in ("3.0", "3.1"):
        return f"https://www.first.org/cvss/calculator/{m.version}#{m.vector}"
    return ""


def _cve(record: VulnRecord) -> dict[str, Any]:
    m = record.best_cvss()
    v = _vector(m)
    complexity = AC.get(v.get("AC", ""), "")
    if v.get("AT") == "P" and complexity:
        complexity = "Élevée"  # CVSS 4.0: attack requirements present
    technical = (record.adp_ssvc or {}).get("technical_impact")
    if technical is None and v:
        keys = ("VC", "VI") if m and m.version == "4.0" else ("C", "I")
        technical = "total" if all(v.get(k) == "H" for k in keys) else "partial"
    components = []
    entries = [e for e in record.affected if e.source == "cna"] or record.affected  # ADP repeats the CNA
    for e in entries[:12]:
        versions = _versions(e)
        components.append(f"{e.vendor} {e.product}".strip() + (f" : {versions}" if versions else ""))
    return {
        "id": record.cve_id,
        "cvss_version": m.version if m else "",
        "cvss_score": f"{m.score:g}" if m and m.score is not None else "non publié",
        "lien_cve": f"https://www.cve.org/CVERecord?id={record.cve_id}",
        "lien_cvss": calculator_url(m),
        "vecteur": AV.get(v.get("AV", ""), "Non précisé"),
        "complexite": complexity or "Non précisée",
        "privileges": PR.get(v.get("PR", ""), "Non précisés"),
        "interaction": UI.get(v.get("UI", ""), "Non précisé"),
        "droits_privilegies": {"total": "Oui", "partial": "Non"}.get(technical or "", "Non précisé"),
        "composants": components,
    }


def context(fiche: Fiche, today: str = "") -> dict[str, Any]:
    """Values for every tag of KNOWN; links are plain URLs here, made clickable at render time."""
    alert = fiche.alert
    facts, recs, item = fiche.facts, alert.records, alert.item
    cves = [_cve(r) for r in recs]
    best = max(
        (r.best_cvss() for r in recs if r.best_cvss() and r.best_cvss().score is not None),
        key=lambda m: m.score,
        default=None,
    )
    risks = list(facts.get("risques") or [])
    if not risks and best:
        v = _vector(best)
        risks = [label for keys, label in IMPACT_RISKS if any(v.get(k) == "H" for k in keys)]
    cwes = []
    for r in recs:
        for c in r.cwes:
            if c.startswith("CWE-") and c not in [w["id"] for w in cwes]:
                number = c.split("-", 1)[1]
                cwes.append(
                    {
                        "id": c,
                        "nom": r.cwe_names.get(c, ""),
                        "lien": f"https://cwe.mitre.org/data/definitions/{number}.html",
                    }
                )
    fixes = list(facts.get("correctifs") or [])
    fixes += [
        f"{r['nom']} : mise à jour vers {r['version_corrigee']}"
        for r in facts.get("actifs", [])
        if r.get("version_corrigee")
    ]
    fix_status = facts.get("correctif", "")
    if not fixes and fix_status.startswith("disponible"):
        fixes = [fix_status[0].upper() + fix_status[1:]]  # e.g. "Disponible — voir les avis éditeur en lien"
    return {
        "titre": item.title,
        "niveau": {"urgent": "URGENT", "info": "INFORMATION"}.get(alert.level, alert.level),
        "date": today,
        "source": item.source,
        "pourquoi": [r[0].upper() + r[1:] for r in alert.reasons],
        "produit_description": facts.get("produit", ""),
        "poc": bool(facts.get("poc")),
        "risques": risks,
        "cvss_version": best.version if best else "",
        "cvss_score": f"{best.score:g}" if best else "non publié",
        "exploitee": "Oui" if facts.get("exploitee") else "Non",
        "correctif_existe": "Oui" if fixes else "Non précisé",
        "contournement_existe": "Non précisé",
        "cwes": cwes,
        "cves": cves,
        "correctifs": fixes
        or ([fix_status[0].upper() + fix_status[1:]] if fix_status.startswith("disponible") else []),
        "contournements": [],
        "references": list(dict.fromkeys(facts.get("liens", []))),
        "actifs": facts.get("actifs", []),
        "impact": facts.get("impact", ""),
        "description": facts.get("description", ""),
        "delai": facts.get("delai", ""),
    }


URL_KEYS = {"lien_cve", "lien_cvss", "lien"}


def render(template: str | Path, ctx: dict[str, Any], out: str | Path) -> Path:
    """Fill `template` with `ctx`; URLs under lien* keys and in `references` become clickable links."""
    from docxtpl import DocxTemplate, RichText

    tpl = DocxTemplate(str(template))

    def link(url: str):
        if not url:
            return ""
        rt = RichText()
        rt.add(url, url_id=tpl.build_url_id(url), color="0563C1", underline=True)
        return rt

    def linked(value):
        if isinstance(value, dict):
            return {k: (link(v) if k in URL_KEYS and isinstance(v, str) else linked(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [linked(v) for v in value]
        return value

    data = linked(ctx)
    data["references"] = [link(u) for u in ctx.get("references", [])]
    tpl.render(data, autoescape=True)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tpl.save(str(out))
    return out


def check_template(template: str | Path) -> list[str]:
    """Problems of a template: unreadable, Jinja errors, or tags A2VM does not fill."""
    from docxtpl import DocxTemplate

    try:
        tpl = DocxTemplate(str(template))
        names = tpl.get_undeclared_template_variables()
    except Exception as exc:  # docx, XML or Jinja syntax: one message for the analyst
        return [f"{template}: not a usable template: {exc}"]
    unknown = sorted(set(names) - KNOWN)
    return [f"{template}: unknown tag(s) {', '.join(unknown)} (see docs/alert-word.md)"] if unknown else []


SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def filename(alert_id: str) -> str:
    return SAFE.sub("-", alert_id) + ".docx"
