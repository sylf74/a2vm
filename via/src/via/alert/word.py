# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The alert sheet as a Word file, from a template with tags (docxtpl).

The client's template lives in its project (`templates/alert.<lang>.docx`, else
`templates/alert.docx`, built from the client's own sheet); without one, the neutral template of
the language shipped here is used. The context is computed from the same facts as the mail
(`Fiche.facts`, the CVE records), in the language of the contact (labels of `i18n.py`); its prose
(title, main impact, description) is taken from the sheet the analyst validated in that language
(`with_text`), so the Word sheet and the mail never say different things. Tags: `docs/alert-word.md`.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

from a2vm.models import CvssMetric, VulnRecord

from .fiche import Fiche, _versions
from .i18n import LABELS, heading_key, known, t

IMPACT_RISKS = ((("C", "VC"), "w.risk.c"), (("I", "VI"), "w.risk.i"), (("A", "VA"), "w.risk.a"))
_KEYS = set(LABELS["en"])
# Every tag A2VM fills; `via check-template` refuses a template naming another one.
KNOWN = {
    "titre", "niveau", "date", "source", "pourquoi", "produit_description", "poc", "risques",
    "cvss_version", "cvss_score", "exploitee", "correctif_existe", "contournement_existe", "cwes",
    "cves", "correctifs", "contournements", "references", "actifs", "impact", "description", "delai",
}  # fmt: skip


def default_template(lang: str = "en") -> Path:
    """The neutral template of `lang`, else the English one."""
    base = resources.files("via.alert").joinpath("templates")
    own = base.joinpath(f"alert.{lang}.docx")
    return Path(str(own if own.is_file() else base.joinpath("alert.en.docx")))


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


def _w(lang: str, prefix: str, code: str, default_key: str) -> str:
    key = f"w.{prefix}.{code}"
    return t(lang, key) if code and key in _KEYS else t(lang, default_key)


def _cve(record: VulnRecord, lang: str = "en") -> dict[str, Any]:
    m = record.best_cvss()
    v = _vector(m)
    complexity = _w(lang, "ac", v.get("AC", ""), "w.unspecified") if v.get("AC") else ""
    if v.get("AT") == "P" and complexity:
        complexity = t(lang, "w.ac.H")  # CVSS 4.0: attack requirements present
    technical = (record.adp_ssvc or {}).get("technical_impact")
    if technical is None and v:
        keys = ("VC", "VI") if m and m.version == "4.0" else ("C", "I")
        technical = "total" if all(v.get(k) == "H" for k in keys) else "partial"
    components = []
    entries = [e for e in record.affected if e.source == "cna"] or record.affected  # ADP repeats the CNA
    for e in entries[:12]:
        versions = _versions(e, lang)
        components.append(f"{e.vendor} {e.product}".strip() + (f": {versions}" if versions else ""))
    privileged = {"total": t(lang, "w.yes"), "partial": t(lang, "w.no")}.get(technical or "", t(lang, "w.unspecified"))
    return {
        "id": record.cve_id,
        "cvss_version": m.version if m else "",
        "cvss_score": f"{m.score:g}" if m and m.score is not None else t(lang, "w.unpublished"),
        "lien_cve": f"https://www.cve.org/CVERecord?id={record.cve_id}",
        "lien_cvss": calculator_url(m),
        "vecteur": _w(lang, "av", v.get("AV", ""), "w.unspecified"),
        "complexite": complexity or t(lang, "w.unspecified"),
        "privileges": _w(lang, "pr", v.get("PR", ""), "w.unspecified"),
        "interaction": _w(lang, "ui", v.get("UI", ""), "w.unspecified"),
        "droits_privilegies": privileged,
        "composants": components,
    }


def context(fiche: Fiche, today: str = "", lang: str = "en") -> dict[str, Any]:
    """Values for every tag of KNOWN, in `lang` (the fiche built in that language); links are plain
    URLs here, made clickable at render time."""
    alert = fiche.alert
    facts, recs = fiche.facts, alert.records
    cves = [_cve(r, lang) for r in recs]
    best = max(
        (r.best_cvss() for r in recs if r.best_cvss() and r.best_cvss().score is not None),
        key=lambda m: m.score,
        default=None,
    )
    risks = list(facts.get("risques") or [])
    if not risks and best:
        v = _vector(best)
        risks = [t(lang, label) for keys, label in IMPACT_RISKS if any(v.get(k) == "H" for k in keys)]
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
        t(lang, "fix.update", name=r["nom"], version=r["version_corrigee"])
        for r in facts.get("actifs", [])
        if r.get("version_corrigee")
    ]
    fix_status = facts.get("correctif", "")
    if not fixes and facts.get("correctif_disponible"):
        fixes = [fix_status[:1].upper() + fix_status[1:]]  # e.g. "Available — see the vendor advisories"
    why = [s for heading, body in fiche.sections if heading == t(lang, "h.why") for s in body]
    return {
        "titre": fiche.title.split("] ", 1)[-1],
        "niveau": t(lang, f"level.{alert.level}") if alert.level in ("urgent", "info") else alert.level,
        "date": today,
        "source": alert.item.source,
        "pourquoi": [line[2:] for line in why if line.startswith("- ")],
        "produit_description": facts.get("produit", "") if lang == "en" else "",
        "poc": bool(facts.get("poc")),
        "risques": risks,
        "cvss_version": best.version if best else "",
        "cvss_score": f"{best.score:g}" if best else t(lang, "w.unpublished"),
        "exploitee": t(lang, "w.yes") if facts.get("exploitee") else t(lang, "w.no"),
        "correctif_existe": t(lang, "w.yes") if fixes else t(lang, "w.unspecified"),
        "contournement_existe": t(lang, "w.unspecified"),
        "cwes": cwes,
        "cves": cves,
        "correctifs": fixes,
        "contournements": [],
        "references": list(dict.fromkeys(facts.get("liens", []))),
        "actifs": facts.get("actifs", []),
        "impact": facts.get("impact", ""),
        "description": facts.get("description", ""),
        "delai": facts.get("delai", ""),
    }


def sections(markdown: str) -> tuple[str, dict[str, str]]:
    """The title and the sections of a sheet in the watch's Markdown, keyed by the catalogue's
    heading keys (`h.impact`...); a heading outside the catalogue is left out."""
    title, out, key = "", {}, None
    for line in markdown.splitlines():
        if line.startswith("# ") and not title:
            title = line[2:].strip()
        elif line.startswith("## "):
            key = heading_key(line[3:])
            if key:
                out[key] = ""
        elif key:
            out[key] = (out[key] + "\n" + line).strip("\n")
    return title, {k: v.strip() for k, v in out.items()}


def with_text(ctx: dict[str, Any], markdown: str, lang: str) -> dict[str, Any]:
    """The context of a language with the prose of the sheet the analyst validated in it: title,
    main impact, description (paragraphs). In a language outside the catalogue the headings are not
    known: the context is left as it is (an English Word file)."""
    if not known(lang):
        return ctx
    title, parts = sections(markdown)
    out = dict(ctx)
    if title:
        out["titre"] = title.split("] ", 1)[-1]
    if parts.get("h.impact"):
        out["impact"] = parts["h.impact"]
    if parts.get("h.description"):
        out["description"] = parts["h.description"]
    return out


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


class ConversionError(RuntimeError):
    """The Word sheet could not be turned into a PDF."""


def to_pdf(docx: str | Path, out_dir: str | Path, timeout: int = 120) -> Path:
    """PDF of `docx` by LibreOffice (headless): the layout of the Word sheet, fonts included when the
    runner has them (Calibri is replaced by the metric-compatible Carlito)."""
    import shutil
    import subprocess
    import tempfile

    office = shutil.which("soffice") or shutil.which("libreoffice")
    if not office:
        raise ConversionError("LibreOffice is not installed in the job (needed for alerts.attach: [pdf])")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as profile:  # a private LibreOffice profile: jobs never share one
        cmd = [office, f"-env:UserInstallation=file://{profile}", "--headless", "--convert-to", "pdf",
               "--outdir", str(out_dir), str(docx)]  # fmt: skip
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ConversionError(f"LibreOffice did not finish in {timeout} s") from exc
    pdf = out_dir / (Path(docx).stem + ".pdf")
    if run.returncode != 0 or not pdf.exists():
        raise ConversionError(f"LibreOffice failed ({run.returncode}): {(run.stderr or run.stdout)[-300:]}")
    return pdf
