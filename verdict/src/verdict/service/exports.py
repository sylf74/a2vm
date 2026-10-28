# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Documents of the conversational search (LLD triage-prioritization §16.6): Word, PowerPoint and
CSV built from the decision service's data, never written by the model.

A document carries the run it comes from, the filters that chose its decisions, the counts per
level, the table of decisions and, for the most urgent ones, the explanation stored with the
decision (rationale, SSVC inputs and their sources, reasons, fixes). Labels are in French, as the
reports of `verdict run`. Text from vendors is kept as text: no link is made from it.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.shared import Cm, Pt
from pptx import Presentation
from pptx.util import Cm as PCm
from pptx.util import Pt as PPt

FORMATS = {
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}
LEVELS = ("ACT", "ATTEND", "TRACK")
COLUMNS = [
    ("level", "Niveau"),
    ("cve", "CVE"),
    ("asset", "Actif"),
    ("ssvc", "SSVC"),
    ("kev", "KEV"),
    ("epss", "EPSS"),
    ("cvss", "CVSS"),
    ("due_date", "Échéance"),
    ("product", "Produit"),
    ("title", "Description"),
]
DOCX_WIDTHS_CM = (1.6, 2.9, 3.4, 1.3, 1.1, 1.4, 1.2, 2.0, 3.0, 8.8)  # 26.7 cm: A4 landscape, 1.5 cm margins
FILTER_LABELS = {
    "level": "niveau",
    "cve": "CVE",
    "asset": "actif",
    "exposure": "exposition",
    "zone": "zone",
    "kev": "KEV",
    "needs_review": "à revoir",
    "source": "source",
    "min_epss": "EPSS min.",
    "min_cvss": "CVSS min.",
    "product": "produit",
    "q": "texte",
}
SSVC_INPUTS = (
    ("exploitation", "Exploitation"),
    ("automatable", "Automatisable"),
    ("technical_impact", "Impact technique"),
)


def cell(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "oui" if value else "non"
    if key == "epss" and isinstance(value, (int, float)):
        return f"{value:.1%}"
    return str(value)


def filters_text(filters: dict[str, str]) -> str:
    parts = [f"{FILTER_LABELS.get(k, k)} = {v}" for k, v in filters.items() if k in FILTER_LABELS]
    return " ; ".join(parts) or "aucun (toutes les décisions)"


def _input(detail: dict[str, Any], key: str) -> str:
    v = detail.get(key) or {}
    if isinstance(v, dict):
        return f"{v.get('value', '—')} (source : {v.get('source', '—')})"
    return str(v)


def _explanation(detail: dict[str, Any]) -> list[tuple[str, str]]:
    lines = [("Justification", detail.get("rationale") or "—")]
    lines += [(label, _input(detail, key)) for key, label in SSVC_INPUTS]
    lines.append(("Exposition", f"{detail.get('exposure', '—')} (source : {detail.get('exposure_source', '—')})"))
    if detail.get("reasons"):
        lines.append(("Raisons", " ; ".join(detail["reasons"])))
    if detail.get("review_reasons"):
        lines.append(("À revoir", " ; ".join(detail["review_reasons"])))
    fixes = detail.get("fixes") or []
    lines.append(
        (
            "Correctifs",
            " ; ".join(fixes[:10]) + (f" (+{len(fixes) - 10})" if len(fixes) > 10 else "") if fixes else "aucun connu",
        )
    )
    if detail.get("rationale_source"):
        lines.append(("Source de la justification", detail["rationale_source"]))
    return lines


def build(kind: str, meta: dict[str, Any], items: list[dict[str, Any]], details: list[dict[str, Any]]) -> bytes:
    """meta: tenant, run {id, generated_at}, filters, total, counts {level: n}, truncated."""
    if kind == "csv":
        return _csv(items)
    if kind == "docx":
        return _docx(meta, items, details)
    if kind == "pptx":
        return _pptx(meta, items, details)
    raise ValueError(f"format: one of {', '.join(FORMATS)}")


def _csv(items: list[dict[str, Any]]) -> bytes:
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["id", *(label for _, label in COLUMNS)])
    for it in items:
        w.writerow([it.get("id", ""), *(cell(it, k) for k, _ in COLUMNS)])
    return ("﻿" + out.getvalue()).encode("utf-8")  # BOM: Excel reads the accents


def _header_lines(meta: dict[str, Any]) -> list[str]:
    counts = meta.get("counts") or {}
    lines = [
        f"Run {meta['run']['id']} du {meta['run']['generated_at'][:16].replace('T', ' ')} (UTC)",
        f"Filtres : {filters_text(meta.get('filters') or {})}",
        f"{meta['total']} décision(s) : " + ", ".join(f"{lv} {counts.get(lv, 0)}" for lv in LEVELS),
    ]
    if meta.get("truncated"):
        lines.append(f"Document limité aux {meta['shown']} premières décisions, les plus urgentes.")
    lines.append("Décisions prises par la politique SSVC d'A2VM ; justifications marquées selon leur source.")
    return lines


def _docx(meta: dict[str, Any], items: list[dict[str, Any]], details: list[dict[str, Any]]) -> bytes:
    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = Cm(29.7), Cm(21.0)  # A4 landscape
    for side in ("left_margin", "right_margin", "top_margin", "bottom_margin"):
        setattr(section, side, Cm(1.5))
    doc.styles["Normal"].font.size = Pt(9)
    doc.add_heading(f"A2VM — {meta['tenant']} — décisions", level=1)
    for line in _header_lines(meta):
        doc.add_paragraph(line)
    table = doc.add_table(rows=1, cols=len(COLUMNS))
    table.style = "Table Grid"
    table.autofit = False
    for i, (_, label) in enumerate(COLUMNS):
        table.rows[0].cells[i].text = label
        for r in table.rows[0].cells[i].paragraphs[0].runs:
            r.bold = True
    for it in items:
        cells = table.add_row().cells
        for i, (key, _) in enumerate(COLUMNS):
            cells[i].text = cell(it, key)
    for i, width in enumerate(DOCX_WIDTHS_CM):  # the grid (LibreOffice) and every cell (Word)
        table.columns[i].width = Cm(width)
        for c in table.columns[i].cells:
            c.width = Cm(width)
    if details:
        doc.add_heading("Explication des décisions les plus urgentes", level=2)
        for d in details:
            asset = d.get("asset_id_full") or d.get("asset_id", "")
            doc.add_heading(f"{d.get('delivery_decision', '')} — {d.get('cve_id', '')} sur {asset}", level=3)
            if d.get("due_date"):
                doc.add_paragraph(f"Échéance : {d['due_date']} ({d.get('bod_timeline', '')})")
            for label, text in _explanation(d):
                p = doc.add_paragraph()
                p.add_run(f"{label} : ").bold = True
                p.add_run(text)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def _pptx(meta: dict[str, Any], items: list[dict[str, Any]], details: list[dict[str, Any]]) -> bytes:
    prs = Presentation()
    prs.slide_width, prs.slide_height = PCm(33.867), PCm(19.05)  # 16:9
    title = prs.slides.add_slide(prs.slide_layouts[0])
    title.shapes.title.text = f"A2VM — {meta['tenant']}"
    title.placeholders[1].text = "\n".join(_header_lines(meta))
    for p in title.placeholders[1].text_frame.paragraphs:
        for r in p.runs:
            r.font.size = PPt(14)
    cols = [c for c in COLUMNS if c[0] != "title"]
    per_slide = 12
    for start in range(0, len(items), per_slide):
        chunk = items[start : start + per_slide]
        slide = prs.slides.add_slide(prs.slide_layouts[5])
        slide.shapes.title.text = f"Décisions {start + 1} à {start + len(chunk)} sur {meta['total']}"
        shape = slide.shapes.add_table(
            len(chunk) + 1, len(cols), PCm(1), PCm(3.2), PCm(31.8), PCm(1) * (len(chunk) + 1)
        )
        tbl = shape.table
        for i, (_, label) in enumerate(cols):
            tbl.cell(0, i).text = label
        for r, it in enumerate(chunk, 1):
            for i, (key, _) in enumerate(cols):
                tbl.cell(r, i).text = cell(it, key)
        for row in tbl.rows:
            for c in row.cells:
                for p in c.text_frame.paragraphs:
                    for run in p.runs:
                        run.font.size = PPt(10)
    for d in details:
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = f"{d.get('delivery_decision', '')} — {d.get('cve_id', '')} — {d.get('asset_id', '')}"
        body = slide.placeholders[1].text_frame
        body.clear()
        first = True
        for label, text in _explanation(d):
            p = body.paragraphs[0] if first else body.add_paragraph()
            first = False
            p.text = f"{label} : {text[:400]}"
            for run in p.runs:
                run.font.size = PPt(12)
    out = io.BytesIO()
    prs.save(out)
    return out.getvalue()
