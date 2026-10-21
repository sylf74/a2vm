# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Build the neutral Word template of the alert sheet (via/src/via/alert/templates/alert.docx).

No client name, logo or classification: a client's own template goes in its project
(templates/alert.docx). Run again after changing this script; the result is committed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.shared import Pt, RGBColor

OUT = Path(__file__).resolve().parents[1] / "via" / "src" / "via" / "alert" / "templates" / "alert.docx"


def main() -> int:
    doc = Document()
    for name in ("Normal", "List Bullet"):
        doc.styles[name].font.name = "Calibri"
        doc.styles[name].font.size = Pt(10.5)
    props = doc.core_properties
    props.author, props.title = "A2VM", "Fiche d'alerte"
    props.comments = "Neutral A2VM template; tags: docs/alert-word.md"

    def p(text: str = "", style: str | None = None, bold: bool = False):
        para = doc.add_paragraph(style=style)
        if text:
            run = para.add_run(text)
            run.bold = bold
        return para

    def ctl(tag: str):
        doc.add_paragraph(tag)

    doc.add_heading("{{ titre }}", level=0)
    meta = p("Niveau {{ niveau }} — {{ date }}{% if source %} — source : {{ source }}{% endif %}")
    meta.runs[0].font.color.rgb = RGBColor(0x59, 0x59, 0x59)

    doc.add_heading("Résumé", level=1)
    ctl("{%p for c in cves %}")
    para = p()
    para.add_run("{{ c.id }}").bold = True
    para.add_run(" [Score CVSS v{{ c.cvss_version }} : ")
    para.add_run("{{ c.cvss_score }}").bold = True
    para.add_run("]")
    p("Lien CVE : {{r c.lien_cve }}")
    ctl("{%p if c.lien_cvss %}")
    p("Lien CVSS : {{r c.lien_cvss }}")
    ctl("{%p endif %}")
    ctl("{%p endfor %}")
    ctl("{%p if produit_description %}")
    p("{{ produit_description }}")
    ctl("{%p endif %}")
    p(
        "{% if poc %}Une preuve de concept ou un exploit est disponible en sources ouvertes."
        "{% else %}Actuellement, aucune preuve de concept n’est disponible en sources ouvertes.{% endif %}"
    )

    doc.add_heading("Pourquoi cette alerte", level=1)
    ctl("{%p for r in pourquoi %}")
    p("{{ r }}", style="List Bullet")
    ctl("{%p endfor %}")

    doc.add_heading("Vos actifs concernés", level=1)
    ctl("{%p if actifs %}")
    table = doc.add_table(rows=4, cols=7)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    heads = ["Actif", "Zone", "Exposition", "Version installée", "Version corrigée", "Responsable", "Source"]
    for cell, text in zip(table.rows[0].cells, heads, strict=True):
        cell.paragraphs[0].add_run(text).bold = True
    table.rows[1].cells[0].paragraphs[0].add_run("{%tr for a in actifs %}")
    fields = ["nom", "zone", "exposition", "version_installee", "version_corrigee", "responsable", "source"]
    for cell, key in zip(table.rows[2].cells, fields, strict=True):
        cell.paragraphs[0].add_run("{{ a." + key + " }}")
    table.rows[3].cells[0].paragraphs[0].add_run("{%tr endfor %}")
    ctl("{%p else %}")
    p("Aucun actif identifié avec certitude.")
    ctl("{%p endif %}")

    doc.add_heading("Informations", level=1)
    doc.add_heading("Risques", level=2)
    ctl("{%p for r in risques %}")
    p("{{ r }}")
    ctl("{%p else %}")
    p("Non précisés par les sources.")
    ctl("{%p endfor %}")
    doc.add_heading("Criticité", level=2)
    para = p("Score CVSS v{{ cvss_version }} : ")
    para.add_run("{{ cvss_score }}").bold = True
    doc.add_heading("Impact principal", level=2)
    p("{{ impact }}")
    doc.add_heading("La faille est activement exploitée", level=2)
    p("{{ exploitee }}", style="List Bullet")
    doc.add_heading("Un correctif existe", level=2)
    p("{{ correctif_existe }}", style="List Bullet")
    doc.add_heading("Une mesure de contournement temporaire existe", level=2)
    p("{{ contournement_existe }}", style="List Bullet")
    doc.add_heading("La vulnérabilité exploitée est de type", level=2)
    ctl("{%p for w in cwes %}")
    p("{{ w.id }}{% if w.nom %} : {{ w.nom }}{% endif %}")
    p("CWE : {{r w.lien }}")
    ctl("{%p endfor %}")
    doc.add_heading("Détails sur l’exploitation", level=2)
    ctl("{%p for c in cves %}")
    ctl("{%p if cves|length > 1 %}")
    para = p("Concernant la ")
    para.add_run("{{ c.id }}").bold = True
    para.add_run(" :")
    ctl("{%p endif %}")
    for line in (
        "Vecteur d’attaque : {{ c.vecteur }}",
        "Complexité de l’attaque : {{ c.complexite }}",
        "Privilèges nécessaires pour réaliser l’attaque : {{ c.privileges }}",
        "L’attaquant doit interagir avec la connexion d’un utilisateur : {{ c.interaction }}",
        "L’exploitation de la faille permet d’obtenir des droits privilégiés : {{ c.droits_privilegies }}",
    ):
        p(line, style="List Bullet")
    ctl("{%p endfor %}")
    doc.add_heading("Composants vulnérables", level=2)
    ctl("{%p for c in cves %}")
    para = p("Concernant la ")
    para.add_run("{{ c.id }}").bold = True
    para.add_run(" :")
    ctl("{%p for v in c.composants %}")
    p("{{ v }}", style="List Bullet")
    ctl("{%p endfor %}")
    ctl("{%p endfor %}")

    doc.add_heading("Description", level=1)
    p("{{ description }}")

    doc.add_heading("Recommandations", level=1)
    ctl("{%p if delai %}")
    p("Délai de remédiation recommandé : {{ delai }} (référentiel CISA BOD 26-04).")
    ctl("{%p endif %}")
    doc.add_heading("Mise en place de correctifs de sécurité", level=2)
    ctl("{%p for x in correctifs %}")
    p("{{ x }}", style="List Bullet")
    ctl("{%p else %}")
    p("Aucun correctif identifié dans les sources à ce jour.")
    ctl("{%p endfor %}")
    doc.add_heading("Solution de contournement", level=2)
    ctl("{%p for x in contournements %}")
    p("{{ x }}", style="List Bullet")
    ctl("{%p else %}")
    p("Aucune mesure de contournement identifiée dans les sources à ce jour.")
    ctl("{%p endfor %}")

    doc.add_heading("Références", level=1)
    ctl("{%p for l in references %}")
    p("{{r l }}")
    ctl("{%p endfor %}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)
    print(OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
