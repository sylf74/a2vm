# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Write a triage run as JSON (full detail), CSV (one row per CVE x asset) and Markdown (French)."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from a2vm.io import write_reporting
from a2vm.models import TriageRow, TriageRun

from . import reporting
from .dashboard import render_dashboard
from .rationale import BOD_FR, EXPLOITATION_FR

CSV_FIELDS = [
    "decision",
    "cve",
    "asset",
    "owner",
    "exposed",
    "exposure",
    "exposure_source",
    "zone",
    "kev",
    "epss",
    "cvss",
    "ssvc",
    "bod_timeline",
    "exploitation",
    "version_status",
    "affected_versions",
    "needs_review",
    "rationale",
]


EXPOSURE_FR = {"open": "ouverte (Internet)", "controlled": "contrôlée", "small": "restreinte"}
EXPOSURE_SOURCE_FR = {"assumed": "supposée", "declared": "déclarée", "rule": "règle", "external-scan": "scan externe"}


def _exposure_cell(r: TriageRow) -> str:
    """e.g. "ouverte (Internet), supposée"; the zone, when set, in front."""
    if not r.exposure:
        return "oui" if r.publicly_exposed else ""
    text = f"{EXPOSURE_FR.get(r.exposure, r.exposure)}, {EXPOSURE_SOURCE_FR.get(r.exposure_source, r.exposure_source)}"
    return f"{r.zone} · {text}" if r.zone else text


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def write_json(run: TriageRun, path: Path) -> None:
    data = {
        "client": {"id": run.client.id, "name": run.client.name, "profile_updated": run.client.updated},
        "generated_at": run.generated_at,
        "cve_count": run.cve_count,
        "llm_model": run.llm_model,
        "rows": [r.to_dict() for r in run.rows],
        "not_affected": [asdict(n) for n in run.not_affected],
        "errors": run.errors,
        "ignored": run.ignored,
        "exposure_gaps": run.exposure_gaps,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(run: TriageRun, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, delimiter=";")
        w.writeheader()
        for r in run.rows:
            w.writerow(
                {
                    "decision": r.delivery_decision,
                    "cve": r.cve_id,
                    "asset": r.asset_id,
                    "owner": r.owner,
                    "exposed": "yes" if r.publicly_exposed else "no",
                    "exposure": r.exposure,
                    "exposure_source": r.exposure_source,
                    "zone": r.zone,
                    "kev": "yes" if r.in_kev else "no",
                    "epss": "" if r.epss is None else f"{r.epss:.3f}",
                    "cvss": "" if not r.cvss else r.cvss.score,
                    "ssvc": r.ssvc_decision,
                    "bod_timeline": r.bod_timeline,
                    "exploitation": r.exploitation.value,
                    "version_status": r.version_status,
                    "affected_versions": ",".join(r.affected_versions),
                    "needs_review": "yes" if r.needs_review else "no",
                    "rationale": r.rationale,
                }
            )


ATTEND_TABLE_LIMIT = 200  # CVEs listed in the ATTEND table; the rest is in triage.csv
LIST_LIMIT = 50
ATTEND_DETAIL_LIMIT = 30  # below this many CVEs, ATTEND rationales are in the report too


def _by_cve(rows: list[TriageRow]) -> list[tuple[str, list[TriageRow]]]:
    """Rows grouped by CVE, in the order of their first row (the run is already sorted by urgency)."""
    groups: dict[str, list[TriageRow]] = {}
    for r in rows:
        groups.setdefault(r.cve_id, []).append(r)
    return list(groups.items())


def _assets_cell(rows: list[TriageRow], limit: int = 6) -> str:
    names = sorted({r.asset_id + (" (Internet)" if r.publicly_exposed else "") for r in rows})
    more = f" +{len(names) - limit}" if len(names) > limit else ""
    return _md_escape(", ".join(names[:limit]) + more)


def _worst_bod(rows: list[TriageRow]) -> str:
    rank = list(BOD_FR)
    return BOD_FR[max((r.bod_timeline for r in rows), key=rank.index)]


def _exploitation_cell(r: TriageRow) -> str:
    return EXPLOITATION_FR[r.exploitation.value] + (" (KEV)" if r.in_kev else "")


def _details(groups: list[tuple[str, list[TriageRow]]]) -> list[str]:
    """One section per CVE: the rationale of its most exposed asset, the assets, what to review."""
    lines: list[str] = []
    for cve, rs in groups:
        lead = sorted(rs, key=lambda r: (not r.publicly_exposed, r.asset_id))[0]
        title = f"{cve} — {lead.asset_id}" if len(rs) == 1 else f"{cve} — {len(rs)} actifs"
        lines += [f"### {title}", "", lead.rationale, ""]
        if len(rs) > 1:
            lines += ["Actifs : " + ", ".join(sorted(r.asset_description for r in rs)) + ".", ""]
        reasons = sorted({reason for r in rs for reason in r.review_reasons})
        if reasons:
            lines += ["À revoir : " + " ; ".join(reasons) + ".", ""]
    return lines


def render_markdown(run: TriageRun) -> str:
    decisions = ("ACT", "ATTEND", "TRACK")
    rows_by = {d: [r for r in run.rows if r.delivery_decision == d] for d in decisions}
    cves_by = {d: _by_cve(rows_by[d]) for d in decisions}
    review = [r for r in run.rows if r.needs_review]
    lines = [
        f"# Triage des vulnérabilités — {run.client.name}",
        "",
        f"Généré le {run.generated_at} · {run.cve_count} CVE analysées · profil client du "
        f"{run.client.updated}" + (f" · justifications rédigées par {run.llm_model}" if run.llm_model else ""),
        "",
        " · ".join(
            f"**{d} : {len(cves_by[d])} CVE** ({len(rows_by[d])} constats)"
            if d != "TRACK"
            else f"{d} : {len(cves_by[d])} CVE ({len(rows_by[d])} constats)"
            for d in decisions
        )
        + f" · à revoir : {len(review)} · non concernées (version) : {len(run.not_affected)}",
        "",
        "Un constat est une CVE sur un actif. Le détail de chaque constat est dans `triage.csv`.",
        "",
    ]
    if run.exposure_gaps:
        lines += [
            "## Écarts d'exposition",
            "",
            "Le scan externe atteint des actifs que le profil client ne décrit pas comme exposés. "
            "Mettre à jour `published` ou l'exposition déclarée dans `client.yaml`, ou fermer l'accès.",
            "",
            "| Actif | Écart | Détail |",
            "|---|---|---|",
        ]
        kinds = {"unlisted": "hôte public non déclaré", "declared-not-open": "déclaré non exposé, vu d'Internet"}
        for g in run.exposure_gaps:
            lines.append(
                f"| {_md_escape(g['name'])} | {kinds.get(g['kind'], g['kind'])} | {_md_escape(g.get('detail', ''))} |"
            )
        lines.append("")

    # Per asset: where the work is.
    assets: dict[str, dict[str, object]] = {}
    for r in run.rows:
        a = assets.setdefault(r.asset_id, {"desc": r.asset_description, "exposure": _exposure_cell(r)})
        a[r.delivery_decision] = int(a.get(r.delivery_decision, 0)) + 1
    if assets:
        lines += ["## Par actif", "", "| Actif | Exposition | ACT | ATTEND | TRACK |", "|---|---|---|---|---|"]
        for _name, a in sorted(assets.items(), key=lambda kv: tuple(-int(kv[1].get(d, 0)) for d in decisions)):
            lines.append(
                f"| {_md_escape(str(a['desc']))} | {a['exposure']} | "
                + " | ".join(str(a.get(d, 0)) for d in decisions)
                + " |"
            )
        lines.append("")

    # ACT: every CVE, with its rationale.
    lines += ["## ACT — remédier maintenant", ""]
    if not cves_by["ACT"]:
        lines += ["Aucune.", ""]
    else:
        lines += ["| CVE | Actifs | Exploitation | EPSS | Délai |", "|---|---|---|---|---|"]
        for cve, rs in cves_by["ACT"]:
            epss = "—" if rs[0].epss is None else f"{rs[0].epss:.3f}"
            lines.append(f"| {cve} | {_assets_cell(rs)} | {_exploitation_cell(rs[0])} | {epss} | {_worst_bod(rs)} |")
        lines.append("")
        lines += _details(cves_by["ACT"])

    # ATTEND: one line per CVE, most urgent first.
    lines += ["## ATTEND — planifier la remédiation", ""]
    if not cves_by["ATTEND"]:
        lines += ["Aucune.", ""]
    else:
        shown = cves_by["ATTEND"][:ATTEND_TABLE_LIMIT]
        lines += ["| CVE | Actifs | Exploitation | EPSS | Délai | Correctif |", "|---|---|---|---|---|---|"]
        for cve, rs in shown:
            epss = "—" if rs[0].epss is None else f"{rs[0].epss:.3f}"
            fix = "oui" if any(r.fixes for r in rs) else "non"
            lines.append(
                f"| {cve} | {_assets_cell(rs)} | {_exploitation_cell(rs[0])} | {epss} | {_worst_bod(rs)} | {fix} |"
            )
        lines.append("")
        rest = len(cves_by["ATTEND"]) - len(shown)
        if rest > 0:
            lines += [f"… et {rest} autres CVE en ATTEND (moins urgentes) : voir `triage.csv`.", ""]
        if len(cves_by["ATTEND"]) <= ATTEND_DETAIL_LIMIT:
            lines += _details(cves_by["ATTEND"])

    lines += [
        "## TRACK — surveillance",
        "",
        f"{len(cves_by['TRACK'])} CVE ({len(rows_by['TRACK'])} constats), sans action planifiée : voir `triage.csv`.",
        "",
    ]
    if run.not_affected:
        lines += ["## Non concernées (versions déployées hors périmètre)", ""]
        lines += [
            f"- {n.cve_id} — {n.asset_id} ({', '.join(n.deployed_versions)})" for n in run.not_affected[:LIST_LIMIT]
        ]
        if len(run.not_affected) > LIST_LIMIT:
            lines.append(f"- … et {len(run.not_affected) - LIST_LIMIT} autres (voir `triage.json`)")
        lines.append("")
    if run.ignored:
        ids = ", ".join(e["cve"] for e in run.ignored[:LIST_LIMIT])
        more = f" et {len(run.ignored) - LIST_LIMIT} autres" if len(run.ignored) > LIST_LIMIT else ""
        lines += [
            "## Ignorées",
            "",
            f"CVE rejetées par le programme CVE, encore citées par une source : {ids}{more}.",
            "",
        ]
    if run.errors:
        lines += ["## Erreurs", ""]
        lines += [f"- {e['cve']} : {e['error']}" for e in run.errors[:LIST_LIMIT]]
        if len(run.errors) > LIST_LIMIT:
            lines.append(f"- … et {len(run.errors) - LIST_LIMIT} autres (voir `triage.json`)")
        lines.append("")
    lines += [
        "---",
        "Méthode : décision SSVC CISA Coordinator v2.0.3 et délai CISA BOD 26-04 calculés de façon "
        "déterministe ; le LLM éventuel ne fait que rédiger la justification et proposer des "
        "valeurs signalées « à revoir ».",
    ]
    return "\n".join(lines) + "\n"


def write_all(run: TriageRun, out_dir: Path, policy: dict | None = None) -> Path:
    stamp = run.generated_at[:10]
    target = out_dir / run.client.id / stamp
    target.mkdir(parents=True, exist_ok=True)
    dataset = reporting.build(run, policy)
    write_reporting(target / "reporting.json", dataset)
    write_reporting(out_dir / run.client.id / "reporting.json", dataset)  # stable path for the portal
    write_json(run, target / "triage.json")
    write_csv(run, target / "triage.csv")
    (target / "report.md").write_text(render_markdown(run), encoding="utf-8")
    (target / "dashboard.html").write_text(render_dashboard(run), encoding="utf-8")
    return target
