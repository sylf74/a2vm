"""Write a triage run as JSON (full detail), CSV (one row per CVE x asset) and Markdown (French)."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import TriageRun
from .rationale import BOD_FR, EXPLOITATION_FR

CSV_FIELDS = [
    "decision",
    "cve",
    "asset",
    "owner",
    "exposed",
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


def render_markdown(run: TriageRun) -> str:
    counts = {d: sum(r.delivery_decision == d for r in run.rows) for d in ("ACT", "ATTEND", "TRACK")}
    review = [r for r in run.rows if r.needs_review]
    lines = [
        f"# Triage des vulnérabilités — {run.client.name}",
        "",
        f"Généré le {run.generated_at} · {run.cve_count} CVE analysées · profil client du "
        f"{run.client.updated}" + (f" · justifications rédigées par {run.llm_model}" if run.llm_model else ""),
        "",
        f"**ACT : {counts['ACT']}** · **ATTEND : {counts['ATTEND']}** · TRACK : {counts['TRACK']} · "
        f"à revoir : {len(review)} · non concernées (version) : {len(run.not_affected)}",
        "",
    ]
    for decision, title in (("ACT", "ACT — remédier maintenant"), ("ATTEND", "ATTEND — planifier la remédiation")):
        rows = [r for r in run.rows if r.delivery_decision == decision]
        lines += [f"## {title}", ""]
        if not rows:
            lines += ["Aucune.", ""]
            continue
        lines += [
            "| CVE | Actif | Propriétaire | Exploitation | EPSS | Délai | Revue |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            epss = "—" if r.epss is None else f"{r.epss:.3f}"
            lines.append(
                f"| {r.cve_id} | {_md_escape(r.asset_description)} | {_md_escape(r.owner)} | "
                f"{EXPLOITATION_FR[r.exploitation.value]}{' (KEV)' if r.in_kev else ''} | {epss} | "
                f"{BOD_FR[r.bod_timeline]} | {'à revoir' if r.needs_review else ''} |"
            )
        lines.append("")
        for r in rows:
            lines += [f"### {r.cve_id} — {r.asset_id}", "", r.rationale, ""]
            if r.needs_review:
                lines += ["À revoir : " + " ; ".join(r.review_reasons) + ".", ""]

    track = [r for r in run.rows if r.delivery_decision == "TRACK"]
    if track:
        lines += ["## TRACK — surveillance", ""]
        lines += [f"- {r.cve_id} — {_md_escape(r.asset_description)} (SSVC {r.ssvc_decision})" for r in track]
        lines.append("")
    if run.not_affected:
        lines += ["## Non concernées (versions déployées hors périmètre)", ""]
        lines += [f"- {n.cve_id} — {n.asset_id} ({', '.join(n.deployed_versions)})" for n in run.not_affected]
        lines.append("")
    if run.errors:
        lines += ["## Erreurs", ""]
        lines += [f"- {e['cve']} : {e['error']}" for e in run.errors]
        lines.append("")
    lines += [
        "---",
        "Méthode : décision SSVC CISA Coordinator v2.0.3 et délai CISA BOD 26-04 calculés de façon "
        "déterministe ; le LLM éventuel ne fait que rédiger la justification et proposer des "
        "valeurs signalées « à revoir ».",
    ]
    return "\n".join(lines) + "\n"


def write_all(run: TriageRun, out_dir: Path) -> Path:
    stamp = run.generated_at[:10]
    target = out_dir / run.client.id / stamp
    target.mkdir(parents=True, exist_ok=True)
    write_json(run, target / "triage.json")
    write_csv(run, target / "triage.csv")
    (target / "report.md").write_text(render_markdown(run), encoding="utf-8")
    return target
