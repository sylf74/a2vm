# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Write a triage run as JSON (full detail), CSV (one row per CVE x asset) and Markdown, with the labels
of the client's language (`client.language`, v0.17.3)."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from a2vm.io import TRIAGE, write_reporting
from a2vm.models import TriageRow, TriageRun
from a2vm.ssvc import BOD_EN

from . import reporting
from .dashboard import render_dashboard
from .i18n import has, lang_of, t

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


def _exposure_cell(r: TriageRow, lang: str = "en") -> str:
    """e.g. "open (internet), assumed"; the zone, when set, in front."""
    if not r.exposure:
        return t(lang, "yes") if r.publicly_exposed else ""
    exp = t(lang, f"exp.{r.exposure}") if _has(f"exp.{r.exposure}") else r.exposure
    src = t(lang, f"exps.{r.exposure_source}") if _has(f"exps.{r.exposure_source}") else r.exposure_source
    text = f"{exp}, {src}"
    return f"{r.zone} · {text}" if r.zone else text


def _has(key: str) -> bool:
    return has(key)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def write_json(run: TriageRun, path: Path) -> None:
    data = {
        "schema": TRIAGE,
        "client": {
            "id": run.client.id,
            "name": run.client.name,
            "profile_updated": run.client.updated,
            "language": lang_of(getattr(run.client, "language", "en")),
        },
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


def _assets_cell(rows: list[TriageRow], lang: str = "en", limit: int = 6) -> str:
    internet = t(lang, "internet")
    names = sorted({r.asset_id + (f" ({internet})" if r.publicly_exposed else "") for r in rows})
    more = f" +{len(names) - limit}" if len(names) > limit else ""
    return _md_escape(", ".join(names[:limit]) + more)


def bod_label(lang: str, code: str, short: bool = False) -> str:
    """The BOD 26-04 delay in `lang`; the code itself when unknown."""
    if short and _has(f"bod.short.{code}"):
        return t(lang, f"bod.short.{code}")
    return t(lang, f"bod.{code}") if _has(f"bod.{code}") else code


def _worst_bod(rows: list[TriageRow], lang: str = "en") -> str:
    rank = list(BOD_EN)
    return bod_label(lang, max((r.bod_timeline for r in rows), key=rank.index))


def _exploitation_cell(r: TriageRow, lang: str = "en") -> str:
    return t(lang, f"expl.{r.exploitation.value}") + (" (KEV)" if r.in_kev else "")


def _details(groups: list[tuple[str, list[TriageRow]]], lang: str = "en") -> list[str]:
    """One section per CVE: the rationale of its most exposed asset, the assets, what to review."""
    lines: list[str] = []
    for cve, rs in groups:
        lead = sorted(rs, key=lambda r: (not r.publicly_exposed, r.asset_id))[0]
        title = f"{cve} — {lead.asset_id}" if len(rs) == 1 else f"{cve} — {t(lang, 'detail.assets_n', n=len(rs))}"
        lines += [f"### {title}", "", lead.rationale, ""]
        if len(rs) > 1:
            lines += [t(lang, "detail.assets", names=", ".join(sorted(r.asset_description for r in rs))), ""]
        reasons = sorted({reason for r in rs for reason in r.review_reasons})
        if reasons:
            lines += [t(lang, "detail.review", reasons="; ".join(reasons)), ""]
    return lines


def render_markdown(run: TriageRun, language: str | None = None) -> str:
    """The daily report; labels in `language`, else the client's (rationales stay in English)."""
    lang = lang_of(language or getattr(run.client, "language", "en"))
    decisions = ("ACT", "ATTEND", "TRACK")
    rows_by = {d: [r for r in run.rows if r.delivery_decision == d] for d in decisions}
    cves_by = {d: _by_cve(rows_by[d]) for d in decisions}
    review = [r for r in run.rows if r.needs_review]

    def count(d: str) -> str:
        text = t(lang, "report.count", level=d, cves=len(cves_by[d]), findings=len(rows_by[d]))
        if d == "TRACK":
            return text
        level, rest = text.split(" (", 1)
        return f"**{level}** ({rest}"

    lines = [
        "# " + t(lang, "report.title", client=run.client.name),
        "",
        t(lang, "report.generated", at=run.generated_at, cves=run.cve_count, updated=run.client.updated)
        + (t(lang, "report.by_llm", model=run.llm_model) if run.llm_model else ""),
        "",
        " · ".join(count(d) for d in decisions)
        + f" · {t(lang, 'report.review', n=len(review))} · {t(lang, 'report.not_affected', n=len(run.not_affected))}",
        "",
        t(lang, "report.finding"),
        "",
    ]
    if run.exposure_gaps:
        lines += [
            "## " + t(lang, "report.gaps"),
            "",
            t(lang, "report.gaps.text"),
            "",
            t(lang, "report.gaps.head"),
            "|---|---|---|",
        ]
        for g in run.exposure_gaps:
            kind = t(lang, f"gap.{g['kind']}") if _has(f"gap.{g['kind']}") else g["kind"]
            lines.append(f"| {_md_escape(g['name'])} | {kind} | {_md_escape(g.get('detail', ''))} |")
        lines.append("")

    # Per asset: where the work is.
    assets: dict[str, dict[str, object]] = {}
    for r in run.rows:
        a = assets.setdefault(r.asset_id, {"desc": r.asset_description, "exposure": _exposure_cell(r, lang)})
        a[r.delivery_decision] = int(a.get(r.delivery_decision, 0)) + 1
    if assets:
        lines += ["## " + t(lang, "report.by_asset"), "", t(lang, "report.by_asset.head"), "|---|---|---|---|---|"]
        for _name, a in sorted(assets.items(), key=lambda kv: tuple(-int(kv[1].get(d, 0)) for d in decisions)):
            lines.append(
                f"| {_md_escape(str(a['desc']))} | {a['exposure']} | "
                + " | ".join(str(a.get(d, 0)) for d in decisions)
                + " |"
            )
        lines.append("")

    # ACT: every CVE, with its rationale.
    lines += ["## " + t(lang, "report.act"), ""]
    if not cves_by["ACT"]:
        lines += [t(lang, "report.none"), ""]
    else:
        lines += [t(lang, "report.act.head"), "|---|---|---|---|---|"]
        for cve, rs in cves_by["ACT"]:
            epss = "—" if rs[0].epss is None else f"{rs[0].epss:.3f}"
            lines.append(
                f"| {cve} | {_assets_cell(rs, lang)} | {_exploitation_cell(rs[0], lang)} | {epss} "
                f"| {_worst_bod(rs, lang)} |"
            )
        lines.append("")
        lines += _details(cves_by["ACT"], lang)

    # ATTEND: one line per CVE, most urgent first.
    lines += ["## " + t(lang, "report.attend"), ""]
    if not cves_by["ATTEND"]:
        lines += [t(lang, "report.none"), ""]
    else:
        shown = cves_by["ATTEND"][:ATTEND_TABLE_LIMIT]
        lines += [t(lang, "report.attend.head"), "|---|---|---|---|---|---|"]
        for cve, rs in shown:
            epss = "—" if rs[0].epss is None else f"{rs[0].epss:.3f}"
            fix = t(lang, "yes") if any(r.fixes for r in rs) else t(lang, "no")
            lines.append(
                f"| {cve} | {_assets_cell(rs, lang)} | {_exploitation_cell(rs[0], lang)} | {epss} "
                f"| {_worst_bod(rs, lang)} | {fix} |"
            )
        lines.append("")
        rest = len(cves_by["ATTEND"]) - len(shown)
        if rest > 0:
            lines += [t(lang, "report.more_attend", n=rest), ""]
        if len(cves_by["ATTEND"]) <= ATTEND_DETAIL_LIMIT:
            lines += _details(cves_by["ATTEND"], lang)

    lines += [
        "## " + t(lang, "report.track"),
        "",
        t(lang, "report.track.text", cves=len(cves_by["TRACK"]), findings=len(rows_by["TRACK"])),
        "",
    ]
    if run.not_affected:
        lines += ["## " + t(lang, "report.not_affected.title"), ""]
        lines += [
            f"- {n.cve_id} — {n.asset_id} ({', '.join(n.deployed_versions)})" for n in run.not_affected[:LIST_LIMIT]
        ]
        if len(run.not_affected) > LIST_LIMIT:
            lines.append(t(lang, "report.more_json", n=len(run.not_affected) - LIST_LIMIT))
        lines.append("")
    if run.ignored:
        ids = ", ".join(e["cve"] for e in run.ignored[:LIST_LIMIT])
        more = t(lang, "report.more_ignored", n=len(run.ignored) - LIST_LIMIT) if len(run.ignored) > LIST_LIMIT else ""
        lines += ["## " + t(lang, "report.ignored"), "", t(lang, "report.ignored.text", ids=ids, more=more), ""]
    if run.errors:
        lines += ["## " + t(lang, "report.errors"), ""]
        lines += [f"- {e['cve']}: {e['error']}" for e in run.errors[:LIST_LIMIT]]
        if len(run.errors) > LIST_LIMIT:
            lines.append(t(lang, "report.more_json", n=len(run.errors) - LIST_LIMIT))
        lines.append("")
    lines += ["---", t(lang, "report.method")]
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
