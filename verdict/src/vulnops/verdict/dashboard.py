"""One-page HTML dashboard of a triage run: self-contained (no script, no external resource), so it
can be opened from the job artifacts, attached to a mail or published with GitLab Pages.

Decisions use the status palette (ACT critical, ATTEND serious, TRACK neutral), always with their
label: colour never carries the meaning alone. Light and dark themes follow the reader's setting.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict

from vulnops.core.models import TriageRun

from .rationale import BOD_FR

DECISIONS = ("ACT", "ATTEND", "TRACK")
BOD_ORDER = ["3 days & forensic investigation", "3 days", "14 days", "60 days", "fix on system upgrade"]
BOD_SHORT = {
    "3 days & forensic investigation": "3 j + forensique",
    "3 days": "3 jours",
    "14 days": "14 jours",
    "60 days": "60 jours",
    "fix on system upgrade": "à la mise à niveau",
}

CSS = """
:root{--surface:#fcfcfb;--plane:#f9f9f7;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;
--ring:rgba(11,11,11,.10);--act:#d03b3b;--attend:#ec835a;--track:#c3c2b7;--seq:#2e6fd8}
@media (prefers-color-scheme:dark){:root{--surface:#1a1a19;--plane:#0d0d0d;--ink:#f0efec;--ink2:#c3c2b7;
--muted:#898781;--grid:#2c2c2a;--ring:rgba(255,255,255,.10);--track:#5d5c57;--seq:#5b8ff0}}
*{box-sizing:border-box}body{margin:0;background:var(--plane);color:var(--ink);
font:14px/1.45 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--ink2);margin:0 0 20px}h2{font-size:16px;margin:28px 0 10px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:14px 16px}
.tile .v{font-size:30px;font-weight:650;line-height:1.1}.tile .l{color:var(--ink2);font-size:13px}
.tile .k{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:var(--ink2)}
.dot{width:10px;height:10px;border-radius:3px;display:inline-block}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:16px;overflow-x:auto}
.card svg{min-width:640px}
.legend{display:flex;gap:16px;color:var(--ink2);font-size:12px;margin:0 0 8px}
svg text{fill:var(--ink2);font-size:12px}svg .val{fill:var(--ink);font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}th{color:var(--ink2);font-weight:600;text-align:left}
th,td{padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}td.n{text-align:right}
.tag{font-size:11px;font-weight:600;border-radius:4px;padding:1px 6px;border:1px solid var(--ring)}
footer{color:var(--muted);font-size:12px;margin-top:28px}
"""


def _e(text: object) -> str:
    return html.escape(str(text))


def _stacked_bars(rows: list[tuple[str, dict[str, int]]], width: int = 1000) -> str:
    """Horizontal stacked bars, one per asset: findings by decision, with totals at the bar end."""
    label_w, bar_h, gap, value_w = 230, 18, 10, 70
    plot_w = width - label_w - value_w
    top = max((sum(c.values()) for _, c in rows), default=1) or 1
    height = len(rows) * (bar_h + gap) + 4
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Constats par actif">']
    for i, (name, counts) in enumerate(rows):
        y = i * (bar_h + gap) + 2
        short = name if len(name) <= 34 else name[:33] + "…"
        parts.append(
            f'<text x="{label_w - 8}" y="{y + 13}" text-anchor="end">{_e(short)}<title>{_e(name)}</title></text>'
        )
        x = float(label_w)
        for d in DECISIONS:
            n = counts.get(d, 0)
            if not n:
                continue
            w = max(plot_w * n / top - 2, 1.5)  # 2px surface gap between segments
            parts.append(
                f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="3" fill="var(--{d.lower()})">'
                f"<title>{_e(name)} — {d} : {n} constats</title></rect>"
            )
            x += w + 2
        total = sum(counts.values())
        parts.append(f'<text class="val" x="{x + 6:.1f}" y="{y + 13}">{total}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _bars(items: list[tuple[str, int]], width: int = 1000) -> str:
    """Single-series vertical bars (one hue): open ACT/ATTEND findings by remediation delay."""
    height, base, top_pad = 190, 160, 18
    n = max(len(items), 1)
    slot = width / n
    bar_w = min(90.0, slot * 0.55)
    top = max((v for _, v in items), default=1) or 1
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Constats par délai">']
    parts.append(f'<line x1="0" x2="{width}" y1="{base}" y2="{base}" stroke="var(--grid)"/>')
    for i, (label, v) in enumerate(items):
        cx = slot * i + slot / 2
        h = (base - top_pad) * v / top
        parts.append(
            f'<rect x="{cx - bar_w / 2:.1f}" y="{base - h:.1f}" width="{bar_w:.1f}" height="{max(h, 1):.1f}" rx="4" '
            f'fill="var(--seq)"><title>{_e(label)} : {v} constats</title></rect>'
        )
        parts.append(f'<text class="val" x="{cx:.1f}" y="{base - h - 5:.1f}" text-anchor="middle">{v}</text>')
        parts.append(f'<text x="{cx:.1f}" y="{base + 18}" text-anchor="middle">{_e(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_dashboard(run: TriageRun) -> str:
    rows = run.rows
    cves = {d: {r.cve_id for r in rows if r.delivery_decision == d} for d in DECISIONS}
    kev_open = {r.cve_id for r in rows if r.in_kev and r.delivery_decision in ("ACT", "ATTEND")}
    exposed_act = {r.asset_id for r in rows if r.publicly_exposed and r.delivery_decision == "ACT"}

    tiles = [
        ("ACT", len(cves["ACT"]), "CVE à remédier maintenant", "var(--act)"),
        ("ATTEND", len(cves["ATTEND"]), "CVE à planifier", "var(--attend)"),
        ("TRACK", len(cves["TRACK"]), "CVE sous surveillance", "var(--track)"),
        ("KEV", len(kev_open), "CVE exploitées activement (ACT ou ATTEND)", "var(--act)"),
        ("Internet", len(exposed_act), "actifs exposés avec un ACT", "var(--act)"),
    ]
    tile_html = "".join(
        f'<div class="tile"><span class="k"><span class="dot" style="background:{c}"></span>{_e(k)}</span>'
        f'<div class="v">{v}</div><div class="l">{_e(label)}</div></div>'
        for k, v, label, c in tiles
    )

    per_asset: dict[str, Counter[str]] = defaultdict(Counter)
    labels: dict[str, str] = {}
    for r in rows:
        per_asset[r.asset_id][r.delivery_decision] += 1
        labels[r.asset_id] = r.asset_description or r.asset_id
    ranked = sorted(per_asset.items(), key=lambda kv: tuple(-kv[1].get(d, 0) for d in DECISIONS))[:25]
    asset_rows = [(labels[a], c) for a, c in ranked]

    delays = Counter(r.bod_timeline for r in rows if r.delivery_decision in ("ACT", "ATTEND"))
    delay_items = [(BOD_SHORT[b], delays[b]) for b in BOD_ORDER if delays.get(b)]

    act_groups: dict[str, list] = defaultdict(list)
    for r in rows:
        if r.delivery_decision == "ACT":
            act_groups[r.cve_id].append(r)
    act_rows = sorted(act_groups.items(), key=lambda kv: (not kv[1][0].in_kev, -(kv[1][0].epss or 0)))[:40]
    table = "".join(
        f"<tr><td>{_e(cve)}</td><td>{_e(', '.join(sorted({r.asset_id for r in rs})))}</td>"
        f"<td>{'<span class=tag>KEV</span>' if rs[0].in_kev else ''}</td>"
        f"<td class=n>{'' if rs[0].epss is None else f'{rs[0].epss:.3f}'}</td>"
        f"<td>{_e(BOD_FR[rs[0].bod_timeline])}</td></tr>"
        for cve, rs in act_rows
    )
    head = "<table><tr><th>CVE</th><th>Actifs</th><th></th><th>EPSS</th><th>Délai</th></tr>"
    act_html = head + table + "</table>" if table else "Aucune."
    assets_html = _stacked_bars(asset_rows) if asset_rows else "Aucun constat."
    legend = "".join(
        f'<span><span class="dot" style="background:var(--{d.lower()})"></span> {d}</span>' for d in DECISIONS
    )
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>vulnops — {_e(run.client.name)}</title>
<style>{CSS}</style></head><body><main>
<h1>Vulnérabilités — {_e(run.client.name)}</h1>
<p class="sub">Triage du {_e(run.generated_at[:16].replace("T", " "))} UTC · {run.cve_count} CVE analysées ·
{len(rows)} constats (CVE × actif)</p>
<div class="tiles">{tile_html}</div>
<h2>Constats par actif</h2>
<div class="card"><div class="legend">{legend}</div>{assets_html}</div>
<h2>Échéances de remédiation (ACT et ATTEND, référentiel CISA BOD 26-04)</h2>
<div class="card">{_bars(delay_items) if delay_items else "Aucune échéance."}</div>
<h2>ACT — CVE à remédier maintenant</h2>
<div class="card">{act_html}</div>
<footer>Décisions SSVC CISA calculées de façon déterministe. Détail de chaque constat : triage.csv.</footer>
</main></body></html>
"""
