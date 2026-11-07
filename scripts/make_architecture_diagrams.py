# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Draw the software architecture of HLD §9 (docs/hld/architecture.svg) and the principle of the
watch (docs/hld/watch.svg) as plain SVG, light and dark, from the coordinates below.

The files are generated: change this script, run it, commit both. With --check, fails when the
committed files differ from what it draws (run in the test suite). A warning is printed when a
label is likely too long for its box.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "hld"
WARN: list[str] = []
CW = 6.1  # width of a character at 12px, roughly
CW_SMALL = 5.5
FONT = "'IBM Plex Sans Condensed', 'Arial Narrow', 'Roboto Condensed', 'Helvetica Neue', Arial, sans-serif"
MONO = "'IBM Plex Mono', ui-monospace, Menlo, Consolas, monospace"
LIGHT = (
    "--bg:#f5f6f4;--fg:#1d2329;--muted:#5d6771;--edge:#56606b;--k8s:#eaeef3;--k8s-line:#9fb0c4;"
    "--ns-line:#b7c3d0;--client:#f0ece4;--client-line:#c8bca6;--ext:#ffffff;--ext-line:#b9c0c7;"
    "--p1:#0f7f74;--p1-bg:#e1f2ef;--p2:#a96a12;--p2-bg:#f8ecd9;--p3:#2c58a8;--p3-bg:#e3eaf7;"
    "--p4:#a83b65;--p4-bg:#f6e3ea;--db-bg:#e9e6f3;--db:#6a5aa6;--label-bg:#f5f6f4"
)
DARK = (
    "--bg:#14181c;--fg:#e4e8ec;--muted:#9aa5b0;--edge:#a3adb8;--k8s:#1b2229;--k8s-line:#3d4c5c;"
    "--ns-line:#364350;--client:#221f1a;--client-line:#4f4636;--ext:#1f252b;--ext-line:#45505b;"
    "--p1:#4cc2b4;--p1-bg:#12302c;--p2:#e0a650;--p2-bg:#33260f;--p3:#7fa4ea;--p3-bg:#172640;"
    "--p4:#e588ab;--p4-bg:#3a1a27;--db-bg:#252038;--db:#a597de;--label-bg:#1b2229"
)
STYLE = (
    "svg{" + LIGHT + "}"
    "@media (prefers-color-scheme: dark){svg{" + DARK + "}}"
    "svg>rect.page{fill:var(--bg)}"
    + """svg { font-family: """
    + FONT
    + """; color: var(--edge); }
.r-k8s { fill: var(--k8s); stroke: var(--k8s-line); stroke-width: 1.5; }
.r-ns { fill: none; stroke: var(--ns-line); stroke-width: 1.2; stroke-dasharray: 6 4; }
.r-ext { fill: none; stroke: var(--ext-line); stroke-width: 1.2; }
.r-client { fill: var(--client); stroke: var(--client-line); stroke-width: 1.2; }
.box { stroke-width: 1.5; }
.b-ext { fill: var(--ext); stroke: var(--ext-line); }
.b-p1 { fill: var(--p1-bg); stroke: var(--p1); }
.b-p2 { fill: var(--p2-bg); stroke: var(--p2); }
.b-p3 { fill: var(--p3-bg); stroke: var(--p3); }
.b-p4 { fill: var(--p4-bg); stroke: var(--p4); }
.b-db { fill: var(--db-bg); stroke: var(--db); }
.t-region { fill: var(--fg); font-size: 13px; font-weight: 600; }
.t-region-sub { fill: var(--muted); font-size: 12px; font-weight: 400; }
.t-title { fill: var(--fg); font-size: 13px; font-weight: 600; }
.t-line { fill: var(--fg); font-size: 12px; }
.t-mono { fill: var(--muted); font-family: """
    + MONO
    + """; font-size: 10.5px; }
.t-chip { fill: var(--fg); font-family: """
    + MONO
    + """; font-size: 12px; }
.t-strip { fill: var(--muted); font-size: 12px; }
.t-edge { fill: var(--fg); font-size: 11px; }
.t-note { fill: var(--muted); font-size: 12.5px; }
.lbl-bg { fill: var(--label-bg); opacity: .92; }
.edge { fill: none; stroke: var(--edge); stroke-width: 1.4; }
.edge.thin { stroke-width: 1.1; }
.edge.dashed { stroke-dasharray: 5 4; }
.halo { fill: none; stroke: var(--k8s); stroke-width: 6; }
.arrowhead { fill: var(--edge); }
"""
)


def text_fits(s: str, w: float, cw: float) -> None:
    if len(s) * cw > w - 14:
        WARN.append(f"tight: {s!r} ({len(s) * cw:.0f} > {w - 14})")


class Svg:
    def __init__(self, w, h, label):
        self.w, self.h, self.label = w, h, label
        self.back, self.mid, self.front = [], [], []

    def region(self, x, y, w, h, cls, title, sub="", bottom=False):
        ty = y + h - 10 if bottom else y + 20
        self.back.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" class="{cls}"/>')
        tail = f'<tspan dx="10" class="t-region-sub">{escape(sub)}</tspan>' if sub else ""
        self.back.append(f'<text x="{x + 14}" y="{ty}" class="t-region">{escape(title)}{tail}</text>')

    def box(self, x, y, w, h, cls, title, lines=(), sub=None):
        self.front.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" class="box {cls}"/>')
        ty = y + 19
        text_fits(title, w, 6.6)
        self.front.append(f'<text x="{x + 10}" y="{ty}" class="t-title">{escape(title)}</text>')
        if sub:
            ty += 15
            text_fits(sub, w, CW_SMALL)
            self.front.append(f'<text x="{x + 10}" y="{ty}" class="t-mono">{escape(sub)}</text>')
        for line in lines:
            ty += 15
            text_fits(line, w, CW)
            self.front.append(f'<text x="{x + 10}" y="{ty}" class="t-line">{escape(line)}</text>')
        if ty > y + h - 6:
            WARN.append(f"overflow in box {title!r}: text to {ty}, box ends {y + h}")

    def chip(self, x, y, w, h, cls, label):
        self.front.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="5" class="box {cls}"/>')
        text_fits(label, w, 6.6)
        self.front.append(
            f'<text x="{x + w / 2}" y="{y + h / 2 + 4}" text-anchor="middle" class="t-chip">{escape(label)}</text>'
        )

    def edge(self, pts, label=None, at=None, halo=True, dashed=False, anchor="middle"):
        d = " ".join(f"{x},{y}" for x, y in pts)
        if halo:
            self.mid.append(f'<polyline points="{d}" class="halo"/>')
        cls = "edge dashed" if dashed else "edge"
        self.mid.append(f'<polyline points="{d}" class="{cls}" marker-end="url(#{self.mid_id})"/>')
        if label:
            lx, ly = at
            tw = len(label) * CW_SMALL + 10
            rx = lx - tw / 2 if anchor == "middle" else (lx - 5 if anchor == "start" else lx - tw + 5)
            self.front.append(f'<rect x="{rx:.0f}" y="{ly - 11}" width="{tw:.0f}" height="15" rx="3" class="lbl-bg"/>')
            self.front.append(f'<text x="{lx}" y="{ly}" text-anchor="{anchor}" class="t-edge">{escape(label)}</text>')

    def caption(self, s, at):
        lx, ly = at
        tw = len(s) * CW_SMALL + 10
        self.front.append(
            f'<rect x="{lx - tw / 2:.0f}" y="{ly - 11}" width="{tw:.0f}" height="15" rx="3" class="lbl-bg"/>'
        )
        self.front.append(f'<text x="{lx}" y="{ly}" text-anchor="middle" class="t-edge">{escape(s)}</text>')

    def note(self, x, y, s, cls="t-note", anchor="start"):
        self.front.append(f'<text x="{x}" y="{y}" text-anchor="{anchor}" class="{cls}">{escape(s)}</text>')

    def render(self, mid_id):
        self.mid_id = mid_id
        return self

    def svg(self):
        marker = (
            f'<defs><marker id="{self.mid_id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse">'
            '<path d="M0,0 L10,5 L0,10 z" class="arrowhead"/></marker></defs>'
        )
        page = f'<rect class="page" x="0" y="0" width="{self.w}" height="{self.h}"/>'
        body = "\n".join([page] + self.back + self.mid + self.front)
        return (
            f'<svg viewBox="0 0 {self.w} {self.h}" role="img" aria-label="{escape(self.label)}" '
            f'xmlns="http://www.w3.org/2000/svg">\n<style>{STYLE}</style>\n{marker}\n{body}\n</svg>\n'
        )


# ---------------------------------------------------------------- figure 1
f1 = Svg(
    1440,
    940,
    "Deployment of A2VM: GitLab deploys a namespace per client and the watch team's "
    "namespace on Kubernetes; collectors and the cloud scanner bring detections in; tickets go to iTop.",
)
f1.render("a1")

# GitLab band
f1.region(300, 14, 840, 96, "r-ext", "GitLab", "code, configuration, results")
f1.box(316, 40, 255, 58, "b-ext", "External project", ["<tenant>-external: scan results"])
f1.box(587, 40, 255, 58, "b-ext", "Tenant projects", ["client.yaml, targets, dispatch.yaml"])
f1.box(858, 40, 266, 58, "b-ext", "Code project vulnops/a2vm", ["images, chart, pipeline template"])

# Left column
f1.box(
    20,
    140,
    250,
    214,
    "b-ext",
    "Public sources",
    [
        "CVE.org records, NVD",
        "CISA KEV, FIRST EPSS",
        "CERT-FR, vendor advisories",
        "Research and news sites",
        "Google TI (optional)",
    ],
    sub="read by the shared service",
)
f1.region(20, 410, 250, 216, "r-client", "Client network")
f1.box(
    36,
    440,
    218,
    170,
    "b-p2",
    "Collector VM",
    [
        "SSH: Trivy, dnf updateinfo",
        "OpenVAS (Greenbone)",
        "iTop (CMDB), Wazuh (EDR)",
        "systemd timers, spool",
    ],
    sub="detect agent",
)
f1.box(20, 656, 250, 78, "b-ext", "iTop CMDB, Wazuh", ["CMDB items, agents' packages", "read only"])
f1.box(
    20,
    776,
    250,
    112,
    "b-ext",
    "Cloud scanner",
    [
        "Greenbone in containers",
        "runner tagged scan-cloud",
        "scans public addresses",
    ],
)

# Cluster
f1.region(300, 132, 840, 790, "r-k8s", "Kubernetes cluster", "deployed by deploy-k8s (Helm, GitLab agent)")

# namespace a2vm-via
f1.region(316, 170, 808, 188, "r-ns", "namespace a2vm-via", "the watch team")
f1.box(
    334,
    206,
    236,
    118,
    "b-p1",
    "Shared intelligence service",
    [
        "records collected once",
        "technologies 48 h, no identity",
        "feed of the radar's events",
    ],
    sub="via intel-serve · intel.v1",
)
f1.box(
    600,
    206,
    230,
    118,
    "b-p1",
    "Radar",
    [
        "items gathered into events",
        "magnitude: info 4, urgent 7",
        "zero-days before their CVE",
    ],
    sub="watch CronJob, every 10 min",
)
f1.box(
    860,
    206,
    248,
    118,
    "b-p1",
    "Review page and sender",
    [
        "the team validates",
        "daily run suspended",
    ],
    sub="oauth2-proxy · via service",
)

# namespace a2vm-<tenant>
f1.region(316, 384, 808, 522, "r-ns", "namespace a2vm-<tenant>", "one per client, e.g. lab", bottom=True)
f1.note(398, 488, "Daily run · CronJob, steps in order", "t-strip")
steps = [
    ("collect", "b-p2"),
    ("via", "b-p1"),
    ("detect", "b-p2"),
    ("assets", "b-p3"),
    ("triage", "b-p3"),
    ("inventory", "b-p1"),
    ("publish", "b-p3"),
    ("dispatch", "b-p4"),
]
sx = [334 + i * 98 for i in range(8)]
for (name, cls), x in zip(steps, sx, strict=True):
    f1.chip(x, 432, 88, 34, cls, name)
for a, b in zip(sx, sx[1:], strict=False):
    f1.mid.append(f'<line x1="{a + 88}" y1="449" x2="{b}" y2="449" class="edge thin"/>')

cx = {name: x + 44 for (name, _), x in zip(steps, sx, strict=True)}
# services row
SVC_Y, SVC_H = 566, 92
svc = {"detect": 334, "verdict": 536, "via": 738, "dispatch": 940}
f1.box(
    svc["detect"],
    SVC_Y,
    172,
    SVC_H,
    "b-p2",
    "Detection service",
    [
        "detections of each source",
    ],
    sub="detect serve",
)
f1.box(
    svc["verdict"],
    SVC_Y,
    172,
    SVC_H,
    "b-p3",
    "Decision service",
    [
        "runs, SSVC decisions, SLA",
    ],
    sub="verdict serve",
)
f1.box(
    svc["via"],
    SVC_Y,
    172,
    SVC_H,
    "b-p1",
    "Watch service",
    [
        "alerts, inventory, state",
    ],
    sub="via serve",
)
f1.box(
    svc["dispatch"],
    SVC_Y,
    168,
    SVC_H,
    "b-p4",
    "Dispatch service",
    [
        "tickets, scan follow-up",
    ],
    sub="dispatch serve",
)

# row 3 and 4
R3, R3H = 696, 62
f1.box(svc["detect"], R3, 172, R3H, "b-p2", "Intake ingress", ["pushes of the collectors"])
f1.box(svc["verdict"], R3, 172, R3H, "b-p3", "Analysts' chat", ["Open WebUI + tools"])
f1.box(svc["via"], R3, 172, R3H, "b-p1", "Watch", ["CronJob, every 10 min"])
f1.box(svc["dispatch"], R3, 168, R3H, "b-p4", "Request page", ["Remediate → confirm"])
R4 = 772
f1.box(svc["via"], R4, 172, 56, "b-p1", "Review page, sender", ["analysts validate"])
f1.box(
    334,
    836,
    774,
    44,
    "b-db",
    "Tenant PostgreSQL (CloudNativePG)",
    ["stores of the detection, decision, watch and dispatch services"],
)

# Right column
f1.box(1170, 140, 250, 74, "b-ext", "LLM endpoint (vLLM)", ["sheet prose, translation, chat"])
f1.box(1170, 226, 250, 56, "b-ext", "Microsoft Teams", ["analysts' channel (webhook)"])
f1.box(1170, 294, 250, 56, "b-ext", "Keycloak (OIDC)", ["sign-in of every page"])
f1.box(
    1170,
    370,
    250,
    112,
    "b-ext",
    "Portal",
    [
        "reporting PostgreSQL",
        "Grafana dashboards",
        "RSSI: Remediate links",
    ],
    sub="chart a2vm-portal",
)
f1.box(
    1170,
    548,
    250,
    92,
    "b-ext",
    "iTop ITSM",
    [
        "one request per asset and fix",
        "resolved or reopened by scans",
    ],
)
f1.box(1170, 770, 250, 66, "b-ext", "Mail (SMTP)", ["alert sheets to client contacts"])

# --- edges, figure 1
# GitLab
f1.edge([(991, 98), (991, 132)], "deploy, images", (1050, 124), halo=False)
f1.edge([(145, 776), (145, 762), (8, 762), (8, 69), (316, 69)], "scan results (artifacts)", (150, 62), halo=False)
f1.edge([(316, 88), (286, 88), (286, 449), (334, 449)], halo=False)
# sources -> intel
f1.edge([(270, 262), (334, 262)], "collects", (302, 254), halo=False)
# collector -> intake
f1.edge([(254, 600), (308, 600), (308, 727), (334, 727)], "push", (281, 593), halo=False)
# cmdb -> collector
f1.edge([(145, 656), (145, 626)], "read CIs", (196, 645), halo=False)
# via ns internal
f1.edge([(570, 250), (600, 250)], halo=False)
f1.edge([(830, 250), (860, 250)], halo=False)
f1.edge([(984, 324), (984, 340), (520, 340), (520, 324)], "validated events into the feed", (752, 344), halo=True)
# via chip -> intel
f1.edge([(cx["via"], 432), (cx["via"], 324)], "records", (cx["via"] + 30, 372), halo=True)
# review -> teams
f1.edge([(1108, 254), (1170, 254)], halo=False)
# daily steps -> services
f1.edge([(cx["collect"], 466), (cx["collect"], 566)], "fetch", (cx["collect"] + 24, 520), halo=True)
f1.edge([(cx["inventory"], 466), (cx["inventory"], 566)], "inventory", (cx["inventory"] - 4, 536), halo=True)
f1.edge([(cx["publish"], 466), (cx["publish"], 506), (600, 506), (600, 566)], "push run", (680, 501), halo=True)
f1.edge([(cx["dispatch"], 466), (cx["dispatch"], 566)], "POST run", (cx["dispatch"] + 30, 520), halo=True)
# publish -> portal
f1.edge([(cx["publish"] + 20, 432), (cx["publish"] + 20, 372), (1170, 372)], "publish run", (1060, 367), halo=True)
# verdict -> dispatch (decisions)
f1.edge([(680, 566), (680, 548), (1000, 548), (1000, 566)], "decisions", (770, 552), halo=True)
# dispatch -> itsm
f1.edge([(1108, 600), (1170, 600)], halo=False)
# watch -> via service
f1.edge([(824, 696), (824, 658)], "alerts", (858, 682), halo=True)
# review <-> via service
f1.edge([(910, 790), (926, 790), (926, 640), (910, 640)], halo=True)
# sender -> mail
f1.edge([(910, 812), (1170, 812)], "validated sheets (Word)", (1040, 806), halo=True)
# request page <- grafana
f1.edge([(1170, 470), (1140, 470), (1140, 727), (1108, 727)], "Remediate", (1112, 690), halo=True, anchor="start")
# intake -> detect service
f1.edge([(420, 696), (420, 658)], halo=True)
# llm / keycloak ties
f1.edge([(1140, 176), (1170, 176)], halo=False)
f1.edge([(1140, 322), (1170, 322)], halo=False, dashed=True)

# ---------------------------------------------------------------- figure 2
f2 = Svg(
    1200,
    500,
    "The watch: sources reach the shared intelligence service once; the radar of the watch "
    "team turns them into events and publishes the validated ones to a feed; each client's watch "
    "matches the records and the feed with its own assets.",
)
f2.render("a2")
f2.region(560, 14, 630, 132, "r-ns", "Watch team", "namespace a2vm-via")
f2.region(560, 324, 630, 168, "r-ns", "Each client", "namespace a2vm-<tenant>", bottom=True)
f2.box(
    20,
    160,
    210,
    150,
    "b-ext",
    "Sources",
    [
        "CERT-FR, CISA KEV",
        "vendor advisories",
        "research and news",
        "GTI (optional)",
    ],
    sub="every 10 min",
)
f2.box(
    290,
    160,
    236,
    150,
    "b-p1",
    "Shared intelligence service",
    [
        "records collected once",
        "feed: validated radar events",
        "technologies 48 h, anonymous",
    ],
    sub="intel.v1",
)
f2.box(576, 46, 180, 86, "b-p1", "Radar", ["items → events", "zero-day before its CVE"])
f2.box(788, 46, 180, 86, "b-p1", "Magnitude", ["deterministic score", "info 4 · urgent 7"])
f2.box(1000, 46, 176, 86, "b-p1", "Team validates", ["review page", "Teams, mail"])
f2.box(576, 360, 180, 96, "b-p1", "Client watch", ["records and feed", "client's own sources"])
f2.box(788, 360, 180, 96, "b-p1", "Match own assets", ["profile, inventory", "watchlist"])
f2.box(1000, 360, 176, 96, "b-p1", "Analyst validates", ["Word sheet", "mail to client contacts"])
f2.edge([(230, 235), (290, 235)], "collect", (260, 228), halo=False)
f2.edge([(526, 190), (546, 190), (546, 89), (576, 89)], "items", (528, 140), halo=True, anchor="start")
f2.edge([(756, 89), (788, 89)], halo=False)
f2.edge([(968, 89), (1000, 89)], halo=False)
f2.edge([(1088, 132), (1088, 166), (526, 166)], "published once validated", (820, 162), halo=True)
f2.edge([(526, 280), (546, 280), (546, 400), (576, 400)], "records, feed", (528, 340), halo=True, anchor="start")
f2.edge([(640, 360), (640, 296), (526, 296)], "technologies watched, ≤ 2 a day", (650, 290), halo=True, dashed=True)
f2.edge([(756, 408), (788, 408)], halo=False)
f2.edge([(968, 408), (1000, 408)], halo=False)
f2.note(1176, 228, "The radar never knows which client has what:", "t-note", "end")
f2.note(1176, 246, "each client's watch matches the events", "t-note", "end")
f2.note(1176, 264, "with its own assets, urgent when the radar", "t-note", "end")
f2.note(1176, 282, "said so.", "t-note", "end")


# ---------------------------------------------------------------- figure 3: the tenants
f3 = Svg(
    1500,
    800,
    "Several tenants on one cluster: a namespace per client with its own services, secrets and database; "
    "the watch team's shared service and the portal are the only shared parts.",
)
f3.render("a3")
COLS = {"client-a": 360, "client-b": 650, "client-n": 940}
f3.region(20, 14, 1210, 96, "r-ext", "GitLab group vulnops/clients", "group variables: shared service, mail, LLM")
f3.box(40, 40, 290, 56, "b-ext", "via", ["the watch team's project"])
for name, x in COLS.items():
    f3.box(x, 40, 260, 56, "b-ext", name, ["profile, contacts, secrets"])
f3.region(20, 130, 1210, 486, "r-k8s", "Kubernetes cluster", "deploy-k8s, one namespace per project")
f3.region(36, 180, 310, 386, "r-ns", "namespace a2vm-via")
f3.box(
    52,
    215,
    278,
    120,
    "b-p1",
    "Shared intelligence service",
    [
        "records collected once",
        "feed of the radar's events",
        "technologies, without who sent them",
    ],
    sub="one read token for every tenant",
)
f3.box(52, 349, 278, 84, "b-p1", "Radar", ["events, magnitude", "validated by the watch team"])
f3.box(52, 447, 278, 48, "b-p1", "Review page, sender", ["the watch team"])
for name, x in COLS.items():
    f3.region(x, 180, 260, 386, "r-ns", f"namespace a2vm-{name}")
    f3.box(x + 16, 215, 228, 48, "b-ext", "Daily run, watch", ["CronJobs of this client"])
    f3.box(x + 16, 273, 228, 48, "b-ext", "Services", ["detect · verdict · via · dispatch"])
    f3.box(x + 16, 331, 228, 48, "b-ext", "Pages, signed in", ["the client's OIDC groups"])
    f3.box(x + 16, 389, 228, 48, "b-ext", "Secret a2vm-tenant", ["its tokens, passwords, keys"])
    f3.box(x + 16, 447, 228, 48, "b-db", "PostgreSQL", [f"a2vm-{name}-db, own roles"])
# shared service -> every tenant
f3.mid.append('<polyline points="191,215 191,168 1170,168" class="edge"/>')
for x in COLS.values():
    f3.edge([(x + 230, 168), (x + 230, 215)], halo=False)
f3.caption("records and the radar's feed down; technologies back, without the tenant's name", (760, 165))
# every tenant -> portal
xs = [x + 245 for x in COLS.values()]
for x in xs:
    f3.mid.append(f'<line x1="{x}" y1="566" x2="{x}" y2="590" class="edge"/>')
f3.edge(
    [(xs[0], 590), (1245, 590), (1245, 300), (1262, 300)],
    "runs published, the tenant on every row",
    (900, 604),
    halo=False,
)
f3.box(
    1262,
    215,
    220,
    150,
    "b-ext",
    "Portal",
    [
        "reporting PostgreSQL",
        "row-level security per tenant",
        "Grafana: an organisation",
        "per tenant",
    ],
    sub="chart a2vm-portal",
)
# each client's own systems
f3.region(350, 636, 880, 104, "r-client", "Per client, outside the cluster", bottom=True)
for x in COLS.values():
    f3.box(x, 650, 82, 58, "b-p2", "Collectors", ["push"])
    f3.box(x + 89, 650, 82, 58, "b-ext", "iTop ITSM", ["tickets"])
    f3.box(x + 178, 650, 82, 58, "b-ext", "LLM", ["per client"])
    f3.edge([(x + 41, 650), (x + 41, 566)], halo=False)
    f3.edge([(x + 130, 566), (x + 130, 650)], halo=False)
    f3.edge([(x + 219, 566), (x + 219, 650)], halo=False)
f3.box(36, 650, 310, 58, "b-ext", "Public sources", ["read once, for every tenant"])
f3.edge([(191, 650), (191, 566)], halo=False)
f3.note(
    36,
    768,
    "Client namespaces never exchange anything: each has its own secrets, database, pages and "
    "NetworkPolicies, and calls only the LLM approved for it.",
)
f3.note(
    36,
    788,
    "Shared: the intelligence service (one read token, no client identity) and the portal "
    "(row-level security and a Grafana organisation per tenant).",
)


FILES = {OUT / "architecture.svg": f1, OUT / "watch.svg": f2, OUT / "tenants.svg": f3}


def main(argv: list[str]) -> int:
    stale = [p for p, fig in FILES.items() if not p.is_file() or p.read_text(encoding="utf-8") != fig.svg()]
    if "--check" in argv:
        for p in stale:
            print(f"{p.relative_to(ROOT)} differs from scripts/make_architecture_diagrams.py: run it", file=sys.stderr)
        return 1 if stale else 0
    for p, fig in FILES.items():
        p.write_text(fig.svg(), encoding="utf-8")
        print(f"wrote {p.relative_to(ROOT)}")
    for w in WARN:
        print(f"WARN {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
