# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Build the A2VM Grafana dashboards (verdict/src/verdict/restitution/grafana/*.json).

- overview.json: one client, its latest run and the trend (v0.11.5);
- assets.json: "which assets to fix first?" - findings (asset x CVE) of a snapshot;
- cves.json: "which CVEs to fix first?" - distinct CVEs of a snapshot, each decided by its most
  urgent finding.

They read the reporting database only (PostgreSQL data source, chosen at import). A snapshot is,
for each client chosen, its latest run on or before a day (a2vm.snapshot_runs); the counters
compare it with an earlier snapshot. Filters are dashboard variables; every label they filter on
comes from the view a2vm.decision_facts, so the dashboards recompute no rule. Run again after
changing this script; the result is committed.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "verdict" / "src" / "verdict" / "restitution" / "grafana"
DS = {"type": "grafana-postgresql-datasource", "uid": "${DS_A2VM}"}
LEVELS = ("ACT", "ATTEND", "TRACK")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
LEVEL_COLORS = (("ACT", "red"), ("ATTEND", "orange"), ("TRACK", "blue"))
# Cells of the decision x severity matrix: steps by order of magnitude, the same for every column
# and every client size (a few findings in a homelab, tens of thousands in a large estate).
HEAT = [
    {"color": "transparent", "value": None},
    {"color": "#F6DDE2", "value": 1},
    {"color": "#E8A6B3", "value": 10},
    {"color": "#C9566E", "value": 100},
    {"color": "#A12843", "value": 1000},
    {"color": "#6E1428", "value": 10000},
]


# -- building blocks -----------------------------------------------------------------------------
def target(sql: str, fmt: str = "table", ref: str = "A") -> dict:
    return {"refId": ref, "datasource": DS, "rawQuery": True, "editorMode": "code", "format": fmt, "rawSql": sql}


def _color(name: str, color: str) -> dict:
    return {
        "matcher": {"id": "byName", "options": name},
        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}],
    }


class Board:
    def __init__(self) -> None:
        self.panels: list[dict] = []

    def add(self, panel: dict, x: int, y: int, w: int, h: int) -> dict:
        panel["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        if panel["type"] not in ("row", "text"):
            panel.setdefault("datasource", DS)
        panel["id"] = len(self.panels) + 1
        self.panels.append(panel)
        return panel


def text(content: str) -> dict:
    return {"type": "text", "title": "", "transparent": True, "options": {"mode": "markdown", "content": content}}


def kpi(title: str, sql: str, desc: str, unit: str = "none", up_is_bad: bool = True) -> dict:
    """A counter of the snapshot; the arrow is its change since the compared snapshot."""
    return {
        "type": "stat",
        "title": title,
        "description": desc + " Arrow: change since the compared snapshot.",
        "targets": [target(sql)],
        "options": {
            "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
            "orientation": "auto",
            "textMode": "value",
            "colorMode": "none",
            "graphMode": "none",
            "justifyMode": "center",
            "wideLayout": True,
            "showPercentChange": True,
            "percentChangeColorMode": "inverted" if up_is_bad else "standard",
        },
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 1 if unit == "percent" else 0}, "overrides": []},
    }


def matrix(title: str, sql: str, desc: str) -> dict:
    return {
        "type": "table",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "options": {"showHeader": True, "cellHeight": "lg", "footer": {"show": False}},
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "center", "cellOptions": {"type": "color-background", "mode": "basic"}},
                "color": {"mode": "thresholds"},
                "thresholds": {"mode": "absolute", "steps": HEAT},
            },
            "overrides": [
                {
                    "matcher": {"id": "byName", "options": "SSVC decision"},
                    "properties": [
                        {"id": "custom.cellOptions", "value": {"type": "auto"}},
                        {"id": "custom.align", "value": "left"},
                        {"id": "custom.width", "value": 130},
                    ],
                }
            ],
        },
    }


def table(title: str, sql: str, desc: str, overrides: list[dict] | None = None) -> dict:
    return {
        "type": "table",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
        "fieldConfig": {"defaults": {"custom": {"filterable": True}}, "overrides": overrides or []},
    }


def cell_color(name: str, steps: list[tuple[float | None, str]]) -> dict:
    return {
        "matcher": {"id": "byName", "options": name},
        "properties": [
            {"id": "custom.cellOptions", "value": {"type": "color-text"}},
            {"id": "color", "value": {"mode": "thresholds"}},
            {
                "id": "thresholds",
                "value": {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]},
            },
        ],
    }


def level_text(name: str) -> dict:
    return {
        "matcher": {"id": "byName", "options": name},
        "properties": [
            {"id": "custom.cellOptions", "value": {"type": "color-text"}},
            {
                "id": "mappings",
                "value": [
                    {
                        "type": "value",
                        "options": {
                            "ACT": {"color": "red", "index": 0},
                            "ATTEND": {"color": "orange", "index": 1},
                            "TRACK": {"color": "blue", "index": 2},
                        },
                    }
                ],
            },
        ],
    }


def link(name: str, url: str, tooltip: str) -> dict:
    return {
        "matcher": {"id": "byName", "options": name},
        "properties": [{"id": "links", "value": [{"title": tooltip, "url": url, "targetBlank": True}]}],
    }


def trend(title: str, sql: str, desc: str) -> dict:
    return {
        "type": "timeseries",
        "title": title,
        "description": desc,
        "targets": [target(sql, "time_series")],
        "fieldConfig": {
            "defaults": {"custom": {"drawStyle": "line", "lineWidth": 2, "pointSize": 5, "showPoints": "always"}},
            "overrides": [_color(n, c) for n, c in LEVEL_COLORS],
        },
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    }


# -- SQL shared by the per-asset and per-CVE dashboards -----------------------------------------
TENANTS = "ARRAY[${tenant:sqlstring}]::text[]"
FILTERS = (
    "x.sources && ARRAY[${scanner:sqlstring}]::text[] AND x.kev_label IN (${kev:sqlstring}) "
    "AND x.severity IN (${severity:sqlstring}) AND x.epss_band IN (${epss:sqlstring}) "
    "AND x.product_type IN (${ptype:sqlstring})"
)
NO_COMPARE = "NULLIF('${compare}', '') IS NULL"


def findings_cte(both: bool = True, level_filter: bool = True) -> str:
    """`snap` (ord 1 = compared snapshot, ord 2 = snapshot) and `f`, the filtered findings of each."""
    snaps = "(1, NULLIF('${compare}', '')::date), (2, '${snapshot}'::date)" if both else "(2, '${snapshot}'::date)"
    level = " AND x.level IN (${decision:sqlstring})" if level_filter else ""
    return (
        f"WITH snap (ord, snap_day) AS (VALUES {snaps}),\n"
        "f AS (SELECT s.ord, s.snap_day, x.* FROM snap s\n"
        f"  CROSS JOIN LATERAL a2vm.snapshot_runs({TENANTS}, s.snap_day) r\n"
        "  JOIN a2vm.decision_facts x ON x.run_id = r.run_id\n"
        f"  WHERE {FILTERS}{level})\n"
    )


CVE_CTE = (
    ",\nc0 AS (SELECT f.ord, f.cve, min(f.level_rank) AS rank, bool_or(f.kev) AS kev, max(f.epss) AS epss,\n"
    "  max(f.cvss_score) AS cvss, min(f.severity_rank) AS sev_rank, bool_or(f.fix_available) AS fix,\n"
    "  count(DISTINCT f.asset) AS assets, count(*) AS exposures, min(f.title) AS title,\n"
    "  string_agg(DISTINCT nullif(concat_ws(' ', f.vendor, f.product), ''), ', ') AS products\n"
    "  FROM f GROUP BY f.ord, f.cve),\n"
    "c AS (SELECT c0.*, (ARRAY['ACT', 'ATTEND', 'TRACK'])[c0.rank] AS level,\n"
    "  (ARRAY['Critical', 'High', 'Medium', 'Low', 'Unknown'])[c0.sev_rank] AS severity\n"
    "  FROM c0 WHERE (ARRAY['ACT', 'ATTEND', 'TRACK'])[c0.rank] IN (${decision:sqlstring}))\n"
)


def kpi_sql(cte: str, rows: str, expr: str) -> str:
    """One row per snapshot (compared first), so the stat panel shows the change between them."""
    return (
        cte + f"SELECT s.snap_day::timestamptz AS time, {expr} AS value\n"
        f"FROM snap s LEFT JOIN {rows} ON {rows}.ord = s.ord\n"
        "WHERE s.snap_day IS NOT NULL GROUP BY s.ord, s.snap_day ORDER BY s.ord"
    )


def matrix_sql(cte: str, rows: str, key: str, kev_only: bool) -> str:
    kev = f" AND {rows}.kev" if kev_only else ""
    cols = ",\n  ".join(
        f"count({rows}.{key}) FILTER (WHERE {rows}.severity = '{s}'{kev}) AS \"{s}\"" for s in SEVERITIES
    )
    return (
        cte + f'SELECT l.level AS "SSVC decision",\n  {cols}\n'
        "FROM (VALUES ('ACT', 1), ('ATTEND', 2), ('TRACK', 3)) l (level, o)\n"
        f"LEFT JOIN {rows} ON {rows}.level = l.level AND {rows}.ord = 2\n"
        "WHERE l.level IN (${decision:sqlstring})\nGROUP BY l.level, l.o ORDER BY l.o"
    )


def day_runs() -> str:
    """For each client chosen and each day, its latest run that day (within the time range)."""
    return (
        "(SELECT DISTINCT ON (tenant, generated_at::date) run_id FROM a2vm.runs\n"
        f"  WHERE tenant = ANY ({TENANTS}) AND $__timeFilter(generated_at)\n"
        "  ORDER BY tenant, generated_at::date, generated_at DESC) r"
    )


# -- variables ------------------------------------------------------------------------------------
def query_var(name: str, label: str, sql: str, multi: bool = True, all_: bool = True, desc: str = "") -> dict:
    return {
        "name": name,
        "label": label,
        "description": desc,
        "type": "query",
        "datasource": DS,
        "query": sql,
        "definition": sql,
        "refresh": 1,
        "sort": 0,
        "multi": multi,
        "includeAll": all_,
        "current": {},
    }


def custom_var(name: str, label: str, values: tuple[str, ...], desc: str = "") -> dict:
    return {
        "name": name,
        "label": label,
        "description": desc,
        "type": "custom",
        "query": ",".join(values),
        "multi": True,
        "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "options": [],
    }


SNAPSHOT_DAYS = (
    "SELECT to_char(d, 'DD Mon YYYY') || ' · W' || to_char(d, 'IW') AS __text, d::text AS __value FROM "
    "(SELECT DISTINCT generated_at::date AS d FROM a2vm.runs WHERE tenant = ANY (" + TENANTS + ")) s "
)
SNAPSHOT_VARS = [
    query_var(
        "tenant",
        "Client",
        "SELECT tenant AS __value, tenant_name AS __text FROM a2vm.latest_runs ORDER BY tenant_name",
    ),
    query_var(
        "snapshot",
        "Snapshot",
        SNAPSHOT_DAYS + "ORDER BY d DESC",
        multi=False,
        all_=False,
        desc="Each client's latest run on or before this day",
    ),
    query_var(
        "compare",
        "Compared with",
        "SELECT __text, __value FROM (" + SNAPSHOT_DAYS + "WHERE d < '${snapshot}'::date "
        "UNION ALL SELECT 'none', '') v ORDER BY __value = '', __value DESC",
        multi=False,
        all_=False,
        desc="Earlier snapshot the counters are compared with",
    ),
]
FILTER_VARS = [
    query_var(
        "scanner",
        "Scanner",
        "SELECT DISTINCT unnest(sources) FROM a2vm.decision_facts WHERE tenant = ANY (" + TENANTS + ") ORDER BY 1",
        desc="Detection sources that observed the finding",
    ),
    custom_var("kev", "Known exploited (KEV)", ("Yes", "No")),
    custom_var("decision", "SSVC decision", LEVELS),
    custom_var("severity", "Severity (CVSS)", SEVERITIES),
    custom_var("epss", "EPSS band", ("EPSS >= 50%", "EPSS 10-50%", "EPSS < 10%", "N/A")),
    query_var(
        "ptype",
        "Product type",
        "SELECT DISTINCT product_type FROM a2vm.decision_facts WHERE tenant = ANY (" + TENANTS + ") ORDER BY 1",
        desc="CPE part of the vulnerable product: application, os, hardware",
    ),
]


def dashboard(title: str, uid: str, panels: list[dict], variables: list[dict], kinds: list[str]) -> dict:
    return {
        "__inputs": [
            {
                "name": "DS_A2VM",
                "label": "A2VM reporting database",
                "description": "PostgreSQL data source of the reporting database",
                "type": "datasource",
                "pluginId": "grafana-postgresql-datasource",
                "pluginName": "PostgreSQL",
            }
        ],
        "__requires": [
            {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "11.0.0"},
            {"type": "datasource", "id": "grafana-postgresql-datasource", "name": "PostgreSQL", "version": "1.0.0"},
            *({"type": "panel", "id": k, "name": k, "version": ""} for k in kinds),
        ],
        "title": title,
        "uid": uid,
        "tags": ["a2vm"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "editable": True,
        "graphTooltip": 1,
        "time": {"from": "now-90d", "to": "now"},
        "refresh": "",
        "links": [
            {
                "type": "dashboards",
                "tags": ["a2vm"],
                "asDropdown": False,
                "includeVars": True,
                "keepTime": True,
                "title": "A2VM",
            }
        ],
        "templating": {"list": variables},
        "panels": panels,
    }


HEADER = (
    "## {question}\n"
    "Snapshot **${{snapshot:text}}**, compared with **${{compare:text}}** — clients: ${{tenant:text}}. "
    "{unit}"
)


# -- per asset ------------------------------------------------------------------------------------
def assets_dashboard() -> dict:
    b = Board()
    cte = findings_cte()
    b.add(
        text(
            HEADER.format(
                question="Threats: which assets to fix first?",
                unit="Counted in **exposures**: one vulnerability (CVE) on one asset.",
            )
        ),
        0, 0, 24, 3,
    )  # fmt: skip
    cards = [
        ("Exposures", "count(f.finding_id)", "Findings (asset × CVE) of the snapshot.", "none", True),
        ("Assets concerned", "count(DISTINCT f.asset)", "Assets with at least one finding.", "none", True),
        ("KEV exposures", "count(f.finding_id) FILTER (WHERE f.kev)", "Findings of a CVE in CISA KEV.", "none", True),
        ("ACT exposures", "count(f.finding_id) FILTER (WHERE f.level = 'ACT')", "Findings to fix now.", "none", True),
        (
            "Assets with ACT",
            "count(DISTINCT f.asset) FILTER (WHERE f.level = 'ACT')",
            "Assets carrying a finding to fix now.",
            "none",
            True,
        ),
        (
            "Overdue",
            "count(f.finding_id) FILTER (WHERE f.level IN ('ACT', 'ATTEND') AND f.due_date < s.snap_day)",
            "ACT and ATTEND findings past their BOD 26-04 due date on the snapshot day.",
            "none",
            True,
        ),
        (
            "Fix available",
            "round(100.0 * count(f.finding_id) FILTER (WHERE f.fix_available) / NULLIF(count(f.finding_id), 0), 1)",
            "Share of findings for which a fixed version or a patch is known.",
            "percent",
            False,
        ),
        (
            "EPSS ≥ 10 %",
            "count(f.finding_id) FILTER (WHERE f.epss >= 0.1)",
            "Findings of a CVE with an exploitation probability of 10 % or more (EPSS, 30 days).",
            "none",
            True,
        ),
    ]
    for i, (title, expr, desc, unit, bad) in enumerate(cards):
        b.add(kpi(title, kpi_sql(cte, "f", expr), desc, unit, bad), 3 * i, 3, 3, 4)
    one = findings_cte(both=False)
    b.add(
        matrix(
            "SSVC decision × severity — exposures",
            matrix_sql(one, "f", "finding_id", False),
            "Findings of the snapshot per decision and CVSS rating.",
        ),
        0, 7, 12, 6,
    )  # fmt: skip
    b.add(
        matrix(
            "… of which known exploited (KEV)",
            matrix_sql(one, "f", "finding_id", True),
            "The same findings, limited to CVEs listed in CISA KEV.",
        ),
        12, 7, 12, 6,
    )  # fmt: skip
    ranked = (
        cte + ",\ncur AS (SELECT f.asset, min(f.asset_name) AS name, min(f.tenant_name) AS client,\n"
        "  min(f.zone) AS zone, min(f.exposure) AS exposure,\n"
        "  count(*) FILTER (WHERE f.level = 'ACT') AS act, count(*) FILTER (WHERE f.level = 'ATTEND') AS attend,\n"
        "  count(*) FILTER (WHERE f.level = 'TRACK') AS track, count(*) FILTER (WHERE f.kev) AS kev,\n"
        "  count(*) FILTER (WHERE f.level IN ('ACT', 'ATTEND') AND f.due_date < f.snap_day) AS overdue,\n"
        "  count(*) FILTER (WHERE f.severity = 'Critical') AS critical, max(f.epss) AS epss,\n"
        "  count(*) FILTER (WHERE f.fix_available) AS fixable\n"
        "  FROM f WHERE f.ord = 2 GROUP BY f.asset),\n"
        "prev AS (SELECT f.asset, count(*) FILTER (WHERE f.level = 'ACT') AS act FROM f WHERE f.ord = 1 "
        "GROUP BY f.asset)\n"
        'SELECT cur.name AS "Asset", cur.client AS "Client", cur.zone AS "Zone", cur.exposure AS "Exposure",\n'
        '  cur.act AS "ACT", cur.attend AS "ATTEND", cur.track AS "TRACK", cur.kev AS "KEV",\n'
        '  cur.overdue AS "Overdue", cur.critical AS "Critical", round(cur.epss::numeric, 3) AS "Max EPSS",\n'
        '  cur.fixable AS "With a fix",\n'
        f'  CASE WHEN {NO_COMPARE} THEN NULL ELSE cur.act - coalesce(prev.act, 0) END AS "ACT change"\n'
        "FROM cur LEFT JOIN prev USING (asset)\n"
        "ORDER BY cur.act DESC, cur.kev DESC, cur.overdue DESC, cur.critical DESC, cur.attend DESC, cur.name\n"
        "LIMIT 500"
    )
    b.add(
        table(
            "Assets to fix first",
            ranked,
            "Assets of the snapshot, most urgent first: findings to fix now, known exploited, overdue. "
            "ACT change: since the compared snapshot.",
            [
                cell_color("ACT", [(None, "text"), (1, "red")]),
                cell_color("KEV", [(None, "text"), (1, "dark-red")]),
                cell_color("Overdue", [(None, "text"), (1, "dark-orange")]),
                cell_color("ACT change", [(None, "green"), (0, "text"), (1, "red")]),
            ],
        ),
        0, 13, 24, 11,
    )  # fmt: skip
    levels = ", ".join(f"count(*) FILTER (WHERE x.level = '{lv}') AS \"{lv}\"" for lv in LEVELS)
    b.add(
        trend(
            "Exposures per decision, day after day",
            f"SELECT x.day::timestamptz AS time, {levels}\nFROM {day_runs()}\n"
            "JOIN a2vm.decision_facts x ON x.run_id = r.run_id\n"
            f"WHERE {FILTERS} AND x.level IN (${{decision:sqlstring}})\nGROUP BY x.day ORDER BY 1",
            "Each day: the findings of each client's latest run that day (dashboard time range).",
        ),
        0, 24, 12, 8,
    )  # fmt: skip
    per_zone = (
        one
        + "SELECT coalesce(nullif(f.zone, ''), 'no zone') || ' · ' || coalesce(f.exposure, '?')"
        + ' AS "Zone · exposure",\n'
        + ", ".join(f"count(*) FILTER (WHERE f.level = '{lv}') AS \"{lv}\"" for lv in LEVELS)
        + "\nFROM f GROUP BY 1 ORDER BY count(*) FILTER (WHERE f.level = 'ACT') DESC, count(*) DESC LIMIT 20"
    )
    b.add(
        {
            "type": "barchart",
            "title": "Exposures per zone and exposure",
            "description": "Findings of the snapshot per zone (client label) and SSVC system exposure.",
            "targets": [target(per_zone)],
            "options": {
                "stacking": "normal",
                "orientation": "horizontal",
                "xField": "Zone · exposure",
                "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            },
            "fieldConfig": {"defaults": {}, "overrides": [_color(n, c) for n, c in LEVEL_COLORS]},
        },
        12, 24, 12, 8,
    )  # fmt: skip
    return dashboard(
        "A2VM — which assets to fix first",
        "a2vm-assets",
        b.panels,
        SNAPSHOT_VARS + FILTER_VARS,
        ["text", "stat", "table", "timeseries", "barchart"],
    )


# -- per CVE --------------------------------------------------------------------------------------
def cves_dashboard() -> dict:
    b = Board()
    cte = findings_cte(level_filter=False) + CVE_CTE
    b.add(
        text(
            HEADER.format(
                question="Threats: which CVEs to fix first?",
                unit="Counted in **distinct CVEs**; a CVE takes the most urgent decision among its findings.",
            )
        ),
        0, 0, 24, 3,
    )  # fmt: skip
    cards = [
        ("Distinct CVEs", "count(c.cve)", "Distinct vulnerabilities of the snapshot.", "none", True),
        ("KEV CVEs", "count(c.cve) FILTER (WHERE c.kev)", "CVEs listed in CISA KEV.", "none", True),
        (
            "KEV exposures",
            "coalesce(sum(c.exposures) FILTER (WHERE c.kev), 0)",
            "Findings (asset × CVE) of the KEV CVEs.",
            "none",
            True,
        ),
        ("CVEs decided ACT", "count(c.cve) FILTER (WHERE c.level = 'ACT')", "CVEs to fix now somewhere.", "none", True),
        (
            "Fix available",
            "round(100.0 * count(c.cve) FILTER (WHERE c.fix) / NULLIF(count(c.cve), 0), 1)",
            "Share of CVEs for which a fixed version or a patch is known.",
            "percent",
            False,
        ),
        (
            "EPSS ≥ 10 %",
            "count(c.cve) FILTER (WHERE c.epss >= 0.1)",
            "CVEs with an exploitation probability of 10 % or more (EPSS, 30 days).",
            "none",
            True,
        ),
    ]
    for i, (title, expr, desc, unit, bad) in enumerate(cards):
        b.add(kpi(title, kpi_sql(cte, "c", expr), desc, unit, bad), 4 * i, 3, 4, 4)
    one = findings_cte(both=False, level_filter=False) + CVE_CTE
    b.add(
        matrix(
            "SSVC decision × severity — CVEs",
            matrix_sql(one, "c", "cve", False),
            "Distinct CVEs of the snapshot per decision (most urgent finding) and CVSS rating.",
        ),
        0, 7, 12, 6,
    )  # fmt: skip
    b.add(
        matrix(
            "… of which known exploited (KEV)",
            matrix_sql(one, "c", "cve", True),
            "The same CVEs, limited to those listed in CISA KEV.",
        ),
        12, 7, 12, 6,
    )  # fmt: skip
    ranked = (
        cte + 'SELECT cur.cve AS "CVE", cur.level AS "Decision", cur.severity AS "Severity",\n'
        '  round(cur.cvss::numeric, 1) AS "CVSS", round(cur.epss::numeric, 3) AS "EPSS",\n'
        "  CASE WHEN cur.kev THEN 'yes' ELSE '' END AS \"KEV\", CASE WHEN cur.fix THEN 'yes' ELSE '' END AS \"Fix\",\n"
        '  cur.assets AS "Assets", cur.exposures AS "Exposures",\n'
        f"  CASE WHEN {NO_COMPARE} THEN NULL WHEN prev.cve IS NULL THEN 'new' "
        "WHEN prev.level <> cur.level THEN 'was ' || prev.level ELSE '' END AS \"Since\",\n"
        '  cur.products AS "Product", cur.title AS "Vulnerability"\n'
        "FROM c cur LEFT JOIN c prev ON prev.cve = cur.cve AND prev.ord = 1\n"
        "WHERE cur.ord = 2\n"
        "ORDER BY cur.rank, cur.kev DESC, cur.epss DESC NULLS LAST, cur.cvss DESC NULLS LAST,\n"
        "  cur.assets DESC, cur.cve\n"
        "LIMIT 500"
    )
    b.add(
        table(
            "CVEs to fix first",
            ranked,
            "Distinct CVEs of the snapshot, most urgent first: decision, known exploitation, EPSS, CVSS. "
            "Since: new since the compared snapshot, or the decision it had then.",
            [
                level_text("Decision"),
                cell_color("KEV", [(None, "dark-red")]),
                link("CVE", "https://www.cve.org/CVERecord?id=${__value.text}", "CVE record"),
                {
                    "matcher": {"id": "byName", "options": "Vulnerability"},
                    "properties": [{"id": "custom.width", "value": 420}],
                },
            ],
        ),
        0, 13, 24, 11,
    )  # fmt: skip
    levels = ", ".join(f"count(DISTINCT x.cve) FILTER (WHERE x.cve_level = '{lv}') AS \"{lv}\"" for lv in LEVELS)
    b.add(
        trend(
            "Distinct CVEs per decision, day after day",
            "SELECT day::timestamptz AS time, " + levels + "\n"
            "FROM (SELECT x.day, x.cve, (ARRAY['ACT', 'ATTEND', 'TRACK'])[min(x.level_rank)] AS cve_level\n"
            f"  FROM {day_runs()}\n"
            "  JOIN a2vm.decision_facts x ON x.run_id = r.run_id\n"
            f"  WHERE {FILTERS} GROUP BY x.day, x.cve) x\n"
            "WHERE x.cve_level IN (${decision:sqlstring})\nGROUP BY day ORDER BY 1",
            "Each day: the CVEs of each client's latest run that day (dashboard time range).",
        ),
        0, 24, 12, 8,
    )  # fmt: skip
    per_product = (
        one
        + "SELECT coalesce(c.products, 'unknown product') AS \"Product\",\n"
        + ", ".join(f"count(*) FILTER (WHERE c.level = '{lv}') AS \"{lv}\"" for lv in LEVELS)
        + "\nFROM c WHERE c.ord = 2 GROUP BY 1\n"
        "ORDER BY count(*) FILTER (WHERE c.level = 'ACT') DESC, count(*) DESC LIMIT 15"
    )
    b.add(
        {
            "type": "barchart",
            "title": "Products with the most CVEs",
            "description": "Distinct CVEs of the snapshot per vulnerable product, most urgent first.",
            "targets": [target(per_product)],
            "options": {
                "stacking": "normal",
                "orientation": "horizontal",
                "xField": "Product",
                "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            },
            "fieldConfig": {"defaults": {}, "overrides": [_color(n, c) for n, c in LEVEL_COLORS]},
        },
        12, 24, 12, 8,
    )  # fmt: skip
    return dashboard(
        "A2VM — which CVEs to fix first",
        "a2vm-cves",
        b.panels,
        SNAPSHOT_VARS + FILTER_VARS,
        ["text", "stat", "table", "timeseries", "barchart"],
    )


# -- overview (v0.11.5): one client, its latest run ----------------------------------------------
def overview_dashboard() -> dict:
    t = "'${tenant}'"
    b = Board()

    def stat(title: str, column: str, x: int, color: str, unit: str = "none", desc: str = "") -> None:
        b.add(
            {
                "type": "stat",
                "title": title,
                "description": desc,
                "targets": [target(f"SELECT {column} AS value FROM a2vm.latest_runs WHERE tenant = {t}")],
                "options": {
                    "colorMode": "background",
                    "graphMode": "none",
                    "reduceOptions": {"calcs": ["lastNotNull"]},
                },
                "fieldConfig": {
                    "defaults": {"unit": unit, "color": {"mode": "fixed", "fixedColor": color}},
                    "overrides": [],
                },
            },
            x, 0, 3, 4,
        )  # fmt: skip

    stat("ACT", "act", 0, "red", desc="Findings to fix now (latest run)")
    stat("ATTEND", "attend", 3, "orange", desc="Findings to fix soon")
    stat("TRACK", "track", 6, "blue", desc="Findings to follow")
    stat("Overdue", "overdue", 9, "dark-red", desc="ACT and ATTEND past their BOD 26-04 due date")
    stat("Due within 7 days", "due_soon", 12, "yellow")
    stat("To review", "needs_review", 15, "purple", desc="Decisions resting on an input to confirm")
    stat("Exposure gaps", "exposure_gaps", 18, "dark-orange", desc="Exposures the client profile does not describe")
    stat("Last run", "generated_at", 21, "text", unit="dateTimeFromNow")
    b.add(
        trend(
            "Findings per level, run after run",
            'SELECT generated_at AS time, act AS "ACT", attend AS "ATTEND", track AS "TRACK" '
            f"FROM a2vm.runs WHERE tenant = {t} AND $__timeFilter(generated_at) ORDER BY 1",
            "",
        ),
        0, 4, 14, 8,
    )  # fmt: skip
    b.add(
        {
            "type": "barchart",
            "title": "Findings per exposure (latest run)",
            "targets": [
                target(
                    "SELECT coalesce(exposure, 'unknown') AS exposure, "
                    "count(*) FILTER (WHERE level = 'ACT') AS \"ACT\", "
                    "count(*) FILTER (WHERE level = 'ATTEND') AS \"ATTEND\", "
                    "count(*) FILTER (WHERE level = 'TRACK') AS \"TRACK\" "
                    f"FROM a2vm.latest_decisions WHERE tenant = {t} GROUP BY 1 ORDER BY 1"
                )
            ],
            "options": {"stacking": "normal", "orientation": "horizontal", "xField": "exposure"},
            "fieldConfig": {"defaults": {}, "overrides": [_color(n, c) for n, c in LEVEL_COLORS]},
        },
        14, 4, 10, 8,
    )  # fmt: skip
    b.add(
        table(
            "Exposure gaps",
            'SELECT name AS "Asset", kind AS "Gap", declared AS "Declared", detail AS "Detail" '
            f"FROM a2vm.latest_exposure_gaps WHERE tenant = {t} ORDER BY kind, name",
            "Hosts the external scan reaches that the client profile does not describe",
        ),
        0, 12, 24, 5,
    )  # fmt: skip
    b.add(
        table(
            "Decisions to act on (ACT, ATTEND)",
            'SELECT level AS "Level", cve AS "CVE", asset_name AS "Asset", zone AS "Zone", exposure AS "Exposure", '
            'bod_timeline AS "BOD 26-04", due_date AS "Due", kev AS "KEV", round(epss::numeric, 3) AS "EPSS", '
            'needs_review AS "Review", title AS "Vulnerability" '
            f"FROM a2vm.latest_decisions WHERE tenant = {t} AND level IN ('ACT', 'ATTEND') "
            "ORDER BY CASE level WHEN 'ACT' THEN 0 ELSE 1 END, due_date NULLS LAST, cve",
            "",
            [level_text("Level")],
        ),
        0, 17, 24, 10,
    )  # fmt: skip
    b.add(
        table(
            "Assets",
            'SELECT name AS "Asset", zone AS "Zone", exposure AS "Exposure", owner AS "Owner", act AS "ACT", '
            f'attend AS "ATTEND", track AS "TRACK" FROM a2vm.latest_assets WHERE tenant = {t} '
            "ORDER BY act DESC, attend DESC, name",
            "",
        ),
        0, 27, 14, 8,
    )  # fmt: skip
    b.add(
        table(
            "Detection sources (latest run)",
            'SELECT s.name AS "Source", s.findings AS "Findings", s.last_observation AS "Last observation" '
            f"FROM a2vm.sources s JOIN a2vm.latest_runs r USING (run_id) WHERE r.tenant = {t} ORDER BY 1",
            "",
        ),
        14, 27, 10, 8,
    )  # fmt: skip
    board = dashboard(
        "A2VM — overview of a client",
        "a2vm-decisions",
        b.panels,
        [
            query_var(
                "tenant",
                "Client",
                "SELECT tenant AS __value, tenant_name AS __text FROM a2vm.latest_runs ORDER BY tenant_name",
                multi=False,
                all_=False,
            )
        ],
        ["stat", "table", "timeseries", "barchart"],
    )
    board["time"] = {"from": "now-30d", "to": "now"}
    return board


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in (("overview", overview_dashboard), ("assets", assets_dashboard), ("cves", cves_dashboard)):
        path = OUT / f"{name}.json"
        path.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(path)


if __name__ == "__main__":
    main()
