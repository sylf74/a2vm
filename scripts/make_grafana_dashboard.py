# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Build the A2VM Grafana dashboard (dispatch/src/dispatch/grafana/a2vm-dashboard.json).

It reads the reporting database only (PostgreSQL data source, chosen at import), one tenant at a
time ($tenant). Run again after changing this script; the result is committed.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "dispatch" / "src" / "dispatch" / "grafana" / "a2vm-dashboard.json"
DS = {"type": "grafana-postgresql-datasource", "uid": "${DS_A2VM}"}
T = "'${tenant}'"
panels: list[dict] = []
LEVEL_COLORS = (("ACT", "red"), ("ATTEND", "orange"), ("TRACK", "blue"))
TENANTS = "SELECT tenant AS __value, tenant_name AS __text FROM a2vm.latest_runs ORDER BY tenant_name"


def _color(name: str, color: str) -> dict:
    return {
        "matcher": {"id": "byName", "options": name},
        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}],
    }


def target(sql: str, fmt: str = "table") -> list[dict]:
    return [{"refId": "A", "datasource": DS, "rawQuery": True, "editorMode": "code", "format": fmt, "rawSql": sql}]


def stat(title: str, column: str, x: int, color: str, unit: str = "none", desc: str = "") -> None:
    panels.append(
        {
            "type": "stat",
            "title": title,
            "description": desc,
            "datasource": DS,
            "gridPos": {"h": 4, "w": 3, "x": x, "y": 0},
            "targets": target(f"SELECT {column} AS value FROM a2vm.latest_runs WHERE tenant = {T}"),
            "options": {"colorMode": "background", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}},
            "fieldConfig": {
                "defaults": {"unit": unit, "color": {"mode": "fixed", "fixedColor": color}},
                "overrides": [],
            },
        }
    )


def table(title: str, sql: str, x: int, y: int, w: int, h: int, desc: str = "") -> None:
    panels.append(
        {
            "type": "table",
            "title": title,
            "description": desc,
            "datasource": DS,
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "targets": target(sql),
            "options": {"showHeader": True, "cellHeight": "sm"},
            "fieldConfig": {"defaults": {}, "overrides": []},
        }
    )


stat("ACT", "act", 0, "red", desc="Findings to fix now (latest run)")
stat("ATTEND", "attend", 3, "orange", desc="Findings to fix soon")
stat("TRACK", "track", 6, "blue", desc="Findings to follow")
stat("Overdue", "overdue", 9, "dark-red", desc="ACT and ATTEND past their BOD 26-04 due date")
stat("Due within 7 days", "due_soon", 12, "yellow")
stat("To review", "needs_review", 15, "purple", desc="Decisions resting on an input to confirm")
stat("Exposure gaps", "exposure_gaps", 18, "dark-orange", desc="Exposures the client profile does not describe")
stat("Last run", "generated_at", 21, "text", unit="dateTimeFromNow")

panels.append(
    {
        "type": "timeseries",
        "title": "Findings per level, run after run",
        "datasource": DS,
        "gridPos": {"h": 8, "w": 14, "x": 0, "y": 4},
        "targets": target(
            'SELECT generated_at AS time, act AS "ACT", attend AS "ATTEND", track AS "TRACK" '
            f"FROM a2vm.runs WHERE tenant = {T} AND $__timeFilter(generated_at) ORDER BY 1",
            "time_series",
        ),
        "fieldConfig": {
            "defaults": {"custom": {"drawStyle": "line", "lineWidth": 2, "pointSize": 5, "showPoints": "always"}},
            "overrides": [_color(n, c) for n, c in LEVEL_COLORS],
        },
    }
)
panels.append(
    {
        "type": "barchart",
        "title": "Findings per exposure (latest run)",
        "datasource": DS,
        "gridPos": {"h": 8, "w": 10, "x": 14, "y": 4},
        "targets": target(
            "SELECT coalesce(exposure, 'unknown') AS exposure, "
            "count(*) FILTER (WHERE level = 'ACT') AS \"ACT\", count(*) FILTER (WHERE level = 'ATTEND') AS \"ATTEND\", "
            "count(*) FILTER (WHERE level = 'TRACK') AS \"TRACK\" "
            f"FROM a2vm.latest_decisions WHERE tenant = {T} GROUP BY 1 ORDER BY 1"
        ),
        "options": {"stacking": "normal", "orientation": "horizontal", "xField": "exposure"},
        "fieldConfig": {
            "defaults": {},
            "overrides": [_color(n, c) for n, c in LEVEL_COLORS],
        },
    }
)
table(
    "Exposure gaps",
    "SELECT name AS \"Asset\", kind AS \"Gap\", declared AS \"Declared\", detail AS \"Detail\" "
    f"FROM a2vm.latest_exposure_gaps WHERE tenant = {T} ORDER BY kind, name",
    0, 12, 24, 5, "Hosts the external scan reaches that the client profile does not describe",
)  # fmt: skip
table(
    "Decisions to act on (ACT, ATTEND)",
    "SELECT level AS \"Level\", cve AS \"CVE\", asset_name AS \"Asset\", zone AS \"Zone\", exposure AS \"Exposure\", "
    "bod_timeline AS \"BOD 26-04\", due_date AS \"Due\", kev AS \"KEV\", round(epss::numeric, 3) AS \"EPSS\", "
    "needs_review AS \"Review\", title AS \"Vulnerability\" "
    f"FROM a2vm.latest_decisions WHERE tenant = {T} AND level IN ('ACT', 'ATTEND') "
    "ORDER BY CASE level WHEN 'ACT' THEN 0 ELSE 1 END, due_date NULLS LAST, cve",
    0, 17, 24, 10,
)  # fmt: skip
table(
    "Assets",
    "SELECT name AS \"Asset\", zone AS \"Zone\", exposure AS \"Exposure\", owner AS \"Owner\", act AS \"ACT\", "
    f"attend AS \"ATTEND\", track AS \"TRACK\" FROM a2vm.latest_assets WHERE tenant = {T} "
    "ORDER BY act DESC, attend DESC, name",
    0, 27, 14, 8,
)  # fmt: skip
table(
    "Detection sources (latest run)",
    "SELECT s.name AS \"Source\", s.findings AS \"Findings\", s.last_observation AS \"Last observation\" "
    f"FROM a2vm.sources s JOIN a2vm.latest_runs r USING (run_id) WHERE r.tenant = {T} ORDER BY 1",
    14, 27, 10, 8,
)  # fmt: skip

for i, p in enumerate(panels, start=1):
    p["id"] = i

dashboard = {
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
    ],
    "title": "A2VM — vulnerability decisions",
    "uid": "a2vm-decisions",
    "tags": ["a2vm"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "time": {"from": "now-30d", "to": "now"},
    "refresh": "1h",
    "templating": {
        "list": [
            {
                "name": "tenant",
                "label": "Client",
                "type": "query",
                "datasource": DS,
                "query": TENANTS,
                "definition": TENANTS,
                "refresh": 1,
                "includeAll": False,
                "multi": False,
            }
        ]
    },
    "panels": panels,
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(OUT)
