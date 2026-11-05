# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.22.1: no container of the tenant chart gives an environment name twice."""

from __future__ import annotations

import re
from pathlib import Path

CHART = Path(__file__).resolve().parents[1] / "deploy" / "charts" / "a2vm-tenant" / "templates"
NAME = re.compile(r"^\s*- name: ([A-Z][A-Z0-9_]*)\s*$", re.M)


def _helper(name: str) -> str:
    text = (CHART / "_helpers.tpl").read_text(encoding="utf-8")
    match = re.search(r'\{\{- define "' + re.escape(name) + r'" -\}\}(.*?)\{\{- end -\}\}\n\n', text, re.S)
    assert match, name
    return match.group(1)


def _names(block: str) -> list[str]:
    names = NAME.findall(block)
    for helper in re.findall(r'include "(a2vm-tenant\.env\w*)"', block):
        names += _names(_helper(helper))
    return names


def test_shared_env_names_once() -> None:
    for template in CHART.glob("*.yaml"):
        text = template.read_text(encoding="utf-8")
        for block in re.findall(r"\n(\s*)env:\n(.*?)(?=\n\1\S)", text, re.S):
            names = _names(block[1])
            duplicates = sorted({n for n in names if names.count(n) > 1})
            assert not duplicates, f"{template.name}: {duplicates}"


def test_watch_cache_in_tmp() -> None:
    text = (CHART / "watch.yaml").read_text(encoding="utf-8")
    assert 'include "a2vm-tenant.envCommon"' in text and "/tmp/cache" in text
    assert "A2VM_CACHE_DIR" not in _helper("a2vm-tenant.envCommon")


def test_daily_suspend_from_variable() -> None:
    pipeline = (CHART.parents[3] / "templates" / "client-pipeline.yml").read_text(encoding="utf-8")
    assert '--set daily.suspend="${A2VM_K8S_SUSPEND:-false}"' in pipeline
    docs = CHART.parents[3] / "docs"
    assert "A2VM_K8S_SUSPEND" in (docs / "kubernetes.md").read_text(encoding="utf-8")
    assert "A2VM_K8S_SUSPEND" in (docs / "radar.md").read_text(encoding="utf-8")


def test_intel_serve_quiet_httpx() -> None:
    cli = CHART.parents[3] / "via" / "src" / "via" / "intel" / "cli.py"
    assert 'logging.getLogger("httpx").setLevel(logging.WARNING)' in cli.read_text(encoding="utf-8")


def test_radar_summary_line() -> None:
    from via.alert import radar

    state = {"events": {"a": {"score": 2, "title": "Low"}, "b": {"score": 5, "title": "Exploited RCE"}}}
    line = radar.summary(state, radar.RadarConfig())
    assert line.startswith("radar: 2 events in 14 days, alert at 4 (urgent 7); best: 5 'Exploited RCE', 2 'Low'")
    assert radar.summary({}, radar.RadarConfig()).endswith("best: none")


def test_operations_manual_current() -> None:
    text = (CHART.parents[3] / "docs" / "operations.md").read_text(encoding="utf-8")
    assert text.startswith("# Operator's manual (v0.22.1)")
    for needle in ("a2vm-team-intel", "A2VM_K8S_SUSPEND", "dispatch of run", "$setElementOrder", "scan-cloud"):
        assert needle in text, needle


def test_release_recorded() -> None:
    root = CHART.parents[3]
    hld = (root / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.22\.1 \(current\) \| Fixes after the first deployment", hld, re.M)
    assert re.search(r"^\| v0\.22\.2 \(consolidation, to confirm\) \|", hld, re.M)
    assert "## v0.22.1 — " in (root / "CHANGELOG.md").read_text(encoding="utf-8")


def test_architecture_diagrams_are_generated() -> None:
    import subprocess
    import sys

    root = CHART.parents[3]
    script = root / "scripts" / "make_architecture_diagrams.py"
    done = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    hld = (root / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert "](architecture.svg)" in hld and "](watch.svg)" in hld
