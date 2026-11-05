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
