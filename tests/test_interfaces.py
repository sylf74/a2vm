# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Every contract between pillars is documented where a reader looks for it (v0.16.2): in the
table of HLD §6 and in §1.1 of the LLD of each pillar that provides or consumes it."""

from __future__ import annotations

import re

import pytest

from .conftest import ROOT

SCHEMAS = ROOT / "a2vm" / "src" / "a2vm" / "schemas"
LLD = {
    "via": ROOT / "docs" / "lld" / "vulnerability-intelligence.md",
    "detect": ROOT / "docs" / "lld" / "vulnerability-detection.md",
    "verdict": ROOT / "docs" / "lld" / "triage-prioritization.md",
}
LIBRARIES = {"a2vm.declared": ("detect", "via"), "a2vm.ssvc": ("verdict", "via")}


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = re.compile(r"^## ", re.M).search(text, start + len(heading))
    return text[start : end.start() if end else len(text)]


def _interfaces(pillar: str) -> str:
    return _section(LLD[pillar].read_text(encoding="utf-8"), "### 1.1 Interfaces with the other pillars")


def _hld() -> str:
    return _section((ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(), "### Interfaces between pillars")


def _rows(section: str, contract: str) -> list[str]:
    return [line for line in section.splitlines() if line.startswith("| ") and f"`{contract}`" in line]


@pytest.mark.parametrize("path", sorted(SCHEMAS.glob("*.json")) + sorted((SCHEMAS / "openapi").glob("*.yaml")))
def test_every_contract_is_in_the_hld_and_in_an_lld(path):
    assert _rows(_hld(), path.name), f"{path.name} missing from HLD §6, Interfaces between pillars"
    assert any(_rows(_interfaces(p), path.name) for p in LLD), f"{path.name} in no LLD §1.1"


@pytest.mark.parametrize("pillar", sorted(LLD))
def test_each_api_is_provided_by_its_pillar(pillar):
    rows = _rows(_interfaces(pillar), f"{pillar}.v1.yaml")
    assert any(r.startswith("| Provides |") and "| API |" in r for r in rows)


@pytest.mark.parametrize("library", sorted(LIBRARIES))
def test_each_library_names_its_owner_and_its_users(library):
    owner, user = LIBRARIES[library]
    assert any(r.startswith("| Provides |") and "owned by" in r for r in _rows(_interfaces(owner), library))
    assert any(r.startswith("| Consumes |") for r in _rows(_interfaces(user), library))
    assert (ROOT / "a2vm" / "src" / "a2vm" / f"{library.split('.')[1]}.py").exists()
    assert _rows(_hld(), library)


def test_each_table_says_what_happens_when_the_other_side_is_missing():
    for pillar in LLD:
        header = [line for line in _interfaces(pillar).splitlines() if line.startswith("| Way |")]
        assert header and header[0].rstrip().endswith("| When the other side is missing |")
