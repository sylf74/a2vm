# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The pillars stay independent: each imports ngvm (the common contract) and itself, never another
pillar; ngvm imports no pillar. What several pillars run is a library of ngvm; what a pillar keeps
for itself is reached through its HTTP API (contracts in ngvm/schemas/openapi/)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "ngvm": ROOT / "ngvm/src/ngvm",
    "via": ROOT / "via/src/via",
    "detect": ROOT / "detect/src/detect",
    "verdict": ROOT / "verdict/src/verdict",
    "dispatch": ROOT / "dispatch/src/dispatch",
}
PILLARS = {"via", "detect", "verdict", "dispatch"}


def imported_roots(path: Path) -> set[str]:
    roots = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("package", sorted(PACKAGES))
def test_no_import_across_pillars(package):
    allowed = {package} | ({"ngvm"} if package in PILLARS else set())
    forbidden = (PILLARS | {"ngvm"}) - allowed
    for path in PACKAGES[package].rglob("*.py"):
        crossing = imported_roots(path) & forbidden
        assert not crossing, f"{path.relative_to(ROOT)} imports {sorted(crossing)}"
