# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The pillars stay independent: each imports a2vm (the common contract) and itself, never another
pillar; a2vm imports no pillar. Capabilities shared across pillars go through a2vm.extensions."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "a2vm": ROOT / "a2vm/src/a2vm",
    "via": ROOT / "via/src/via",
    "detect": ROOT / "detect/src/detect",
    "verdict": ROOT / "verdict/src/verdict",
}
PILLARS = {"via", "detect", "verdict"}


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
    allowed = {package} | ({"a2vm"} if package in PILLARS else set())
    forbidden = (PILLARS | {"a2vm"}) - allowed
    for path in PACKAGES[package].rglob("*.py"):
        crossing = imported_roots(path) & forbidden
        assert not crossing, f"{path.relative_to(ROOT)} imports {sorted(crossing)}"
