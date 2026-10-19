# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""SSVC decision tables, loaded from the CERT/CC SSVC data files shipped in `data/`.

- CISA Coordinator v2.0.3: Exploitation x Automatable x Technical Impact x Mission & Well-Being
  -> track | track* | attend | act
- CISA BOD 26-04 v1.0.0: In KEV x Publicly Exposed x Automatable x Technical Impact
  -> remediation timeline

Source: https://github.com/CERTCC/SSVC (data/ directory, MIT (SEI)-style license, see
data/LICENSE-SSVC).
"""

from __future__ import annotations

import csv
from functools import cache
from importlib import resources

COORDINATOR_FILE = "cisa_coordinator_2_0_3.csv"
BOD_FILE = "cisa_bod_26_04_1_0_0.csv"

DECISIONS = ("track", "track*", "attend", "act")
BOD_TIMELINES = (
    "fix on system upgrade",
    "60 days",
    "14 days",
    "3 days",
    "3 days & forensic investigation",
)


def _rows(name: str) -> list[list[str]]:
    text = resources.files("vulnops.verdict").joinpath("data", name).read_text(encoding="utf-8")
    rows = list(csv.reader(text.splitlines()))
    return [[c.strip().lower() for c in r[1:]] for r in rows[1:] if r]


@cache
def coordinator_table() -> dict[tuple[str, str, str, str], str]:
    table = {}
    for exploitation, automatable, impact, mwi, outcome in _rows(COORDINATOR_FILE):
        exploitation = "poc" if exploitation == "public poc" else exploitation
        table[(exploitation, automatable, impact, mwi)] = outcome
    if len(table) != 36:
        raise RuntimeError(f"{COORDINATOR_FILE}: expected 36 rows, got {len(table)}")
    return table


@cache
def bod_table() -> dict[tuple[str, str, str, str], str]:
    table = {}
    for kev, exposed, automatable, impact, outcome in _rows(BOD_FILE):
        table[(kev, exposed, automatable, impact)] = outcome
    if len(table) != 16:
        raise RuntimeError(f"{BOD_FILE}: expected 16 rows, got {len(table)}")
    return table


def mission_wellbeing(mission_prevalence: str, wellbeing: str) -> str:
    """CISA "Mission and Well-Being Impact" (low | medium | high).

    The CISA definition leaves Mission=minimal with Well-being=material undefined;
    it is mapped to "medium" here (the conservative choice).
    """
    mp, wb = mission_prevalence.lower(), wellbeing.lower()
    if mp == "essential" or wb == "irreversible":
        return "high"
    if mp == "minimal" and wb == "minimal":
        return "low"
    return "medium"


def coordinator_decision(exploitation: str, automatable: str, technical_impact: str, mwi: str) -> str:
    return coordinator_table()[(exploitation, automatable, technical_impact, mwi)]


def bod_timeline(in_kev: bool, publicly_exposed: bool, automatable: str, technical_impact: str) -> str:
    key = ("yes" if in_kev else "no", "yes" if publicly_exposed else "no", automatable, technical_impact)
    return bod_table()[key]
