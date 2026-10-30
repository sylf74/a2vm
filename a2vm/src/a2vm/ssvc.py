# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""CISA SSVC reference tables, shared by the pillars (as KEV and EPSS are), loaded from the CERT/CC
SSVC data files shipped in `data/`:

- CISA Coordinator v2.0.3: Exploitation x Automatable x Technical Impact x Mission & Well-Being
  -> track | track* | attend | act
- CISA BOD 26-04 v1.0.0: In KEV x Publicly Exposed x Automatable x Technical Impact
  -> remediation timeline

Also the CVSS heuristic that derives Automatable and Technical Impact from a vector, and
`remediation_delay`, the recommended delay of one record that the watch writes in its sheets.

The tables are reference data; the decision of a finding (inputs and their sources, policy,
escalations, review) belongs to pillar 3 (`verdict.triage`). Source:
https://github.com/CERTCC/SSVC (data/ directory, MIT (SEI)-style license, see data/LICENSE-SSVC).
"""

from __future__ import annotations

import csv
from functools import cache
from importlib import resources

from .models import CvssMetric, VulnRecord

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
BOD_FR = {
    "fix on system upgrade": "à la prochaine mise à niveau majeure",
    "60 days": "60 jours",
    "14 days": "14 jours",
    "3 days": "3 jours",
    "3 days & forensic investigation": "3 jours, avec investigation forensique",
}


def _rows(name: str) -> list[list[str]]:
    text = resources.files("a2vm").joinpath("data", name).read_text(encoding="utf-8")
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


def cvss_fields(metric: CvssMetric) -> dict[str, str]:
    fields = {}
    for part in metric.vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            fields[k] = v
    return fields


def cvss_heuristic(metric: CvssMetric) -> tuple[str, str]:
    """(automatable, technical_impact) derived from a CVSS v2 / v3.x / v4.0 vector."""
    f = cvss_fields(metric)
    if metric.version == "2.0":  # no user-interaction metric in v2; complete loss of C and I = total
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "Au": "N"}.items())
        total = f.get("C") == "C" and f.get("I") == "C"
    elif metric.version == "4.0":
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N"}.items())
        total = f.get("VC") == "H" and f.get("VI") == "H"
    else:
        auto = all(f.get(k) == v for k, v in {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}.items())
        total = f.get("C") == "H" and f.get("I") == "H"
    return ("yes" if auto else "no"), ("total" if total else "partial")


def remediation_delay(record: VulnRecord, publicly_exposed: bool, unknown_inputs: str = "conservative") -> str:
    """CISA BOD 26-04 delay of one record, in French, for an asset exposed or not.

    Automatable and Technical Impact from the CISA ADP, else the CVSS heuristic, else the policy's
    default for unknown inputs (`policy.unknown_inputs`). The triage may refine them later (LLM
    estimate, scanner vector): the watch's delay is a first recommendation, the decision stays the
    triage's.
    """
    adp = record.adp_ssvc or {}
    if "automatable" in adp and "technical_impact" in adp:
        automatable, impact = adp["automatable"], adp["technical_impact"]
    elif (metric := record.best_cvss()) is not None:
        automatable, impact = cvss_heuristic(metric)
    elif unknown_inputs == "optimistic":
        automatable, impact = "no", "partial"
    else:
        automatable, impact = "yes", "total"
    return BOD_FR[bod_timeline(record.in_kev, publicly_exposed, automatable, impact)]
