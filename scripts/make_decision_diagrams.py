# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Build the decision diagrams of LLD triage-prioritization §4 from the SSVC tables themselves
(a2vm/src/a2vm/data/*.csv), so that the pictures can never disagree with the tables.

Prints three Mermaid blocks: the decision chain, the CISA Coordinator tree and the BOD 26-04
tree; with --check, fails when the LLD does not contain them as printed (run in the test suite).
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "a2vm" / "src" / "a2vm" / "data"
LLD = ROOT / "docs" / "lld" / "triage-prioritization.md"
# Default delivery mapping (policy.decision_mapping, LLD §4.4); colours show the level delivered.
MAPPING = {"track": "TRACK", "track*": "ATTEND", "attend": "ATTEND", "act": "ACT"}
STYLE = (
    "  classDef act fill:#c0392b,stroke:#922b21,color:#fff\n"
    "  classDef attend fill:#e67e22,stroke:#a04000,color:#fff\n"
    "  classDef track fill:#2e86c1,stroke:#1b4f72,color:#fff\n"
    "  classDef input fill:#f4f6f7,stroke:#839192,color:#1c2833\n"
    "  classDef none fill:#d5d8dc,stroke:#839192,color:#1c2833\n"
)


def _rows(name: str) -> list[list[str]]:
    with (DATA / name).open(encoding="utf-8") as f:
        return list(csv.reader(f))[1:]


def chain() -> str:
    return (
        "```mermaid\nflowchart TD\n"
        '  F["Finding: one CVE on one asset"]\n'
        '  F --> CVE["Per-CVE inputs (vulnerability record)"]\n'
        '  F --> AST["Per-asset inputs (asset context, §14)"]\n'
        '  CVE --> E["Exploitation<br/>KEV, CISA ADP, GTI, exploit reference; else none"]\n'
        '  CVE --> A["Automatable<br/>CISA ADP, CVSS heuristic, LLM, policy default"]\n'
        '  CVE --> T["Technical Impact<br/>CISA ADP, CVSS heuristic, LLM, policy default"]\n'
        '  CVE --> K["In KEV"]\n'
        '  AST --> M["Mission and Well-Being<br/>mission_prevalence × public_wellbeing_impact"]\n'
        '  AST --> X["Publicly exposed<br/>exposure = open"]\n'
        '  E & A & T & M --> CO["CISA Coordinator table, 36 rows<br/>track, track*, attend, act"]\n'
        '  K & X & A & T --> BO["CISA BOD 26-04 table, 16 rows<br/>remediation timeline"]\n'
        '  CO --> P["Delivery policy §4.4<br/>map the outcome, then only raise:<br/>'
        '3 days → ACT · 14 days → ATTEND at least<br/>EPSS ≥ 0.1 → ATTEND at least"]\n'
        "  BO --> P\n"
        '  P --> L(["ACT · ATTEND · TRACK"])\n'
        "  class E,A,T,K,M,X input\n" + STYLE + "```"
    )


def coordinator() -> str:
    leaves: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for _, e, a, t, m, o in _rows("cisa_coordinator_2_0_3.csv"):
        leaves[(e.replace("public poc", "poc"), a, t)][m] = o
    out = ["```mermaid", "flowchart LR", '  R["Exploitation"]']
    for e in ("none", "poc", "active"):
        out.append(f'  R -- {e} --> E_{e}["Automatable"]')
        for a in ("no", "yes"):
            out.append(f'  E_{e} -- {a} --> A_{e}_{a}["Technical Impact"]')
            for t in ("partial", "total"):
                o = leaves[(e, a, t)]
                node = f"T_{e}_{a}_{t}"
                out.append(f'  A_{e}_{a} -- {t} --> {node}["Mission & Well-Being"]')
                for m in ("low", "medium", "high"):
                    level = MAPPING[o[m]]
                    out.append(f'  {node} -- {m} --> {node}_{m}["{o[m]} · {level}"]:::{level.lower()}')
    return "\n".join(out) + "\n" + STYLE + "```"


def bod() -> str:
    leaves: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for _, k, p, a, t, o in _rows("cisa_bod_26_04_1_0_0.csv"):
        leaves[(k, p, a)][t] = o
    level = {"3 days": "act", "14 days": "attend"}
    out = ["```mermaid", "flowchart LR", '  R["In KEV"]']
    for k in ("no", "yes"):
        out.append(f'  R -- {k} --> K_{k}["Publicly exposed"]')
        for p in ("no", "yes"):
            out.append(f'  K_{k} -- {p} --> P_{k}_{p}["Automatable"]')
            for a in ("no", "yes"):
                o = leaves[(k, p, a)]
                node = f"A_{k}_{p}_{a}"
                out.append(f'  P_{k}_{p} -- {a} --> {node}["Technical Impact"]')
                for t in ("partial", "total"):
                    effect = next((v for key, v in level.items() if o[t].startswith(key)), "")
                    text = o[t] + {"act": " · ACT", "attend": " · ATTEND at least"}.get(effect, "")
                    out.append(f'  {node} -- {t} --> {node}_{t}["{text}"]:::{effect or "none"}')
    return "\n".join(out) + "\n" + STYLE + "```"


def blocks() -> list[str]:
    return [chain(), coordinator(), bod()]


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        text = LLD.read_text(encoding="utf-8")
        missing = [i for i, b in enumerate(blocks()) if b not in text]
        sys.exit(f"{LLD}: diagram(s) {missing} out of date: run scripts/make_decision_diagrams.py" if missing else 0)
    print("\n\n".join(blocks()))
