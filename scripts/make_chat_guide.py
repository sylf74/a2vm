# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Build docs/chat-questions.md, the analysts' guide to the conversational search, from
tests/chat-questions.yaml (the questions the chat must answer) and the tool server's own
descriptions, so that the guide can never disagree with the tools.

Prints the guide; with --write, writes it; with --check, fails when the file differs (run in the
test suite).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
QUESTIONS = ROOT / "tests" / "chat-questions.yaml"
GUIDE = ROOT / "docs" / "chat-questions.md"

THEMES = [
    ("The watch and the new CVEs", {
        "list_new_cves": "the CVEs published or updated in a period, whoever they concern, and the alert the watch "
        "drafted for this tenant, if any",
        "list_alerts": "the watch's alerts for the tenant in a period, with their status (pending, validated, sent...)",
        "get_alert": "one alert: its sheet for the client and its journal (drafted, validated, sent, by whom)",
        "list_radar_events": "the major vulnerabilities the watch team found and validated (radar)",
        "get_watch_status": "the watch's last passage and the sources in error",
    }),
    ("Are we concerned, and why", {
        "get_cve": "one CVE as the run knows it, the assets it concerns and those with a version not affected",
        "find_component": "the assets that carry a package or product, vulnerable or not, with its versions",
        "list_applications": "the applications the EDRs list, and whether their CPE is validated",
        "get_run_summary": "the overview of the latest run: decisions per level, exposure, KEV, top assets "
        "and CVEs, SLA",
        "search_decisions": "the decisions (one per CVE and asset) with filters: level, exposure, KEV, EPSS, "
        "review, SLA",
        "get_decision": "one decision in full: why this level, its SSVC inputs, fixes, due dates",
        "get_asset": "one asset, its context and its decisions",
    }),
    ("What changed, what was fixed, what to do", {
        "what_changed": "the decisions new, gone or at another level since the run before, and why",
        "list_closed_findings": "the findings fixed in a period, confirmed by a new scan",
        "list_unverified_findings": "the findings gone while their asset was not scanned again",
        "get_fix_plan": "what to apply on one asset, in order: the fix that clears most ACT first",
        "list_tickets": "the remediation tickets sent to the ITSM, with their numbers and states",
    }),
    ("Coverage of the assets", {
        "list_coverage": "each host against the CMDB: covered, partial, stale, never scanned, not in the CMDB",
    }),
    ("Documents to send", {
        "export_decisions": "a Word, PowerPoint or CSV document of decisions, to download",
    }),
    ("The platform itself", {
        "list_runs": "the daily runs kept, with their date and counts",
        "get_platform_status": "the version of each service and of the latest run, its LLM and cost, collectors late",
        "list_collectors": "each collector and source: last push, age, late or refused, connector, agent's version",
    }),
]  # fmt: skip

HEADER = """# Questions for the analysts' chat

Generated from `tests/chat-questions.yaml` by `scripts/make_chat_guide.py`: add a question there,
then run `python scripts/make_chat_guide.py --write`. The test suite checks that each question names
a tool that exists, with parameters it takes, and that this page is up to date. Set-up of the chat:
[`chat.md`](chat.md).

The chat answers in the language of the question. It reads only: it never changes a decision, sends
a ticket or validates an alert. It answers for one tenant, from the decision service (the daily
run), the watch, the detection service, the dispatch service and the shared intelligence service,
whichever run for that tenant.

How to ask:

- Dates and times are in the tenant's time zone: « depuis hier 18 h », « entre le 1er et le 31
  octobre », « depuis lundi 9 h ».
- Name things the way A2VM does: a CVE (`CVE-2024-3094`), an asset as the chat listed it
  (`host:web01.lab.example`, or simply `web01`), a level (ACT, ATTEND, TRACK).
- Long answers come in pages: « la suite », « les 20 suivantes ».
- Ask for the reason: « pourquoi ? » after a decision gives its justification and its SSVC inputs.
- When no tool covers a question, the chat must say so rather than answer « aucun ». The last table
  lists the questions it cannot answer yet.
"""


def build() -> str:
    data = yaml.safe_load(QUESTIONS.read_text(encoding="utf-8"))
    questions = data["questions"]
    themed = {tool for _, tools in THEMES for tool in tools}
    lines = [HEADER]
    for title, tools in THEMES:
        rows = [q for q in questions if q.get("tool") in tools]
        if not rows:
            continue
        lines.append(f"## {title}\n")
        for tool, what in tools.items():
            asked = [q for q in rows if q["tool"] == tool]
            if not asked:
                continue
            lines.append(f"**`{tool}`**: {what}.\n")
            lines.extend(f"- {q['q']}" for q in asked)
            lines.append("")
    other = [q for q in questions if "tool" in q and q["tool"] not in themed]
    if other:
        lines.append("## Other questions\n")
        lines.append("| Question | Tool |")
        lines.append("| --- | --- |")
        lines.extend(f"| {q['q']} | `{q['tool']}` |" for q in other)
        lines.append("")
    missing = [q for q in questions if "missing" in q]
    if missing:
        lines.append("## Not answered yet\n")
        lines.append("| Question | Why |")
        lines.append("| --- | --- |")
        lines.extend(f"| {q['q']} | {q['missing']} |" for q in missing)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str]) -> int:
    text = build()
    if "--check" in argv:
        current = GUIDE.read_text(encoding="utf-8") if GUIDE.exists() else ""
        if current != text:
            print(f"{GUIDE.relative_to(ROOT)} is out of date: python scripts/make_chat_guide.py --write")
            return 1
        return 0
    if "--write" in argv:
        GUIDE.write_text(text, encoding="utf-8")
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
