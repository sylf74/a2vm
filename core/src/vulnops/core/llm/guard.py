"""Checks applied to free text produced by the LLM before it reaches a report.

The model only rephrases facts computed by the pipeline. Any version number, score or CVE id it
writes must therefore already appear in those facts; otherwise the text is discarded and the
template rationale is used instead.
"""

from __future__ import annotations

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NUMBER_RE = re.compile(r"\b\d+(?:[.,]\d+)+(?:[-._]?[a-z]+\d*)?\b", re.IGNORECASE)
DECISION_RE = re.compile(r"\b(ACT|ATTEND|TRACK)\b")


def unsupported_tokens(text: str, facts_text: str, decision: str) -> list[str]:
    haystack = facts_text.lower()
    problems: list[str] = []
    for token in CVE_RE.findall(text):
        if token.lower() not in haystack:
            problems.append(token)
    for token in NUMBER_RE.findall(text):
        candidates = {token.lower(), token.lower().replace(",", ".")}
        if not any(c in haystack for c in candidates):
            problems.append(token)
    for token in DECISION_RE.findall(text):
        if token != decision:
            problems.append(token)
    return problems
