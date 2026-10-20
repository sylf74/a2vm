# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Turn SSVC outcomes into the delivery decision used in client reports (ACT / ATTEND / TRACK).

Everything here is configurable in settings.yaml (`policy` section); each escalation that fires
is recorded in the row's `reasons` (in French, as they end up in client reports) so a decision
can always be explained.
"""

from __future__ import annotations

from dataclasses import dataclass, field

LEVELS = ("TRACK", "ATTEND", "ACT")

DEFAULT_MAPPING = {"act": "ACT", "attend": "ATTEND", "track*": "ATTEND", "track": "TRACK"}


@dataclass
class Policy:
    decision_mapping: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_MAPPING))
    bod_3_days_to_act: bool = True
    bod_14_days_min_attend: bool = True
    epss_attend_threshold: float | None = 0.1
    unknown_inputs: str = "conservative"  # conservative | optimistic
    fuzzy_match_without_llm: str = "review"  # review | drop

    @classmethod
    def from_dict(cls, data: dict | None) -> Policy:
        data = data or {}
        esc = data.get("escalations", {}) or {}
        p = cls(
            decision_mapping={**DEFAULT_MAPPING, **(data.get("decision_mapping") or {})},
            bod_3_days_to_act=esc.get("bod_3_days_to_act", True),
            bod_14_days_min_attend=esc.get("bod_14_days_min_attend", True),
            epss_attend_threshold=esc.get("epss_attend_threshold", 0.1),
            unknown_inputs=data.get("unknown_inputs", "conservative"),
            fuzzy_match_without_llm=data.get("fuzzy_match_without_llm", "review"),
        )
        for k, v in p.decision_mapping.items():
            if v not in LEVELS:
                raise ValueError(f"policy.decision_mapping[{k!r}] must be one of {LEVELS}, got {v!r}")
        if p.unknown_inputs not in {"conservative", "optimistic"}:
            raise ValueError("policy.unknown_inputs must be 'conservative' or 'optimistic'")
        if p.fuzzy_match_without_llm not in {"review", "drop"}:
            raise ValueError("policy.fuzzy_match_without_llm must be 'review' or 'drop'")
        return p


def _raise(current: str, target: str) -> str:
    return target if LEVELS.index(target) > LEVELS.index(current) else current


def delivery_decision(ssvc: str, bod: str, epss: float | None, policy: Policy) -> tuple[str, list[str]]:
    decision = policy.decision_mapping[ssvc]
    reasons = [f"SSVC CISA Coordinator : {ssvc} -> {decision}"]

    if policy.bod_3_days_to_act and bod.startswith("3 days") and decision != "ACT":
        decision = "ACT"
        reasons.append(f"relevé à ACT : délai BOD 26-04 « {bod} »")
    if policy.bod_14_days_min_attend and bod == "14 days" and decision == "TRACK":
        decision = "ATTEND"
        reasons.append("relevé à ATTEND : délai BOD 26-04 « 14 days »")
    threshold = policy.epss_attend_threshold
    if threshold is not None and epss is not None and epss >= threshold and decision == "TRACK":
        decision = _raise(decision, "ATTEND")
        reasons.append(f"relevé à ATTEND : EPSS {epss:.3f} >= {threshold}")
    return decision, reasons
