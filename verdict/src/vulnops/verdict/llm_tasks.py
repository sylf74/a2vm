"""verdict's two LLM tasks. Neither takes a triage decision; each one is optional.

1. assess_ssvc_inputs  - Automatable / Technical Impact when neither CISA ADP data nor a CVSS
                         vector is available (fresh CVEs). Result is always flagged for review.
2. write_rationale     - French explanation of a decision that was computed deterministically.

Vendor text (descriptions, product names) is untrusted: it is passed inside <untrusted> tags and
the model is told to treat it as data. The model has no tools, so injected instructions can at
worst produce a wrong answer, which the schema, the guard and human review are there to catch.
"""

from __future__ import annotations

from typing import Any

from vulnops.core.llm import UNTRUSTED as _UNTRUSTED
from vulnops.core.llm import LlmClient
from vulnops.core.models import VulnRecord

SSVC_INPUTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["automatable", "technical_impact", "justification"],
    "properties": {
        "automatable": {"enum": ["yes", "no"]},
        "technical_impact": {"enum": ["partial", "total"]},
        "justification": {"type": "string", "maxLength": 600},
    },
}

_SSVC_SYSTEM = f"""You assess two SSVC decision points for a vulnerability, from its description only.

Automatable:
- yes: an attacker can reliably automate reconnaissance, weaponization, delivery and exploitation
  (typically: network reachable, no authentication, no user interaction, no race or special setup).
- no: at least one of those steps cannot be reliably automated.

Technical Impact:
- total: the exploit gives the adversary total control over the software's behaviour, or total
  disclosure of all information on the system.
- partial: anything less (limited control, limited disclosure, denial of service only...).

When the description is too vague, choose the worst case (yes / total) and say so.
{_UNTRUSTED}
Answer in English, justification in at most 3 sentences."""


def assess_ssvc_inputs(llm: LlmClient, facts: VulnRecord) -> dict[str, Any]:
    user = (
        f"CVE: {facts.cve_id}\nCWE: {', '.join(facts.cwes) or 'unknown'}\n"
        f"<untrusted>\n{facts.description[:4000]}\n</untrusted>"
    )
    return llm.structured(_SSVC_SYSTEM, user, "ssvc_inputs", SSVC_INPUTS_SCHEMA)


RATIONALE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "action"],
    "properties": {
        "summary": {"type": "string", "maxLength": 700},
        "action": {"type": "string", "maxLength": 400},
    },
}

_RATIONALE_SYSTEM = f"""Tu rédiges, en français, la justification d'une décision de triage de vulnérabilité
destinée à un client. La décision est DÉJÀ prise par un calcul déterministe (SSVC CISA) : tu ne la
discutes pas et tu ne la modifies pas.

Règles :
- N'utilise QUE les faits fournis dans le JSON. N'invente aucun numéro de version, score, date ou
  identifiant. Si une information manque, ne la mentionne pas.
- "summary" : 2 à 3 phrases expliquant pourquoi la décision est celle-ci (exploitation, exposition,
  impact, criticité de l'actif). Cite la décision telle quelle (ACT, ATTEND ou TRACK).
- "action" : 1 à 2 phrases sur ce que le propriétaire de l'actif doit faire, dans le délai indiqué
  par le champ bod_timeline. Ne cite pas de version corrective si elle n'est pas dans les faits.
- Ton factuel, sans emphase.
{_UNTRUSTED}"""


def write_rationale(llm: LlmClient, facts_json: str, description: str) -> dict[str, Any]:
    user = (
        f"Faits :\n{facts_json}\n\n"
        f"Description éditeur (contexte uniquement) :\n<untrusted>\n{description[:1500]}\n</untrusted>"
    )
    return llm.structured(_RATIONALE_SYSTEM, user, "rationale", RATIONALE_SCHEMA)
