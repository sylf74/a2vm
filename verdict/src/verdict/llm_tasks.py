# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""verdict's two LLM tasks. Neither takes a triage decision; each one is optional.

1. assess_ssvc_inputs  - Automatable / Technical Impact when neither CISA ADP data nor a CVSS
                         vector is available (fresh CVEs). Result is always flagged for review.
2. write_rationale     - English explanation of a decision that was computed deterministically.

Vendor text (descriptions, product names) is untrusted: it is passed inside <untrusted> tags and
the model is told to treat it as data. The model has no tools, so injected instructions can at
worst produce a wrong answer, which the schema, the guard and human review are there to catch.
"""

from __future__ import annotations

from typing import Any

from a2vm.llm import UNTRUSTED as _UNTRUSTED
from a2vm.llm import LlmClient
from a2vm.models import VulnRecord

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

_RATIONALE_SYSTEM = f"""You write, in English, the rationale of a vulnerability triage decision for a
client. The decision is ALREADY taken by a deterministic computation (CISA SSVC): you do not discuss
it and you do not change it.

Rules:
- Use ONLY the facts given in the JSON. Invent no version number, score, date or identifier. When
  something is missing, leave it out.
- "summary": 2 to 3 sentences on why the decision is this one (exploitation, exposure, impact,
  criticality of the asset). Quote the decision as it is (ACT, ATTEND or TRACK).
- "action": 1 to 2 sentences on what the owner of the asset must do, within the delay given by the
  field bod_timeline. When the field fixed_packages is not empty, name the fixing package(s) as
  given; otherwise name no fixed version.
- When the field assumptions is not empty, say in one short sentence that the decision rests on an
  assumption (e.g. an assumed exposure), without inventing another one.
- When the field affected_assets holds several assets, the rationale covers them all: give their
  number, and name the internet-facing asset if there is one.
- Factual tone, no emphasis.
{_UNTRUSTED}"""


def write_rationale(llm: LlmClient, facts_json: str, description: str) -> dict[str, Any]:
    user = (
        f"Facts:\n{facts_json}\n\nVendor description (context only):\n<untrusted>\n{description[:1500]}\n</untrusted>"
    )
    return llm.structured(_RATIONALE_SYSTEM, user, "rationale", RATIONALE_SCHEMA)
