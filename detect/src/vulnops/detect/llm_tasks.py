# SPDX-License-Identifier: AGPL-3.0-only
"""detect's LLM task: is the product named in a vulnerability record the client's asset?

Only called for fuzzy (name-similarity) candidates; a confirmed match is always flagged for
review, a rejected one is dropped. Vendor text is untrusted and passed as data.
"""

from __future__ import annotations

import json
from typing import Any

from vulnops.core.llm import UNTRUSTED as _UNTRUSTED
from vulnops.core.llm import LlmClient
from vulnops.core.models import AffectedEntry, DeclaredAsset, VulnRecord

MATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["same_product", "justification"],
    "properties": {
        "same_product": {"type": "boolean"},
        "justification": {"type": "string", "maxLength": 400},
    },
}

_MATCH_SYSTEM = f"""You decide whether the product named in a vulnerability record is the same software
product as an asset in a client's inventory. Different products from the same vendor, different
editions with separate code bases, or plugins/clients of a product are NOT the same product.
Ignore version numbers: only the product identity matters.
{_UNTRUSTED}
Answer in English, justification in at most 2 sentences."""


def adjudicate_match(llm: LlmClient, facts: VulnRecord, entry: AffectedEntry, asset: DeclaredAsset) -> dict[str, Any]:
    inventory = {
        "vendor": asset.vendor,
        "product": asset.product,
        "aliases": asset.product_aliases,
        "description": asset.description,
    }
    user = (
        f"Client asset: {json.dumps(inventory, ensure_ascii=False)}\n"
        f"Vulnerability {facts.cve_id}, product as named in the record:\n"
        f"<untrusted>\nvendor: {entry.vendor}\nproduct: {entry.product}\n"
        f"description: {facts.description[:1500]}\n</untrusted>"
    )
    return llm.structured(_MATCH_SYSTEM, user, "product_match", MATCH_SCHEMA)
