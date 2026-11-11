# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Which model serves the tenant, and how to ask it to reason more or less (v0.23.8).

The tenant chooses its model (`llm.model`, `llm.base_url`): a client may refuse a model of some
origin. Each family takes the level of reasoning its own way, through vLLM's chat completions:

  family    how                                               off           low / medium / high
  qwen3     chat_template_kwargs.enable_thinking              false         true
  gemma     chat_template_kwargs.enable_thinking              false         true
  gpt-oss   reasoning_effort                                  low (no off)  low / medium / high
  mistral   reasoning_effort (Mistral Small 4, Magistral)     none          high
  generic   nothing sent                                      -             -

`llm.family` empty: found from the model's name. `llm.reasoning` empty: nothing sent, the model's
own default. The v0.23.7 setting `llm.thinking` (off | on), alone, is sent as then: Qwen3's
switch (`enable_thinking`), whatever the model.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("a2vm.llm")

FAMILIES = ("qwen3", "gemma", "gpt-oss", "mistral", "generic")
LEVELS = ("off", "low", "medium", "high")
_NAMES = (("gpt-oss", "gpt-oss"), ("qwen3", "qwen3"), ("gemma-4", "gemma"), ("gemma4", "gemma"),
          ("magistral", "mistral"), ("mistral", "mistral"))  # fmt: skip


def family_of(model: str, declared: str = "") -> str:
    """The family declared, else found from the model's name (`Qwen/Qwen3-14B-AWQ` -> qwen3)."""
    declared = (declared or "").strip().lower()
    if declared:
        if declared in FAMILIES:
            return declared
        log.warning("llm.family %r unknown (one of %s): generic", declared, ", ".join(FAMILIES))
        return "generic"
    name = (model or "").lower()
    for part, family in _NAMES:
        if part in name:
            return family
    return "generic"


def reasoning_of(reasoning: str, thinking: str = "") -> str:
    """The level asked: `reasoning`, else the v0.23.7 `thinking` (off | on -> off | medium)."""
    level = (reasoning or "").strip().lower()
    if not level:
        old = (thinking or "").strip().lower()
        level = {"off": "off", "false": "off", "on": "medium", "true": "medium"}.get(old, "")
    if level and level not in LEVELS:
        log.warning("llm.reasoning %r unknown (one of %s): not sent", level, ", ".join(LEVELS))
        return ""
    return level


def request_fields(family: str, level: str) -> dict[str, Any]:
    """The fields of the request that set the level of reasoning of this family."""
    if not level:
        return {}
    if family in ("qwen3", "gemma"):
        return {"chat_template_kwargs": {"enable_thinking": level != "off"}}
    if family == "gpt-oss":
        return {"reasoning_effort": "low" if level == "off" else level}
    if family == "mistral":
        return {"reasoning_effort": "none" if level == "off" else "high"}
    return {}
