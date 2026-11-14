# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.8: the tenant chooses its LLM. The model's family, found from its name or declared, and
the level of reasoning sent the way that family takes it."""

from __future__ import annotations

import pytest

from ngvm.config import LlmSettings, describe_llm, load_settings
from ngvm.llm import LlmClient
from ngvm.llm.families import family_of, reasoning_of, request_fields

from .conftest import ROOT, fake_llm_transport

SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"], "additionalProperties": False}


@pytest.mark.parametrize(
    ("model", "family"),
    [
        ("Qwen/Qwen3-14B-AWQ", "qwen3"),
        ("openai/gpt-oss-20b", "gpt-oss"),
        ("openai/gpt-oss-120b", "gpt-oss"),
        ("mistralai/Mistral-Small-4-2603", "mistral"),
        ("mistralai/Magistral-Small-2509", "mistral"),
        ("google/gemma-4-26b-a4b-it", "gemma"),
        ("meta-llama/Llama-3.1-8B-Instruct", "generic"),
        ("", "generic"),
    ],
)
def test_family_from_the_name(model, family) -> None:
    assert family_of(model) == family


def test_family_declared() -> None:
    assert family_of("my-own-finetune", "qwen3") == "qwen3"
    assert family_of("Qwen/Qwen3-14B", "unknown") == "generic"  # a warning, nothing sent


@pytest.mark.parametrize(
    ("family", "level", "fields"),
    [
        ("qwen3", "off", {"chat_template_kwargs": {"enable_thinking": False}}),
        ("qwen3", "high", {"chat_template_kwargs": {"enable_thinking": True}}),
        ("gemma", "off", {"chat_template_kwargs": {"enable_thinking": False}}),
        ("gpt-oss", "off", {"reasoning_effort": "low"}),
        ("gpt-oss", "medium", {"reasoning_effort": "medium"}),
        ("mistral", "off", {"reasoning_effort": "none"}),
        ("mistral", "low", {"reasoning_effort": "high"}),
        ("generic", "off", {}),
        ("qwen3", "", {}),
    ],
)
def test_request_fields(family, level, fields) -> None:
    assert request_fields(family, level) == fields


def test_reasoning_levels() -> None:
    assert reasoning_of("LOW") == "low"
    assert reasoning_of("", "off") == "off" and reasoning_of("", "on") == "medium"
    assert reasoning_of("max") == ""  # a warning, nothing sent


@pytest.mark.parametrize(
    ("settings", "sent"),
    [
        ({"model": "openai/gpt-oss-20b", "reasoning": "off"}, {"reasoning_effort": "low"}),
        ({"model": "mistralai/Mistral-Small-4-2603", "reasoning": "off"}, {"reasoning_effort": "none"}),
        ({"model": "Qwen/Qwen3-14B", "reasoning": "off"}, {"chat_template_kwargs": {"enable_thinking": False}}),
        ({"model": "my-model", "family": "gpt-oss", "reasoning": "high"}, {"reasoning_effort": "high"}),
        ({"model": "openai/gpt-oss-20b", "thinking": "off"}, {"chat_template_kwargs": {"enable_thinking": False}}),
        ({"model": "openai/gpt-oss-20b", "thinking": "off", "reasoning": "low"}, {"reasoning_effort": "low"}),
        ({"model": "openai/gpt-oss-20b"}, {}),
    ],
)
def test_the_request_carries_the_level(settings, sent) -> None:
    transport = fake_llm_transport(lambda name, body: {"x": "y"})
    llm = LlmClient(LlmSettings(enabled=True, max_retries=0, **settings), transport=transport)
    llm.structured("s", "u", "q", SCHEMA)
    (body,) = transport.calls
    assert {k: body[k] for k in ("chat_template_kwargs", "reasoning_effort") if k in body} == sent
    usage = llm.usage_summary()
    assert usage["family"] == family_of(settings["model"], settings.get("family", ""))


def test_settings_and_log_line(monkeypatch) -> None:
    monkeypatch.setenv("NGVM_LLM_MODEL", "mistralai/Mistral-Small-4-2603")
    monkeypatch.setenv("NGVM_LLM_REASONING", "off")
    monkeypatch.setenv("NGVM_LLM_ENABLED", "true")
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert (s.llm.family, s.llm.reasoning) == ("", "off")
    line = describe_llm(s)
    assert line.endswith("model=mistralai/Mistral-Small-4-2603, api key not set, family mistral, reasoning off")
    monkeypatch.setenv("NGVM_LLM_FAMILY", "generic")
    assert "family generic, reasoning off" in describe_llm(load_settings(ROOT / "config" / "settings.yaml"))


def test_wiring() -> None:
    pipeline = (ROOT / "templates" / "client-pipeline.yml").read_text()
    assert "NGVM_LLM_FAMILY NGVM_LLM_REASONING" in pipeline
    guide = (ROOT / "docs" / "llm.md").read_text()
    for name in ("gpt-oss-20b", "Mistral-Small-4", "gemma-4", "Qwen3", "NGVM_LLM_REASONING"):
        assert name in guide
