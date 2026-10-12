# SPDX-License-Identifier: AGPL-3.0-only
from vulnops.core.config import describe_llm, load_settings

from .conftest import ROOT


def test_env_overrides_new_and_legacy_prefix(monkeypatch):
    monkeypatch.setenv("VERDICT_LLM_ENABLED", "true")  # legacy prefix still honoured
    monkeypatch.setenv("VULNOPS_LLM_MODEL", "qwen3-14b")
    monkeypatch.setenv("VERDICT_LLM_MODEL", "ignored")  # VULNOPS_ wins over VERDICT_
    monkeypatch.setenv("VULNOPS_LLM_BASE_URL", "http://192.0.2.103:8000/v1")
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert (s.llm.enabled, s.llm.model, s.llm.base_url) == (True, "qwen3-14b", "http://192.0.2.103:8000/v1")
    line = describe_llm(s)
    assert "qwen3-14b" in line and "192.0.2.103" in line and "api key not set" in line


def test_policy_stays_a_mapping_in_core():
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert s.policy["decision_mapping"]["track*"] == "ATTEND"
    assert s.fuzzy_threshold == 0.75
