# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
from ngvm.config import describe_llm, load_settings

from .conftest import ROOT


def test_env_overrides_new_and_legacy_prefix(monkeypatch):
    monkeypatch.setenv("VERDICT_LLM_ENABLED", "true")  # legacy prefix still honoured
    monkeypatch.setenv("NGVM_LLM_MODEL", "qwen3-14b")
    monkeypatch.setenv("VERDICT_LLM_MODEL", "ignored")  # NGVM_ wins over VERDICT_
    monkeypatch.setenv("NGVM_LLM_BASE_URL", "http://192.0.2.103:8000/v1")
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert (s.llm.enabled, s.llm.model, s.llm.base_url) == (True, "qwen3-14b", "http://192.0.2.103:8000/v1")
    line = describe_llm(s)
    assert "qwen3-14b" in line and "192.0.2.103" in line and "api key not set" in line


def test_policy_stays_a_mapping_in_core():
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert s.policy["decision_mapping"]["track*"] == "ATTEND"
    assert s.fuzzy_threshold == 0.75


def test_env_reads_ngvm_then_legacy_a2vm_with_a_warning(monkeypatch, capsys):
    from ngvm import config

    monkeypatch.setattr(config, "_warned", set())
    assert config.env("SMTP_HOST", "none") == "none"
    monkeypatch.setenv("A2VM_SMTP_HOST", "old.example")
    assert config.env("SMTP_HOST") == "old.example"
    assert "A2VM_SMTP_HOST is deprecated: rename it NGVM_SMTP_HOST" in capsys.readouterr().err
    monkeypatch.setenv("NGVM_SMTP_HOST", "new.example")
    assert config.env("SMTP_HOST") == "new.example"
    assert config.env("GVM_USER", environ={"A2VM_GVM_USER": "scan"}) == "scan"


def test_settings_override_by_legacy_a2vm_prefix(monkeypatch):
    monkeypatch.setenv("A2VM_LLM_MODEL", "legacy-model")
    assert load_settings(ROOT / "config" / "settings.yaml").llm.model == "legacy-model"
    monkeypatch.setenv("NGVM_LLM_MODEL", "new-model")
    assert load_settings(ROOT / "config" / "settings.yaml").llm.model == "new-model"
