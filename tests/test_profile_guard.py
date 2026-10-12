# SPDX-License-Identifier: AGPL-3.0-only
import yaml

from vulnops.core.llm.guard import unsupported_tokens
from vulnops.core.profile import validate_profile_data

from .conftest import ROOT


def _data():
    return yaml.safe_load((ROOT / "examples" / "example-client" / "client.yaml").read_text())


def test_example_profile_is_valid(profile):
    assert profile.id == "example-client"
    assert profile.updated == "2026-10-10"  # YAML date converted to ISO string
    assert len(profile.assets) == 4


def test_profile_errors():
    data = _data()
    data["client"]["updated"] = "2026-10-10"
    data["assets"][0]["exposure"] = "dmz"
    data["assets"][1]["id"] = data["assets"][2]["id"]
    errors = validate_profile_data(data, "x.yaml")
    assert any("exposure" in e for e in errors)

    data = _data()
    data["client"]["updated"] = "2026-10-10"
    data["assets"][1]["id"] = data["assets"][2]["id"]
    assert any("duplicate asset id" in e for e in validate_profile_data(data, "x.yaml"))


def test_guard():
    facts = '{"cve": "CVE-2024-3400", "epss": 0.943, "deployed": ["11.1.2-h1"]}'
    assert unsupported_tokens("CVE-2024-3400 : ACT, version 11.1.2-h1, EPSS 0,943.", facts, "ACT") == []
    assert unsupported_tokens("Corrigé en 11.1.2-h3.", facts, "ACT") == ["11.1.2-h3"]
    assert unsupported_tokens("Voir CVE-2024-9999.", facts, "ACT") == ["CVE-2024-9999"]
    assert unsupported_tokens("Décision ATTEND.", facts, "ACT") == ["ATTEND"]
