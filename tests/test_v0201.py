# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.20.1: the dispatch service reaches the tenant's database; the size of the chat tools' answers
is set per tenant."""

from __future__ import annotations

import importlib.util
import re

import pytest

from .conftest import ROOT

CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"


def test_every_service_with_a_database_is_let_in_by_its_network_policy():
    policy = (CHART / "templates" / "database.yaml").read_text()
    allowed = set(re.search(r'range list ((?:"[a-z]+" ?)+)', policy).group(1).replace('"', "").split())
    users = {
        f.stem
        for f in (CHART / "templates").glob("*.yaml")
        if 'include "a2vm-tenant.dbEnv"' in f.read_text() and f.stem in ("via", "verdict", "intake", "dispatch")
    }
    assert {"via", "verdict", "detect", "dispatch"} <= allowed
    assert "dispatch" in users


def _chat_values():
    spec = importlib.util.spec_from_file_location("cv", ROOT / "deploy" / "chat" / "chat_values.py")
    cv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cv)
    return cv


def test_the_tools_answer_size_is_set_per_tenant():
    cv = _chat_values()
    env = {"A2VM_CHAT_HOST": "chat.example.org", "A2VM_LLM_BASE_URL": "http://192.0.2.5:8000/v1",
           "A2VM_LLM_MODEL": "m"}  # fmt: skip
    assert "maxChars" not in cv.values(env)["chat"]
    assert cv.values({**env, "A2VM_CHAT_MAX_CHARS": "4000"})["chat"]["maxChars"] == 4000
    with pytest.raises(ValueError, match="A2VM_CHAT_MAX_CHARS"):
        cv.values({**env, "A2VM_CHAT_MAX_CHARS": "50"})
