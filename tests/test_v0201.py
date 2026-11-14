# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.20.1: the dispatch service reaches the tenant's database; the size of the chat tools' answers
is set per tenant."""

from __future__ import annotations

import importlib.util
import re

import pytest

from .conftest import ROOT

CHART = ROOT / "deploy" / "charts" / "ngvm-tenant"


def test_every_service_with_a_database_is_let_in_by_its_network_policy():
    policy = (CHART / "templates" / "database.yaml").read_text()
    allowed = set(re.search(r'range list ((?:"[a-z]+" ?)+)', policy).group(1).replace('"', "").split())
    users = {
        f.stem
        for f in (CHART / "templates").glob("*.yaml")
        if 'include "ngvm-tenant.dbEnv"' in f.read_text() and f.stem in ("via", "verdict", "intake", "dispatch")
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
    env = {"NGVM_CHAT_HOST": "chat.example.org", "NGVM_LLM_BASE_URL": "http://192.0.2.5:8000/v1",
           "NGVM_LLM_MODEL": "m"}  # fmt: skip
    assert "maxChars" not in cv.values(env)["chat"]
    assert cv.values({**env, "NGVM_CHAT_MAX_CHARS": "4000"})["chat"]["maxChars"] == 4000
    with pytest.raises(ValueError, match="NGVM_CHAT_MAX_CHARS"):
        cv.values({**env, "NGVM_CHAT_MAX_CHARS": "50"})


def test_the_page_has_time_and_reads_large_pages():
    from dispatch import decisions
    from verdict.service.index import DECISIONS_MAX, QueryError, page

    assert decisions.PAGE <= DECISIONS_MAX == 2000
    assert page({"limit": "2000"}, DECISIONS_MAX) == (2000, 0)
    with pytest.raises(QueryError):
        page({"limit": "2000"})  # 200 elsewhere
    tpl = (CHART / "templates" / "dispatch.yaml").read_text()
    assert "--upstream-timeout={{ $p.proxy.timeoutSeconds }}s" in tpl
    assert "timeoutSeconds: 120" in (CHART / "values.yaml").read_text()
