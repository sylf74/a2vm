# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from a2vm.config import Settings
from a2vm.profile import load_profile
from via.intel.sources import Sources

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
# An administrator connection to a disposable PostgreSQL (read before the environment is cleared).
TEST_DSN = __import__("os").environ.get("A2VM_TEST_DSN", "")


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Tests never see the CI/CD variables of the runner (LLM endpoint, API keys, cache dir)."""
    import os

    for name in list(os.environ):
        if name.startswith(("A2VM_", "VULNOPS_", "VERDICT_")) or name in ("LLM_API_KEY", "GTI_API_KEY"):
            monkeypatch.delenv(name)


@pytest.fixture
def profile():
    return load_profile(ROOT / "examples" / "example-client" / "client.yaml")


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.sources.cache_dir = str(tmp_path / "cache")
    return s


@pytest.fixture
def sources(settings):
    src = Sources(settings.sources, fixtures_dir=FIXTURES)
    yield src
    src.close()


def fake_llm_transport(answer: Callable[[str, dict], dict]) -> httpx.MockTransport:
    """Mock OpenAI-compatible server: `answer(schema_name, request_json)` returns the JSON object."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        calls.append(body)
        content = json.dumps(answer(name, body), ensure_ascii=False)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})

    transport = httpx.MockTransport(handler)
    transport.calls = calls  # type: ignore[attr-defined]
    return transport


@pytest.fixture
def tenant_db():
    """A new database owned by a new role, as a tenant's CloudNativePG cluster gives its services
    (the role owns the tables, is no superuser: row-level security applies); its connection string."""
    import uuid

    import psycopg
    from psycopg import sql

    if not TEST_DSN:
        pytest.skip("A2VM_TEST_DSN not set (disposable PostgreSQL)")
    name = f"t_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(TEST_DSN, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD 'app'").format(sql.Identifier(name)))
        conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(name)))
    try:
        yield psycopg.conninfo.make_conninfo(TEST_DSN, user=name, password="app", dbname=name, sslmode="disable")
    finally:
        with psycopg.connect(TEST_DSN, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


@pytest.fixture(params=["files", "postgres"])
def backend(request):
    """Where a service keeps its data: None (files on its volume) or the tenant database's DSN."""
    if request.param == "files":
        return None
    return request.getfixturevalue("tenant_db")
