from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from verdict.config import Settings
from verdict.profile import load_profile
from verdict.sources import Sources

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def profile():
    return load_profile(ROOT / "clients" / "example-client.yaml")


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
