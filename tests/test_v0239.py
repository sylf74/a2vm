# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.9: the chat knows the platform. The version of each service and of the latest run, the
collectors with their last pushes, the agent's version and the connector that pushed."""

from __future__ import annotations

import json

import httpx
import pytest

from ngvm import __version__
from ngvm.service import Problem

from .conftest import ROOT
from .test_v0232 import CHAT, _tools

COLLECTORS = [
    {"id": "lan", "description": "LAN collector", "sources": [
        {"source": "openvas", "max_age_hours": 36, "last_received_at": "2026-11-11T06:40:00+00:00", "age_hours": 5.2,
         "stale": False, "agent_version": "0.23.9", "connector": "lan-openvas", "at": "2026-11-11T06:40:00+00:00"},
        {"source": "cmdb", "max_age_hours": 36, "age_hours": 50.0, "stale": True, "last_error": "x refused"},
    ]},
    {"id": "dmz", "description": "", "sources": [{"source": "trivy", "max_age_hours": 36, "stale": False}]},
]  # fmt: skip


def _handler(asked):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.path))
        if request.url.host == "detect.example":
            return httpx.Response(200, json={"service": "detect", "version": "0.23.9", "collectors": COLLECTORS})
        if request.url.host == "via.example":
            return httpx.Response(200, json={"version": "0.23.9", "last_passage": "2026-11-11T11:00:00+00:00"})
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json={"service": "verdict", "version": "0.23.9", "runs": 7, "latest_run": {}})
        if request.url.path.endswith("/summary"):
            usage = {"questions": 120, "from_cache": 104, "seconds": 41.0}
            return httpx.Response(200, json={"run_id": "r7", "generated_at": "2026-11-11T08:53:29+00:00",
                                             "ngvm_version": "0.23.9", "llm_model": "openai/gpt-oss-20b",
                                             "llm_usage": usage, "findings": {}})  # fmt: skip
        return httpx.Response(404, json={"detail": "no"})

    return handler


def test_the_platform_status(tmp_path) -> None:
    asked: list = []
    tools = _tools(tmp_path, _handler(asked), via_url="http://via.example", via_token="v",
                   detect_url="http://detect.example", detect_token="d")  # fmt: skip
    out = tools.call(CHAT, "/platform", {})
    assert out["services"] == {
        "tools": __version__, "decision": "0.23.9", "watch": "0.23.9", "detection": "0.23.9",
        "dispatch": "does not run for this tenant", "shared_intelligence": "not used",
    }  # fmt: skip
    assert out["latest_run"]["ngvm_version"] == "0.23.9" and out["latest_run"]["llm_usage"]["from_cache"] == 104
    assert out["runs_kept"] == 7 and out["collectors"] == 2
    assert out["collectors_late_or_refused"] == [
        {"collector": "lan", "source": "cmdb", "age_hours": 50.0, "last_error": "x refused"}
    ]
    assert ("detect.example", "/v1/tenants/example-client/status") in asked


def test_the_platform_status_without_the_other_services(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    out = _tools(tmp_path, handler).call(CHAT, "/platform", {})
    assert out["services"]["decision"] == "the decision service answered 503"
    assert out["services"]["watch"] == "the watch service does not run for this tenant"
    assert out["services"]["detection"] == "the detection service does not run for this tenant"
    assert out["collectors"] == 0


def test_list_collectors(tmp_path) -> None:
    tools = _tools(tmp_path, _handler([]), detect_url="http://detect.example", detect_token="d")
    out = tools.call(CHAT, "/collectors", {})
    assert out["total"] == 2 and out["detection_service_version"] == "0.23.9"
    out = tools.call(CHAT, "/collectors", {"source": "openvas"})
    (lan,) = out["items"]
    assert lan["sources"][0]["connector"] == "lan-openvas" and lan["sources"][0]["agent_version"] == "0.23.9"
    assert tools.call(CHAT, "/collectors", {"collector": "dmz"})["items"][0]["id"] == "dmz"
    assert tools.call(CHAT, "/collectors", {"collector": "nope"})["total"] == 0
    with pytest.raises(Problem) as p:
        _tools(tmp_path, _handler([])).call(CHAT, "/collectors", {})
    assert p.value.status == 503


# -- the detection service keeps the agent's version and connector -------------------------------
def test_the_push_carries_the_agent_and_the_connector(tmp_path) -> None:
    from detect.intake.client import AGENT_HEADER, CONNECTOR_HEADER, push

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(202, json={"id": "d1"})

    doc = {"source": "openvas", "generated_at": "2026-11-11T06:40:00+00:00"}
    push("https://detect.example", "lab", "t", doc, "lan", transport=httpx.MockTransport(handler),
         connector="lan-openvas")  # fmt: skip
    assert seen[AGENT_HEADER.lower()] == __version__ and seen[CONNECTOR_HEADER.lower()] == "lan-openvas"
    seen.clear()
    push("https://detect.example", "lab", "t", doc, "lan", transport=httpx.MockTransport(handler))
    assert CONNECTOR_HEADER.lower() not in seen


def test_the_detection_service_remembers_the_last_push(tmp_path) -> None:
    import datetime as dt

    from detect.intake.server import Service

    svc = Service.__new__(Service)
    svc.agents = {}
    now = dt.datetime(2026, 11, 11, 6, 40, tzinfo=dt.UTC)
    svc._seen("lan", "openvas", "0.23.9", "lan-openvas", now)
    svc._seen("lan", "cmdb", "0.23.9; rm -rf /", "x y", now)  # unsafe values are dropped
    assert svc.agents == {("lan", "openvas"): {"agent_version": "0.23.9", "connector": "lan-openvas",
                                               "at": "2026-11-11T06:40:00+00:00"}}  # fmt: skip


def test_statuses_name_their_version(tmp_path) -> None:
    import inspect

    from detect.intake import server as detect_server
    from verdict.service import server as verdict_server

    assert '"service": "detect", "version": __version__' in inspect.getsource(detect_server.Service.status)
    assert 'if rest == "status"' in inspect.getsource(verdict_server)


def test_the_run_names_its_version(settings, sources, profile, tmp_path) -> None:
    from verdict.report import write_json
    from verdict.service.index import RunIndex

    from .test_pipeline import _run

    run = _run(settings, sources, profile)
    write_json(run, tmp_path / "triage.json")
    doc = json.loads((tmp_path / "triage.json").read_text())
    assert doc["ngvm_version"] == __version__
    assert RunIndex and doc["client"]


def test_wiring() -> None:
    chat = (ROOT / "deploy" / "charts" / "ngvm-tenant" / "templates" / "chat.yaml").read_text()
    assert "--detect-token-file=/secrets/detect-read-token" in chat and "key: detect-read-token" in chat
    schema = json.loads((ROOT / "ngvm" / "src" / "ngvm" / "schemas" / "triage.schema.json").read_text())
    assert "ngvm_version" in schema["properties"]


def test_the_guide_of_the_questions_is_up_to_date() -> None:
    import subprocess
    import sys

    script = ROOT / "scripts" / "make_chat_guide.py"
    done = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout
    guide = (ROOT / "docs" / "chat-questions.md").read_text(encoding="utf-8")
    assert "Quelle version d'NGVM tourne sur mon tenant ?" in guide and "## Not answered yet" in guide
    import runpy

    import yaml

    themes = runpy.run_path(str(script))["THEMES"]
    described = {tool for _, tools in themes for tool in tools}
    asked = {q["tool"] for q in yaml.safe_load((ROOT / "tests" / "chat-questions.yaml").read_text())["questions"]
             if "tool" in q}  # fmt: skip
    assert asked <= described, asked - described  # each tool asked has its line in the guide
