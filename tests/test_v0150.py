# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.15.0 (HLD §8): conversational search in the tenant's namespace (Open WebUI and the tool server
`verdict tools` on the decision service), several LLM endpoints, and the v0.14.0 follow-ups."""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import subprocess
import threading
from pathlib import Path

import httpx
import pytest
import yaml

from a2vm.config import LlmSettings
from a2vm.llm.client import LlmClient
from a2vm.service import JsonHandler, Problem, TokenSet, digest
from verdict.service.server import serve as serve_verdict
from verdict.service.tools import OPERATIONS, Tools, fit, shrink

from .test_verdict_service import READ, _push, _service, triage  # noqa: F401 - fixture

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"
CHAT_VALUES = ROOT / "deploy" / "chat" / "chat_values.py"
CHAT = "chat-token-0123456789abcdef0123456789"


# -- v0.14.0 follow-ups --------------------------------------------------------------------------
def test_successful_probes_are_not_logged(caplog):
    class H(JsonHandler):
        def __init__(self, path):
            self.path, self.command = path, "GET"

    caplog.set_level(logging.INFO, logger="a2vm.service")
    H("/readyz").log_message("%s", "GET /readyz", "200", "-")
    H("/healthz").log_message("%s", "GET /healthz", "503", "-")
    H("/v1/tenants/lab/summary?run=latest").log_message("%s", "x", "200", "-")
    lines = [r.getMessage() for r in caplog.records]
    assert lines == ["GET /healthz 503", "GET /v1/tenants/lab/summary 200"]  # no query string either


def test_decision_service_has_resources_and_the_read_command_mounts_the_token():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["verdict"]["resources"]["limits"]["memory"] == "1Gi"
    doc = (ROOT / "docs" / "kubernetes.md").read_text()
    assert '--env="TOKEN' not in doc and '"key":"verdict-read-token"' in doc


# -- several LLM endpoints -----------------------------------------------------------------------
def test_base_url_takes_one_or_several_endpoints():
    assert LlmSettings(base_url="http://a:8000/v1/").base_urls == ["http://a:8000/v1"]
    assert LlmSettings(base_url="http://a/v1, http://b/v1;http://c/v1").base_urls == [
        "http://a/v1",
        "http://b/v1",
        "http://c/v1",
    ]
    assert LlmSettings(base_url=["http://a/v1", "http://b/v1"]).base_urls == ["http://a/v1", "http://b/v1"]


def test_calls_move_to_the_next_endpoint_when_one_is_down():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "llm-a.example":
            raise httpx.ConnectError("down", request=request)
        if request.url.host == "llm-b.example":
            return httpx.Response(503)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": true}'}}]})

    settings = LlmSettings(
        base_url="http://llm-a.example/v1,http://llm-b.example/v1,http://llm-c.example/v1", max_retries=0
    )
    llm = LlmClient(settings, transport=httpx.MockTransport(handler))
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
    assert llm.structured("s", "u", "t", schema) == {"ok": True}
    assert seen == ["llm-a.example", "llm-b.example", "llm-c.example"]
    seen.clear()
    llm.structured("s", "u", "t", schema)
    assert seen == ["llm-c.example"]  # later calls stay on the endpoint that answered


def test_a_refused_request_is_not_sent_elsewhere():
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(400, json={"error": "bad request"})

    llm = LlmClient(
        LlmSettings(base_url="http://a.example/v1,http://b.example/v1", max_retries=0),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(Exception, match="400"):
        llm.structured("s", "u", "t", {"type": "object"})
    assert seen == ["a.example"]


# -- the tool server -----------------------------------------------------------------------------
@pytest.fixture
def tools(triage, tmp_path):  # noqa: F811 - fixture
    run, path = triage
    service = _service(tmp_path, run.client.id)
    _push(service, path)
    httpd = serve_verdict(service, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    digests = tmp_path / "chat-digests"
    digests.write_text(f"chat {digest(CHAT)}\n")
    t = Tools(run.client.id, TokenSet.load(digests, {"chat"}), f"http://127.0.0.1:{httpd.server_address[1]}", READ)
    yield run, t
    t.close()
    httpd.shutdown()
    httpd.server_close()


def test_the_tools_need_the_chat_token_and_answer_short_pages(tools):
    run, t = tools
    for token in (None, READ):
        with pytest.raises(Problem) as p:
            t.call(token, "/summary", {})
        assert p.value.status == 401
    summary = t.call(CHAT, "/summary", {})
    assert summary["run"]["id"] and "source" in summary
    page = t.call(CHAT, "/decisions", {})
    assert page["limit"] == 10 and len(page["items"]) <= 10
    assert len(json.dumps(page, ensure_ascii=False)) <= t.max_chars
    one = t.call(CHAT, f"/decisions/{page['items'][0]['id']}", {})
    assert one["cve_id"] == page["items"][0]["cve"] and one["rationale"]
    cve = t.call(CHAT, f"/cves/{run.rows[0].cve_id}", {})
    assert cve["cve"] == run.rows[0].cve_id
    assets = t.call(CHAT, "/assets", {"limit": "2"})
    assert len(assets["items"]) <= 2
    assert t.call(CHAT, f"/assets/{assets['items'][0]['asset']}", {})["asset"] == assets["items"][0]["asset"]
    assert t.call(CHAT, "/runs", {})["items"][0]["id"] == summary["run"]["id"]


@pytest.mark.parametrize(
    ("path", "query", "status"),
    [
        ("/decisions", {"limit": "50"}, 400),
        ("/decisions", {"level": "URGENT"}, 400),
        ("/cves/not-a-cve", {}, 400),
        ("/cves/CVE-1999-0001", {}, 404),
        ("/decisions/..%2F..%2Fetc", {}, 400),
        ("/delete_everything", {}, 404),
    ],
)
def test_bad_tool_calls_are_problems(tools, path, query, status):
    _, t = tools
    with pytest.raises(Problem) as p:
        t.call(CHAT, path, query)
    assert int(p.value.status) == status


def test_vendor_text_cannot_make_the_browser_fetch_anything():
    text = "See https://evil.example/x?data=1 and ![x](https://evil.example/p.png) " + "a" * 2000
    out = shrink({"description": text, "fixes": [f"fix {i}" for i in range(30)]})
    assert "https://" not in out["description"] and "[link: evil.example]" in out["description"]
    assert "[image removed]" in out["description"] and len(out["description"]) <= 600
    assert out["fixes"][-1] == "… 20 more" and len(out["fixes"]) == 11
    page = {
        "total": 40,
        "offset": 20,
        "limit": 20,
        "items": [{"title": "x" * 500} for _ in range(20)],
        "next_offset": 40,
    }
    small = fit(page, 1200)
    assert len(json.dumps(small, ensure_ascii=False)) <= 1200 and small["truncated"]
    assert all(isinstance(i, dict) for i in small["items"]) and small["next_offset"] == 20 + len(small["items"])


def test_the_tool_server_publishes_read_operations_only(tools):
    _, t = tools
    spec = t.spec
    assert spec["openapi"].startswith("3.1")
    ops = [op for item in spec["paths"].values() for op in item.values()]
    assert {o["operationId"] for o in ops} == {o[1] for o in OPERATIONS}
    assert all(m == "get" for item in spec["paths"].values() for m in item)
    assert all(len(o["summary"]) > 40 for o in ops)  # described for a model


# -- chart and deploy job ------------------------------------------------------------------------
def test_chat_is_closed_offline_and_configured_from_the_values():
    text = (CHART / "templates" / "chat.yaml").read_text()
    for needle in (
        "{{- if .Values.chat.enabled }}",
        'command: ["verdict", "tools"]',
        'a2vm.io/verdict-reader: "true"',
        '{name: ENABLE_PERSISTENT_CONFIG, value: "false"}',
        '{name: ENABLE_SIGNUP, value: "false"}',
        '{name: OFFLINE_MODE, value: "true"}',
        '{name: ENABLE_WEB_SEARCH, value: "false"}',
        '{name: ENABLE_CODE_EXECUTION, value: "false"}',
        '{name: USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS, value: "false"}',
        '{name: ENABLE_DIRECT_CONNECTIONS, value: "false"}',
        '{name: ENABLE_OLLAMA_API, value: "false"}',
        "CONTENT_SECURITY_POLICY",
        "OPENAI_API_BASE_URLS",
        "TOOL_SERVER_CONNECTIONS_TEMPLATE",
        '"enable" true',
        "readOnlyRootFilesystem: true",
        "runAsNonRoot: true",
        "automountServiceAccountToken: false",
        "helm.sh/resource-policy: keep",
        "ipBlock:",
    ):
        assert needle in text, needle
    assert text.count("kind: NetworkPolicy") == 3  # tools, chat, LLM gateway
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    chat = values["chat"]
    assert chat["enabled"] is False and chat["networkPolicy"]["enabled"] is True
    assert chat["image"]["tag"].startswith("v") and "connect-src 'self'" in chat["ingress"]["contentSecurityPolicy"]
    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    for message in (
        "chat.enabled needs verdict.enabled",
        "chat.llm.endpoints is required",
        "chat.llm.egress is required",
    ):
        assert message in helpers, message


def _chat_values(env: dict) -> subprocess.CompletedProcess:
    out = Path(env.pop("OUT"))
    full = {"PATH": os.environ["PATH"], **env}
    return subprocess.run(["python3", "-I", str(CHAT_VALUES), str(out)], env=full, capture_output=True, text=True)


def test_chat_values_resolve_the_endpoints_for_the_network_policy(tmp_path):
    out = tmp_path / "v.json"
    r = _chat_values(
        {
            "OUT": str(out),
            "A2VM_CHAT_HOST": "chat-lab.apps.example.org",
            "A2VM_LLM_BASE_URL": "http://192.0.2.10:8000/v1/, https://198.51.100.7/v1",
            "A2VM_LLM_MODEL": "qwen3-14b",
            "A2VM_INTAKE_INGRESS_CONTROLLER": "traefik",
            "A2VM_CHAT_ALLOW": "203.0.113.0/24",
        }
    )
    assert r.returncode == 0, r.stderr
    chat = json.loads(out.read_text())["chat"]
    assert chat["llm"]["endpoints"] == ["http://192.0.2.10:8000/v1", "https://198.51.100.7/v1"]
    assert chat["llm"]["egress"] == [{"cidr": "192.0.2.10/32", "port": 8000}, {"cidr": "198.51.100.7/32", "port": 443}]
    assert chat["ingress"]["controller"] == "traefik" and chat["ingress"]["allowFrom"] == ["203.0.113.0/24"]
    r = _chat_values(
        {
            "OUT": str(out),
            "A2VM_CHAT_HOST": "c",
            "A2VM_LLM_BASE_URL": "http://llm.example/v1",
            "A2VM_LLM_MODEL": "m",
            "A2VM_CHAT_LLM_EGRESS": "192.0.2.0/28:8000",
        }
    )
    assert r.returncode == 0 and json.loads(out.read_text())["chat"]["llm"]["egress"] == [
        {"cidr": "192.0.2.0/28", "port": 8000}
    ]
    r = _chat_values({"OUT": str(out), "A2VM_CHAT_HOST": "c"})
    assert r.returncode == 1 and "A2VM_LLM_BASE_URL" in r.stderr


def test_chat_values_run_with_the_standard_library_only():
    tree = ast.parse(CHAT_VALUES.read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "ipaddress", "json", "os", "re", "socket", "sys", "urllib"}


def test_deploy_job_makes_the_chat_secrets_once_and_hands_the_values_to_the_chart():
    pipeline = yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())
    script = "\n".join(pipeline["deploy-k8s"]["script"])
    block = next(s for s in pipeline["deploy-k8s"]["script"] if 'CHAT=""' in s)
    assert 'if [ -n "${A2VM_CHAT_HOST:-}" ] && [ -n "$VERDICT" ]' in block
    for k in ("chat-secret-key", "chat-admin-password", "chat-tools-token"):
        assert f"put {k} " in script
    assert "create secret generic a2vm-chat" in block and "chat_values.py" in block
    assert "$INTAKE $VERDICT $CHAT" in script
    assert script.index('CHAT=""') < script.index("put chat-tools-token")


def test_tool_server_over_http(tools):
    from verdict.service.tools import serve as serve_tools

    _, t = tools
    httpd = serve_tools(t, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with httpx.Client(base_url=url) as c:
            assert c.get("/healthz").status_code == 200
            assert c.get("/openapi.json").status_code == 401
            auth = {"Authorization": f"Bearer {CHAT}"}
            assert c.get("/openapi.json", headers=auth).json()["info"]["title"] == "A2VM"
            r = c.get("/decisions", params={"level": "ACT,ATTEND", "limit": 3}, headers=auth)
            assert r.status_code == 200 and len(r.json()["items"]) <= 3
            bad = c.get("/decisions", params={"limit": 99}, headers=auth)
            assert bad.status_code == 400 and bad.headers["content-type"] == "application/problem+json"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_every_open_webui_setting_of_the_chart_is_explained_in_the_lld():
    chart = (CHART / "templates" / "chat.yaml").read_text()
    names = set(re.findall(r"\{name: ([A-Z_]+), value:", chart)) | set(re.findall(r"export ([A-Z_]+)=", chart))
    lld = (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text()
    section = lld.split("### 16.4 Open WebUI: how it is locked", 1)[1].split("### 16.5", 1)[0]
    missing = sorted(n for n in names if f"`{n}`" not in section)
    assert names and not missing, missing


def test_an_endpoint_is_left_for_the_next_one_on_failures_only():
    from a2vm.llm.client import _endpoint_down

    req = httpx.Request("POST", "http://a.example/v1/chat/completions")
    for code, down in ((429, True), (500, True), (503, True), (400, False), (404, False), (422, False)):
        exc = httpx.HTTPStatusError("x", request=req, response=httpx.Response(code, request=req))
        assert _endpoint_down(exc) is down, code
    assert _endpoint_down(httpx.ConnectError("x", request=req)) and _endpoint_down(httpx.ReadTimeout("x", request=req))
    lld = (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text()
    section = lld.split("### 7.1 Several endpoints", 1)[1].split("## 8.", 1)[0]
    for needle in ("429 or 5xx", "Answer 4xx other than 429", "max_consecutive_errors", "Retried on the same endpoint"):
        assert needle in section, needle


def test_several_endpoints_go_through_a_gateway_that_is_documented_line_by_line():
    chart = (CHART / "templates" / "chat.yaml").read_text()
    gateway = chart.split("nginx.conf: |", 1)[1].split("---", 1)[0]
    for needle in (
        "max_fails=1",
        "proxy_next_upstream error timeout http_429 http_502 http_503 http_504 non_idempotent",
        "proxy_next_upstream_tries 0",
        "proxy_buffering off",
        "location / { return 404; }",
        "server_tokens off",
    ):
        assert needle in gateway, needle
    directives = set(
        re.findall(r"^\s*(proxy_[a-z_]+|upstream|server_tokens|log_format|max_fails|fail_timeout)\b", gateway, re.M)
    )
    directives |= {"max_fails", "fail_timeout"}
    lld = (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text()
    table = lld.split("### 16.5 LLM gateway of the chat", 1)[1].split("### 16.6", 1)[0]
    undocumented = sorted(
        d
        for d in directives
        - {"proxy_pass", "proxy_http_version", "proxy_set_header", "proxy_request_buffering", "proxy_temp_path"}
        if f"`{d}" not in table
    )
    assert not undocumented, undocumented
    assert 'include "a2vm-tenant.chatLlmUrl"' in chart and "{{- if $gateway }}" in chart
    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    assert "over http only" in helpers and "must share their path" in helpers
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["chat"]["llm"]["gateway"]["image"].startswith("nginx/nginx-unprivileged:")
