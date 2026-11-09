# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.4: a corporate network (the relay of the public sources, the outgoing proxy, a tenant that
never reads the sources itself, images pushed to another registry) and the chat (the CVEs published
in a period, the watch's status, the applications table, the questions it must answer). Fixes: a
portal without data, a reporting database that refuses every run."""

from __future__ import annotations

import json
import re

import httpx
import pytest
import yaml

from a2vm.config import SourceSettings, describe_relay, load_settings
from a2vm.service import Problem
from via.intel.sources import RELAY_TOKEN_HEADER, SourceError, Sources

from .conftest import ROOT
from .test_v0220 import READ, _service
from .test_v0232 import CHAT, _tools


# -- the relay of the sources -------------------------------------------------------------------------
def _sources(tmp_path, handler, hosts=("www.cisa.gov", "raw.githubusercontent.com")):
    (tmp_path / "relay-token").write_text("relay-secret\n")
    settings = SourceSettings(
        cache_dir=str(tmp_path / "cache"), relay_url="https://relay.example.org", relay_hosts=list(hosts),
        relay_token_file=str(tmp_path / "relay-token"),
    )  # fmt: skip
    return Sources(settings, transport=httpx.MockTransport(handler))


def test_listed_hosts_go_through_the_relay_redirects_and_found_urls_included(tmp_path) -> None:
    seen: list[tuple[str, str | None, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get(RELAY_TOKEN_HEADER), request.headers["host"]))
        if request.url.path.endswith("/old"):  # an upstream redirect, absolute to the upstream
            return httpx.Response(301, headers={"Location": "https://www.cisa.gov/new?x=1"})
        return httpx.Response(200, json={"ok": True})

    src = _sources(tmp_path, handler)
    assert src._get_json("https://www.cisa.gov/old", 0) == {"ok": True}
    src.fetch_json("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json")
    src._get_json("https://api.first.org/data/v1/epss", 0, params={"cve": "CVE-2024-3094"})
    assert seen[0] == ("https://relay.example.org/www.cisa.gov/old", "relay-secret", "relay.example.org")
    assert seen[1][0] == "https://relay.example.org/www.cisa.gov/new?x=1"  # the redirect too
    assert seen[2][0].startswith("https://relay.example.org/raw.githubusercontent.com/CVEProject/")
    assert seen[3][0].startswith("https://api.first.org/") and seen[3][1] is None  # not listed: direct
    assert src.relay.routes == {
        "relay www.cisa.gov": 2,
        "relay raw.githubusercontent.com": 1,
        "direct api.first.org": 1,
    }
    src.close()


def test_credentials_never_go_through_the_relay(tmp_path) -> None:
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        return httpx.Response(200, json={})

    src = _sources(tmp_path, handler, hosts=("www.virustotal.com",))
    src._get_json("https://www.virustotal.com/api/v3/collections/x", 0, headers={"x-apikey": "k"})
    src._client.get("https://www.virustotal.com/x", headers={"Authorization": "Bearer t"})
    assert hosts == ["www.virustotal.com", "www.virustotal.com"]
    with pytest.raises(SourceError, match="https"):
        Sources(SourceSettings(relay_url="http://relay.example.org"))


def test_relay_settings_from_the_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("A2VM_RELAY_URL", "https://relay.example.org")
    monkeypatch.setenv("A2VM_RELAY_HOSTS", "www.cisa.gov, raw.githubusercontent.com;api.first.org")
    monkeypatch.setenv("A2VM_RELAY_TOKEN", "t")
    monkeypatch.setenv("A2VM_INTEL_FALLBACK", "false")
    settings = load_settings(ROOT / "config" / "settings.yaml")
    assert settings.sources.relay_hosts == ["www.cisa.gov", "raw.githubusercontent.com", "api.first.org"]
    assert settings.sources.intel_fallback is False
    line = describe_relay(settings)
    assert "relay.example.org" in line and "token set" in line and "t," not in line


def test_a_tenant_that_must_never_read_the_sources(tmp_path) -> None:
    from via.intel.collect import collect

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    settings = SourceSettings(cache_dir=str(tmp_path), intel_url="http://intel.example", intel_fallback=False)
    sources = Sources(settings, transport=httpx.MockTransport(down))
    (tmp_path / "t").write_text("token")
    settings.intel_token_file = str(tmp_path / "t")
    with pytest.raises(SourceError, match="not read"):
        collect(sources, ["CVE-2024-3094"])


def test_check_sources_says_the_route(tmp_path, capsys, monkeypatch) -> None:
    from via.alert.cli import main

    monkeypatch.setenv("A2VM_RELAY_URL", "https://relay.example.org")
    monkeypatch.setenv("A2VM_RELAY_HOSTS", "www.cisa.gov")
    config = ROOT / "config"
    main(["check-sources", "--settings", str(config / "settings.yaml"), "--sources",
          str(config / "watch-sources.yaml"), "--fixtures", str(ROOT / "tests" / "fixtures")])  # fmt: skip
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("relay: https://relay.example.org for www.cisa.gov, token NOT SET")


def test_the_relay_checks_everything_before_any_upstream() -> None:
    caddy = (ROOT / "deploy" / "relay" / "cloud-init.yaml.tftpl").read_text(encoding="utf-8")
    route = caddy[caddy.index("route {") :]
    first_upstream = route.index("handle_path")
    for check in ("respond @outside 403", "respond @notoken 401", "respond @credentials", "respond @apikey",
                  "respond @write 405"):  # fmt: skip
        assert route.index(check) < first_upstream, check
    assert "request_header -X-A2VM-Relay-Token" in route and "CONNECT" not in route
    variables = (ROOT / "deploy" / "relay" / "variables.tf").read_text(encoding="utf-8")
    assert "www.virustotal.com" not in variables  # an authenticated API is never a host of the relay


def test_the_chart_and_the_pipeline_carry_the_way_out() -> None:
    helpers = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
    common = helpers[helpers.index('define "a2vm-tenant.envCommon"') :]
    assert 'include "a2vm-tenant.outbound"' in common[: common.index("{{- end -}}")]
    for name in ("HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "A2VM_RELAY_URL", "A2VM_RELAY_TOKEN_FILE"):
        assert name in helpers
    intel = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "intel.yaml").read_text(encoding="utf-8")
    assert 'include "a2vm-tenant.outbound"' in intel and "relay-token" in intel
    values = yaml.safe_load((ROOT / "deploy" / "charts" / "a2vm-tenant" / "values.yaml").read_text(encoding="utf-8"))
    assert values["proxy"] == {"https": "", "noProxy": [], "ca": False} and values["relay"] == {"url": "", "hosts": []}
    assert values["daily"]["publishFailures"] == 3
    pipeline = (ROOT / "templates" / "client-pipeline.yml").read_text(encoding="utf-8")
    for var in ("A2VM_HTTPS_PROXY", "A2VM_NO_PROXY", "A2VM_PROXY_CA", "A2VM_RELAY_URL", "A2VM_RELAY_HOSTS",
                "A2VM_RELAY_TOKEN"):  # fmt: skip
        assert var in pipeline, var
    assert "$OUT -f" in pipeline


def test_images_pushed_to_another_registry() -> None:
    ci = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    job = ci["images"]
    assert all("$A2VM_PUSH_REGISTRY" in r["if"] for r in job["rules"])
    script = "\n".join(job["script"])
    for var in ("A2VM_PUSH_IMAGE", "A2VM_PUSH_USER", "A2VM_PUSH_PASSWORD", "A2VM_PYTHON_IMAGE", "$CI_REGISTRY_IMAGE"):
        assert var in script, var


# -- fixes ------------------------------------------------------------------------------------------
def test_dashboards_hold_no_list_that_an_empty_variable_breaks() -> None:
    for path in (ROOT / "verdict" / "src" / "verdict" / "restitution" / "grafana").glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"IN \(\$\{\w+:sqlstring\}\)", text), path.name  # IN () with no option is SQL error
        assert "'${snapshot}'::date" not in text, path.name


def test_publish_failures_end_the_daily_job_failed() -> None:
    daily = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "cronjob-daily.yaml").read_text(
        encoding="utf-8"
    )
    assert "/data/.publish-failures" in daily and ".Values.daily.publishFailures" in daily
    dispatch = daily[daily.index('define "a2vm-tenant.step.dispatch"') :]
    assert "exit 1" in dispatch[: dispatch.index("{{- end -}}")]


# -- the chat -----------------------------------------------------------------------------------------
def test_the_shared_service_lists_the_cves_of_a_period(tmp_path) -> None:
    service = _service(tmp_path)
    out = service.new_records(READ, {"since": "2099-10-05"})
    assert out["total"] == 3 and out["counts"] == {"new": 2, "updated": 1}
    assert [i["cve"] for i in out["items"]] == ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-10003"]
    assert out["items"][0]["at"] == "2099-10-10T04:00:00+00:00" and "cvss" in out["items"][0]
    assert out["oldest"] == "2099-10-01T04:00:00+00:00"
    assert service.new_records(READ, {"change": "new", "limit": "1"})["next_offset"] == 1
    assert service.new_records(READ, {"until": "2099-10-02"})["total"] == 1
    with pytest.raises(Problem):
        service.new_records(READ, {"limit": "500"})
    with pytest.raises(Problem):
        service.new_records("nope", {})


def test_list_new_cves_names_the_tenants_alerts(tmp_path) -> None:
    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.path, dict(request.url.params)))
        if request.url.host == "intel.example":
            at = "2099-10-10T04:00:00+00:00"
            items = [{"cve": "CVE-2099-10001", "change": "new", "at": at, "cvss": 9.8},
                     {"cve": "CVE-2099-10002", "change": "new", "at": at, "cvss": 5.0}]  # fmt: skip
            return httpx.Response(200, json={"total": 2, "counts": {"new": 2, "updated": 0}, "items": items})
        return httpx.Response(200, json={"items": [{"id": "a1", "cves": ["CVE-2099-10001"]}]})

    tools = _tools(tmp_path, handler, intel_url="http://intel.example", intel_token="t",
                   via_url="http://via.example", via_token="v")  # fmt: skip
    out = tools.call(CHAT, "/new-cves", {"since": "2099-10-09T18:00", "min_cvss": "5"})
    assert (
        asked[0][1] == "/v1/records/new" and asked[0][2]["since"] == "2099-10-09T16:00:00+00:00"
    )  # Paris, summer time
    assert [(i["cve"], i["alert"]) for i in out["items"]] == [("CVE-2099-10001", "a1"), ("CVE-2099-10002", None)]
    assert out["total"] == 2 and "cvelistV5" in out["source"]
    tools.close()
    with pytest.raises(Problem) as p:
        _tools(tmp_path, handler).call(CHAT, "/new-cves", {})
    assert p.value.status == 503


def test_the_watch_status_and_the_applications_through_the_chat(tmp_path) -> None:
    from a2vm import applications as apps
    from a2vm.service import TokenSet, digest
    from via.service.server import WatchService
    from via.service.store import WatchStore

    store = WatchStore(tmp_path / "store")
    digests = tmp_path / "digests"
    digests.write_text(f"read {digest(READ)}\n")
    svc = WatchService("lab", TokenSet.load(digests, {"run", "read"}), store)
    assert svc.get_status("lab", READ) == {"tenant": "lab", "state": "the watch has not run yet"}
    state = {"failures": {"cisco": 2, "kev": 0}, "saved_at": "2026-11-09T20:00:00+00:00", "delta_since": "x"}
    store.put_run("lab", json.dumps(state).encode(), [], {})
    status = svc.get_status("lab", READ)
    assert status["last_passage"] == "2026-11-09T20:00:00+00:00"
    assert status["failing_sources"] == [{"source": "cisco", "failed_passages_in_a_row": 2}]
    comps = [{"name": f"App {i}", "version": "1.0", "type": "win", "vendor": "V"} for i in range(3)]
    store.update_applications("lab", lambda t: apps.merge(t, apps.candidates([{"components": comps}]), "t"))
    page = svc.get_applications("lab", READ, {"q": "app", "limit": "2"})
    assert page["total"] == 3 and len(page["applications"]) == 2 and page["next_offset"] == 2


def test_the_questions_the_chat_must_answer() -> None:
    from verdict.service.tools import openapi

    spec = openapi("lab")
    tools = {op["operationId"]: op for path in spec["paths"].values() for op in path.values()}
    data = yaml.safe_load((ROOT / "tests" / "chat-questions.yaml").read_text(encoding="utf-8"))
    assert len(data["questions"]) >= 25
    for item in data["questions"]:
        if "missing" in item:
            continue
        op = tools.get(item["tool"])
        assert op is not None, item
        names = {p["name"] for p in op["parameters"]}
        assert set(item["params"]) <= names, item
        assert item["why"].lower() in (op["summary"] + op.get("description", "")).lower(), item
    rule = spec["info"]["description"]
    assert "When no tool covers a question, say so" in rule and "never answer that nothing exists" in rule
    assert "empty answer does not mean nothing was published" in tools["list_radar_events"]["summary"]


def test_release_recorded() -> None:
    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.4( \(current\))? \| A corporate network and the chat", hld, re.M)
    assert re.search(r"^\| v0\.23\.5( \(to confirm\))? \| D20: Cyberwatch", hld, re.M)
    assert "## v0.23.4 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (ROOT / "deploy" / "relay" / "README.md").exists()
    assert (ROOT / "docs" / "hld" / "proposals" / "intel-placement.md").exists()
    for f in ("a2vm", "via", "detect", "verdict", "dispatch"):
        assert re.search(r'^version = "0\.(23\.[4-9]|2[4-9]\.\d+)"', (ROOT / f / "pyproject.toml").read_text(), re.M)
