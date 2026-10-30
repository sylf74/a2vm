# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.16.0: the watch on Kubernetes. The watch service of the tenant (`via serve`) keeps the state,
the last inventory, the alerts and their journal; the watch, the send and the daily run use it."""

from __future__ import annotations

import gzip
import json
import threading
from pathlib import Path

import pytest
import yaml

from a2vm.service import Problem, TokenSet, digest
from via.alert.watch import State
from via.cli import main
from via.service.server import WatchService, serve
from via.service.store import WatchStore

from .conftest import FIXTURES, ROOT
from .test_alert import PROFILE, _inventory

RUN, READ = "run-token-0123456789abcdef0123456789", "read-token-0123456789abcdef012345678"
TENANT = "example-client"


@pytest.fixture
def service(tmp_path):
    digests = tmp_path / "digests"
    digests.write_text(f"run {digest(RUN)}\nread {digest(READ)}\n")
    svc = WatchService(TENANT, TokenSet.load(digests, {"run", "read"}), WatchStore(tmp_path / "store"))
    httpd = serve(svc, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    token = tmp_path / "run-token"
    token.write_text(RUN)
    yield svc, f"http://127.0.0.1:{httpd.server_address[1]}", token
    httpd.shutdown()
    httpd.server_close()


def _service(url, token, job, *extra):
    return main(["service", job, "--url", url, "--tenant", TENANT, "--token-file", str(token), *extra])


def _watch(url, token, profile=PROFILE):
    settings = ["--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm", "--fixtures", str(FIXTURES)]
    return _service(url, token, "watch", profile, *settings, "--contacts", "none.yaml")


def test_the_watch_runs_from_the_service_and_names_the_inventory(service, tmp_path, monkeypatch):
    import datetime as dt

    svc, url, token = service
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    seen = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    _inventory(tmp_path / "inv", TENANT, "CVE-2099-10001", seen)
    assert _service(url, token, "push-inventory", "--assets-dir", str(tmp_path / "inv" / TENANT)) == 0

    assert _watch(url, token) == 0  # first passage: the baseline, kept by the service
    assert svc.store.state(TENANT) is not None and svc.store.alerts(TENANT) == []
    state_path = svc.store.root / TENANT / "state.json"
    state = State.load(state_path)
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.save()

    assert _watch(url, token) == 0
    alerts = svc.store.alerts(TENANT)
    assert alerts and all(a["status"] == "pending" for a in alerts)
    inv = next(
        a for a in alerts if any("CVE-2099-10001" in c for c in a.get("cves") or []) or "CVE-2099-10001" in a["id"]
    )
    sheet = svc.get_alert(TENANT, READ, inv["id"])["sheet"]
    assert "web01" in sheet  # the inventory of the daily run reached the watch
    assert [e["event"] for e in svc.store.events(TENANT)].count("drafted") == len(alerts)
    page = svc.list_alerts(TENANT, READ, {"status": "pending"})
    assert page["total"] == len(alerts) and set(page["items"][0]) >= {"id", "level", "title", "status", "run"}


def test_the_validated_alert_is_sent_once_and_journaled(service, tmp_path, monkeypatch):
    svc, url, token = service
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    monkeypatch.delenv("A2VM_SMTP_HOST", raising=False)
    monkeypatch.delenv("A2VM_SEND_ONLY", raising=False)
    assert _watch(url, token) == 0
    state = State.load(svc.store.root / TENANT / "state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.save()
    assert _watch(url, token) == 0
    first = svc.store.alerts(TENANT)[0]

    data = yaml.safe_load(Path(PROFILE).read_text())
    data.setdefault("alerts", {})["recipients"] = ["it@example.org"]
    profile = tmp_path / "client.yaml"
    profile.write_text(yaml.safe_dump(data, allow_unicode=True))
    assert _service(url, token, "send", str(profile), "--only", first["id"], "--contacts", "none.yaml") == 0
    assert svc.store.alert(TENANT, first["id"])["status"] == "sent"
    sent = [e for e in svc.store.events(TENANT) if e["event"] == "sent"]
    assert [e["alert"] for e in sent] == [first["id"]] and sent[0]["to"] == ["it@example.org"]

    assert _service(url, token, "send", str(profile), "--only", first["id"]) == 1  # never twice by mistake
    assert _service(url, token, "send", str(profile), "--only", "no-such-alert") == 1


def test_the_link_in_the_analysts_mail_opens_a_prefilled_pipeline(monkeypatch):
    from via.alert.cli import _send_link

    monkeypatch.delenv("A2VM_SEND_PIPELINE_URL", raising=False)
    assert _send_link("a1") == ""
    monkeypatch.setenv("A2VM_SEND_PIPELINE_URL", "https://gitlab.example.org/vulnops/clients/lab/-/pipelines/new")
    link = _send_link("lab-CERTFR-2026-ALE-001")
    assert "pipelines/new?ref=main&var[A2VM_JOB]=send&var[A2VM_SEND_ONLY]=lab-CERTFR-2026-ALE-001" in link


def test_roles_and_refusals(service, tmp_path):
    svc, _, _ = service
    with pytest.raises(Problem) as p:
        svc.get_state(TENANT, READ)  # readers see alerts, not the state nor the files to send
    assert p.value.status == 401
    with pytest.raises(Problem) as p:
        svc.list_alerts("other", READ, {})
    assert p.value.status == 404
    with pytest.raises(Problem) as p:
        svc.get_state(TENANT, RUN)
    assert p.value.status == 404 and "baseline" in p.value.detail
    bad = {"state": {}, "events": [], "files": {"index.json": "W3siaWQiOiAiYTEifV0="}}  # [{"id": "a1"}], no sheet
    with pytest.raises(Problem) as p:
        svc.put_run(TENANT, RUN, gzip.compress(json.dumps(bad).encode()), True)
    assert p.value.status == 422 and "missing" in p.value.detail
    with pytest.raises(Problem) as p:
        svc.put_run(
            TENANT, RUN, json.dumps({"state": {}, "events": [{"event": "deleted", "alert": "a1"}]}).encode(), False
        )
    assert p.value.status == 422
    with pytest.raises(Problem) as p:
        svc.put_inventory(TENANT, RUN, json.dumps({"assets": {"schema": "x"}, "findings": {}}).encode(), False)
    assert p.value.status == 422
    with pytest.raises(Problem) as p:
        svc.list_alerts(TENANT, READ, {"status": "lost"})
    assert p.value.status == 400


# -- the pipeline, the chart, the deploy job ---------------------------------------------------------
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"


def _pipeline() -> dict:
    return yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())


def test_kubernetes_mode_turns_the_scheduled_pipelines_off():
    pipeline = _pipeline()
    assert pipeline["variables"]["A2VM_RUN_MODE"] == "gitlab"
    for job in (".data", "watch", "send-alerts"):
        rules = pipeline[job]["rules"]
        assert any(r.get("if") == '$A2VM_RUN_MODE == "kubernetes"' and r.get("when") == "never" for r in rules), job
    send = pipeline["send-alerts-k8s"]
    assert send["rules"][0]["if"].startswith('$A2VM_RUN_MODE == "kubernetes" && $A2VM_JOB == "send"')
    script = "\n".join(send["script"])
    assert "tr -cd 'A-Za-z0-9._ -'" in script  # what the analyst types never reaches a shell unfiltered
    assert "helm get values a2vm" in script and "--show-only templates/watch.yaml" in script
    assert "--from-file=edits/" in script
    for job in ("validate", "deploy-k8s"):
        assert '$A2VM_JOB == "send"' in pipeline[job]["rules"][0]["if"], job
    assert "A2VM_RUN_MODE=kubernetes needs A2VM_K8S_CONTEXT" in "\n".join(pipeline["validate"]["script"])


def test_deploy_job_deploys_the_watch_with_its_tokens_and_files():
    script = "\n".join(_pipeline()["deploy-k8s"]["script"])
    block = next(s for s in _pipeline()["deploy-k8s"]["script"] if 'WATCH=""' in s)
    assert 'if [ "$A2VM_RUN_MODE" = "kubernetes" ]' in block
    assert "create secret generic a2vm-via" in block and "a2vm-alert-template" in block
    assert "--set-file files.contacts=contacts.yaml" in block and "pipelines/new" in block
    for key in ("via-run-token", "via-read-token", "smtp-password", "graph-client-secret"):
        assert f"put {key} " in script, key
    assert "$CHAT $WATCH" in script and "A2VM_ANALYST_TO" in script


def test_chart_runs_the_watch_beside_a_closed_service():
    text = (CHART / "templates" / "watch.yaml").read_text()
    for needle in (
        "{{- if .Values.watch.enabled }}",
        'command: ["via", "serve"]',
        "via service watch",
        "via service send",
        "concurrencyPolicy: Forbid",
        "readOnlyRootFilesystem: true",
        "helm.sh/resource-policy: keep",
        "egress: []",
        'regexReplaceAll "[^A-Za-z0-9._ -]"',
        "ttlSecondsAfterFinished",
    ):
        assert needle in text, needle
    daily = (CHART / "templates" / "cronjob-daily.yaml").read_text()
    assert "via service push-inventory" in daily and '"name" "inventory" "pillar" "via"' in daily
    chat = (CHART / "templates" / "chat.yaml").read_text()
    assert "--via-token-file=/secrets/via-read-token" in chat
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["watch"]["enabled"] is False and values["watch"]["schedule"] == "*/10 * * * *"


def test_the_chat_reads_the_alerts_of_the_watch(service, monkeypatch):
    from verdict.service.tools import Tools

    svc, url, token = service
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    assert _watch(url, token) == 0
    state = State.load(svc.store.root / TENANT / "state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.save()
    assert _watch(url, token) == 0
    chat = "chat-token-0123456789abcdef0123456789"
    digests = svc.store.root / "chat-digests"
    digests.write_text(f"chat {digest(chat)}\n")
    tools = Tools(TENANT, TokenSet.load(digests, {"chat"}), "http://127.0.0.1:9", "unused", via_url=url, via_token=READ)
    page = tools.call(chat, "/alerts", {"status": "pending"})
    assert page["total"] >= 1 and page["items"][0]["status"] == "pending"
    one = tools.call(chat, f"/alerts/{page['items'][0]['id']}", {})
    assert one["sheet"].startswith("#") and "source" in one
    without = Tools(TENANT, TokenSet.load(digests, {"chat"}), "http://127.0.0.1:9", "unused")
    with pytest.raises(Problem) as p:
        without.call(chat, "/alerts", {})
    assert p.value.status == 503
    tools.close()
    without.close()


def test_contract_names_the_calls_the_service_answers():
    from .test_detect_api_contract import _refs

    spec_path = ROOT / "a2vm" / "src" / "a2vm" / "schemas" / "openapi" / "via.v1.yaml"
    spec = yaml.safe_load(spec_path.read_text())
    assert spec["openapi"].startswith("3.1")
    for ref in _refs(spec):
        if not ref.startswith("#/"):
            assert (spec_path.parent / ref).resolve().exists(), ref
    assert set(spec["paths"]) == {
        "/v1/tenants/{tenant}/inventory",
        "/v1/tenants/{tenant}/inventory/{file}",
        "/v1/tenants/{tenant}/watch/state",
        "/v1/tenants/{tenant}/watch/runs",
        "/v1/tenants/{tenant}/events",
        "/v1/tenants/{tenant}/alerts",
        "/v1/tenants/{tenant}/alerts/{alert}",
        "/v1/tenants/{tenant}/alerts/{alert}/edit",
        "/v1/tenants/{tenant}/alerts/{alert}/translations",
        "/v1/tenants/{tenant}/alerts/{alert}/translations/{language}",
        "/v1/tenants/{tenant}/alerts/{alert}/files/{file}",
        "/healthz",
        "/readyz",
    }
    for path, item in spec["paths"].items():
        for op in item.values():
            if path.startswith("/v1/tenants/{tenant}"):
                assert {"$ref": "#/components/parameters/tenant"} in op["parameters"] and op["security"], path
