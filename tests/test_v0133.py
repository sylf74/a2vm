# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.13.3: large detections (a retry answered before any validation, the gzip body stored as
received, longer waits) and one daily run at a time on the tenant's volume."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import logging
from pathlib import Path

import pytest

import detect.intake.client as client_module
from detect.agent import AgentError, load_config
from detect.intake.registry import digest, load_registry
from detect.intake.server import Problem, Service
from detect.intake.store import FileStore

from .test_intake import COLLECTORS, LAN, _document

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path):
    collectors = tmp_path / "collectors.yaml"
    collectors.write_text(COLLECTORS)
    digests = tmp_path / "digests"
    digests.write_text(f"lab-lan {digest(LAN)}\n")
    return Service(load_registry("lab", collectors, digests), FileStore(tmp_path / "store"))


def test_a_retry_is_answered_without_decompressing_or_validating(tmp_path, service, monkeypatch):
    doc = _document(tmp_path, generated_at=dt.datetime.now(dt.UTC))
    body = gzip.compress(json.dumps(doc).encode())
    first = service.push("lab", LAN, "run-1", body, True)

    def never(*args, **kwargs):
        raise AssertionError("a retry must not be validated again")

    monkeypatch.setattr("detect.intake.server.validate_detection", never)
    monkeypatch.setattr(service.store, "get", never)  # the receipt alone is read
    again = service.push("lab", LAN, "run-1", b"not even gzip", True)
    assert again["id"] == first["id"] and again["duplicate"] is True
    with pytest.raises(Problem) as p:
        service.push("lab", "stolen", "run-1", body, True)  # the key does not bypass the token
    assert p.value.status == 401


def test_the_gzip_body_is_stored_as_received(tmp_path, service):
    doc = _document(tmp_path, generated_at=dt.datetime.now(dt.UTC))
    body = gzip.compress(json.dumps(doc).encode(), 1)
    receipt = service.push("lab", LAN, "run-1", body, True)
    stored = tmp_path / "store" / "lab" / "trivy" / f"{receipt['id']}.json.gz"
    assert stored.read_bytes() == body
    assert service.store.get("lab", receipt["id"])[1] == doc


@pytest.mark.parametrize("extra", [b"trailing", gzip.compress(b"{}")])
def test_anything_after_the_gzip_stream_is_refused(tmp_path, service, extra):
    doc = _document(tmp_path, generated_at=dt.datetime.now(dt.UTC))
    with pytest.raises(Problem) as p:
        service.push("lab", LAN, "run-1", gzip.compress(json.dumps(doc).encode()) + extra, True)
    assert p.value.status == 400 and "one complete gzip stream" in p.value.detail
    truncated = gzip.compress(json.dumps(doc).encode())[:-8]
    with pytest.raises(Problem):
        service.push("lab", LAN, "run-2", truncated, True)


def test_an_accepted_push_logs_its_size_and_time(tmp_path, service, caplog):
    doc = _document(tmp_path, generated_at=dt.datetime.now(dt.UTC))
    raw = json.dumps(doc).encode()
    with caplog.at_level(logging.INFO, logger="detect.serve"):
        service.push("lab", LAN, "run-1", gzip.compress(raw), True)
    line = next(r.getMessage() for r in caplog.records if "duplicate=False" in r.getMessage())
    assert f"document={len(raw)} bytes" in line and "seconds=" in line


def test_clients_wait_ten_minutes_by_default_and_the_agent_can_say_otherwise(tmp_path, monkeypatch):
    seen = []
    real = client_module._client

    def spy(base_url, token, ca_file, transport, timeout=client_module.TIMEOUT):
        seen.append(timeout)
        return real(base_url, token, ca_file, transport, timeout)

    monkeypatch.setattr(client_module, "_client", spy)
    import httpx

    ok = httpx.MockTransport(lambda r: httpx.Response(202, json={"id": "x"}))
    client_module.push("http://detect", "lab", LAN, {"source": "trivy"}, "lab-lan", transport=ok)
    client_module.push("http://detect", "lab", LAN, {"source": "trivy"}, "lab-lan", transport=ok, timeout=30)
    assert seen == [600.0, 30]

    token = tmp_path / "token"
    token.write_text(LAN)
    base = f"collector: lab-lan\ntenant: lab\nservice: https://x\ntoken_file: {token}\n"
    base += "connectors: [{name: drop, type: file-import, source: trivy, folder: /x}]\n"
    cfg = tmp_path / "collector.yaml"
    cfg.write_text(base)
    assert load_config(cfg).timeout_seconds == 600.0
    cfg.write_text(base + "timeout_seconds: 900\n")
    assert load_config(cfg).timeout_seconds == 900.0
    cfg.write_text(base + "timeout_seconds: 0\n")
    with pytest.raises(AgentError, match="positive"):
        load_config(cfg)


def test_one_daily_run_at_a_time_on_the_volume():
    chart = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "cronjob-daily.yaml").read_text()
    collect = chart.split('{{- define "a2vm-tenant.step.collect" -}}', 1)[1].split("{{- end -}}", 1)[0]
    assert collect.index("mkdir /data/.a2vm-run") < collect.index("rm -rf /data/work/detect")
    assert "{{ .Values.daily.activeDeadlineSeconds }}" in collect  # an older lock is a killed run's
    assert 'echo "$HOSTNAME" > /data/.a2vm-run/pod' in collect
    owner = '"$(cat /data/.a2vm-run/pod 2>/dev/null)" = "$HOSTNAME"'
    publish = chart.split('{{- define "a2vm-tenant.step.publish" -}}', 1)[1].split("{{- end -}}", 1)[0]
    assert f"trap 'if [ {owner} ]; then rm -rf /data/.a2vm-run; fi' EXIT" in publish
    assert f'[ "$rc" -ne 0 ] && [ {owner} ]' in chart  # a failed step releases its own run's lock only
