# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.14: an LLM behind mutual TLS.

The reverse proxy in front of a shared model may ask each client for a certificate. The triage
presents the tenant's own; the chat goes through the LLM gateway, which presents it for Open WebUI.
Tested against a local server that requires a client certificate signed by a test CA."""

from __future__ import annotations

import http.server
import json
import re
import ssl
import subprocess
import threading

import httpx
import pytest

from ngvm.config import LlmSettings, load_settings

from .conftest import ROOT


def _openssl(*args: str, cwd) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A test CA, a server certificate for localhost and a client certificate."""
    d = tmp_path_factory.mktemp("pki")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
             "-days", "2", "-subj", "/CN=NGVM test CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)  # fmt: skip
    (d / "server.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    (d / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
    for name in ("server", "client"):
        _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                 "-subj", f"/CN=ngvm-{name}", cwd=d)  # fmt: skip
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                 "-out", f"{name}.pem", "-days", "2", "-extfile", f"{name}.ext", cwd=d)  # fmt: skip
    return d


@pytest.fixture(scope="module")
def mtls_server(pki):
    """An OpenAI-like endpoint that refuses a client without a certificate of the test CA."""
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            seen.append((self.path, self.connection.getpeercert().get("subject")))
            self._send({"data": [{"id": "local-llm"}]})

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append((self.path, self.headers.get("Authorization")))
            self._send({"choices": [{"message": {"content": "OK"}}], "usage": {}})

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "server.pem", pki / "server.key")
    ctx.load_verify_locations(pki / "ca.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"https://localhost:{httpd.server_address[1]}/v1", seen
    httpd.shutdown()
    httpd.server_close()


def _settings(url, pki, cert=True, ca_file="") -> LlmSettings:
    return LlmSettings(
        enabled=True, base_url=url, model="local-llm", api_key_env="NGVM_TEST_LLM_KEY",
        client_cert_file=str(pki / "client.pem") if cert else "",
        client_key_file=str(pki / "client.key") if cert else "",
        ca_file=ca_file or str(pki / "ca.pem"),
    )  # fmt: skip


def test_the_triage_presents_its_certificate(mtls_server, pki, monkeypatch) -> None:
    from ngvm.llm.client import LlmClient

    url, seen = mtls_server
    monkeypatch.setenv("NGVM_TEST_LLM_KEY", "k" * 32)
    client = LlmClient(_settings(url, pki))
    r = client._client.get(f"{url}/models")
    assert r.json()["data"][0]["id"] == "local-llm"
    assert any(dict(x[0] for x in subject).get("commonName") == "ngvm-client" for _, subject in seen if subject)
    r = client._post({"model": "local-llm", "messages": [{"role": "user", "content": "OK?"}]})
    assert r.json()["choices"][0]["message"]["content"] == "OK"
    assert seen[-1] == ("/v1/chat/completions", "Bearer " + "k" * 32)  # the API key goes along


def test_without_the_certificate_the_server_refuses(mtls_server, pki) -> None:
    from ngvm.llm.client import LlmClient

    url, _ = mtls_server
    client = LlmClient(_settings(url, pki, cert=False))
    with pytest.raises(httpx.HTTPError):
        client._client.get(f"{url}/models")


def test_the_endpoint_is_checked_against_the_ca(mtls_server, pki, tmp_path) -> None:
    from ngvm.llm.client import LlmClient

    url, _ = mtls_server
    other = tmp_path / "other"
    other.mkdir()
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "o.key", "-out", "o.pem", "-days", "1",
             "-subj", "/CN=other", "-addext", "keyUsage=critical,keyCertSign", cwd=other)  # fmt: skip
    client = LlmClient(_settings(url, pki, ca_file=str(other / "o.pem")))
    with pytest.raises(httpx.HTTPError):  # not the CA of the endpoint: refused before any key is sent
        client._client.get(f"{url}/models")


def test_files_absent_or_empty_count_as_none(tmp_path, pki) -> None:
    empty = tmp_path / "empty"
    empty.write_text("")
    s = LlmSettings(client_cert_file=str(tmp_path / "missing"), client_key_file=str(empty), ca_file="")
    assert s.tls() == {}
    with pytest.raises(ValueError):
        LlmSettings(client_cert_file=str(pki / "client.pem"), client_key_file=str(empty)).tls()


def test_the_settings_read_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("NGVM_LLM_CLIENT_CERT_FILE", "/secrets/llm-client-cert")
    monkeypatch.setenv("NGVM_LLM_CLIENT_KEY_FILE", "/secrets/llm-client-key")
    monkeypatch.setenv("NGVM_LLM_CA_FILE", "/secrets/llm-ca")
    llm = load_settings(ROOT / "config" / "settings.yaml").llm
    assert (llm.client_cert_file, llm.client_key_file, llm.ca_file) == (
        "/secrets/llm-client-cert", "/secrets/llm-client-key", "/secrets/llm-ca",
    )  # fmt: skip
    assert llm.tls() == {}  # no such files here


# -- the chart and deploy-k8s -----------------------------------------------------------------------
CHART = ROOT / "deploy/charts/ngvm-tenant"


def test_the_daily_run_reads_the_secret_files() -> None:
    helpers = (CHART / "templates/_helpers.tpl").read_text()
    for var, key in (("NGVM_LLM_CLIENT_CERT_FILE", "llm-client-cert"), ("NGVM_LLM_CLIENT_KEY_FILE", "llm-client-key"),
                     ("NGVM_LLM_CA_FILE", "llm-ca")):  # fmt: skip
        assert f"- name: {var}\n  value: /secrets/{key}" in helpers
    pipeline = (ROOT / "templates/client-pipeline.yml").read_text()
    assert 'put llm-client-cert "${NGVM_LLM_CLIENT_CERT:-}"' in pipeline
    assert 'put llm-client-key "${NGVM_LLM_CLIENT_KEY:-}"' in pipeline
    assert 'put llm-ca "${NGVM_LLM_CA:-}"' in pipeline


def test_the_chat_goes_through_the_gateway() -> None:
    chat = (CHART / "templates/chat.yaml").read_text()
    helpers = (CHART / "templates/_helpers.tpl").read_text()
    assert "{{- $gateway := or (gt (len $chat.llm.endpoints) 1) $chat.llm.clientCert }}" in chat
    assert "{{- if or (gt (len $eps) 1) .Values.chat.llm.clientCert -}}" in helpers
    for line in ("proxy_pass https://llm;", "proxy_ssl_certificate /etc/ngvm-tls/llm-client-cert;",
                 "proxy_ssl_certificate_key /etc/ngvm-tls/llm-client-key;",
                 "proxy_ssl_trusted_certificate /etc/ngvm-tls/llm-ca;", "proxy_ssl_verify on;",
                 "proxy_ssl_server_name on;", "proxy_set_header Host {{ $h }};"):  # fmt: skip
        assert line in chat
    assert "- {key: llm-client-key, path: llm-client-key}" in chat and "fsGroup: 101" in chat
    assert '{{ if eq $u.scheme "https" }}443{{ else }}80{{ end }}' in chat
    assert (
        "chat.llm.clientCert: one endpoint only" in helpers
        and "chat.llm.clientCert: the endpoint must be https" in helpers
    )
    assert "clientCert: false" in (CHART / "values.yaml").read_text()


def test_deploy_k8s_sets_client_cert() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("chat_values", ROOT / "deploy/chat/chat_values.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = {"NGVM_CHAT_HOST": "chat.example.org", "NGVM_LLM_BASE_URL": "https://192.0.2.10/v1", "NGVM_LLM_MODEL": "m"}
    assert mod.values(env)["chat"]["llm"]["clientCert"] is False
    with_cert = mod.values({**env, "NGVM_LLM_CLIENT_CERT": "/builds/tmp/NGVM_LLM_CLIENT_CERT"})
    assert with_cert["chat"]["llm"]["clientCert"] is True
    assert with_cert["chat"]["llm"]["egress"] == [{"cidr": "192.0.2.10/32", "port": 443}]


def test_docs() -> None:
    llm = (ROOT / "docs/llm.md").read_text(encoding="utf-8")
    assert "## 5. An LLM behind mutual TLS (v0.23.14)" in llm and "NGVM_LLM_CLIENT_CERT" in llm
    assert "Mutual TLS (v0.23.14)" in (ROOT / "docs/lld/triage-prioritization.md").read_text(encoding="utf-8")


def test_release_recorded() -> None:
    assert "## v0.23.14 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (CHART / "Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[4-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
