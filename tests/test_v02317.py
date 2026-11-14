# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.17: a Cyberwatch master behind a reverse proxy that asks for a client certificate.

Found in integration: httpx 0.28 does not send `cert=` when `verify` is a path, so the certificate
never left and the proxy answered 403 to everything; tests through a mock transport could not see
it. Here the client meets a real TLS server that requires a certificate of the test CA, and a test
keeps `cert=` and paths in `verify` out of NGVM's code (`ngvm.tls`)."""

from __future__ import annotations

import re
import ssl

import httpx
import pytest

from ngvm import tls

from . import test_v02314 as _mtls
from .conftest import ROOT

pki = _mtls.pki
mtls_server = _mtls.mtls_server


def _cfg(tmp_path, url, pki_dir=None, cert=True, **extra):
    from detect.cyberwatch import CyberwatchConfig

    (tmp_path / "ak").write_text("access")
    (tmp_path / "sk").write_text("secret")
    data = {"url": url, "access_key_file": str(tmp_path / "ak"), "secret_key_file": str(tmp_path / "sk"), **extra}
    if pki_dir is not None:
        data["ca_file"] = str(pki_dir / "ca.pem")
        if cert:
            data.update(cert_file=str(pki_dir / "client.pem"), key_file=str(pki_dir / "client.key"))
    return CyberwatchConfig.from_dict(data)


def test_the_client_certificate_reaches_a_real_tls_server(tmp_path, mtls_server, pki) -> None:
    from detect.cyberwatch import CyberwatchClient

    url, seen = mtls_server
    base = url.removesuffix("/v1")
    client = CyberwatchClient(_cfg(tmp_path, base, pki))  # ca_file AND the certificate: the case of the bug
    assert client.get("/api/v3/ping") == {"data": [{"id": "local-llm"}]}
    path, subject = seen[-1]
    assert path == "/api/v3/ping" and dict(x[0] for x in subject)["commonName"] == "ngvm-client"
    client.close()


def test_without_the_certificate_the_proxy_stops_it(tmp_path, mtls_server, pki) -> None:
    from detect.cyberwatch import CyberwatchClient, CyberwatchError

    base = mtls_server[0].removesuffix("/v1")
    client = CyberwatchClient(_cfg(tmp_path, base, pki, cert=False))
    with pytest.raises(CyberwatchError, match="not reached"):
        client.get("/api/v3/ping")


def test_the_certificate_and_its_key_go_together(tmp_path, pki) -> None:
    with pytest.raises(ValueError, match="cert_file` and `key_file` go together"):
        _cfg(tmp_path, "https://cbw.example.org", cert_file=str(pki / "client.pem"))
    with pytest.raises(ValueError):
        tls.verify(None, str(pki / "client.pem"), None)


def test_a_403_names_the_reverse_proxy(tmp_path) -> None:
    from detect.cyberwatch import CyberwatchClient, CyberwatchError

    t = httpx.MockTransport(lambda r: httpx.Response(403, text="<html>403 Forbidden</html>"))
    client = CyberwatchClient(_cfg(tmp_path, "https://cbw.example.org"), transport=t)
    with pytest.raises(CyberwatchError, match=r"reverse proxy .* client certificate \(cert_file, key_file\)"):
        client.get("/api/v3/ping")


def test_a_master_shared_without_groups_warns(tmp_path) -> None:
    from detect.cyberwatch import CyberwatchClient, fetch

    assets = [{"id": 1, "hostname": "web01", "groups": [{"name": "Customer A"}]},
              {"id": 2, "hostname": "db01", "groups": [{"name": "Customer B"}]}]  # fmt: skip

    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path.endswith("/servers"):
            return httpx.Response(200, json=assets if r.url.params.get("page") == "1" else [])
        i = int(r.url.path.rsplit("/", 1)[1])
        return httpx.Response(200, json={**assets[i - 1], "cve_announcements": []})

    lines: list[str] = []
    cfg = _cfg(tmp_path, "https://cbw.example.org")
    fetch(cfg, "lab", CyberwatchClient(cfg, transport=httpx.MockTransport(handler)), log=lines.append)
    assert any(ln.startswith("WARN cyberwatch: no `groups`") and "2 groups" in ln for ln in lines)
    lines.clear()
    cfg = _cfg(tmp_path, "https://cbw.example.org", groups=["Customer A"])
    fetch(cfg, "lab", CyberwatchClient(cfg, transport=httpx.MockTransport(handler)), log=lines.append)
    assert not any(ln.startswith("WARN") for ln in lines)


def test_a_push_too_big_says_why() -> None:
    from detect.intake.client import IntakeError, push

    t = httpx.MockTransport(lambda r: httpx.Response(413, json={"title": "body larger than 209715200 bytes"}))
    doc = {"source": "cyberwatch", "observations": [{}] * 442, "findings": [{}] * 3}
    with pytest.raises(IntakeError, match=r"source cyberwatch: 442 assets, 3 findings.*`groups` for cyberwatch"):
        push("https://detect.example.org", "lab", "t" * 32, doc, "lan", transport=t)


def test_gitlab_presents_its_certificate_in_the_context(pki) -> None:
    from ngvm.gitlab import _client_options

    env = {
        "CI_JOB_TOKEN": "x",
        "CI_SERVER_TLS_CA_FILE": str(pki / "ca.pem"),
        "CI_SERVER_TLS_CERT_FILE": str(pki / "client.pem"),
        "CI_SERVER_TLS_KEY_FILE": str(pki / "client.key"),
    }
    options = _client_options(env)
    assert isinstance(options["verify"], ssl.SSLContext) and "cert" not in options
    assert _client_options({"CI_JOB_TOKEN": "x"})["verify"] is True


def test_no_cert_and_no_path_in_verify_in_the_code() -> None:
    """The mix httpx 0.28 gets wrong: a CA path in `verify` beside a client certificate in `cert`."""
    offenders = []
    for pkg in ("ngvm", "detect", "verdict", "via", "dispatch"):
        for path in (ROOT / pkg / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for n, line in enumerate(text.splitlines(), 1):
                code = line.split("#", 1)[0]
                if re.search(r"[\s(,]cert=", code) or re.search(r"""\[["']cert["']\]\s*=""", code):
                    offenders.append(f"{path.relative_to(ROOT)}:{n}: cert=")
                if re.search(r"verify=[^,)]*\bor True", code) or re.search(r"""verify=["'/]""", code):
                    offenders.append(f"{path.relative_to(ROOT)}:{n}: a path in verify")
    assert offenders == [], "use ngvm.tls.verify(ca_file, cert_file, key_file):\n" + "\n".join(offenders)


def test_docs() -> None:
    doc = (ROOT / "docs/cyberwatch.md").read_text(encoding="utf-8")
    assert "Acceptable client certificate CA names" in doc and "cert_file: /etc/ngvm/collector/" in doc
    assert "**A master shared between several perimeters (customers, entities): `groups` is required.**" in doc
    assert "| Behind a reverse proxy |" in (ROOT / "docs/lld/vulnerability-detection.md").read_text(encoding="utf-8")


def test_release_recorded() -> None:
    assert "## v0.23.17 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[7-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
