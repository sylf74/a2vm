# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.5 (D20): Cyberwatch as a scanner, read only: its assets with their components and the CVEs
still open on each, as a detection of source cyberwatch."""

from __future__ import annotations

import re

import httpx
import pytest

from detect.cyberwatch import CyberwatchClient, CyberwatchConfig, CyberwatchError, fetch

from .conftest import ROOT

ASSETS = [
    {"id": 1, "hostname": "web01.lab.example", "groups": [{"name": "Prod"}]},
    {"id": 2, "hostname": "pc02", "groups": [{"name": "Desktops"}]},
    {"id": 3, "hostname": "", "groups": [{"name": "Prod"}]},
]
DETAILS = {
    1: {
        "addresses": ["192.0.2.10", "127.0.0.1", "web01.lab.example"],
        "os": {"name": "Rocky Linux 9.4", "key": "rocky_9"},
        "analyzed_at": "2026-11-09T06:00:00.000+01:00",
        "packages": [
            {"product": "openssh-server", "version": "8.7p1-38.el9", "type": "Packages::Rpm", "vendor": ""},
            {"product": "old", "version": "1", "type": "Packages::Rpm", "active": False},
        ],
        "cve_announcements": [
            {"cve_code": "CVE-2024-6387", "active": True, "level": "level_high"},
            {"cve_code": "CVE-2023-38408", "active": True, "fixed_at": "2026-01-01T00:00:00Z"},
            {"cve_code": "CVE-2024-1086", "active": True, "ignored": True},
            {"cve_code": "CVE-2023-48795", "active": False},
            {"cve_code": "not-a-cve", "active": True},
        ],
        "updates": [
            {
                "current": {"product": "openssh-server", "version": "8.7p1-38.el9", "type": "Packages::Rpm"},
                "target": {"product": "openssh-server", "version": "8.7p1-38.el9_4.1"},
                "cve_announcements": [{"cve_code": "CVE-2024-6387"}],
            }
        ],
    },
    2: {
        "addresses": [{"value": "192.0.2.20"}],
        "os": {"name": "Windows 11"},
        "updates": [
            {
                "current": {
                    "product": "Mozilla Firefox",
                    "version": "128.0",
                    "vendor": "Mozilla",
                    "type": "Packages::Msi",
                },
                "target": {"version": "131.0"},
                "cve_announcements": ["CVE-2024-9680"],
            },
        ],  # fmt: skip
        "cve_announcements": [{"cve_code": "CVE-2024-9680", "active": True, "level": "level_critical"}],
    },
    3: {},
}


class FakeMaster:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        self.calls.append((request.method, request.url.path, q))
        assert request.headers["authorization"].startswith("Basic ")
        if request.url.path == "/api/v3/vulnerabilities/servers":
            page, size = int(q["page"]), int(q["per_page"])
            return httpx.Response(200, json=ASSETS[(page - 1) * size : page * size])
        m = re.match(r"^/api/v3/vulnerabilities/servers/(\d+)$", request.url.path)
        if m:
            return httpx.Response(200, json=DETAILS[int(m[1])])
        return httpx.Response(404)


def _cfg(tmp_path, **extra):
    (tmp_path / "ak").write_text("access\n")
    (tmp_path / "sk").write_text("secret\n")
    return CyberwatchConfig.from_dict(
        {
            "url": "https://cyberwatch.example.org",
            "access_key_file": str(tmp_path / "ak"),
            "secret_key_file": str(tmp_path / "sk"),
            "page_size": 2,
            **extra,
        }  # fmt: skip
    )


def test_every_asset_with_its_components_and_open_cves(tmp_path) -> None:
    from ngvm.io import write_detection

    master = FakeMaster()
    cfg = _cfg(tmp_path)
    lines: list[str] = []
    d = fetch(cfg, "example-client", CyberwatchClient(cfg, transport=httpx.MockTransport(master)), log=lines.append)
    write_detection(tmp_path / "cbw.json", d)  # checked against the detection schema
    assert d.source == "cyberwatch" and d.skipped == {"asset without a name": 1}
    by = {o.ref: o for o in d.observations}
    web = by["server:1"]
    assert web.identifiers == {"fqdn": "web01.lab.example", "hostname": "web01", "ips": ["192.0.2.10"]}
    assert web.os == "Rocky Linux 9.4" and web.attributes == {"cyberwatch_groups": "Prod"}
    assert [c["name"] for c in web.components] == ["openssh-server"] and web.components[0]["type"] == "rpm"
    found = {(f.asset_ref, f.cve_id): f for f in d.findings}
    assert set(found) == {("server:1", "CVE-2024-6387"), ("server:2", "CVE-2024-9680")}  # fixed, ignored, inactive out
    ssh = found[("server:1", "CVE-2024-6387")].observations[0]
    assert (ssh.package, ssh.installed_version, ssh.fixed_version, ssh.source_severity) == (
        "openssh-server", "8.7p1-38.el9", "8.7p1-38.el9_4.1", "high",
    )  # fmt: skip
    pc = by["server:2"]
    assert pc.components[0]["vendor"] == "Mozilla" and pc.components[0]["type"] == "win"  # through the table
    assert all(m == "GET" for m, _, _ in master.calls)
    assert [q.get("page") for _, p, q in master.calls if p.endswith("/servers")] == ["1", "2"]
    assert lines[-1] == "cyberwatch: 2 assets, 2 open CVEs, components on 2"
    assert lines[0].startswith("WARN cyberwatch: no `groups`")  # two groups, no filter (v0.23.17)


def test_groups_and_ignored_cves(tmp_path) -> None:
    cfg = _cfg(tmp_path, groups=["Prod"], include_ignored=True)
    d = fetch(cfg, "t", CyberwatchClient(cfg, transport=httpx.MockTransport(FakeMaster())), log=print)
    assert [o.ref for o in d.observations] == ["server:1"] and d.skipped["asset outside the groups"] == 1
    assert {f.cve_id for f in d.findings} == {"CVE-2024-6387", "CVE-2024-1086"}


def test_read_only_and_clear_errors(tmp_path) -> None:
    cfg = _cfg(tmp_path)
    client = CyberwatchClient(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    with pytest.raises(CyberwatchError, match="refused: DELETE"):
        client.get("/api/v3/vulnerabilities/servers/1", method="DELETE")
    with pytest.raises(CyberwatchError, match="API keys"):
        client.get("/api/v3/vulnerabilities/servers")
    gone = CyberwatchClient(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(CyberwatchError, match="assets_path"):
        list(gone.assets())
    for bad, message in (({"url": "http://cbw.example.org"}, "https"), ({"page_size": 900}, "page_size"),
                         ({"asset_path": "/api/v3/x"}, "{id}"), ({"secret": 1}, "unknown")):  # fmt: skip
        with pytest.raises(ValueError, match=message):
            CyberwatchConfig.from_dict({"url": "https://cbw.example.org", "access_key_file": "a",
                                        "secret_key_file": "b", **bad})  # fmt: skip


def test_the_collector_reads_a_cyberwatch_connector_and_it_is_a_scan(tmp_path) -> None:
    from detect.agent import CyberwatchConnector, load_config
    from ngvm.profile import load_profile
    from verdict.assets.build import NOT_SCANS, build_inventory

    (tmp_path / "token").write_text("t")
    (tmp_path / "collector.yaml").write_text(
        "collector: lan\ntenant: lab\nservice: https://detect.example.org\n"
        f"token_file: {tmp_path / 'token'}\nconnectors:\n"
        "  - {name: cbw, type: cyberwatch, url: https://cbw.example.org, access_key_file: /a, secret_key_file: /b}\n"
    )
    (connector,) = load_config(tmp_path / "collector.yaml").connectors
    assert isinstance(connector, CyberwatchConnector)
    cfg = _cfg(tmp_path)
    d = fetch(cfg, "example-client", CyberwatchClient(cfg, transport=httpx.MockTransport(FakeMaster())), log=print)
    inv = build_inventory(load_profile(ROOT / "examples" / "example-client" / "client.yaml"), [d])
    (web,) = [a for a in inv.assets if a.name == "web01"]
    assert "cyberwatch" not in NOT_SCANS and "cyberwatch" in web.scans


def test_release_recorded() -> None:
    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.5( \(current\))? \| D20: Cyberwatch", hld, re.M)
    assert "## v0.23.5 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (ROOT / "docs" / "cyberwatch.md").exists()
    for f in ("ngvm", "via", "detect", "verdict", "dispatch"):
        text = (ROOT / f / "pyproject.toml").read_text()
        assert re.search(r'^version = "0\.(23\.([5-9]|[1-9]\d)|2[4-9]\.\d+)"', text, re.M)
