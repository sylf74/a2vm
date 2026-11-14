# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.1 (D20): Wazuh's software inventory as a source of components, read only, from the
indexer or from the manager's API."""

from __future__ import annotations

import json

import httpx
import pytest

from detect.wazuh import WazuhClient, WazuhConfig, WazuhError, distro_of, fetch, platform
from ngvm.models import AssetObservation

from .conftest import ROOT

SYSTEMS = [
    {"agent": {"id": "001", "name": "web01", "host": {"ip": "192.0.2.10"}},
     "host": {"hostname": "web01.lab.example",
              "os": {"name": "Rocky Linux", "platform": "rocky", "version": "9.4 (Blue Onyx)",
                     "major": "9", "minor": "4"}}},
    {"agent": {"id": "002", "name": "app01", "host": {"ip": "192.0.2.11"}},
     "host": {"hostname": "app01", "os": {"name": "Ubuntu", "version": "22.04.4 LTS (Jammy Jellyfish)",
                                           "major": "22", "minor": "04"}}},
    {"agent": {"id": "003", "name": "pc01", "host": {"ip": "192.0.2.12"}},
     "host": {"hostname": "PC01", "os": {"name": "Microsoft Windows 11 Pro", "major": "10", "minor": "0"}}},
]  # fmt: skip
PACKAGES = [
    {"agent": {"id": "001"}, "package": {"name": "openssl-libs", "version": "1:3.0.7-27.el9", "architecture": "x86_64",
                                         "type": "rpm", "source": "openssl-3.0.7-27.el9.src.rpm"}},
    {"agent": {"id": "001"},
     "package": {"name": "bash", "version": "5.1.8-9.el9", "architecture": "x86_64", "type": "rpm"}},
    {"agent": {"id": "002"}, "package": {"name": "libssl3", "version": "3.0.2-0ubuntu1.15", "architecture": "amd64",
                                         "type": "deb", "source": "openssl"}},
    {"agent": {"id": "003"}, "package": {"name": "7-Zip 23.01 (x64)", "version": "23.01", "architecture": "x86_64",
                                         "type": "win", "vendor": "Igor Pavlov"}},
]  # fmt: skip


def _cfg(tmp_path, api="indexer", page_size=2):
    (tmp_path / "pw").write_text("secret\n")
    url = "https://wazuh.example.org:9200" if api == "indexer" else "https://wazuh.example.org:55000"
    return WazuhConfig.from_dict({"url": url, "user": "ngvm-inventory", "password_file": str(tmp_path / "pw"),
                                  "api": api, "page_size": page_size})  # fmt: skip


class FakeIndexer:
    """The _search and scroll API of OpenSearch over two index patterns, `page_size` per page."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.scrolls: dict[str, list[dict]] = {}
        self.cleared: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        assert request.headers["authorization"].startswith("Basic ")
        body = json.loads(request.content) if request.content else {}
        if request.method == "DELETE":
            self.cleared += body["scroll_id"]
            return httpx.Response(200, json={"succeeded": True})
        if request.url.path == "/_search/scroll":
            docs = self.scrolls[body["scroll_id"]]
        else:
            assert request.url.params["scroll"] == "2m"
            docs = list(SYSTEMS if "system" in request.url.path else PACKAGES)
            self.scrolls[request.url.path] = docs
            body["scroll_id"] = request.url.path
        size = 2
        page, rest = docs[:size], docs[size:]
        self.scrolls[body["scroll_id"]] = rest
        return httpx.Response(
            200, json={"_scroll_id": body["scroll_id"], "hits": {"hits": [{"_source": d} for d in page]}}
        )


def test_the_indexer_gives_every_agent_with_its_packages(tmp_path) -> None:
    fake = FakeIndexer()
    cfg = _cfg(tmp_path)
    lines = []
    det = fetch(cfg, "lab", WazuhClient(cfg, transport=httpx.MockTransport(fake)), log=lines.append)
    assert det.source == "wazuh" and det.findings == []
    by = {o.ref: o for o in det.observations}
    web = by["agent:001"]
    assert web.identifiers == {"fqdn": "web01.lab.example", "hostname": "web01", "ips": ["192.0.2.10"]}
    assert web.os == "rocky 9.4 (Blue Onyx)"
    ssl = next(c for c in web.components if c["name"] == "openssl-libs")
    assert ssl == {
        "name": "openssl-libs", "version": "1:3.0.7-27.el9", "arch": "x86_64", "type": "rpm",
        "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4&epoch=1",
        "source_package": "openssl", "distro": "rocky-9.4", "source": "wazuh",
    }  # fmt: skip
    app = by["agent:002"].components[0]
    assert (app["source_package"], app["distro"]) == ("openssl", "ubuntu-22.04")
    win = by["agent:003"].components[0]
    assert win["type"] == "win" and "distro" not in win and "purl" not in win
    assert by["agent:003"].name == "pc01"
    assert lines == ["wazuh: 3 agents, packages listed on 3 (indexer)"]
    assert sorted(fake.cleared) == [
        "/wazuh-states-inventory-packages-*/_search",
        "/wazuh-states-inventory-system-*/_search",
    ]
    assert {m for m, _ in fake.calls} <= {"POST", "DELETE"}


def test_the_manager_api_agent_by_agent(tmp_path) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/security/user/authenticate":
            assert request.method == "POST" and request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        assert request.method == "GET" and request.headers["authorization"] == "Bearer jwt"
        if request.url.path == "/agents":
            items = [
                {"id": "000", "name": "wazuh", "ip": "127.0.0.1", "status": "active",
                 "os": {"name": "Ubuntu", "platform": "ubuntu", "major": "24", "minor": "04"}},
                {"id": "004", "name": "db01", "ip": "192.0.2.13", "status": "disconnected",
                 "lastKeepAlive": "2026-11-01T03:00:00+00:00",
                 "os": {"name": "Debian GNU/Linux", "platform": "debian", "major": "12", "version": "12"}},
                {"id": "005", "name": "new01", "status": "never_connected"},
            ]  # fmt: skip
            offset = int(request.url.params["offset"])
            return httpx.Response(
                200, json={"data": {"affected_items": items[offset : offset + 2], "total_affected_items": 3}}
            )
        if request.url.path == "/syscollector/004/packages":
            return httpx.Response(200, json={"data": {"affected_items": [
                {"name": "libssl3", "version": "3.0.11-1~deb12u2", "architecture": "amd64", "format": "deb",
                 "source": "openssl"}
            ], "total_affected_items": 1}})  # fmt: skip
        return httpx.Response(200, json={"data": {"affected_items": [], "total_affected_items": 0}})

    cfg = _cfg(tmp_path, api="manager")
    det = fetch(cfg, "lab", WazuhClient(cfg, transport=httpx.MockTransport(handler)), log=lambda line: None)
    by = {o.ref: o for o in det.observations}
    assert set(by) == {"agent:000", "agent:004"}  # never connected: no inventory
    db = by["agent:004"]
    assert db.observed_at == "2026-11-01T03:00:00+00:00"  # its last keep-alive: the age of its inventory
    assert db.components[0]["distro"] == "debian-12" and db.components[0]["source_package"] == "openssl"
    assert "ips" not in by["agent:000"].identifiers  # loopback
    assert det.skipped == {"agent without packages": 1}
    assert calls.count(("POST", "/security/user/authenticate")) == 1


def test_nothing_but_reads_leaves(tmp_path) -> None:
    sent = []
    cfg = _cfg(tmp_path)
    client = WazuhClient(cfg, transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})))
    index = "/wazuh-states-inventory-packages-x"
    for method, path in (("PUT", index), ("DELETE", index), ("POST", "/_bulk"), ("GET", "/_cat/indices")):
        with pytest.raises(WazuhError, match="read only"):
            client._request(method, path)
    manager = WazuhClient(_cfg(tmp_path, api="manager"), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(WazuhError, match="read only"):
        manager._request("PUT", "/agents/restart")
    assert sent == []


def test_errors_say_what_to_do(tmp_path) -> None:
    cfg = _cfg(tmp_path)
    missing = WazuhClient(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(404, json={})))
    with pytest.raises(WazuhError, match="api: manager reads every 4.x version"):
        fetch(cfg, "lab", missing, log=lambda line: None)
    refused = WazuhClient(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(401, json={})))
    with pytest.raises(WazuhError, match="refused the user 'ngvm-inventory'"):
        fetch(cfg, "lab", refused, log=lambda line: None)
    with pytest.raises(ValueError, match="indexer .* or manager"):
        WazuhConfig.from_dict({"url": "https://w.example.org", "user": "u", "password_file": "f", "api": "x"})


def test_platforms_and_distributions() -> None:
    assert platform("Rocky Linux") == "rocky" and platform("Red Hat Enterprise Linux") == "rhel"
    assert platform("Debian GNU/Linux") == "debian" and platform("Microsoft Windows 11") == ""
    assert distro_of({"name": "AlmaLinux", "major": "9", "minor": "5"}) == "almalinux-9.5"
    assert distro_of({"name": "Debian GNU/Linux", "major": "12"}) == "debian-12"
    assert distro_of({"name": "Microsoft Windows 11", "major": "10"}) == ""


def test_the_collector_reads_a_wazuh_connector(tmp_path) -> None:
    from detect.agent import AgentError, WazuhConnector, load_config

    conf = tmp_path / "collector.yaml"
    base = "collector: lab-lan\ntenant: lab\nservice: https://detect.example.org\ntoken_file: /t\nconnectors:\n"
    conf.write_text(
        base + "  - {name: edr, type: wazuh, url: 'https://w.example.org:9200', user: u, password_file: /p}\n"
    )
    (connector,) = load_config(conf).connectors
    assert isinstance(connector, WazuhConnector) and connector.config.api == "indexer"
    conf.write_text(base + "  - {name: edr, type: wazuh, url: 'https://w.example.org', user: u}\n")
    with pytest.raises(AgentError, match="password_file"):
        load_config(conf)


def test_wazuh_and_ssh_components_meet_on_one_host(tmp_path) -> None:
    from ngvm.io import Detection, write_detection
    from ngvm.profile import load_profile
    from verdict.assets.build import build_inventory

    cfg = _cfg(tmp_path)
    wazuh = fetch(cfg, "example-client", WazuhClient(cfg, transport=httpx.MockTransport(FakeIndexer())), log=print)
    write_detection(tmp_path / "wazuh.json", wazuh)  # schema-checked
    ssh = AssetObservation(
        ref="web01.lab.example", kind="host", source="trivy", observed_at="2026-11-06T06:00:00+00:00", name="web01",
        identifiers={"hostname": "web01", "fqdn": "web01.lab.example"},
        components=[{"name": "bash", "version": "5.1.8-9.el9", "type": "rpm", "source": "ssh"}],
    )  # fmt: skip
    profile = load_profile(ROOT / "examples" / "example-client" / "client.yaml")
    inv = build_inventory(profile, [Detection(profile.id, "trivy", [ssh], []), wazuh])
    (asset,) = [a for a in inv.assets if a.name == "web01"]
    assert {c["source"] for c in asset.components} == {"ssh", "wazuh"}
    assert "wazuh" in asset.sources and "wazuh" not in asset.scans  # an inventory, not a scan


def test_the_watch_names_a_host_seen_by_wazuh(settings, sources, profile) -> None:
    from detect.inventory import InventoryScanner
    from via.alert.fiche import concerned_rows
    from via.alert.inventory import Inventory
    from via.alert.watch import Item, relevant

    from .test_v0230 import CVE, _asset

    comps = [{"name": "openssl-libs", "version": "1:1.1.1g-15.el8_3", "type": "rpm", "source_package": "openssl",
              "distro": "rocky-8.4", "source": "wazuh", "seen": "2026-11-07T04:00:00+00:00"}]  # fmt: skip
    inv = Inventory(profile.id, {"host:web01": _asset("host:web01", "web01", comps)}, {}, "2026-11-07T05:00:00+00:00")
    profile.alerts["level"] = "all"
    item = Item(f"CVE:{CVE}", "cve", CVE, [CVE], "")
    [alert] = relevant([item], profile, sources, settings, InventoryScanner(settings), inventory=inv)
    (row,) = [r for r in concerned_rows(alert, "CVE", "en")[0] if r["nom"] == "web01"]
    assert row["preuve"] == "exposed" and row["source"] == "packages listed (wazuh, 2026-11-07)"


def test_release_recorded() -> None:
    import re

    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.1( \(current\))? \| D20: Wazuh", hld, re.M)
    assert re.search(r"^\| v0\.23\.[2-9]( \(to confirm\)| \(current\))? \| D20: SentinelOne", hld, re.M)
    assert "## v0.23.1 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (ROOT / "docs" / "wazuh.md").exists()
