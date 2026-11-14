# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.3 (D20): SentinelOne's application inventory as a source of components, read only; the
tenant's applications table (the LLM proposes the CPE of each application, a validator decides); the
watch names the hosts of an application through it. Dispatch: a caller looked for in one
organisation, the requested tickets left proposed sent again."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from detect.sentinelone import SentinelOneClient, SentinelOneConfig, SentinelOneError, fetch
from ngvm import applications as apps
from ngvm.models import AffectedEntry, VulnRecord

from .conftest import ROOT

AGENTS = [
    {"id": "101", "computerName": "PC01", "domain": "lab.example", "osName": "Windows 11 Pro", "osRevision": "22631",
     "osType": "windows", "isActive": True, "networkInterfaces": [{"inet": ["192.0.2.21", "127.0.0.1"]}]},
    {"id": "102", "computerName": "srv02", "domain": "EXAMPLE", "osName": "Windows Server 2022", "osType": "windows",
     "isActive": False, "lastActiveDate": "2026-11-01T08:00:00Z", "networkInterfaces": [{"inet": ["192.0.2.22"]}]},
    {"id": "103", "computerName": "", "osType": "linux"},
]  # fmt: skip
APPS = {
    "101": [{"name": "Mozilla Firefox (x64 fr)", "version": "128.0", "publisher": "Mozilla"},
            {"name": "7-Zip 23.01 (x64)", "version": "23.01", "publisher": "Igor Pavlov"}],
    "102": [{"name": "Mozilla Firefox (x64 en-US)", "version": "131.0.2", "publisher": "Mozilla"}],
}  # fmt: skip


class FakeConsole:
    """The agents and applications lists of the management console, two items per page."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    @staticmethod
    def _page(items, cursor):
        start = int(cursor or 0)
        nxt = str(start + 2) if start + 2 < len(items) else None
        return {"data": items[start : start + 2], "pagination": {"nextCursor": nxt, "totalItems": len(items)}}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        self.calls.append((request.method, request.url.path, q))
        assert request.headers["authorization"] == "ApiToken s1-token"
        path = request.url.path.removeprefix("/web/api/v2.1")
        if path == "/agents":
            return httpx.Response(200, json=self._page(AGENTS, q.get("cursor")))
        if path == "/agents/applications":
            return httpx.Response(200, json={"data": APPS.get(q["ids"], [])})
        if path == "/installed-applications":
            rows = [{**a, "agentId": aid} for aid, items in APPS.items() for a in items]
            return httpx.Response(200, json=self._page(rows, q.get("cursor")))
        return httpx.Response(404)


def _cfg(tmp_path, **extra):
    (tmp_path / "token").write_text("s1-token\n")
    return SentinelOneConfig.from_dict(
        {"url": "https://console.example.org", "token_file": str(tmp_path / "token"), "page_size": 2, **extra}
    )


@pytest.mark.parametrize("api", ["agents", "installed-applications"])
def test_every_agent_with_its_applications(tmp_path, api) -> None:
    from ngvm.io import write_detection

    console = FakeConsole()
    cfg = _cfg(tmp_path, api=api, site_ids=["555"])
    lines: list[str] = []
    d = fetch(cfg, "example-client", SentinelOneClient(cfg, transport=httpx.MockTransport(console)), log=lines.append)
    write_detection(tmp_path / "s1.json", d)  # checked against the detection schema
    assert d.source == "sentinelone" and d.findings == []
    by = {o.ref: o for o in d.observations}
    assert set(by) == {"agent:101", "agent:102"} and d.skipped == {"agent without a name": 1}
    pc = by["agent:101"]
    assert pc.name == "pc01" and pc.identifiers["fqdn"] == "pc01.lab.example"
    assert pc.identifiers == {"hostname": "pc01", "fqdn": "pc01.lab.example", "ips": ["192.0.2.21"]}
    assert pc.os == "Windows 11 Pro 22631"
    firefox = next(c for c in pc.components if c["name"].startswith("Mozilla"))
    name = "Mozilla Firefox (x64 fr)"
    assert firefox == {"name": name, "version": "128.0", "arch": "", "type": "win", "source_package": name,
                       "vendor": "Mozilla", "source": "sentinelone"}  # fmt: skip
    srv = by["agent:102"]
    assert "fqdn" not in srv.identifiers and srv.observed_at == "2026-11-01T08:00:00Z"  # NetBIOS domain, inactive
    assert all(m == "GET" for m, _, _ in console.calls)
    listed = [q for _, p, q in console.calls if p.endswith(("/agents", "/installed-applications"))]
    assert listed and all(q.get("siteIds") == "555" for q in listed)
    assert lines == [f"sentinelone: 2 agents, applications listed on 2 ({api})"]


def test_nothing_but_reads_and_errors_say_what_to_do(tmp_path) -> None:
    cfg = _cfg(tmp_path)
    client = SentinelOneClient(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    with pytest.raises(SentinelOneError, match="refused"):
        client.get("/agents", method="POST")
    with pytest.raises(SentinelOneError, match="Viewer role"):
        client.get("/agents")
    waits: list[float] = []
    answers = iter([httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200, json={"data": []})])
    busy = SentinelOneClient(cfg, transport=httpx.MockTransport(lambda r: next(answers)), sleep=waits.append)
    assert busy.get("/agents") == {"data": []} and waits == [3.0]
    for bad, message in (({"url": "http://console.example.org"}, "https"), ({"api": "threats"}, "api"),
                         ({"site_ids": ["x1"]}, "numeric"), ({"secret": 1}, "unknown")):  # fmt: skip
        with pytest.raises(ValueError, match=message):
            SentinelOneConfig.from_dict({"url": "https://console.example.org", "token_file": "t", **bad})


def test_the_collector_reads_a_sentinelone_connector(tmp_path) -> None:
    from detect.agent import SentinelOneConnector, load_config

    (tmp_path / "token").write_text("t")
    (tmp_path / "collector.yaml").write_text(
        "collector: lan\ntenant: lab\nservice: https://detect.example.org\n"
        f"token_file: {tmp_path / 'token'}\nconnectors:\n"
        "  - {name: s1, type: sentinelone, url: https://console.example.org, token_file: /etc/ngvm/collector/s1}\n"
    )
    (connector,) = load_config(tmp_path / "collector.yaml").connectors
    assert isinstance(connector, SentinelOneConnector) and connector.config.api == "agents"


def test_sentinelone_is_an_inventory_not_a_scan(tmp_path) -> None:
    from ngvm.profile import load_profile
    from verdict.assets.build import NOT_SCANS, build_inventory

    cfg = _cfg(tmp_path)
    d = fetch(cfg, "example-client", SentinelOneClient(cfg, transport=httpx.MockTransport(FakeConsole())), log=print)
    profile = load_profile(ROOT / "examples" / "example-client" / "client.yaml")
    inv = build_inventory(profile, [d])
    (pc,) = [a for a in inv.assets if a.name == "pc01"]
    assert "sentinelone" in NOT_SCANS and "sentinelone" in pc.sources and "sentinelone" not in pc.scans
    assert {c["vendor"] for c in pc.components} == {"Mozilla", "Igor Pavlov"}


# -- the applications table -------------------------------------------------------------------------
@pytest.mark.parametrize(
    "vendor, name, key",
    [
        ("Mozilla", "Mozilla Firefox (x64 fr)", "mozilla|mozilla firefox"),
        ("Igor Pavlov", "7-Zip 23.01 (x64)", "igor pavlov|7-zip"),
        ("Microsoft Corporation", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130",
         "microsoft|microsoft visual c++ 2015-2022 redistributable"),
        ("Oracle Corporation", "Java 8 Update 381 (64-bit)", "oracle|java 8"),
        ("Google LLC", "Google Chrome", "google|google chrome"),
    ],
)  # fmt: skip
def test_application_keys_leave_versions_and_architectures_out(vendor, name, key) -> None:
    assert apps.app_key(vendor, name) == key


def test_wazuh_windows_packages_keep_their_publisher() -> None:
    from detect.wazuh import _package

    win = _package({"name": "7-Zip 23.01 (x64)", "version": "23.01", "type": "win", "vendor": "Igor Pavlov"}, "")
    assert win["vendor"] == "Igor Pavlov" and "purl" not in win and apps.is_application(win)
    rpm = _package({"name": "bash", "version": "5.1", "type": "rpm", "vendor": "Rocky"}, "rocky-9.4")
    assert "vendor" not in rpm and not apps.is_application(rpm)


def _record(cve="CVE-2099-0001", versions=None, cpes=()):
    ranges = versions or [{"version": "0", "lessThan": "131.0", "status": "affected"}]
    entry = AffectedEntry("Mozilla", "Firefox", ranges, "unaffected", list(cpes), "cna")
    return VulnRecord(cve, "PUBLISHED", None, "", [], [], [entry], None, None, [])


def _table(state=apps.VALIDATED):
    found = apps.candidates([{"components": [{"name": "Mozilla Firefox (x64 fr)", "version": "128.0", "type": "win",
                                              "vendor": "Mozilla", "source": "sentinelone"}]}])  # fmt: skip
    table, added = apps.merge({}, found, "2026-11-09T08:00:00+00:00")
    assert added == 1 and table["mozilla|mozilla firefox"].state == apps.NEW
    if state != apps.NEW:
        apps.apply_proposals(table, [{"key": "mozilla|mozilla firefox", "cpe": "cpe:2.3:a:mozilla:firefox:*:*",
                                      "justification": "the browser", "by": "llm:test"}], "t")  # fmt: skip
    if state == apps.VALIDATED:
        apps.decide(table, "mozilla|mozilla firefox", "validate", "analyst@lab.example", "t")
    return table


def test_the_table_keeps_the_decision_of_an_analyst() -> None:
    table = _table()
    row = table["mozilla|mozilla firefox"]
    assert row.state == apps.VALIDATED and row.cpe == "cpe:2.3:a:mozilla:firefox" and row.decided_by
    assert apps.apply_proposals(table, [{"key": row.key, "cpe": "cpe:2.3:a:other:thing"}], "t") == 0  # untouched
    again, added = apps.merge(table, {}, "t2")
    assert added == 0 and again[row.key].hosts == 0 and again[row.key].cpe  # gone from the inventory, kept
    with pytest.raises(ValueError, match="CPE"):
        apps.decide(table, row.key, "validate", "a", "t", cpe="firefox")
    assert apps.decide(table, row.key, "reject", "a", "t", note="not used").state == apps.REJECTED
    assert apps.load_table(json.loads(json.dumps(apps.dump_table(table))))[row.key].note == "not used"


@pytest.mark.parametrize(
    "state, version, proof, reason",
    [
        (apps.VALIDATED, "128.0", "exposed", ""),
        (apps.VALIDATED, "131.0.2", None, ""),  # out of the range
        (apps.PROPOSED, "128.0", "possible", "mapping to validate"),
        (apps.NEW, "128.0", None, ""),
    ],
)
def test_matches_through_the_table(state, version, proof, reason) -> None:
    comps = [{"name": "Mozilla Firefox (x64 fr)", "version": version, "type": "win", "vendor": "Mozilla",
              "source": "sentinelone", "seen": "2026-11-09T07:00:00+00:00"}]  # fmt: skip
    hits = apps.matches(_record(), comps, _table(state))
    assert [(h.proof, h.reason) for h in hits] == ([(proof, reason)] if proof else [])
    if proof == "exposed":
        assert hits[0].exposure.fixed == "131.0" and hits[0].exposure.advisory == "cpe:2.3:a:mozilla:firefox"


def test_a_version_the_record_does_not_decide_is_possible() -> None:
    comps = [{"name": "Mozilla Firefox (x64 fr)", "version": "128.0", "type": "win", "vendor": "Mozilla"}]
    record = _record(versions=[{"version": "Fixed in 131 (all before)", "status": "affected"}])
    record.affected[0].default_status = "unknown"
    [hit] = apps.matches(record, comps, _table())
    assert (hit.proof, hit.reason) == ("possible", "version not decided")
    by_cpe = _record(cpes=["cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"])
    by_cpe.affected[0].vendor, by_cpe.affected[0].product = "Mozilla Corporation", "Mozilla Firefox"
    assert [h.proof for h in apps.matches(by_cpe, comps, _table())] == ["exposed"]


class _FakeLlm:
    model = "fake-model"

    def __init__(self):
        self.calls = []

    def structured(self, system, user, name, schema):
        self.calls.append((name, user))
        listing = json.loads(user.split("<untrusted>\n", 1)[1].split("\n</untrusted>", 1)[0])
        out = []
        for item in listing:
            if "Firefox" in item["name"]:
                out.append({"id": item["id"], "cpe_vendor": "mozilla", "cpe_product": "firefox", "justification": "x"})
            elif "Driver" in item["name"]:
                out.append({"id": item["id"], "cpe_vendor": "", "cpe_product": "", "justification": "a driver"})
            else:
                out.append({"id": item["id"], "cpe_vendor": "bad vendor:", "cpe_product": "x", "justification": "?"})
        return {"applications": out}


def test_the_llm_proposes_and_a_malformed_answer_is_no_proposal() -> None:
    rows = [apps.Row("mozilla|mozilla firefox", "Mozilla", "Mozilla Firefox (x64 fr)"),
            apps.Row("intel|intel graphics driver", "Intel", "Intel Graphics Driver"),
            apps.Row("x|weird", "X", "Weird")]  # fmt: skip
    llm = _FakeLlm()
    proposals, error = apps.propose(llm, rows, by="llm:fake-model")
    assert not error and llm.calls[0][0] == "application_cpes" and "<untrusted>" in llm.calls[0][1]
    assert {p["key"]: p["cpe"] for p in proposals} == {
        "mozilla|mozilla firefox": "cpe:2.3:a:mozilla:firefox",
        "intel|intel graphics driver": "",  # no product of CVE records
    }
    table = {r.key: r for r in rows}
    assert apps.apply_proposals(table, proposals, "t") == 2 and table["x|weird"].state == apps.NEW
    assert table["intel|intel graphics driver"].product() == ""  # proposed, but names nothing


def test_a_tenant_project_table_in_the_gitlab_mode(tmp_path, monkeypatch) -> None:
    from via.alert.cli import _applications

    monkeypatch.chdir(tmp_path)
    (tmp_path / "applications.yaml").write_text(
        "applications:\n"
        "  - {vendor: Mozilla, name: Mozilla Firefox, cpe: 'cpe:2.3:a:mozilla:firefox'}\n"
        "  - {vendor: Intel, name: Intel Graphics Driver}\n"
    )
    table = _applications("auto")
    assert table["mozilla|mozilla firefox"].state == apps.VALIDATED
    assert table["intel|intel graphics driver"].state == apps.REJECTED
    (tmp_path / "applications.yaml").write_text("applications:\n  - {name: X, cpe: firefox}\n")
    with pytest.raises(ValueError, match="cpe"):
        _applications("auto")


# -- the watch service and the watch ----------------------------------------------------------------
def _inventory_doc(profile_id="example-client"):
    asset = {
        "id": "host:pc01", "client_id": profile_id, "kind": "host", "name": "pc01", "description": "",
        "identifiers": {"hostname": "pc01"}, "attributes": {}, "sources": ["sentinelone"], "first_seen": "x",
        "last_seen": "2026-11-09T07:00:00+00:00",
        "components": [{"name": "Mozilla Firefox (x64 fr)", "version": "128.0", "type": "win", "vendor": "Mozilla",
                        "source": "sentinelone", "seen": "2026-11-09T07:00:00+00:00"}],
    }  # fmt: skip
    return asset


def test_the_service_fills_the_table_from_the_inventory(tmp_path, backend) -> None:
    from ngvm.service import Problem, TokenSet, digest
    from via.service.server import WatchService

    from .test_v0160 import RUN, TENANT, watch_store

    store = watch_store(tmp_path, backend)
    digests = tmp_path / "digests"
    digests.write_text(f"run {digest(RUN)}\n")
    svc = WatchService(TENANT, TokenSet.load(digests, {"run", "read"}), store)
    found = apps.candidates([_inventory_doc()])
    store.update_applications(TENANT, lambda t: apps.merge(t, found, "2026-11-09T08:00:00+00:00"))
    out = svc.get_applications(TENANT, RUN, {})
    assert out["counts"]["new"] == 1 and out["applications"][0]["key"] == "mozilla|mozilla firefox"
    body = json.dumps({"proposals": [{"key": "mozilla|mozilla firefox", "cpe": "cpe:2.3:a:mozilla:firefox"}]})
    assert svc.put_proposals(TENANT, RUN, body.encode(), False) == {"proposed": 1}
    assert svc.get_applications(TENANT, RUN, {"state": "proposed"})["counts"]["proposed"] == 1
    with pytest.raises(Problem):
        svc.get_applications(TENANT, RUN, {"state": "maybe"})
    row = store.update_applications(
        TENANT, lambda t: apps.decide(t, "mozilla|mozilla firefox", "validate", "v@lab.example", "t")
    )
    assert row.state == apps.VALIDATED and store.applications(TENANT)["mozilla|mozilla firefox"].cpe


def test_the_inventory_endpoint_records_the_applications(tmp_path) -> None:
    from ngvm.service import TokenSet, digest
    from via.service.server import WatchService
    from via.service.store import WatchStore

    from .test_alert import _inventory
    from .test_v0160 import RUN, TENANT

    digests = tmp_path / "digests"
    digests.write_text(f"run {digest(RUN)}\n")
    svc = WatchService(TENANT, TokenSet.load(digests, {"run"}), WatchStore(tmp_path / "store"))
    _inventory(tmp_path, TENANT, "CVE-2024-38476", "2026-11-09T07:00:00+00:00")
    assets = json.loads((tmp_path / TENANT / "assets.json").read_text())
    findings = json.loads((tmp_path / TENANT / "findings.json").read_text())
    assets["assets"][0]["components"] = _inventory_doc()["components"]
    meta = svc.put_inventory(TENANT, RUN, json.dumps({"assets": assets, "findings": findings}).encode(), False)
    assert meta["applications"] == {"seen": 1, "rows": 1, "new": 1}


def test_the_review_page_lets_a_validator_decide(tmp_path) -> None:
    from via.service.review import Denied, Review
    from via.service.store import WatchStore

    store = WatchStore(tmp_path / "store")
    store.update_applications("lab", lambda t: apps.merge(t, apps.candidates([_inventory_doc()]), "t"))
    review = Review("lab", store, b"k" * 32, {"readers"}, {"validators"}, "https://alerts-lab.example.org")
    reader = {"X-Forwarded-Email": "r@lab.example", "X-Forwarded-Groups": "readers"}
    page = review.applications_page("r@lab.example", False, "new")
    assert "Mozilla Firefox (x64 fr)" in page and "<form" not in page
    user = "v@lab.example"
    tok = review.token(user, "applications:mozilla|mozilla firefox")
    headers = {
        "X-Forwarded-Email": user,
        "X-Forwarded-Groups": "validators",
        "Origin": "https://alerts-lab.example.org",
    }
    form = {"key": ["mozilla|mozilla firefox"], "action": ["validate"], "cpe": ["cpe:2.3:a:mozilla:firefox"],
            "token": [tok], "note": [""]}  # fmt: skip
    assert "<form" in review.applications_page(user, True, "new")
    with pytest.raises(Denied):
        review.decide_application(user, {**form, "token": ["forged"]}, headers)
    review.decide_application(user, form, headers)
    row = store.applications("lab")["mozilla|mozilla firefox"]
    assert row.state == apps.VALIDATED and row.decided_by == user
    assert review.who(reader) == ("r@lab.example", False)


def test_the_watch_names_a_host_through_the_table(settings, sources, profile) -> None:
    from detect.inventory import InventoryScanner
    from via.alert.fiche import concerned_rows
    from via.alert.inventory import Inventory
    from via.alert.watch import Item, relevant

    from .test_v0230 import CVE, _asset

    comps = [{"name": "OpenSSL 1.1.1k (64-bit)", "version": "1.1.1k", "type": "win", "vendor": "The OpenSSL Project",
              "source": "sentinelone", "seen": "2026-11-09T07:00:00+00:00"}]  # fmt: skip
    inv = Inventory(profile.id, {"host:pc01": _asset("host:pc01", "pc01", comps)}, {}, "2026-11-09T07:00:00+00:00")
    profile.alerts["level"] = "all"
    item = Item(f"CVE:{CVE}", "cve", CVE, [CVE], "")
    assert relevant([item], profile, sources, settings, InventoryScanner(settings), inventory=inv) == []
    key = apps.app_key("The OpenSSL Project", "OpenSSL 1.1.1k (64-bit)")
    row = apps.Row(key, "The OpenSSL Project", "OpenSSL", apps.VALIDATED, "cpe:2.3:a:openssl:openssl")
    inv.applications = {key: row}
    [alert] = relevant([item], profile, sources, settings, InventoryScanner(settings), inventory=inv)
    (row,) = [r for r in concerned_rows(alert, "CVE", "en")[0] if r["nom"] == "pc01"]
    assert row["preuve"] == "possible" and "version not decided" in row["version_installee"]


def test_the_watch_proposes_in_kubernetes_mode_only(tmp_path, profile) -> None:
    from via.alert.cli import propose_applications
    from via.alert.inventory import Inventory

    from .test_v0230 import _asset

    comps = _inventory_doc()["components"]
    inv = Inventory(profile.id, {"host:pc01": _asset("host:pc01", "pc01", comps)}, {}, "x")
    assert "applications.yaml" in propose_applications(inv, _FakeLlm(), None)
    assert "no LLM" in propose_applications(inv, None, str(tmp_path / "p.json"))
    llm = _FakeLlm()
    note = propose_applications(inv, llm, str(tmp_path / "p.json"))
    assert note.startswith("applications: 1 CPE proposed") and len(llm.calls) == 1
    (p,) = json.loads((tmp_path / "p.json").read_text())["proposals"]
    assert p == {"key": "mozilla|mozilla firefox", "cpe": "cpe:2.3:a:mozilla:firefox", "justification": "x",
                 "by": "llm:fake-model"}  # fmt: skip
    inv.applications = apps.load_table([{"key": p["key"], "vendor": "Mozilla", "name": "x", "state": "proposed"}])
    assert propose_applications(inv, llm, str(tmp_path / "p.json")) == "" and len(llm.calls) == 1


def test_package_matching_leaves_applications_out() -> None:
    from ngvm.packages import exposures

    advisory = [{"distro": "rhel:9", "name": "mozilla firefox (x64 fr)", "state": "affected", "fixed": "999"}]
    comps = [{"name": "Mozilla Firefox (x64 fr)", "version": "128.0", "type": "win", "vendor": "Mozilla"}]
    assert exposures("CVE-2099-0001", comps, advisory, "Rocky Linux 9.4") == []


# -- dispatch ---------------------------------------------------------------------------------------
def test_itop_caller_in_its_organisation_or_by_email() -> None:
    from dispatch.connectors.itop import ItopConnector
    from dispatch.rules import Rules

    from .test_v0200 import RULES

    def connector(**settings):
        target = {**RULES["targets"]["itsm"], **settings}
        return ItopConnector(Rules.from_dict({**RULES, "targets": {"itsm": target}}).targets["itsm"], "pw")

    assert connector().caller_criteria() == {"name": "NGVM", "org_name": "Lab"}
    assert connector(caller="ngvm@lab.example", caller_organization="IT").caller_criteria() == {
        "email": "ngvm@lab.example",
        "org_name": "IT",
    }


def test_requested_tickets_left_proposed_are_sent_by_the_next_live_run(tmp_path) -> None:
    from dispatch.rules import Rules

    from .test_v0200 import RULES, dec, dispatcher

    a, b = "host:web01.lab.example", "host:db01.lab.example"
    manual = {"target": "itsm", "automatic": "none"}
    items = [dec(1, a, "ATTEND", ["openssl 3.0.15"]), dec(2, b, "TRACK", ["zlib 1.3"])]
    dry = Rules.from_dict({**RULES, "mode": "dry-run", "tickets": manual})
    d, tool = dispatcher(tmp_path, items, rules=dry)
    for asset in (a, b):
        d.confirm({"asset": asset}, [k["key"] for k in d.preview({"asset": asset})["tickets"]], "rssi@lab.example")
    assert {t.state for t in d.store.tickets()} == {"proposed"} and tool.created == []
    live = Rules.from_dict({**RULES, "tickets": manual})
    d2, tool2 = dispatcher(tmp_path, items[:1], rules=live)  # db01's finding was fixed meanwhile
    summary = d2.process_run()
    assert summary["sent"] == 1 and len(tool2.created) == 1
    assert d2.store.get(f"{a} / openssl 3.0.15").state == "sent"
    gone = d2.store.get(f"{b} / zlib 1.3")
    assert gone.state == "dropped" and gone.history[-1]["what"].startswith("dropped before sending")
    assert d2.process_run()["sent"] == 0  # nothing twice


def test_the_page_shows_the_last_error_of_a_proposed_ticket(tmp_path) -> None:
    from dispatch.connectors import ConnectorError
    from dispatch.rules import Rules

    from .test_v0200 import RULES, FakeTool, dec, dispatcher

    class Refusing(FakeTool):
        def create(self, ticket, text, title):
            raise ConnectorError("iTop refused: code 100: Error: caller_id: Several items found (2)", retry=False)

    a = "host:web01.lab.example"
    rules = Rules.from_dict({**RULES, "tickets": {"target": "itsm", "automatic": "none"}})
    d, _ = dispatcher(tmp_path, [dec(1, a, "ATTEND", ["openssl 3.0.15"])], rules=rules, tool=Refusing())
    d.confirm({"asset": a}, [f"{a} / openssl 3.0.15"], "rssi@lab.example")
    (t,) = d.preview({"asset": a})["tickets"]
    assert t["status"] == "proposed" and "Several items found" in t["error"]


def test_release_recorded() -> None:
    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.3( \(current\))? \| D20: SentinelOne", hld, re.M)
    assert "## v0.23.3 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (ROOT / "docs" / "sentinelone.md").exists()
    for f in ("ngvm", "via", "detect", "verdict", "dispatch"):
        text = (ROOT / f / "pyproject.toml").read_text()
        assert re.search(r'^version = "0\.(23\.([3-9]|[1-9]\d)|2[4-9]\.\d+)"', text, re.M)
