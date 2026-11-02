# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.19.0: the tenant's CMDB (iTop) as a read-only detection source, its place in the asset
context (after a declaration, before the rules), and the scan coverage of each asset."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest
import yaml

from a2vm.io import Detection, validate_detection, write_detection
from a2vm.models import AssetObservation, CoveragePolicy
from a2vm.profile import ProfileError, load_profile
from detect.agent import AgentError, CmdbConnector, load_config
from detect.cli import main as detect_main
from detect.cmdb import CmdbError, ItopClient, ItopConfig, export_candidates, fetch
from verdict.assets.build import build_inventory
from verdict.assets.coverage import build_coverage

from .conftest import ROOT

AT = datetime(2026, 11, 2, 6, 0, tzinfo=UTC)


def _day(days_ago: float) -> str:
    return (AT - timedelta(days=days_ago)).isoformat()


# -- iTop, simulated --------------------------------------------------------------------------------
ITEMS = {
    "PhysicalDevice": {
        "Server::1": {
            "class": "Server",
            "key": "1",
            "fields": {
                "name": "web01.lab.example",
                "finalclass": "Server",
                "organization_name": "Lab",
                "status": "production",
                "business_criticity": "high",
                "managementip": "192.0.2.10",
                "osfamily_name": "Linux",
                "osversion_name": "Rocky 10",
                "contacts_list": [{"contact_id": "4", "contact_name": "Web team"}],
                "physicalinterface_list": [{"ipaddress": "192.0.2.11"}, {"ipaddress": "fe80::1"}],
            },
        },
        "IoTDevice::3": {
            "class": "IoTDevice",
            "key": "3",
            "fields": {
                "name": "Camera garden",
                "finalclass": "IoTDevice",
                "organization_name": "Lab",
                "status": "production",
                "business_criticity": "low",
                "device_type": "camera",
                "managementip": "192.0.2.40",
            },
        },
        "Rack::9": {"class": "Rack", "key": "9", "fields": {"name": "rack1", "finalclass": "Rack"}},
        "Peripheral::7": {
            "class": "Peripheral",
            "key": "7",
            "fields": {"name": "Smart plug", "finalclass": "Peripheral", "status": "production"},
        },
    },
    "VirtualDevice": {
        "VirtualMachine::2": {
            "class": "VirtualMachine",
            "key": "2",
            "fields": {
                "name": "db01",
                "finalclass": "VirtualMachine",
                "organization_name": "Lab",
                "status": "obsolete",
                "business_criticity": "medium",
                "managementip": "192.0.2.20",
                "logicalinterface_list": [{"ipaddress": "198.51.100.20"}],
            },
        },
        "Hypervisor::5": {
            "class": "Hypervisor",
            "key": "5",
            "fields": {"name": "hv1", "finalclass": "Hypervisor", "server_id": "1", "status": "production"},
        },
    },
}


class FakeItop:
    def __init__(self, code: int = 0):
        self.code = code
        self.requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        payload = json.loads(form["json_data"])
        self.requests.append({"form": form, "payload": payload, "url": str(request.url)})
        if form["auth_pwd"] != "s3cret":
            return httpx.Response(200, json={"code": 1, "message": "Invalid login", "objects": None})
        cls = payload["key"].split()[1]
        return httpx.Response(200, json={"code": self.code, "message": "Found", "objects": ITEMS.get(cls, {})})


def _cfg(tmp_path, **kw) -> ItopConfig:
    password = tmp_path / "itop-password"
    password.write_text("s3cret\n")
    return ItopConfig.from_dict(
        {"url": "https://itop.example.org", "user": "a2vm", "password_file": str(password), **kw}
    )


def _fetch(tmp_path, fake=None, **kw) -> Detection:
    fake = fake or FakeItop()
    cfg = _cfg(tmp_path, **kw)
    return fetch(cfg, "lab", ItopClient(cfg, transport=httpx.MockTransport(fake)), log=lambda line: None)


def test_every_configuration_item_with_a_name_becomes_an_observation(tmp_path):
    d = _fetch(tmp_path)
    assert d.source == "cmdb" and d.findings == []
    refs = [o.ref for o in d.observations]
    assert refs == ["IoTDevice::3", "Peripheral::7", "Server::1", "VirtualMachine::2"]
    assert d.skipped == {"class Rack": 1, "hypervisor of a server": 1}
    validate_detection(json.loads(write_detection(tmp_path / "cmdb.json", d).read_text()), "cmdb.json")


def test_identifiers_attributes_and_item(tmp_path):
    web = {o.ref: o for o in _fetch(tmp_path).observations}["Server::1"]
    assert web.identifiers["fqdn"] == "web01.lab.example" and web.identifiers["hostname"] == "web01"
    assert web.identifiers["ips"] == ["192.0.2.10", "192.0.2.11"]  # link-local left out
    assert web.identifiers["cmdb"] == {
        "class": "Server",
        "key": "1",
        "status": "production",
        "criticality": "high",
        "organization": "Lab",
        "type": "",
    }
    assert web.attributes == {"mission_prevalence": "essential", "owner": "Web team"}
    assert web.os == "Linux Rocky 10" and web.name == "web01"


def test_a_name_that_is_not_a_host_name_gives_no_host_name(tmp_path):
    camera = {o.ref: o for o in _fetch(tmp_path).observations}["IoTDevice::3"]
    assert "hostname" not in camera.identifiers and camera.identifiers["ips"] == ["192.0.2.40"]
    assert camera.name == "Camera garden" and camera.identifiers["cmdb"]["type"] == "camera"
    assert camera.attributes == {"mission_prevalence": "minimal", "owner": "Lab"}


def test_the_client_only_reads(tmp_path):
    fake = FakeItop()
    _fetch(tmp_path, fake, organization="Lab")
    assert {r["payload"]["operation"] for r in fake.requests} == {"core/get"}
    assert fake.requests[0]["payload"]["key"] == "SELECT PhysicalDevice WHERE organization_name = 'Lab'"
    assert fake.requests[0]["url"].startswith("https://itop.example.org/webservices/rest.php?version=1.3")
    client = ItopClient(_cfg(tmp_path), transport=httpx.MockTransport(fake))
    with pytest.raises(CmdbError, match="read only"):
        client._call({"operation": "core/create", "class": "Server"})


def test_errors_of_itop_are_reported(tmp_path):
    with pytest.raises(CmdbError, match="code 1"):
        _fetch(tmp_path, FakeItop(code=1))
    (tmp_path / "itop-password").write_text("wrong")
    cfg = ItopConfig.from_dict(
        {"url": "https://itop.example.org", "user": "a", "password_file": str(tmp_path / "itop-password")}
    )
    with pytest.raises(CmdbError, match="Invalid login"):
        fetch(cfg, "lab", ItopClient(cfg, transport=httpx.MockTransport(FakeItop())), log=lambda x: None)
    page = httpx.MockTransport(lambda r: httpx.Response(200, text="<html>sign in</html>"))
    with pytest.raises(CmdbError, match="JSON"):
        fetch(_cfg(tmp_path), "lab", ItopClient(_cfg(tmp_path), transport=page), log=lambda x: None)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"url": "https://x", "user": "u"}, "password_file"),
        ({"url": "ftp://x", "user": "u", "password_file": "p"}, "http"),
        ({"url": "https://x", "user": "u", "password_file": "p", "colour": "red"}, "unknown keys"),
        ({"url": "https://x", "user": "u", "password_file": "p", "classes": ["Server; DROP"]}, "class name"),
    ],
)
def test_bad_settings(data, message):
    with pytest.raises(ValueError, match=message):
        ItopConfig.from_dict(data)


def test_agent_connector_itop(tmp_path):
    token = tmp_path / "token"
    token.write_text("t" * 40)
    path = tmp_path / "collector.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "collector": "lab-lan",
                "tenant": "lab",
                "service": "https://detect.example.org",
                "token_file": str(token),
                "connectors": [
                    {"name": "cmdb", "type": "itop", "url": "https://itop.example.org", "user": "a2vm",
                     "password_file": str(tmp_path / "pw"), "organization": "Lab"},
                ],
            }
        )
    )  # fmt: skip
    cfg = load_config(path)
    assert isinstance(cfg.connectors[0], CmdbConnector) and cfg.connectors[0].config.organization == "Lab"
    path.write_text(path.read_text().replace("password_file", "password"))
    with pytest.raises(AgentError, match="unknown keys"):
        load_config(path)
    lines = []
    detections, errors = cfg.connectors[0].run("lab", tmp_path, log=lines.append)
    assert detections == [] and errors and "password_file" in errors[0] and lines[0].startswith("FAIL cmdb")


# -- asset context ----------------------------------------------------------------------------------
def _obs(ref, source, observed_at=None, **ids) -> AssetObservation:
    return AssetObservation(ref, "host", source, observed_at or _day(0), ref.split(".")[0], identifiers=ids)


def _profile(tmp_path, extra: str = ""):
    path = tmp_path / "client.yaml"
    path.write_text(
        "schema_version: 2\nclient: {id: lab, name: Lab, updated: 2026-11-02}\n"
        "rules:\n  - hostname: 'web*'\n    set: {mission_prevalence: minimal, owner: rule-team}\n" + extra
    )
    return load_profile(path)


def _cmdb_detection(tmp_path) -> Detection:
    return _fetch(tmp_path)


def test_the_cmdb_comes_after_a_declaration_and_before_the_rules(tmp_path):
    scanned = Detection("lab", "openvas", [_obs("web01.lab.example", "openvas", fqdn="web01.lab.example")], [])
    inv = build_inventory(_profile(tmp_path), [scanned, _cmdb_detection(tmp_path)])
    web = next(a for a in inv.assets if a.id == "host:web01.lab.example")
    assert web.attributes["mission_prevalence"].value == "essential"
    assert web.attributes["mission_prevalence"].source == "cmdb"
    assert web.attributes["mission_prevalence"].note == "Server::1"
    assert web.attributes["owner"].value == "Web team"
    assert web.identifiers["cmdb"][0]["key"] == "1" and "192.0.2.11" in web.identifiers["ips"]
    assert set(web.sources) == {"openvas", "cmdb"} and set(web.scans) == {"openvas"}  # the CMDB is no scan


def test_a_rule_still_sets_what_the_cmdb_does_not_say(tmp_path):
    no_contact = Detection(
        "lab",
        "cmdb",
        [
            AssetObservation(
                "Server::8", "host", "cmdb", _day(0), "web02",
                identifiers={"hostname": "web02", "cmdb": {"class": "Server", "key": "8", "status": "production"}},
            )
        ],
        [],
    )  # fmt: skip
    inv = build_inventory(_profile(tmp_path), [no_contact])
    web = inv.assets[0]
    assert web.attributes["mission_prevalence"].source == "rule" and web.attributes["owner"].value == "rule-team"


# -- coverage ---------------------------------------------------------------------------------------
def _coverage(tmp_path, detections, extra=""):
    profile = _profile(tmp_path, extra)
    inv = build_inventory(profile, detections)
    return build_coverage("lab", inv.assets, profile.coverage, at=AT)


def _states(cov):
    return {e["name"]: e["state"] for e in cov["assets"]}


def test_coverage_states(tmp_path):
    openvas = Detection(
        "lab",
        "openvas",
        [
            _obs("web01.lab.example", "openvas", _day(1), fqdn="web01.lab.example"),
            _obs("db01", "openvas", _day(1), hostname="db01", ips=["192.0.2.20"]),
            _obs("printer", "openvas", _day(1), hostname="printer", ips=["192.0.2.99"]),
            _obs("192.0.2.40", "openvas", _day(9), ips=["192.0.2.40"]),
        ],
        [],
    )
    trivy = Detection("lab", "trivy", [_obs("web01.lab.example", "trivy", _day(2), fqdn="web01.lab.example")], [])
    cov = _coverage(tmp_path, [openvas, trivy, _cmdb_detection(tmp_path)])
    states = _states(cov)
    assert states["web01"] == "covered"  # openvas and trivy within 7 days
    assert states["db01"] == "retired-but-alive"  # obsolete in the CMDB, scanned yesterday
    assert states["printer"] == "not-in-cmdb"
    assert states["Camera garden"] == "stale"  # last scan 9 days ago
    assert states["Smart plug"] == "not-scannable"  # no address, no host name, never scanned
    camera = next(e for e in cov["assets"] if e["name"] == "Camera garden")
    assert (
        camera["cmdb_class"] == "IoTDevice" and camera["expected"] == ["openvas"] and camera["missing"] == ["openvas"]
    )
    assert cov["cmdb"] is True and cov["counts"]["covered"] == 1 and cov["expected_assets"] == 3
    assert cov["covered_share"] == pytest.approx(1 / 3, abs=1e-4)
    assert cov["means"] == ["openvas", "trivy"]


def test_partial_when_an_expected_means_is_missing(tmp_path):
    openvas = Detection("lab", "openvas", [_obs("web01.lab.example", "openvas", _day(1), fqdn="web01.lab.example")], [])
    web = next(e for e in _coverage(tmp_path, [openvas, _cmdb_detection(tmp_path)])["assets"] if e["name"] == "web01")
    assert web["state"] == "partial" and web["missing"] == ["trivy|dnf-updateinfo"]
    relaxed = "coverage:\n  stale_days: 3\n  expected:\n    Server: [openvas]\n"
    cov = _coverage(tmp_path, [openvas, _cmdb_detection(tmp_path)], relaxed)
    assert _states(cov)["web01"] == "covered" and cov["stale_days"] == 3


def test_never_scanned_and_not_expected(tmp_path):
    cmdb = _cmdb_detection(tmp_path)
    for o in cmdb.observations:
        if o.ref == "VirtualMachine::2":
            o.identifiers["cmdb"]["status"] = "implementation"
    states = _states(_coverage(tmp_path, [cmdb]))
    assert states["web01"] == "never-scanned" and states["db01"] == "not-expected"


def test_without_a_cmdb_every_host_is_judged_in_production(tmp_path):
    openvas = Detection("lab", "openvas", [_obs("web01.lab.example", "openvas", _day(1), fqdn="web01.lab.example")], [])
    cov = _coverage(tmp_path, [openvas])
    assert cov["cmdb"] is False and _states(cov) == {"web01": "covered"}  # class default: openvas


def test_bad_coverage_section_is_refused(tmp_path):
    with pytest.raises(ProfileError):
        _profile(tmp_path, "coverage:\n  expected:\n    Server: ['openvas||trivy']\n")
    assert CoveragePolicy().expected_for("PC") == [["edr"]]


# -- seed file --------------------------------------------------------------------------------------
def test_export_lists_the_hosts_not_in_the_cmdb(tmp_path):
    triage = {
        "schema": "a2vm.triage/1",
        "assets": [
            {"id": "host:printer", "name": "printer", "kind": "host", "ips": ["192.0.2.99"], "scans": {"openvas": "x"}},
            {"id": "host:web01.lab.example", "name": "web01", "kind": "host", "scans": {"trivy": "x", "openvas": "x"}},
            {"id": "image:nginx:1", "name": "nginx", "kind": "image"},
        ],
        "coverage": {
            "assets": [
                {"asset": "host:printer", "state": "not-in-cmdb"},
                {"asset": "host:web01.lab.example", "state": "covered"},
            ]
        },
    }  # fmt: skip
    rows = export_candidates(triage, "Lab")
    assert [r["name"] for r in rows] == ["printer"] and rows[0]["managementip"] == "192.0.2.99"
    assert rows[0]["org_id->name"] == "Lab" and rows[0]["description"] == "seen by openvas"
    del triage["coverage"]
    assert [r["name"] for r in export_candidates(triage, "Lab")] == ["printer", "web01"]
    assert "likely a server" in export_candidates(triage, "Lab")[1]["description"]
    path = tmp_path / "triage.json"
    path.write_text(json.dumps(triage))
    out = tmp_path / "seed.csv"
    assert detect_main(["cmdb", "export", str(path), "--organization", "Lab", "--out", str(out)]) == 0
    rows = list(csv.DictReader(out.open(), delimiter=";"))
    assert rows[0]["org_id->name"] == "Lab" and len(rows) == 2


def test_examples_and_schemas_stay_valid():
    for client in ("lab", "demo-industrie"):
        load_profile(ROOT / "examples" / client / "client.yaml")


# -- decision service and chat ----------------------------------------------------------------------
def _index():
    from verdict.service.index import RunIndex

    coverage = {
        "cmdb": True,
        "stale_days": 7,
        "counts": {"covered": 1, "never-scanned": 1, "not-in-cmdb": 1},
        "expected_assets": 2,
        "covered_share": 0.5,
        "means": ["openvas"],
        "assets": [
            {"asset": "host:printer", "name": "printer", "state": "not-in-cmdb", "cmdb_class": ""},
            {"asset": "host:db01", "name": "db01", "state": "never-scanned", "cmdb_class": "VirtualMachine"},
            {"asset": "host:web01", "name": "web01", "state": "covered", "cmdb_class": "Server"},
        ],
    }
    document = {
        "client": {"id": "lab", "name": "Lab"},
        "cve_count": 0,
        "rows": [],
        "assets": [{"id": "host:web01", "name": "web01", "cmdb": [{"class": "Server", "key": "1"}], "scans": {}}],
        "coverage": coverage,
    }
    return RunIndex({"id": "r1", "generated_at": "2026-11-02T06:00:00+00:00"}, document)


def test_service_reads_the_coverage():
    idx = _index()
    assert idx.summary()["coverage"]["covered_share"] == 0.5
    gaps = idx.coverage({"state": "gaps"})
    assert [c["name"] for c in gaps["items"]] == ["printer", "db01"] and gaps["cmdb"] is True
    assert [c["name"] for c in idx.coverage({"class": "server"})["items"]] == ["web01"]
    with pytest.raises(ValueError, match="unknown"):
        idx.coverage({"state": "lost"})
    card = idx.assets({})["items"][0]
    assert card["coverage"] == "covered" and card["cmdb"][0]["class"] == "Server"


def test_chat_has_the_coverage_tool():
    from verdict.service.tools import OPERATIONS

    assert any(op[1] == "list_coverage" and op[-1] == "coverage" for op in OPERATIONS)
    values = yaml.safe_load((ROOT / "deploy/charts/a2vm-tenant/values.yaml").read_text())
    assert "list_coverage" in values["chat"]["systemPrompt"]


# -- reporting database and dashboard ---------------------------------------------------------------
from .test_pipeline import _run  # noqa: E402
from .test_restitution import ADMIN, _grafana, needs_db, reporting_db  # noqa: E402, F401


@needs_db
def test_coverage_is_published_and_the_dashboard_counts_it(settings, sources, profile, tmp_path, reporting_db):  # noqa: F811
    import psycopg

    from verdict.reporting import build
    from verdict.restitution import db
    from verdict.restitution.cli import dashboard, main

    run = _run(settings, sources, profile)
    hosts = run.assets  # the assets of the fixture run are declared ones: enough to load rows
    assert len(hosts) >= 2
    states = ["covered", "never-scanned", "not-in-cmdb", "partial"]
    run.coverage = {
        "cmdb": True,
        "stale_days": 7,
        "counts": {},
        "expected_assets": 0,
        "covered_share": None,
        "means": ["openvas"],
        "assets": [
            {"asset": a["id"], "name": a["name"], "state": states[i % 4], "cmdb_class": "Server" if i % 4 != 2 else "",
             "missing": ["trivy|dnf-updateinfo"] if i % 4 == 3 else [], "expected": ["openvas"],
             "scans": a.get("scans") or {}, "last_scan": "2026-11-01T06:00:00+00:00"}
            for i, a in enumerate(hosts)
        ],
    }  # fmt: skip
    for state in states:
        run.coverage["counts"][state] = sum(1 for c in run.coverage["assets"] if c["state"] == state)
    run.coverage["expected_assets"] = sum(run.coverage["counts"][s] for s in ("covered", "never-scanned", "partial"))
    data = {"schema": "a2vm.reporting/1", **build(run, settings.policy)}
    assert data["coverage"]["cmdb"] is True and any(a.get("coverage") for a in data["assets"])
    rdb = reporting_db
    assert db.init(ADMIN, rdb["writer"]).startswith("schema a2vm version 4")
    path = tmp_path / "r.json"
    path.write_text(json.dumps(data))
    assert main(["publish", str(path), "--dsn", rdb["as_writer"]]) == 0
    password = db.grant(ADMIN, rdb["reader"], ["*"])
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=rdb["reader"], password=password)
    board = json.loads(dashboard("coverage"))
    values = {"tenant": [profile.id], "state": states + ["retired-but-alive", "not-scannable", "not-expected"]}
    results = {}
    with psycopg.connect(as_reader) as conn:
        row = conn.execute(
            "SELECT cmdb, expected_assets, covered_assets, coverage_gaps FROM a2vm.latest_runs"
        ).fetchone()
        assert row == (True, run.coverage["expected_assets"], run.coverage["counts"]["covered"],
                       len(hosts) - run.coverage["counts"]["covered"])  # fmt: skip
        for panel in board["panels"]:
            for t in panel.get("targets", []):
                cur = conn.execute(_grafana(t["rawSql"], values))
                results[panel["title"]] = ([c.name for c in cur.description], cur.fetchall())
    assert results["Never scanned"][1] == [(run.coverage["counts"]["never-scanned"],)]
    assert results["Not in the CMDB"][1] == [(run.coverage["counts"]["not-in-cmdb"],)]
    cols, rows = results["Assets and their means of detection"]
    assert len(rows) == len(hosts) and "OpenVAS" in cols and "Other means" in cols
    cols, rows = results["Coverage per class"]
    assert sum(r[cols.index("Assets")] for r in rows) == len(hosts)
    fr = json.loads(dashboard("coverage", "fr"))
    assert fr["uid"] == "a2vm-coverage-fr" and fr["title"] == "A2VM — actifs et couverture des scans"
