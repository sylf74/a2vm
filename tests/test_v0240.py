# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.24.0: the asset graph and the exposure computed from a path.

Zones and flows in the client profile (an intention); the services the scanners and the hosts report
(what is observed); the graph of the assets stage, the exposure set from it with its path, the gaps
where the two differ, the flows proposed from the observations; the path in the triage and the chat.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess

import pytest
import yaml

from a2vm.io import Detection, read_assets, read_detection, write_detection
from a2vm.models import AssetObservation, Flow, port_label
from a2vm.profile import ProfileError, load_profile, validate_profile_data
from detect.collect import LISTENING, parse_listening
from detect.openvas import parse_gmp_report
from verdict.assets.build import build_inventory
from verdict.assets.graph import AssetGraph, proposed_flows, read_graph, write_graph

from .conftest import ROOT

NOW = dt.datetime(2026, 11, 14, 6, 0, tzinfo=dt.UTC)
TODAY = "2026-11-14T03:00:00+00:00"


def _profile(tmp_path, **extra):
    data = {
        "schema_version": 2,
        "client": {"id": "acme", "name": "ACME", "updated": "2026-11-14"},
        "defaults": {"exposure": "controlled"},
        "assets": [],
        "zones": [
            {"id": "dmz", "networks": ["192.0.2.0/26"]},
            {"id": "lan", "networks": ["192.0.2.64/26", "198.51.100.0/24"]},
            {"id": "guest", "networks": ["192.0.2.192/27"], "open": True},
        ],
        "flows": [{"from": "lan", "to": "dmz", "ports": [443]}],
        **extra,
    }
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    return load_profile(path)


def _host(ref, source, ips, services=None, observed_at=TODAY, hostname=None):
    ids = {"hostname": hostname or ref, "ips": list(ips)}
    return AssetObservation(ref, "host", source, observed_at, hostname or ref, identifiers=ids, services=services)


def _det(source, *observations):
    return Detection("acme", source, list(observations), [])


def _reached(*ports, zone="lan"):
    return [{"port": port_label(p), "view": "network", "from_zone": zone} for p in ports]


def _assets(inv):
    return {a.name: a for a in inv.assets}


def _external(*observations):
    return _det("external-scan", *observations)


# -- the profile --------------------------------------------------------------------------------------
def test_zones_and_flows_are_read_and_checked(tmp_path) -> None:
    p = _profile(tmp_path, off_premises_days=3)
    assert [z.id for z in p.zones] == ["dmz", "lan", "guest"] and p.zones[2].open
    assert p.flows == [Flow("lan", "dmz", ["443/tcp"], "")] and p.off_premises_days == 3
    base = {"schema_version": 2, "client": {"id": "x", "name": "X", "updated": "2026-11-14"}}
    errors = validate_profile_data(
        {
            **base,
            "zones": [{"id": "dmz"}, {"id": "dmz"}, {"id": "lan", "networks": ["not-a-network"]}],
            "flows": [{"from": "wan", "to": "dmz"}, {"from": "dmz", "to": "internet"}, {"from": "*", "to": "lan"}],
        }
    )
    assert any("duplicate zone 'dmz'" in e for e in errors)
    assert any("'not-a-network' is not a network" in e for e in errors)
    assert any("flows/0: from 'wan'" in e for e in errors) and any("flows/1: to 'internet'" in e for e in errors)
    assert not any("flows/2" in e for e in errors)  # * stands for every zone
    assert validate_profile_data({**base, "zones": [{"id": "off-premises"}]})  # reserved
    with pytest.raises(ProfileError):
        _profile(tmp_path, flows=[{"from": "lan", "to": "dmz", "ports": ["https"]}])


def test_a_flow_allows_its_zones_and_ports() -> None:
    f = Flow("lan", "dmz", ["443/tcp"])
    assert f.allows("lan", "dmz", "443/tcp") and not f.allows("lan", "dmz", "22/tcp")
    assert not f.allows("dmz", "lan", "443/tcp")
    assert Flow("*", "dmz").allows("ot", "dmz", "502/tcp") and Flow("lan", "*").allows("lan", "ot", None)
    assert port_label(443) == "443/tcp" and port_label("53/UDP") == "53/udp"


# -- what the scanners and the hosts report ---------------------------------------------------------
def test_openvas_keeps_the_open_ports_and_where_it_scans_from() -> None:
    d = parse_gmp_report((ROOT / "tests" / "fixtures" / "openvas" / "report.xml").read_bytes(), "lab", zone="lan")
    services = {o.identifiers["ips"][0]: o.services for o in d.observations}
    assert services and all(s is not None for s in services.values())
    every = [x for s in services.values() for x in s]
    assert all(x["view"] == "network" and x["from_zone"] == "lan" for x in every)
    assert all(re.match(r"^\d+/(tcp|udp)$", x["port"]) for x in every)  # general/tcp is not a port
    xml = b"""<report><scan_start>2026-11-14T02:00:00Z</scan_start><results/><ports>
      <port>8443/tcp<host>192.0.2.77</host><severity>0</severity></port></ports></report>"""
    alone = parse_gmp_report(xml, "lab", zone="dmz")
    assert [(o.identifiers["ips"], o.services) for o in alone.observations] == [
        (["192.0.2.77"], [{"port": "8443/tcp", "view": "network", "from_zone": "dmz"}])
    ]  # a host with an open port and no finding: the scan reached it


def test_the_host_lists_its_listening_sockets() -> None:
    assert LISTENING.endswith("ss -ltnu")
    out = parse_listening(
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        "tcp LISTEN 0 128 [::1]:631 [::]:*\n"
        "tcp LISTEN 0 511 192.0.2.5:8443 *:*\n"
    )
    assert out == [
        {"port": "22/tcp", "view": "local", "bind": "any"},
        {"port": "53/udp", "view": "local", "bind": "loopback"},
        {"port": "631/tcp", "view": "local", "bind": "loopback"},
        {"port": "8443/tcp", "view": "local", "bind": "192.0.2.5"},
    ]


def test_ss_runs_without_root_where_it_exists() -> None:
    try:
        proc = subprocess.run(["ss", "-ltnu"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        pytest.skip("no ss here")
    assert proc.returncode == 0 and isinstance(parse_listening(proc.stdout), list)


def test_services_survive_the_detection_file(tmp_path) -> None:
    obs = _host("web01", "openvas", ["192.0.2.10"], _reached(443))
    path = write_detection(tmp_path / "openvas.json", _det("openvas", obs, _host("db01", "openvas", ["192.0.2.11"])))
    back = read_detection(path)
    assert back.observations[0].services == obs.services and back.observations[1].services is None


def test_what_the_external_scan_reached_it_reached_from_the_internet(tmp_path) -> None:
    from detect.external import as_internal

    p = _profile(tmp_path, external={"client": "acme-external"})
    seen = AssetObservation(
        "203.0.113.10", "host", "openvas", TODAY, "203.0.113.10", identifiers={"ips": ["203.0.113.10"]},
        services=_reached(443, zone=""),
    )  # fmt: skip
    result = as_internal(p, [Detection("acme-external", "openvas", [seen], [])], now=NOW)
    assert result.detection.observations[0].services == [
        {"port": "443/tcp", "view": "network", "from_zone": "internet"}
    ]


# -- the zone of an asset ------------------------------------------------------------------------------
def test_an_address_in_the_networks_of_a_zone_places_the_host(tmp_path) -> None:
    p = _profile(tmp_path, rules=[{"hostname": "app*", "set": {"zone": "dmz"}}])
    inv = build_inventory(
        p,
        [_det("trivy", _host("db01", "trivy", ["198.51.100.20"]), _host("app01", "trivy", ["198.51.100.21"]))],
        now=NOW,
    )
    a = _assets(inv)
    assert (a["db01"].attributes["zone"].value, a["db01"].attributes["zone"].source) == ("lan", "networks")
    assert a["db01"].attributes["zone"].note == "198.51.100.0/24"
    assert a["app01"].attributes["zone"].source == "rule"  # a rule comes first


# -- the exposure from the graph -------------------------------------------------------------------------
def test_reached_from_an_internal_zone_and_not_from_the_internet_is_controlled(tmp_path) -> None:
    p = _profile(tmp_path, defaults={"exposure": "open"}, external={"client": "acme-external"})
    inv = build_inventory(
        p,
        [
            _det("openvas", _host("db01", "openvas", ["192.0.2.70"], _reached(5432))),
            _external(_host("203.0.113.9", "external-scan", ["203.0.113.9"])),
        ],
        now=NOW,
    )
    db = _assets(inv)["db01"]
    exposure = db.attributes["exposure"]
    assert (exposure.value, exposure.source) == ("controlled", "graph") and not exposure.assumed
    assert "reached from zone lan on 5432/tcp (openvas)" in exposure.note and "2026-11-14" in exposure.note
    assert [s["node"] for s in db.exposure_path] == ["zone:lan", "service:host:db01:5432/tcp", "host:db01"]
    assert inv.graph.exposure["host:db01"]["path"] == db.exposure_path


def test_without_a_recent_external_scan_the_assumption_is_the_worst_case(tmp_path) -> None:
    p = _profile(tmp_path, external={"client": "acme-external"})  # client default: controlled
    inv = build_inventory(p, [_det("openvas", _host("db01", "openvas", ["192.0.2.70"], _reached(5432)))], now=NOW)
    exposure = _assets(inv)["db01"].attributes["exposure"]
    assert (exposure.value, exposure.source) == ("open", "default") and exposure.assumed
    assert "no recent external scan" in exposure.note


def test_without_an_external_scan_the_default_stands_and_a_gap_says_so(tmp_path) -> None:
    p = _profile(tmp_path)
    inv = build_inventory(p, [_det("openvas", _host("db01", "openvas", ["192.0.2.70"], _reached(5432)))], now=NOW)
    exposure = _assets(inv)["db01"].attributes["exposure"]
    assert (exposure.value, exposure.source, exposure.note) == ("controlled", "default", "client default")
    gaps = [g for g in inv.exposure_gaps if g["kind"] == "no-external-scan"]
    assert len(gaps) == 1 and gaps[0]["asset"] == "" and gaps[0]["name"] == "acme"


def test_an_open_zone_and_a_flow_from_the_internet_make_open(tmp_path) -> None:
    flows = [{"from": "internet", "to": "dmz", "ports": [443]}]
    p = _profile(tmp_path, flows=flows, external={"client": "acme-external"})
    inv = build_inventory(
        p,
        [
            _det(
                "openvas",
                _host("kiosk01", "openvas", ["192.0.2.200"], _reached(80)),  # zone guest, declared open
                _host("web01", "openvas", ["192.0.2.10"], _reached(443)),  # dmz, serves 443
                _host("dns01", "openvas", ["192.0.2.11"], _reached(53)),  # dmz, does not serve 443
            ),
            _external(_host("203.0.113.9", "external-scan", ["203.0.113.9"])),
        ],
        now=NOW,
    )
    a = _assets(inv)
    assert (a["kiosk01"].attributes["exposure"].value, a["kiosk01"].attributes["exposure"].source) == ("open", "graph")
    assert "zone guest, declared open" in a["kiosk01"].attributes["exposure"].note
    assert a["web01"].attributes["exposure"].value == "open"
    assert "flow from the internet to zone dmz on 443/tcp (flows/0)" in a["web01"].attributes["exposure"].note
    assert [s["node"] for s in a["web01"].exposure_path] == [
        "internet", "zone:dmz", "service:host:web01:443/tcp", "host:web01",
    ]  # fmt: skip
    assert a["dns01"].attributes["exposure"].value == "controlled"  # it serves 53 only


def test_seen_off_the_premises_is_open_within_the_window(tmp_path) -> None:
    p = _profile(tmp_path, external={"client": "acme-external"})
    laptop = _host("pc042", "sentinelone", ["10.20.30.40"], observed_at="2026-11-12T19:00:00+00:00")
    inv = build_inventory(
        p, [_det("sentinelone", laptop), _external(_host("203.0.113.9", "external-scan", ["203.0.113.9"]))], now=NOW
    )
    pc = _assets(inv)["pc042"]
    assert (pc.attributes["exposure"].value, pc.attributes["exposure"].source) == ("open", "graph")
    assert pc.attributes["exposure"].note == "seen off the premises on 2026-11-12"
    assert [s["node"] for s in pc.exposure_path] == ["internet", "zone:off-premises", "host:pc042"]
    assert inv.graph.off_premises == {"host:pc042": "2026-11-12T19:00:00+00:00"}

    # Back at the office the next day: still open, the sighting of the run before counts for 7 days.
    office = _host("pc042", "sentinelone", ["198.51.100.40"], observed_at="2026-11-14T08:00:00+00:00")
    later = build_inventory(p, [_det("sentinelone", office)], previous=inv.graph, now=NOW + dt.timedelta(days=1))
    assert _assets(later)["pc042"].attributes["exposure"].note == "seen off the premises on 2026-11-12"
    gone = build_inventory(p, [_det("sentinelone", office)], previous=inv.graph, now=NOW + dt.timedelta(days=8))
    assert _assets(gone)["pc042"].attributes["exposure"].source != "graph" or (
        "off the premises" not in _assets(gone)["pc042"].attributes["exposure"].note
    )


def test_no_networks_declared_no_machine_is_off_the_premises(tmp_path) -> None:
    p = _profile(tmp_path, zones=[{"id": "lan"}], flows=[])
    inv = build_inventory(p, [_det("sentinelone", _host("pc042", "sentinelone", ["10.20.30.40"]))], now=NOW)
    assert inv.graph.off_premises == {}


def test_off_the_premises_overrides_a_declaration_and_says_so(tmp_path) -> None:
    rules = [{"hostname": "pc*", "set": {"exposure": "controlled"}}]
    p = _profile(tmp_path, rules=rules, external={"client": "acme-external"})
    inv = build_inventory(p, [_det("sentinelone", _host("pc042", "sentinelone", ["10.20.30.40"]))], now=NOW)
    assert _assets(inv)["pc042"].attributes["exposure"].value == "open"
    gap = next(g for g in inv.exposure_gaps if g["asset"] == "host:pc042")
    assert gap["kind"] == "declared-not-open" and gap["declared"] == "controlled"
    assert inv.graph.checks[0]["state"] == "contradicted"


def test_small_needs_proof(tmp_path) -> None:
    p = _profile(tmp_path, external={"client": "acme-external"})
    local = [{"port": "631/tcp", "view": "local", "bind": "loopback"}]
    inv = build_inventory(
        p,
        [
            _det("trivy", _host("iso01", "trivy", ["192.0.2.80"], local), _host("unk01", "trivy", ["192.0.2.81"])),
            _external(_host("203.0.113.9", "external-scan", ["203.0.113.9"])),
        ],
        now=NOW,
    )
    a = _assets(inv)
    assert (a["iso01"].attributes["exposure"].value, a["iso01"].attributes["exposure"].source) == ("small", "graph")
    assert a["unk01"].attributes["exposure"].source == "default"  # nothing listed: no proof of anything


def test_a_declared_small_that_a_scanner_reaches_is_a_gap(tmp_path) -> None:
    rules = [{"hostname": "plc*", "set": {"exposure": "small"}}]
    p = _profile(tmp_path, rules=rules)
    inv = build_inventory(p, [_det("openvas", _host("plc01", "openvas", ["192.0.2.90"], _reached(502)))], now=NOW)
    assert _assets(inv)["plc01"].attributes["exposure"].value == "small"  # the declaration stands
    gap = next(g for g in inv.exposure_gaps if g["kind"] == "declared-small-but-reachable")
    assert gap["asset"] == "host:plc01" and "502/tcp reached" in gap["detail"]


def test_the_external_scan_path_goes_through_the_published_endpoint(tmp_path) -> None:
    published = [{"endpoint": "www.example.org:443", "asset": "rproxy01", "behind": ["app01"]}]
    p = _profile(tmp_path, published=published, external={"client": "acme-external"})
    pub = AssetObservation(
        "www.example.org", "host", "external-scan", TODAY, "www.example.org",
        identifiers={"fqdn": "www.example.org", "ips": ["203.0.113.10"]},
    )  # fmt: skip
    inv = build_inventory(
        p,
        [
            _det("trivy", _host("rproxy01", "trivy", ["192.0.2.5"]), _host("app01", "trivy", ["192.0.2.6"])),
            _external(pub),
        ],
        now=NOW,
    )
    a = _assets(inv)
    assert [s["node"] for s in a["rproxy01"].exposure_path] == [
        "internet",
        "endpoint:www.example.org:443",
        "host:rproxy01",
    ]
    assert [s["node"] for s in a["app01"].exposure_path] == [
        "internet", "endpoint:www.example.org:443", "host:rproxy01", "host:app01",
    ]  # fmt: skip
    assert a["app01"].exposure_path[-1]["via"] == "routes_to"


# -- flows: declared, observed, proposed -------------------------------------------------------------------
def test_flows_observed_confirm_or_reveal(tmp_path) -> None:
    p = _profile(tmp_path, external={"client": "acme-external"})
    inv = build_inventory(
        p,
        [
            _det(
                "openvas",
                _host("web01", "openvas", ["192.0.2.10"], _reached(443, 5432)),  # from lan: 443 allowed, 5432 not
                _host("db01", "openvas", ["192.0.2.70"], _reached(5432)),  # lan to lan: needs no flow
            )
        ],
        now=NOW,
    )
    assert inv.graph.flows == [{"from": "lan", "to": "dmz", "ports": ["443/tcp"], "state": "confirmed", "seen": ""}]
    undeclared = [g for g in inv.exposure_gaps if g["kind"] == "undeclared-flow"]
    assert [g["name"] for g in undeclared] == ["lan -> dmz 5432/tcp"]
    text = proposed_flows(inv.graph)
    proposal = yaml.safe_load(text)["flows"]
    assert proposal == [
        {"from": "lan", "to": "dmz", "ports": ["443/tcp", "5432/tcp"], "description": "observed, partly declared"}
    ]
    validate = {"schema_version": 2, "client": {"id": "x", "name": "X", "updated": "2026-11-14"}}
    assert validate_profile_data({**validate, "zones": [{"id": "lan"}, {"id": "dmz"}], "flows": proposal}) == []


def test_without_declared_flows_nothing_is_undeclared(tmp_path) -> None:
    p = _profile(tmp_path, flows=[])
    inv = build_inventory(p, [_det("openvas", _host("web01", "openvas", ["192.0.2.10"], _reached(5432)))], now=NOW)
    assert not [g for g in inv.exposure_gaps if g["kind"] == "undeclared-flow"]
    assert inv.graph.observed_flows == [
        {"from": "lan", "to": "dmz", "port": "5432/tcp", "assets": ["host:web01"], "declared": False}
    ]


# -- the files and the commands ------------------------------------------------------------------------------
def test_the_graph_is_written_read_and_carried_to_the_next_run(tmp_path, capsys) -> None:
    from verdict.assets.cli import main as assets_main

    p = _profile(tmp_path, external={"client": "acme-external"})
    detect = tmp_path / "detect" / "acme"
    write_detection(detect / "sentinelone.json", _det("sentinelone", _host("pc042", "sentinelone", ["10.20.30.40"])))
    write_detection(detect / "openvas.json", _det("openvas", _host("web01", "openvas", ["192.0.2.10"], _reached(5432))))
    out = tmp_path / "assets"
    args = ["build", p.source_path, "--detect", str(tmp_path / "detect"), "--out", str(out), "--previous", str(out)]
    assert assets_main(args) == 0  # no graph before: fine
    graph = read_graph(out / "acme" / "asset_graph.json", "acme")
    assert isinstance(graph, AssetGraph) and graph.to_dict()["schema"] == "a2vm.asset_graph/1"
    assert "host:pc042" in graph.off_premises
    _, assets = read_assets(out / "acme" / "assets.json")
    assert assets["host:pc042"].exposure_path[1]["node"] == "zone:off-premises"
    assert assets["host:web01"].services[0]["source"] == "openvas"
    assert "flows observed between zones, 1 not declared" in capsys.readouterr().out
    assert assets_main(["flows", str(out / "acme")]) == 0
    assert "5432/tcp" in capsys.readouterr().out
    write_graph(tmp_path / "copy.json", graph)
    assert read_graph(tmp_path / "copy.json", "acme").to_dict() == graph.to_dict()
    with pytest.raises(ValueError):
        read_graph(tmp_path / "copy.json", "other")


def test_the_graph_grows_with_the_assets_not_their_square(tmp_path) -> None:
    p = _profile(tmp_path)
    hosts = [_host(f"h{i}", "openvas", [f"198.51.100.{i % 250 + 1}"], _reached(22)) for i in range(400)]
    inv = build_inventory(p, [_det("openvas", *hosts)], now=NOW)
    assert len(inv.graph.edges) < 6 * len(hosts)


def test_the_asset_graph_artefact_is_documented() -> None:
    lld = (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text(encoding="utf-8")
    assert "a2vm.asset_graph/1" in lld and "flows_proposed.yaml" in lld


def test_the_daily_job_carries_the_graph_of_the_run_before() -> None:
    cron = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "cronjob-daily.yaml").read_text()
    assert "--previous /data/work/assets" in cron
    pipeline = (ROOT / "templates" / "client-pipeline.yml").read_text()
    assert "--previous work/assets" in pipeline


def test_json_schemas_know_the_new_fields() -> None:
    schemas = ROOT / "a2vm" / "src" / "a2vm" / "schemas"
    detection = json.loads((schemas / "detection.schema.json").read_text())
    assert "services" in detection["$defs"]["observation"]["properties"]
    assets = json.loads((schemas / "assets.schema.json").read_text())
    assert {"services", "exposure_path"} <= set(assets["$defs"]["asset"]["properties"])
    reporting = json.loads((schemas / "reporting.schema.json").read_text())
    kinds = set(reporting["properties"]["exposure_gaps"]["items"]["properties"]["kind"]["enum"])
    assert {"undeclared-flow", "declared-small-but-reachable", "no-external-scan"} <= kinds


# -- the path in the triage, the decision service and the chat ---------------------------------------------
def test_the_triage_lists_the_path_and_the_service_answers_why(tmp_path) -> None:
    from verdict.service.index import RunIndex
    from verdict.triage import run_asset

    p = _profile(tmp_path, external={"client": "acme-external"})
    inv = build_inventory(
        p,
        [
            _det("openvas", _host("db01", "openvas", ["192.0.2.70"], _reached(5432))),
            _det("trivy", _host("unk01", "trivy", ["192.0.2.81"])),
            _external(_host("203.0.113.9", "external-scan", ["203.0.113.9"])),
        ],
        now=NOW,
    )
    listed = {a.name: run_asset(a) for a in inv.assets}
    assert listed["db01"]["exposure_path"][0]["node"] == "zone:lan" and listed["db01"]["services"]
    assert "exposure_path" not in listed["unk01"]  # assumed: nothing to show
    idx = RunIndex({"id": "r1", "generated_at": TODAY}, {"rows": [], "assets": list(listed.values())})
    why = idx.exposure_path("db01")
    assert why["exposure"] == "controlled" and why["exposure_source"] == "graph" and not why["assumed"]
    assert why["path_text"] == "lan -> db01 5432/tcp -> db01"
    assert why["origin"].startswith("graph (reached from zone lan")
    assumed = idx.exposure_path("unk01")
    assert assumed["assumed"] and assumed["path"] == []
    assert idx.exposure_path("nothing-like-this") is None


def test_the_chat_has_a_tool_for_the_path() -> None:
    from verdict.service.tools import openapi

    spec = openapi("acme")
    op = spec["paths"]["/assets/{asset}/exposure"]["get"]
    assert op["operationId"] == "get_exposure_path" and "path" in op["description"]
    contract = yaml.safe_load((ROOT / "a2vm" / "src" / "a2vm" / "schemas" / "openapi" / "verdict.v1.yaml").read_text())
    assert contract["paths"]["/v1/tenants/{tenant}/assets/{asset}/exposure"]["get"]["operationId"] == "getExposurePath"
    guide = (ROOT / "docs" / "chat-questions.md").read_text(encoding="utf-8")
    assert "get_exposure_path" in guide and "joignable depuis Internet" in guide


# -- the scale of a subsidiary ---------------------------------------------------------------------------------
def test_sixty_thousand_assets_in_fifty_zones_within_the_budget() -> None:
    """The load test of the graph (v0.24.0): 60,000 hosts reached by a scanner in 50 zones, 10,000
    machines of an EDR off the premises, one external host. The graph grows with the assets, and the
    assets stage stays within its budget (about 7 s and 600 MB on the development machine)."""
    import time

    from a2vm.models import ClientProfile, ExternalScan, Zone

    zones = [Zone(f"z{i}", [f"10.{i}.0.0/16"]) for i in range(50)]
    flows = [Flow(f"z{i}", f"z{(i + 1) % 50}", ["443/tcp"]) for i in range(50)] + [Flow("internet", "z0", ["443/tcp"])]
    p = ClientProfile("big", "Big", "2026-11-14", [], zones=zones, flows=flows, external=ExternalScan("big-ext"))
    hosts = []
    for i in range(60000):
        z = i % 50
        ip = f"10.{z}.{(i // 50) // 250}.{(i // 50) % 250 + 1}"
        services = [
            {"port": "443/tcp", "view": "network", "from_zone": f"z{(z - 1) % 50}"},
            {"port": "22/tcp", "view": "network", "from_zone": "z49"},
        ]
        ids = {"hostname": f"h{i}", "ips": [ip]}
        hosts.append(AssetObservation(f"h{i}", "host", "openvas", TODAY, f"h{i}", identifiers=ids, services=services))
    pcs = [
        AssetObservation(f"pc{i}", "host", "sentinelone", TODAY, f"pc{i}",
                         identifiers={"hostname": f"pc{i}", "ips": [f"172.16.{i // 250}.{i % 250 + 1}"]})
        for i in range(10000)
    ]  # fmt: skip
    ext = AssetObservation(
        "203.0.113.9", "host", "external-scan", TODAY, "203.0.113.9", identifiers={"ips": ["203.0.113.9"]}
    )
    detections = [
        Detection("big", "openvas", hosts, []),
        Detection("big", "sentinelone", pcs, []),
        Detection("big", "external-scan", [ext], []),
    ]
    started = time.monotonic()
    inv = build_inventory(p, detections, now=NOW)
    elapsed = time.monotonic() - started
    assert len(inv.assets) == 70001 and len(inv.graph.edges) < 5 * len(inv.assets)
    assert len(inv.graph.off_premises) == 10000
    assert elapsed < 120, f"assets stage of 70,000 assets in {elapsed:.0f} s"
