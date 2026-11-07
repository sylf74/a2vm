# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.22.2: consolidation (radar precision, optional sharing of technologies, chat questions, full
package list, respect of the SLA measured on when a fix happened, radar proposals of the LLM)."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from via.alert import radar

NOW = dt.datetime(2026, 11, 7, 8, 0, tzinfo=dt.UTC)


def _item(title, cves=(), source="vendor-x", category="vendor", origin="rss", summary="", urgent=False):
    pub = SimpleNamespace(title=title, summary=summary, link=f"https://example.org/{source}", systems=[])
    return SimpleNamespace(
        title=title, cves=list(cves), source=source, category=category, origin=origin, publication=pub,
        facts={}, urgent_source=urgent,
    )  # fmt: skip


def test_markers_of_one_source_not_added_to_another() -> None:
    state: dict = {}
    cfg = radar.RadarConfig()
    a = _item("Product A flaw", ["CVE-2026-0001"], source="s1", summary="remote code execution")
    b = _item("Product A issue", ["CVE-2026-0001"], source="s2", summary="proof of concept available")
    radar.assess([a, b], {}, state, cfg, NOW)
    (event,) = state["events"].values()
    # best source 1 + 1 (rce), plus 2 for the other source; not 1 + 1 + 1 + 2
    assert event["score"] == 4
    assert sorted(event["markers"]) == ["poc", "rce"]


def test_bulletin_does_not_gather_by_cve() -> None:
    state: dict = {}
    cfg = radar.RadarConfig()
    cves = [f"CVE-2026-{1000 + i}" for i in range(20)]
    bulletin = _item(
        "Multiples vulnérabilités dans les produits Exemple", cves, source="certfr", category="institutional"
    )
    advisory = _item("SSA-1: remote code execution in Exemple Gateway", [cves[3]], source="vendor-exemple",
                     summary="unauthenticated remote code execution")  # fmt: skip
    radar.assess([bulletin, advisory], {}, state, cfg, NOW)
    assert len(state["events"]) == 2
    bulk = [e for e in state["events"].values() if e["bulk"]]
    assert len(bulk) == 1 and len(bulk[0]["cves"]) == 20


def test_old_sources_without_markers_take_the_event_markers() -> None:
    event = {"markers": ["rce"], "sources": [{"source": "s1", "base": 1}]}
    assert radar._score(event) == 2


def test_bulk_cves_in_profile_schema() -> None:
    from a2vm.io import load_schema

    radar_props = load_schema("client_profile")["properties"]["alerts"]["properties"]["radar"]["properties"]
    assert "bulk_cves" in radar_props
    assert radar.RadarConfig().bulk_cves == 10


def test_technologies_are_not_sent_unless_the_profile_shares_them(tmp_path) -> None:
    from pathlib import Path

    import httpx

    from a2vm.config import load_settings
    from a2vm.profile import load_profile
    from via.alert.cli import push_technologies
    from via.alert.watch import State

    root = Path(__file__).resolve().parents[1]
    sent = []
    token = tmp_path / "token"
    token.write_text("t" * 40)
    settings = load_settings(root / "config" / "settings.yaml")
    settings.sources.intel_url, settings.sources.intel_token_file = "http://intel.example", str(token)
    profile = load_profile(root / "examples" / "example-client" / "client.yaml")
    state = State.load(tmp_path / "state.json")
    transport = httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={"kept": 1}))
    assert push_technologies(settings, profile, state, transport) == "" and not sent


def _index_with_components():
    from verdict.service.index import RunIndex

    doc = {
        "rows": [],
        "assets": [
            {"id": "host:web01.lab.example", "name": "web01", "kind": "host", "zone": "dmz", "exposure": "open",
             "components": [{"name": "openssl", "version": "3.0.7-27.el9", "type": "rpm"},
                            {"name": "openssl-libs", "version": "3.0.7-27.el9", "type": "rpm"}],
             "components_seen": "2026-11-07T06:00:00+00:00"},
            {"id": "host:db01.lab.example", "name": "db01", "kind": "host",
             "components": [{"name": "openssl", "version": "3.2.2-6.el9", "type": "rpm"}],
             "components_seen": "2026-11-07T06:00:00+00:00"},
            {"id": "host:edge01.lab.example", "name": "edge01", "kind": "host"},
        ],
    }  # fmt: skip
    return RunIndex({"id": "r1", "generated_at": "2026-11-07T06:00:00+00:00"}, doc)


def test_find_component_counts_in_the_service() -> None:
    idx = _index_with_components()
    out = idx.components({"name": "openssl"})
    assert out["assets_with_it"] == 2 and out["assets_listed"] == 2 and out["hosts_not_listed"] == 1
    assert out["versions"] == {"openssl 3.0.7-27.el9": 1, "openssl-libs 3.0.7-27.el9": 1, "openssl 3.2.2-6.el9": 1}
    exact = idx.components({"name": "OpenSSL", "exact": "true", "version": "3.2"})
    assert [i["asset"] for i in exact["items"]] == ["host:db01.lab.example"]


def test_find_component_needs_a_name() -> None:
    import pytest

    from verdict.service.index import QueryError

    with pytest.raises(QueryError):
        _index_with_components().components({})


def test_find_component_is_a_tool_and_in_the_contract() -> None:
    from pathlib import Path

    import yaml

    from verdict.service.tools import OPERATIONS

    assert any(op[1] == "find_component" and op[4] == "components" for op in OPERATIONS)
    spec = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "a2vm/src/a2vm/schemas/openapi/verdict.v1.yaml").read_text()
    )
    assert spec["paths"]["/v1/tenants/{tenant}/components"]["get"]["operationId"] == "findComponent"


def test_components_reach_the_asset_and_the_triage() -> None:
    from a2vm.models import AssetObservation
    from verdict.assets.build import build_inventory  # noqa: F401 - imported for its module's use below
    from verdict.triage import run_asset

    obs_old = AssetObservation(
        ref="web01",
        kind="host",
        source="trivy",
        observed_at="2026-11-06T06:00:00+00:00",
        name="web01",
        components=[{"name": "bash", "version": "5.1"}],
    )
    obs_new = AssetObservation(ref="web01", kind="host", source="dnf-updateinfo",
                               observed_at="2026-11-07T06:00:00+00:00", name="web01",
                               components=[{"name": "bash", "version": "5.2"}])  # fmt: skip
    from pathlib import Path

    from a2vm.io import Detection
    from a2vm.profile import load_profile

    root = Path(__file__).resolve().parents[1]
    profile = load_profile(root / "examples" / "example-client" / "client.yaml")
    inv = build_inventory(profile, [Detection(profile.id, "trivy", [obs_old], []),
                                    Detection(profile.id, "dnf-updateinfo", [obs_new], [])])  # fmt: skip
    (asset,) = [a for a in inv.assets if a.name == "web01"]
    assert asset.components == [{"name": "bash", "version": "5.2"}]
    entry = run_asset(asset)
    assert entry["components"] == [{"name": "bash", "version": "5.2"}] and entry["components_seen"].startswith(
        "2026-11-07"
    )
