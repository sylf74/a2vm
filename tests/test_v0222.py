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
