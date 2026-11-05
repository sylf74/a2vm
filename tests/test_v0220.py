# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.22.0 (HLD D17): the shared intelligence service of every tenant, the radar of the watch team
(major vulnerabilities whoever they concern, zero-days before their CVE included, GTI as discovery,
optional), its validated events in the tenants' watches, and the analysts' Teams channel."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading

import httpx
import pytest
import yaml

from a2vm.config import load_settings
from a2vm.models import AffectedEntry, CvssMetric, VulnRecord
from a2vm.profile import load_profile, validate_profile_data
from a2vm.service import TokenSet, digest
from via.alert import radar, teams
from via.alert.certfr import Publication
from via.alert.cli import main as via_main
from via.alert.cli import push_technologies
from via.alert.feeds import Source
from via.alert.watch import Item, State, discover, relevant
from via.intel import collect as collect_mod
from via.intel.remote import IntelClient, IntelError
from via.intel.service import IntelService, IntelStore, make_handler
from via.intel.sources import Sources

from .conftest import FIXTURES, ROOT

READ, RADAR = "read-token-0123456789abcdef0123456789", "radar-token-0123456789abcdef012345678"
NOW = dt.datetime(2026, 11, 5, 8, 0, tzinfo=dt.UTC)


def _item(title, source="watchTowr Labs", category="research", cves=(), summary="", origin="lab", urgent=False,
          systems=(), link="https://lab.example/post"):  # fmt: skip
    pub = Publication(ref=title[:20], kind="rss", title=title, link=link, published="", cves=list(cves),
                      systems=list(systems), summary=summary, source=source)  # fmt: skip
    return Item(f"{origin}:{title[:20]}", origin, title, list(cves), "", publication=pub, source=source,
                category=category, urgent_source=urgent)  # fmt: skip


def _record(cve, vendor="Acme", product="Gateway", score=9.8):
    return VulnRecord(
        cve_id=cve, state="PUBLISHED", published=None, description="x", cwes=[],
        cvss=[CvssMetric("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score, "CRITICAL", "cna")],
        affected=[AffectedEntry(vendor, product, [], "affected", [], "cna")], adp_ssvc=None, adp_kev=None,
        references=[],
    )  # fmt: skip


# -- the radar's events ---------------------------------------------------------------------------
def test_markers_and_words():
    assert radar.markers(["Pre-auth RCE zero-day in Acme Gateway exploited in the wild"]) == [
        "in_the_wild", "zero_day", "unauthenticated", "rce"
    ]  # fmt: skip
    assert radar.markers(["Exécution de code arbitraire à distance, vulnérabilité activement exploitée"]) == [
        "in_the_wild", "rce"
    ]  # fmt: skip
    assert radar.words("Critical vulnerability in Acme Gateway SSL-VPN") == ["acme", "gateway", "ssl-vpn"]


def test_a_zero_day_without_cve_is_an_urgent_event_and_noise_is_not():
    state, cfg = {}, radar.RadarConfig()
    zero = _item("Acme Gateway SSL-VPN pre-auth RCE zero-day exploited in the wild")
    noise = _item("Stored XSS in a WordPress plugin", source="Some blog")
    out = radar.assess([zero, noise], {}, state, cfg, NOW)
    assert [(e["title"], why) for e, why in out] == [(zero.title, "new")]
    event = out[0][0]
    assert event["score"] == 8 and event["alerted"] == "urgent" and event["cves"] == []
    assert len(state["events"]) == 2  # the noise is kept, below the thresholds


def test_independent_sources_gather_and_raise_an_event():
    state, cfg = {}, radar.RadarConfig()
    first = _item("Acme Gateway SSL-VPN flaw under investigation", source="Lab A")
    out = radar.assess([first], {}, state, cfg, NOW)
    assert out == []  # 1: below info
    second = _item("Acme Gateway SSL-VPN flaw: proof of concept published", source="Lab B")
    third = _item("Acme Gateway SSL-VPN flaw reported to the vendor", source="Lab C")
    out = radar.assess([second, third], {}, state, cfg, NOW + dt.timedelta(hours=2))
    (event, why), = out  # fmt: skip
    assert why == "new" and event["alerted"] == "info" and len(event["sources"]) == 3
    assert event["score"] == 1 + 1 + 4  # one source, a proof of concept, two other sources
    cert = _item("Acme Gateway SSL-VPN flaw exploited in the wild", source="CERT-FR — alerts",
                 category="institutional", urgent=True)  # fmt: skip
    (event, why), = radar.assess([cert], {}, state, cfg, NOW + dt.timedelta(hours=3))  # fmt: skip
    assert why == "raised" and event["alerted"] == "urgent" and event["title"] == cert.title


def test_the_cve_joins_the_event_and_is_announced_once():
    state, cfg = {}, radar.RadarConfig()
    zero = _item("Acme Gateway pre-auth RCE zero-day exploited in the wild")
    radar.assess([zero], {}, state, cfg, NOW)
    rec = _record("CVE-2026-0001")
    cve = _item("CVE-2026-0001", source="CVE (cvelistV5)", category="institutional", cves=["CVE-2026-0001"],
                origin="cve")  # fmt: skip
    out = radar.assess([cve], {"CVE-2026-0001": rec}, state, cfg, NOW + dt.timedelta(hours=5))
    (event, why), = out  # fmt: skip
    assert why == "cve" and event["cves"] == ["CVE-2026-0001"] and len(state["events"]) == 1
    assert radar.assess([cve], {"CVE-2026-0001": rec}, state, cfg, NOW + dt.timedelta(hours=6)) == []
    old = NOW + dt.timedelta(days=20)
    radar.assess([], {}, state, cfg, old)
    assert state["events"] == {}  # kept 14 days


def test_the_payload_of_a_validated_event():
    state = {}
    zero = _item("Acme Gateway pre-auth RCE zero-day exploited in the wild", summary="Attackers use it.",
                 systems=[{"vendor": "Acme", "product": "Gateway", "description": ""}])  # fmt: skip
    other = _item("Acme Gateway zero-day exploited in the wild, patch out", source="Lab B",
                  link="https://b.example/post")  # fmt: skip
    (event, _), = radar.assess([zero, other], {}, state, radar.RadarConfig(), NOW)  # fmt: skip
    p = radar.payload(event, "urgent")
    assert p["products"] == [{"vendor": "Acme", "product": "Gateway"}] and p["summary"] == "Attackers use it."
    assert [link["url"] for link in p["links"]] == ["https://lab.example/post", "https://b.example/post"]
    assert p["terms"] == ["in_the_wild", "rce", "unauthenticated", "zero_day"]


def _radar_profile(tmp_path):
    data = {"schema_version": 2, "client": {"id": "via", "name": "Watch team", "updated": "2026-11-05"},
            "alerts": {"mode": "radar", "radar": {"info": 4, "urgent": 7}}}  # fmt: skip
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_the_radar_profile_is_valid():
    data = {"schema_version": 2, "client": {"id": "via", "name": "Watch team", "updated": "2026-11-05"},
            "alerts": {"mode": "radar", "radar": {"urgent": 8}}}  # fmt: skip
    assert validate_profile_data(data) == []
    data["alerts"]["radar"]["level"] = 3
    assert validate_profile_data(data)


def test_the_radar_watch_drafts_event_sheets(tmp_path, monkeypatch):
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    monkeypatch.delenv("A2VM_TEAMS_WEBHOOK", raising=False)
    profile = _radar_profile(tmp_path)
    args = ["watch", str(profile), "--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm",
            "--fixtures", str(FIXTURES), "--state", str(tmp_path / "state.json"),
            "--out", str(tmp_path / "alerts")]  # fmt: skip
    assert via_main(args) == 0
    state = State.load(tmp_path / "state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.kev.discard("CVE-2024-3400")
    state.save()
    assert via_main(args) == 0
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    pan = [a for a in index if "RADAR" in a["id"]]
    assert len(pan) == 1 and pan[0]["cves"] == ["CVE-2024-3400"] and pan[0]["radar"]["score"] >= 7
    assert pan[0]["level"] == "urgent"
    md = (tmp_path / "alerts" / f"{pan[0]['id']}.md").read_text()
    assert "Radar of the watch team: an event of magnitude" in md and "not matched to a client's assets" in md
    assert "## Links" in md and "CERTFR-2024-ALE-006" in md


# -- the shared intelligence service --------------------------------------------------------------
def _service(tmp_path, gti=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    digests = tmp_path / "digests"
    digests.write_text(f"read {digest(READ)}\nradar {digest(RADAR)}\n")
    settings = load_settings(ROOT / "config" / "settings.yaml")
    settings.sources.cache_dir = str(tmp_path / "cache")
    settings.sources.gti_enabled = gti
    service = IntelService(TokenSet.load(digests, {"read", "radar"}), IntelStore(tmp_path / "store"), settings)
    service.fixtures = str(FIXTURES)
    return service


@pytest.fixture
def intel(tmp_path):
    from a2vm.service import serve

    service = _service(tmp_path)
    httpd = serve(make_handler(service), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield service, f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_records_once_for_every_tenant(tmp_path, intel):
    service, url = intel
    client = IntelClient(url, READ)
    records, errors, _ = client.records(["CVE-2024-3400", "CVE-2099-99999"])
    assert [r.cve_id for r in records] == ["CVE-2024-3400"] and records[0].in_kev
    assert errors and errors[0]["cve"] == "CVE-2099-99999"
    with pytest.raises(IntelError, match="401"):
        IntelClient(url, RADAR).records(["CVE-2024-3400"])
    with pytest.raises(IntelError, match="400"):
        client.records(["not-a-cve"])


def test_collect_uses_the_shared_service_and_falls_back(tmp_path, intel, monkeypatch):
    _, url = intel
    token = tmp_path / "token"
    token.write_text(READ)
    settings = load_settings(ROOT / "config" / "settings.yaml")
    settings.sources.cache_dir = str(tmp_path / "tenant-cache")
    settings.sources.intel_url, settings.sources.intel_token_file = url, str(token)
    sources = Sources(settings.sources)
    out = collect_mod.collect_shared(sources, ["CVE-2024-3400"])
    assert out.records[0].cve_id == "CVE-2024-3400" and "from the shared service" in out.notes[-1]
    settings.sources.intel_url = "http://127.0.0.1:9"  # nothing listens there
    monkeypatch.setattr(collect_mod, "collect_direct", lambda s, ids: collect_mod.Collection(requested=ids))
    out = collect_mod.collect(sources, ["CVE-2024-3400"])
    assert out.notes[0].startswith("intel: shared intelligence service unreachable")


def test_technologies_are_kept_48_hours_without_who_sent_them(tmp_path):
    store = IntelStore(tmp_path)
    store.add_technologies([{"vendor": "Acme", "product": "Gateway"}, {"vendor": "", "product": ""}], NOW)
    store.add_technologies([{"vendor": "acme", "product": "gateway", "cpe": ""}], NOW + dt.timedelta(hours=1))
    assert store.technologies(NOW + dt.timedelta(hours=2)) == [{"vendor": "acme", "product": "gateway", "cpe": ""}]
    assert store.technologies(NOW + dt.timedelta(hours=50)) == []
    assert "tenant" not in (tmp_path / "technologies.json").read_text()


def test_the_feed_and_the_radar_events(tmp_path):
    service = _service(tmp_path)
    event = {"id": "R20261105-0001", "level": "urgent", "title": "Acme Gateway zero-day", "cves": ["CVE-2026-0001"],
             "products": [{"vendor": "Acme", "product": "Gateway"}], "terms": ["zero_day"],
             "links": [{"title": "Lab", "url": "https://lab.example/post"}, {"title": "x", "url": "javascript:x"}],
             "score": 9, "secret": "never kept"}  # fmt: skip
    from a2vm.service import Problem

    with pytest.raises(Problem):
        service.publish(READ, event)
    assert service.publish(RADAR, event) == {"id": "radar:R20261105-0001"}
    first = service.feed(READ)
    (item,) = first["items"]
    assert item["links"] == [{"title": "Lab", "url": "https://lab.example/post"}] and "secret" not in item
    assert service.feed(READ, first["next"]) == {"items": [], "next": first["next"]}
    service.publish(RADAR, {**event, "level": "info"})  # the same event again: replaced, after the mark
    later = service.feed(READ, first["next"])["items"]
    assert len(later) == 1 and later[0]["level"] == "info" and len(service.feed(READ)["items"]) == 1
    with pytest.raises(Problem):
        service.publish(RADAR, {"id": "x", "title": "no product"})


def test_gti_searches_the_technologies_watched(tmp_path):
    service = _service(tmp_path, gti=True)
    fixtures = tmp_path / "fx"
    (fixtures / "gti" / "search").mkdir(parents=True)
    service.fixtures = str(fixtures)
    service.store.add_technologies([{"vendor": "Acme", "product": "Gateway"}], NOW)
    query = (
        'collection_type:vulnerability AND vulnerable_product:"Gateway" AND vulnerable_vendor:"Acme" AND '
        "last_modification_date:2026-11-03+"
    )
    obj = {"id": "vulnerability--cve-2026-0001", "attributes": {
        "name": "CVE-2026-0001", "exploitation_state": "EXPLOITATION_STATE_CONFIRMED", "risk_rating": "CRITICAL",
        "executive_summary": "Licensed prose."}}  # fmt: skip
    (fixtures / "gti" / "search" / f"{hashlib.sha256(query.encode()).hexdigest()[:16]}.json").write_text(
        json.dumps({"data": [obj]})
    )
    notes = service.search_technologies(NOW)
    assert notes[-1].startswith("GTI: 1 searches") and "1 new" in notes[-1]
    (item,) = service.store.feed()
    assert item["id"] == "gti:CVE-2026-0001" and item["facts"]["exploitation_state"] == "confirmed"
    assert "Licensed prose" not in json.dumps(item)
    service.search_technologies(NOW)
    assert len(service.store.feed()) == 1  # known: not again
    assert _service(tmp_path / "off").search_technologies(NOW) == ["GTI: disabled, no search on the technologies"]


def test_a_tenant_watch_reads_the_feed_and_matches_its_assets(tmp_path, intel):
    service, url = intel
    token = tmp_path / "token"
    token.write_text(READ)
    settings = load_settings(ROOT / "config" / "settings.yaml")
    settings.sources.cache_dir = str(tmp_path / "tenant-cache")
    settings.sources.intel_url, settings.sources.intel_token_file = url, str(token)
    sources = Sources(settings.sources, fixtures_dir=FIXTURES)
    catalogue = [Source("a2vm-intel", "A2VM — radar", "radar", "intel")]
    state = State.load(tmp_path / "state.json")
    state.new = False
    items, errors = discover(sources, state, catalogue=catalogue)
    assert items == [] and errors == [] and "a2vm-intel" in state.marks  # baseline
    service.publish(RADAR, {"id": "R1", "level": "urgent", "title": "Acme SecureGate OS zero-day exploited",
                            "products": [{"vendor": "Acme Networks", "product": "SecureGate OS"}]})  # fmt: skip
    service.publish(RADAR, {"id": "R2", "level": "urgent", "title": "Another product",
                            "products": [{"vendor": "Nobody", "product": "Nothing Server"}]})  # fmt: skip
    items, errors = discover(sources, state, catalogue=catalogue)
    assert [i.key for i in items] == ["a2vm-intel:radar:R1", "a2vm-intel:radar:R2"] and items[0].urgent_source
    profile = load_profile(ROOT / "examples" / "example-client" / "client.yaml")
    from a2vm.declared import DeclaredMatcher

    alerts = relevant(items, profile, sources, settings, DeclaredMatcher(settings, None), None, catalogue, None)
    assert [a.item.key for a in alerts] == ["a2vm-intel:radar:R1"] and alerts[0].level == "urgent"
    assert alerts[0].product_matches and items[0].category == "radar"


def test_the_watch_sends_its_technologies_at_most_twice_a_day(tmp_path):
    sent = []

    def answer(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"kept": 3})

    token = tmp_path / "token"
    token.write_text(READ)
    settings = load_settings(ROOT / "config" / "settings.yaml")
    settings.sources.intel_url, settings.sources.intel_token_file = "http://intel.example", str(token)
    profile = load_profile(ROOT / "examples" / "example-client" / "client.yaml")
    state = State.load(tmp_path / "state.json")
    note = push_technologies(settings, profile, state, httpx.MockTransport(answer))
    assert (
        note.startswith("intel:")
        and {"vendor": "Acme Networks", "product": "SecureGate OS", "cpe": ""} in sent[0]["items"]
    )
    assert "client" not in json.dumps(sent[0]) and profile.id not in json.dumps(sent[0])
    assert push_technologies(settings, profile, state, httpx.MockTransport(answer)) == ""
    assert len(sent) == 1


def test_a_validated_radar_alert_is_published(tmp_path, monkeypatch):
    got = {}

    def answer(request):
        got["auth"], got["body"] = request.headers["authorization"], json.loads(request.content)
        return httpx.Response(200, json={"id": "radar:R1"})

    token = tmp_path / "radar-token"
    token.write_text(RADAR)
    monkeypatch.setenv("A2VM_INTEL_URL", "http://intel.example")
    monkeypatch.setenv("A2VM_INTEL_RADAR_TOKEN_FILE", str(token))
    entry = {"id": "via-RADAR-R1", "radar": {"id": "R1", "title": "t", "products": [{"product": "p"}]}}
    assert radar.publish(entry, httpx.MockTransport(answer)) == "radar: radar:R1 published to the tenants' watches"
    assert got["auth"] == f"Bearer {RADAR}" and got["body"]["id"] == "R1"
    assert radar.publish({"id": "x"}) == ""
    monkeypatch.delenv("A2VM_INTEL_URL")
    assert "not published" in radar.publish(entry)


# -- Teams --------------------------------------------------------------------------------------------
def test_the_analysts_teams_channel(tmp_path, monkeypatch):
    posted = []

    def answer(request):
        posted.append(json.loads(request.content))
        return httpx.Response(202)

    class P:
        id = "homelab"

    monkeypatch.delenv("A2VM_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("A2VM_TEAMS_WEBHOOK_FILE", raising=False)
    alert = {"id": "a1", "level": "urgent", "title": "Zero-day", "cves": ["CVE-2026-0001"], "radar": {"score": 9}}
    assert teams.notify(P, alert, 1, 2, "https://review.example/alerts/a1") == ""
    hook = tmp_path / "hook"
    hook.write_text("https://teams.example/webhook/secret-sig\n")
    monkeypatch.setenv("A2VM_TEAMS_WEBHOOK_FILE", str(hook))
    assert teams.notify(P, alert, 1, 2, "https://review.example/alerts/a1", httpx.MockTransport(answer)).startswith(
        "posted to Teams"
    )
    card = posted[0]["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    content = json.dumps(card["content"])
    assert "Zero-day" in content and "CVE-2026-0001" in content and "review.example/alerts/a1" in content
    assert "Magnitude" in content

    def down(request):
        raise httpx.ConnectError("https://teams.example/webhook/secret-sig refused")

    with pytest.raises(teams.TeamsError) as e:
        teams.notify(P, alert, 1, 1, "", httpx.MockTransport(down))
    assert "secret-sig" not in str(e.value)


# -- deployment and documents -------------------------------------------------------------------------
def test_the_chart_runs_the_shared_service_for_the_watch_team_only():
    charts = ROOT / "deploy" / "charts" / "a2vm-tenant"
    values = yaml.safe_load((charts / "values.yaml").read_text())
    assert values["intel"]["url"] == "" and values["intel"]["serve"]["enabled"] is False
    intel = (charts / "templates" / "intel.yaml").read_text()
    assert "via intel-serve" in intel and "{{- if .Values.intel.serve.enabled }}" in intel
    assert "values: [daily, watch, send]" in intel and "key: gti-api-key" in intel
    helpers = (charts / "templates" / "_helpers.tpl").read_text()
    for var in ("A2VM_INTEL_URL", "A2VM_INTEL_TOKEN_FILE", "A2VM_INTEL_RADAR_TOKEN_FILE", "A2VM_TEAMS_WEBHOOK_FILE"):
        assert var in helpers
    pipeline = (ROOT / "templates" / "client-pipeline.yml").read_text()
    assert (
        'put intel-token "${A2VM_INTEL_TOKEN:-}"' in pipeline
        and 'put teams-webhook "${A2VM_TEAMS_WEBHOOK:-}"' in pipeline
    )
    assert "$DISPATCH $INTEL -f" in pipeline and "A2VM_INTEL_SERVE" in pipeline


def test_the_catalogue_keeps_the_radar_sources_for_the_radar():
    from via.alert.feeds import load_catalogue

    catalogue = {s.id: s for s in load_catalogue(ROOT / "config" / "watch-sources.yaml")}
    assert catalogue["a2vm-intel"].kind == "intel" and not catalogue["a2vm-intel"].radar_only
    assert catalogue["gti-radar"].kind == "gti" and catalogue["gti-radar"].radar_only
    assert all(not s.enabled for s in catalogue.values() if s.radar_only and s.kind == "rss")


def test_d17_and_the_release_are_recorded():
    import re

    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text()
    assert re.search(r"^\| v0\.22\.0( \(current\))? \| D17: the shared intelligence service", hld, re.M)
    assert re.search(r"^\| v0\.22\.[12] \(consolidation, to confirm\) \| Respect of the client's SLA", hld, re.M)
    assert "`intel.v1.yaml`" in hld and "radar of the watch team" in hld
    lld = (ROOT / "docs" / "lld" / "vulnerability-intelligence.md").read_text()
    assert "### 3.10 The shared intelligence service" in lld and "### 3.11 The radar" in lld
    assert (ROOT / "docs" / "radar.md").is_file()
