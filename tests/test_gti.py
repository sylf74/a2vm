# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
import json

import httpx
import pytest

from vulnops.core.config import describe_gti, load_settings
from vulnops.core.gti import gti_unconfirmed, ssvc_exploitation
from vulnops.core.io import read_records, write_records
from vulnops.intel.collect import collect
from vulnops.intel.gti import enrich, parse_gti
from vulnops.intel.sources import Sources
from vulnops.verdict.triage import Triage

from .conftest import FIXTURES

CVES = ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-10004", "CVE-2024-3400"]


@pytest.fixture
def gti_settings(settings):
    settings.sources.gti_enabled = True
    return settings


def _fixture(cve):
    return json.loads((FIXTURES / "gti" / f"{cve}.json").read_text())


def test_parse_flat_view():
    view = parse_gti(_fixture("CVE-2099-10001"))
    assert view["id"] == "vulnerability--cve-2099-10001"
    assert view["exploitation_state"] == "confirmed" and view["exploit_availability"] == "publicly available"
    assert view["risk_rating"] == "high" and not view["risk_rating_predicted"]
    assert view["first_exploitation"] == "2100-01-02"
    predicted = parse_gti(_fixture("CVE-2099-10002"))
    assert predicted["risk_rating"] == "medium" and predicted["risk_rating_predicted"]


@pytest.mark.parametrize(
    "state, availability, expected",
    [
        ("Confirmed", "None", "active"),
        ("Wide", "Publicly Available", "active"),
        ("EXPLOITATION_STATE_CONFIRMED", "", "active"),
        ("Reported", "Trivial", "poc"),
        ("No Known", "Publicly Available", "poc"),
        ("No Known", "None", "none"),
        ("Suspected", "Known", None),  # not confirmed, no public exploit: no opinion, flagged
    ],
)
def test_ssvc_mapping(state, availability, expected):
    attributes = {"exploitation_state": state, "exploit_availability": availability}
    view = parse_gti({"data": {"id": "x", "attributes": attributes}})
    assert ssvc_exploitation(view)[0] == expected


def test_collect_enriches_and_round_trips(gti_settings, sources, tmp_path):
    out = collect(sources, CVES)
    assert {r.cve_id for r in out.records if r.gti} == set(CVES)
    assert any("4/4 CVE known to GTI" in n for n in out.notes)
    write_records(tmp_path / "records.json", out.records, out.requested, out.errors)  # schema-checked
    _, records, _ = read_records(tmp_path / "records.json")
    assert records["CVE-2099-10001"].gti["exploitation_state"] == "confirmed"


def test_disabled_by_default(settings, sources):
    assert all(r.gti is None for r in collect(sources, CVES).records)
    assert describe_gti(settings) == "GTI: disabled"


def test_triage_uses_gti_without_lowering_other_sources(gti_settings, sources):
    records = {r.cve_id: r for r in collect(sources, CVES).records}
    triage = Triage(gti_settings)

    confirmed = triage.cve_inputs(records["CVE-2099-10001"])  # no ADP, no KEV: GTI decides
    assert (confirmed.exploitation.value, confirmed.exploitation.source) == ("active", "gti")
    assert "2100-01-02" in confirmed.exploitation.note

    adp_poc = triage.cve_inputs(records["CVE-2099-10002"])  # ADP poc, GTI "no known": ADP kept
    assert (adp_poc.exploitation.value, adp_poc.exploitation.source) == ("poc", "cisa-adp")

    kev = triage.cve_inputs(records["CVE-2024-3400"])  # KEV and GTI agree: KEV is cited
    assert (kev.exploitation.value, kev.exploitation.source) == ("active", "kev")

    suspected = triage.cve_inputs(records["CVE-2099-10004"])
    assert gti_unconfirmed(records["CVE-2099-10004"].gti)
    assert suspected.exploitation.value != "active"
    assert any("suspectée par GTI" in r for r in suspected.review_reasons)


def _network_sources(settings, handler):
    return Sources(settings.sources, transport=httpx.MockTransport(handler))


def _records(sources_fixture, cves):
    return collect(sources_fixture, cves).records  # records from fixtures, GTI looked up separately


def test_request_shape_and_key(settings, sources, monkeypatch):
    monkeypatch.setenv("GTI_API_KEY", "k-test")
    seen = []

    def handler(request):
        seen.append(request)
        cve = request.url.path.rsplit("--", 1)[-1].upper()
        return httpx.Response(200, json=_fixture(cve))

    net = _network_sources(settings, handler)
    records = _records(sources, ["CVE-2099-10001"])
    notes = enrich(net, records)
    assert records[0].gti["risk_rating"] == "high"
    assert seen[0].url.path == "/api/v3/collections/vulnerability--cve-2099-10001"
    assert seen[0].headers["x-apikey"] == "k-test"
    assert "k-test" not in " ".join(notes)
    enrich(net, records)  # second run: answered from the cache
    assert len(seen) == 1


def test_refused_key_stops_lookups(settings, sources, monkeypatch):
    monkeypatch.setenv("GTI_API_KEY", "bad")
    settings.sources.gti_workers = 1
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})

    notes = enrich(_network_sources(settings, handler), _records(sources, CVES))
    assert len(calls) == 1
    assert any("stopped" in n and "401" in n for n in notes)


def test_budget_and_missing_key(settings, sources, monkeypatch):
    records = _records(sources, CVES)
    assert "not set" in enrich(_network_sources(settings, lambda r: httpx.Response(500)), records)[0]

    monkeypatch.setenv("GTI_API_KEY", "k")
    settings.sources.gti_max_calls = 1
    settings.sources.gti_workers = 1
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(404)

    notes = enrich(_network_sources(settings, handler), records)
    assert len(calls) == 1
    assert "cve-2099-10001" in calls[0]  # not in KEV and most severe first
    assert any("budget of 1" in n and "3 CVE" in n for n in notes)


def test_env_override(monkeypatch):
    monkeypatch.setenv("VULNOPS_GTI_ENABLED", "true")
    monkeypatch.setenv("GTI_API_KEY", "secret-123")
    line = describe_gti(load_settings())
    assert line.startswith("GTI: enabled") and "api key set" in line and "secret-123" not in line


def test_alert_fiche_uses_gti_facts_not_prose(gti_settings):
    from vulnops.alert.fiche import build
    from vulnops.alert.watch import Item, relevant
    from vulnops.core.profile import load_profile
    from vulnops.detect.inventory import InventoryScanner

    from .conftest import ROOT

    profile = load_profile(ROOT / "examples" / "example-client" / "client.yaml")
    src = Sources(gti_settings.sources, fixtures_dir=FIXTURES)
    item = Item("CVE:CVE-2099-10001", "cve", "CVE-2099-10001", ["CVE-2099-10001"], "")
    [alert] = relevant([item], profile, src, gti_settings, InventoryScanner(gti_settings))
    text = build(alert, gti_settings).markdown()
    assert "exploitation confirmée (Google Threat Intelligence), première exploitation observée le 2100-01-02" in text
    assert "Licensed analyst prose" not in text
    assert "exploitation confirmée par Google Threat Intelligence" in alert.reasons and alert.level == "urgent"
