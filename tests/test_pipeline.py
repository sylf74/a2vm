# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
import datetime as dt
import json

from a2vm.io import (
    read_assets,
    read_detection,
    read_findings,
    read_records,
    write_assets,
    write_detection,
    write_findings,
    write_records,
)
from a2vm.llm import LlmClient
from a2vm.models import Finding
from detect.inventory import InventoryScanner
from verdict.assets.build import build_inventory
from verdict.report import render_markdown, write_all
from verdict.triage import Triage, cvss_heuristic
from via.intel.collect import collect, select_cve_ids

from .conftest import fake_llm_transport

ALL = [f"CVE-2099-1000{i}" for i in range(1, 8)] + ["CVE-2024-3400"]


def _run(settings, sources, profile, llm=None, tmp=None):
    """intel -> detect -> assets -> verdict, through the exchange files when `tmp` is given."""
    collected = collect(sources, ALL)
    records = {r.cve_id: r for r in collected.records}
    requested, errors = collected.requested, collected.errors
    if tmp:
        write_records(tmp / "records.json", collected.records, requested, errors)
        requested, records, errors = read_records(tmp / "records.json")
    ordered = [records[c] for c in requested if c in records]
    detection = InventoryScanner(settings, llm).scan(profile, ordered)
    if tmp:
        write_detection(tmp / "detect.json", detection)
        detection = read_detection(tmp / "detect.json")
    inv = build_inventory(profile, [detection])
    assets = {a.id: a for a in inv.assets}
    findings, not_affected = inv.findings, inv.not_affected
    if tmp:
        write_assets(tmp / "assets.json", profile.id, inv.assets)
        write_findings(tmp / "findings.json", profile.id, findings, not_affected)
        _, assets = read_assets(tmp / "assets.json")
        _, findings, not_affected = read_findings(tmp / "findings.json")
    return Triage(settings, llm).run(profile, records, assets, findings, not_affected, len(requested), errors)


def _by_cve(run):
    return {r.cve_id: r for r in run.rows}


def test_deterministic_run(settings, sources, profile, tmp_path):
    run = _run(settings, sources, profile, tmp=tmp_path)
    rows = _by_cve(run)

    pan = rows["CVE-2024-3400"]
    assert (pan.delivery_decision, pan.ssvc_decision, pan.exploitation.source) == ("ACT", "act", "kev")
    assert pan.bod_timeline == "3 days & forensic investigation"
    assert not pan.needs_review and pan.affected_versions == ["11.1.2-h1"]

    hr = rows["CVE-2099-10001"]  # no ADP: CVSS heuristic, SSVC track, EPSS escalation
    assert (hr.ssvc_decision, hr.delivery_decision) == ("track", "ATTEND")
    assert hr.automatable.source == "cvss-heuristic" and hr.needs_review

    vpn = rows["CVE-2099-10002"]  # ADP poc/no/partial on an essential asset -> track* -> ATTEND
    assert (vpn.ssvc_decision, vpn.delivery_decision) == ("track*", "ATTEND")
    assert vpn.affected_versions == ["7.2.1"]

    assert [n.cve_id for n in run.not_affected] == ["CVE-2099-10003"]
    assert rows["CVE-2099-10004"].match.method == "fuzzy" and rows["CVE-2099-10004"].needs_review

    build = rows["CVE-2099-10005"]  # nothing known: conservative defaults
    assert (build.automatable.value, build.technical_impact.value) == ("yes", "total")
    assert build.automatable.source == "default" and build.version_status == "unknown"

    assert {e["cve"]: e["error"] for e in run.errors} == {"CVE-2099-10007": "CVE record not found"}
    assert [e["cve"] for e in run.ignored] == ["CVE-2099-10006"]  # rejected: listed, not an error
    assert [r.delivery_decision for r in run.rows] == sorted(
        (r.delivery_decision for r in run.rows), key=["ACT", "ATTEND", "TRACK"].index
    )

    target = write_all(run, tmp_path)
    data = json.loads((target / "triage.json").read_text())
    assert len(data["rows"]) == len(run.rows)
    assert "ACT — remédier maintenant" in (target / "report.md").read_text()
    assert (target / "triage.csv").read_text().splitlines()[0].startswith("decision;cve")


def test_fuzzy_drop_policy(settings, sources, profile):
    settings.policy["fuzzy_match_without_llm"] = "drop"
    assert "CVE-2099-10004" not in _by_cve(_run(settings, sources, profile))


def test_llm_run(settings, sources, profile):
    def answer(name, body):
        user = body["messages"][1]["content"]
        if name == "ssvc_inputs":
            return {"automatable": "no", "technical_impact": "partial", "justification": "Local user required."}
        if name == "product_match":
            return {"same_product": False, "justification": "Mobile client, not the gateway OS."}
        facts = json.loads(user.split("Faits :\n", 1)[1].split("\n\nDescription", 1)[0])
        if facts["cve"] == "CVE-2099-10002":  # invents a fixed version: must be rejected by the guard
            return {"summary": f"{facts['decision']} : faille corrigée en 7.2.9.", "action": "Mettre à jour."}
        return {"summary": f"Décision {facts['decision']} pour {facts['cve']}.", "action": "Planifier."}

    settings.llm.enabled = True
    transport = fake_llm_transport(answer)
    llm = LlmClient(settings.llm, transport=transport)
    rows = _by_cve(_run(settings, sources, profile, llm))

    # The LLM proposes "unlikely" for the fuzzy match: the candidate stays, flagged with the proposal.
    fuzzy = rows["CVE-2099-10004"]
    assert fuzzy.needs_review
    assert any("proposition du LLM : peu probable" in r for r in fuzzy.review_reasons)
    build = rows["CVE-2099-10005"]
    assert (build.automatable.value, build.automatable.source) == ("no", "llm")
    assert build.ssvc_decision == "track" and build.needs_review

    assert rows["CVE-2024-3400"].rationale_source.startswith("llm")
    assert rows["CVE-2024-3400"].rationale.startswith("Décision ACT")
    assert rows["CVE-2099-10002"].rationale_source.startswith("template (LLM output rejected: 7.2.9")

    # The decision never depends on the LLM: same decisions as the deterministic run for shared rows.
    names = [c["response_format"]["json_schema"]["name"] for c in transport.calls]
    assert names.count("ssvc_inputs") == 1 and names.count("product_match") == 1


def test_llm_failure_falls_back(settings, sources, profile):
    import httpx

    settings.llm.enabled = True
    settings.llm.max_retries = 0
    settings.llm.max_consecutive_errors = 100
    llm = LlmClient(settings.llm, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    run = _run(settings, sources, profile, llm)
    rows = _by_cve(run)
    assert rows["CVE-2024-3400"].rationale_source.startswith("template (LLM error: rationale:")
    assert "503" in rows["CVE-2024-3400"].rationale_source
    assert rows["CVE-2099-10005"].automatable.source == "default"
    assert "CVE-2099-10004" in rows and rows["CVE-2099-10004"].needs_review
    assert "ACT" in render_markdown(run)


def test_llm_circuit_breaker_and_budget(settings, sources, profile):
    import httpx

    calls = []

    def down(request):
        calls.append(request)
        return httpx.Response(503)

    settings.llm.enabled = True
    settings.llm.max_retries = 0
    settings.llm.max_consecutive_errors = 1
    run = _run(settings, sources, profile, LlmClient(settings.llm, transport=httpx.MockTransport(down)))
    # one failure, then the triage leaves the LLM alone for the rest of the run
    assert sum(r.rationale_source.startswith("template (LLM error") for r in run.rows) <= 1
    assert any("LLM down after 1 errors" in r.rationale_source for r in run.rows if r.delivery_decision != "TRACK")

    settings.llm.max_consecutive_errors = 3
    settings.llm.max_calls = 0
    calls.clear()
    run = _run(settings, sources, profile, LlmClient(settings.llm, transport=httpx.MockTransport(down)))
    assert any("budget of 0 calls" in r.rationale_source for r in run.rows)


def test_select_cve_ids(sources):
    since = dt.datetime(2099, 10, 5, tzinfo=dt.UTC)
    assert select_cve_ids(sources, ["cve-2024-3400"], since) == ["CVE-2024-3400", "CVE-2099-10001", "CVE-2099-10002"]
    assert "CVE-2099-10003" in select_cve_ids(sources, [], since, include_updated=True)


def test_records_merge_kev_and_epss(sources):
    collected = collect(sources, ["CVE-2024-3400", "CVE-2099-10001"])
    pan, hr = collected.records
    assert pan.in_kev and pan.kev["dateAdded"] == "2024-04-12" and pan.epss == 0.943
    assert not hr.in_kev and hr.epss == 0.2 and hr.epss_percentile == 0.95


def test_exchange_files_are_validated(tmp_path):
    import pytest

    from a2vm.io import ExchangeError

    bad = tmp_path / "records.json"
    bad.write_text(json.dumps({"schema": "vulnops.findings/2"}))
    with pytest.raises(ExchangeError, match="expected a vulnops.records/1 file"):
        read_records(bad)
    bad.write_text(
        json.dumps(
            {"schema": "vulnops.records/1", "generated_at": "x", "requested": ["nope"], "records": [], "errors": []}
        )
    )
    with pytest.raises(ExchangeError, match="requested/0"):
        read_records(bad)


def test_one_rationale_per_cve_most_urgent_first(settings, sources, profile):
    import copy

    run = _run(settings, sources, profile)  # no LLM: template rationales
    act = _by_cve(run)["CVE-2024-3400"]
    others = []
    for i, exposed in enumerate((False, True, False)):
        r = copy.deepcopy(act)
        r.asset_id, r.asset_description, r.publicly_exposed = f"host{i}", f"host{i} (rocky 9)", exposed
        others.append(r)

    def answer(name, body):
        facts = body["messages"][1]["content"]
        assert '"affected_assets_count": 3' in facts and "host1 (rocky 9)" in facts
        return {"summary": "Décision ACT sur 3 actifs.", "action": "Appliquer le correctif."}

    transport = fake_llm_transport(answer)
    settings.llm.enabled = True
    triage = Triage(settings, LlmClient(settings.llm, transport=transport))
    triage._llm_rationales(others)
    assert len(transport.calls) == 1
    assert all(r.rationale == "Décision ACT sur 3 actifs. Appliquer le correctif." for r in others)
    assert all(r.rationale_source.endswith("3 actifs") for r in others)


def test_scanner_cvss_replaces_missing_record_cvss(settings):
    from a2vm.models import FindingObservation, Match
    from verdict.triage import scanner_metrics

    vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    match = Match("scanner", "", "kernel", 1.0, "")
    obs = FindingObservation("trivy", "2026-10-11", match, cvss_vector=vector, cvss_source="trivy:nvd")
    f = Finding("id", "c", "host:a", "CVE-2099-1", "affected", [], [obs])
    metric = scanner_metrics([f])["CVE-2099-1"]
    assert (metric.version, metric.source) == ("3.1", "trivy:nvd")
    assert cvss_heuristic(metric) == ("no", "total")


def test_cvss_v2_heuristic_and_preference_for_v3():
    from a2vm.models import FindingObservation, Match
    from verdict.triage import scanner_metrics

    match = Match("scanner", "", "443/tcp", 1.0, "")
    v2 = FindingObservation("openvas", "2026-10-18", match, cvss_vector="AV:N/AC:M/Au:N/C:P/I:P/A:N")
    metric = scanner_metrics([Finding("id", "c", "host:a", "CVE-2003-1567", "affected", [], [v2])])["CVE-2003-1567"]
    assert metric.version == "2.0" and cvss_heuristic(metric) == ("no", "partial")
    full = FindingObservation("openvas", "2026-10-18", match, cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert cvss_heuristic(scanner_metrics([Finding("i", "c", "h", "CVE-1", "affected", [], [full])])["CVE-1"]) == (
        "yes",
        "total",
    )
    v3 = FindingObservation("trivy", "2026-10-18", match, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    both = Finding("i", "c", "h", "CVE-2", "affected", [], [v2, v3])
    assert scanner_metrics([both])["CVE-2"].version == "3.1"


def test_rejected_cves_are_ignored_not_errors(settings, sources, profile):
    from a2vm.models import REJECTED

    collected = collect(sources, ALL)
    detection = InventoryScanner(settings).scan(profile, collected.records)
    inv = build_inventory(profile, [detection])
    records = {r.cve_id: r for r in collected.records}
    errors = [{"cve": "CVE-2026-105391", "error": REJECTED}, {"cve": "CVE-2099-99999", "error": "timeout"}]
    run = Triage(settings).run(profile, records, {a.id: a for a in inv.assets}, inv.findings, errors=errors)
    assert [e["cve"] for e in run.ignored] == ["CVE-2026-105391"]
    assert [e["cve"] for e in run.errors] == ["CVE-2099-99999"]
    md = render_markdown(run)
    assert "## Ignorées" in md and "CVE-2026-105391" in md.split("## Ignorées")[1].split("##")[0]


def test_reporting_dataset_follows_the_decisions(settings, sources, profile, tmp_path):
    import datetime as dt

    from a2vm.io import read_reporting
    from verdict import reporting

    run = _run(settings, sources, profile, tmp=tmp_path)
    write_all(run, tmp_path, settings.policy)
    data = read_reporting(tmp_path / profile.id / "reporting.json")  # stable path, schema checked
    assert data["schema"] == "a2vm.reporting/1" and data["run"]["tenant"]["id"] == profile.id
    assert len(data["decisions"]) == len(run.rows)
    assert sum(data["totals"]["findings"].values()) == len(run.rows)
    for level in ("ACT", "ATTEND", "TRACK"):
        assert data["totals"]["findings"][level] == sum(r.delivery_decision == level for r in run.rows)
    assert sum(sum(c.values()) for c in data["by_exposure"].values()) <= len(run.rows)
    assert data["run"]["sources"] and data["run"]["policy_hash"] == reporting.policy_hash(settings.policy)
    assert all(d["first_seen"] for d in data["decisions"])
    assert "client_id" not in json.dumps(data)  # one tenant, no internal model dump

    pan = next(d for d in data["decisions"] if d["cve"] == "CVE-2024-3400")
    start = dt.date.fromisoformat(pan["first_seen"])
    assert pan["due_date"] == (start + dt.timedelta(days=3)).isoformat()
    later = reporting.build(run, settings.policy, today=start + dt.timedelta(days=10))
    assert later["deadlines"]["overdue"] >= 1

    # Deterministic: the same run gives the same dataset.
    assert reporting.build(run, settings.policy) == reporting.build(run, settings.policy)
