import datetime as dt
import json

from vulnops.core.io import read_findings, read_records, write_findings, write_records
from vulnops.core.llm import LlmClient
from vulnops.detect.inventory import InventoryScanner
from vulnops.intel.collect import collect, select_cve_ids
from vulnops.verdict.report import render_markdown, write_all
from vulnops.verdict.triage import Triage

from .conftest import fake_llm_transport

ALL = [f"CVE-2099-1000{i}" for i in range(1, 8)] + ["CVE-2024-3400"]


def _run(settings, sources, profile, llm=None, tmp=None):
    """intel -> detect -> verdict, through the exchange files when `tmp` is given."""
    collected = collect(sources, ALL)
    records = {r.cve_id: r for r in collected.records}
    requested, errors = collected.requested, collected.errors
    if tmp:
        write_records(tmp / "records.json", collected.records, requested, errors)
        requested, records, errors = read_records(tmp / "records.json")
    ordered = [records[c] for c in requested if c in records]
    found = InventoryScanner(settings, llm).scan(profile, ordered)
    findings, not_affected = found.findings, found.not_affected
    if tmp:
        write_findings(tmp / "findings.json", profile.id, findings, not_affected)
        _, findings, not_affected = read_findings(tmp / "findings.json")
    return Triage(settings, llm).run(profile, records, findings, not_affected, len(requested), errors)


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

    assert {e["cve"]: e["error"] for e in run.errors} == {
        "CVE-2099-10006": "CVE rejected",
        "CVE-2099-10007": "CVE record not found",
    }
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

    assert "CVE-2099-10004" not in rows  # fuzzy match rejected by the LLM
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
    llm = LlmClient(settings.llm, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    run = _run(settings, sources, profile, llm)
    rows = _by_cve(run)
    assert rows["CVE-2024-3400"].rationale_source.startswith("template (LLM error: rationale:")
    assert "503" in rows["CVE-2024-3400"].rationale_source
    assert rows["CVE-2099-10005"].automatable.source == "default"
    assert "CVE-2099-10004" in rows and rows["CVE-2099-10004"].needs_review
    assert "ACT" in render_markdown(run)


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

    from vulnops.core.io import ExchangeError

    bad = tmp_path / "records.json"
    bad.write_text(json.dumps({"schema": "vulnops.findings/1"}))
    with pytest.raises(ExchangeError, match="expected a vulnops.records/1 file"):
        read_records(bad)
    bad.write_text(
        json.dumps(
            {"schema": "vulnops.records/1", "generated_at": "x", "requested": ["nope"], "records": [], "errors": []}
        )
    )
    with pytest.raises(ExchangeError, match="requested/0"):
        read_records(bad)
