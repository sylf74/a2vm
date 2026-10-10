import json

from cve_triage.matching import match_assets
from cve_triage.models import AffectedEntry, Asset
from cve_triage.record import parse_record
from cve_triage.versions import evaluate, version_key

from .conftest import FIXTURES


def _entry(versions, default="unaffected", source="cna"):
    return AffectedEntry("v", "p", versions, default, [], source)


def test_version_ordering():
    assert version_key("11.1.2") < version_key("11.1.2-h1") < version_key("11.1.2-h3") < version_key("11.1.3")
    assert version_key("1.0.0rc1") < version_key("1.0.0") < version_key("1.0.1")
    assert version_key("10.2.9-h1 ") == version_key("10.2.9-h1")


def test_ranges_and_default_status():
    e = _entry([{"version": "7.2.0", "lessThan": "7.2.4", "status": "affected"}])
    assert evaluate("7.2.1", [e]) == "affected"
    assert evaluate("7.2.4", [e]) == "unaffected"
    assert evaluate("7.0.9", [e]) == "unaffected"
    unknown = _entry([{"version": "7.2.0", "lessThan": "7.2.4", "status": "affected"}], default="unknown")
    assert evaluate("7.0.9", [unknown]) == "unknown"
    le = _entry([{"version": "0", "lessThanOrEqual": "2.1", "status": "affected"}])
    assert evaluate("2.1", [le]) == "affected"
    assert evaluate("2.2", [le]) == "unaffected"


def test_changes_and_cna_precedence():
    e = _entry(
        [
            {
                "version": "10.0",
                "lessThan": "11.0",
                "status": "affected",
                "changes": [{"at": "10.5", "status": "unaffected"}],
            }
        ]
    )
    assert evaluate("10.4", [e]) == "affected"
    assert evaluate("10.6", [e]) == "unaffected"
    adp = _entry([{"version": "10.0", "lessThan": "11.0", "status": "affected"}], source="adp")
    assert evaluate("10.6", [e, adp]) == "unaffected"  # CNA statement wins


def test_real_record_pan_os():
    facts = parse_record(json.loads((FIXTURES / "cves" / "CVE-2024-3400.json").read_text()))
    assert facts.adp_ssvc == {
        "timestamp": facts.adp_ssvc["timestamp"],
        "exploitation": "active",
        "automatable": "yes",
        "technical_impact": "total",
    }
    asset = Asset(
        "fw",
        "fw",
        "Palo Alto Networks",
        "PAN-OS",
        "internet",
        "essential",
        "minimal",
        "net",
        cpe="cpe:2.3:o:paloaltonetworks:pan-os",
        versions=["11.1.2-h1", "11.1.2-h3"],
    )
    [m] = match_assets(facts, [asset])
    assert m.match.method == "cpe"
    assert evaluate("11.1.2-h1", m.entries) == "affected"
    assert evaluate("11.1.2-h3", m.entries) == "unaffected"
    assert evaluate("10.1.0", m.entries) == "unaffected"


def test_fuzzy_and_alias_matching(profile):
    facts = parse_record(json.loads((FIXTURES / "cves" / "CVE-2099-10004.json").read_text()))
    matches = match_assets(facts, profile.assets)
    assert [(m.asset.id, m.match.method) for m in matches] == [("vpn-gateways", "fuzzy")]
    facts.affected[0].product = "HR Portal"
    facts.affected[0].vendor = "Example Soft"
    matches = match_assets(facts, profile.assets)
    assert [(m.asset.id, m.match.method) for m in matches] == [("hr-portal", "alias")]
