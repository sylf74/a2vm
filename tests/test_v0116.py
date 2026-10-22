# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.11.6: what each decision tells the dashboards - CVSS rating, product kind, fix availability."""

from __future__ import annotations

from a2vm.models import AffectedEntry, Asset, CvssMetric, Finding, FindingObservation, Match, VulnRecord
from verdict.reporting import severity
from verdict.triage import fix_available, product_type


def _record(**kw) -> VulnRecord:
    base = dict(cve_id="CVE-2099-1", state="PUBLISHED", published=None, description="", cwes=[], cvss=[],
                affected=[], adp_ssvc=None, adp_kev=None, references=[])  # fmt: skip
    base.update(kw)
    return VulnRecord(**base)


def _entry(product: str, cpes: list[str], versions: list[dict] | None = None) -> AffectedEntry:
    return AffectedEntry("Acme", product, versions or [], "unaffected", cpes, "cna")


def _asset(kind: str = "host", os: str | None = None) -> Asset:
    return Asset("host:a", "t", kind, "a", "", {}, {}, ["inventory"], "", "", os)


def _finding(fixed: str = "") -> Finding:
    obs = FindingObservation("trivy", "2026-10-01T00:00:00Z", Match("exact", "acme", "lib", 1.0), "lib", "1.0", fixed)
    return Finding("t:a:CVE-2099-1", "t", "host:a", "CVE-2099-1", "affected", ["1.0"], [obs])


class _Row:
    def __init__(self, score):
        self.cvss = None if score == "none" else CvssMetric("3.1", "CVSS:3.1/AV:N", score, None, "cna")


def test_severity_follows_the_cvss_qualitative_scale():
    got = [severity(_Row(s)) for s in (9.8, 9.0, 7.0, 6.9, 4.0, 3.9, 0.0, None, "none")]
    assert got == ["Critical", "Critical", "High", "Medium", "Medium", "Low", "Low", "Unknown", "Unknown"]


def test_product_type_from_the_cpe_part_of_the_product_else_from_its_name_or_the_asset():
    rec = _record(affected=[_entry("Gate", ["cpe:2.3:o:acme:gate:*:*:*:*:*:*:*:*"]),
                            _entry("Portal", ["cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*"])])  # fmt: skip
    assert product_type(rec, "Acme", "Portal", _asset()) == "application"
    assert product_type(rec, "Acme", "Gate", _asset()) == "os"
    bare = _record()
    assert product_type(bare, "Acme", "SecureGate OS", _asset()) == "os"
    assert product_type(bare, "Microsoft", "Windows Server 2022", _asset(os="Windows Server 2022")) == "os"
    assert product_type(bare, "Acme", "lib", _asset(kind="image")) == "application"
    assert product_type(bare, "Acme", "Thing", _asset()) == ""


def test_a_fix_is_known_from_a_scanner_a_closed_range_or_a_patch_reference():
    assert fix_available(_record(), _finding(fixed="1.1"))
    closed = _record(affected=[_entry("lib", [], [{"version": "1.0", "lessThan": "1.1", "status": "affected"}])])
    assert fix_available(closed, _finding())
    open_ = _record(affected=[_entry("lib", [], [{"version": "0", "lessThan": "*", "status": "affected"}])])
    assert not fix_available(open_, _finding())
    patched = _record(references=[{"url": "https://example.org/p", "tags": ["patch"]}])
    assert fix_available(patched, _finding())
