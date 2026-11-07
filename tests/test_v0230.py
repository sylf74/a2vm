# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.0 (D20, first step): the components of each asset with their source and age, the package
advisories of the distributions in the records, and the watch naming the hosts whose packages hold
an affected version, with a level of proof."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from a2vm.models import Asset, Attribute, VulnRecord
from a2vm.packages import compare, covered, deb_compare, exposures, family, present, rpm_compare

from .conftest import FIXTURES, ROOT

CVE = "CVE-2021-3712"  # OpenSSL: the record is in the fixtures, with Red Hat and Debian advisories


# -- pillar 2: the distribution and the source package of each package ------------------------------
def test_packages_name_their_distribution_and_source_package() -> None:
    from detect.collect import PACKAGES, parse_packages

    assert "/etc/os-release" in PACKAGES and "%{SOURCERPM}" in PACKAGES and "${Source}" in PACKAGES
    rpm = parse_packages(
        "os\trocky\t9.4\n"
        "openssl-libs\t1:3.0.7-27.el9\tx86_64\trpm\topenssl-3.0.7-27.el9.src.rpm\n"
        "gpg-pubkey\t0:5a6340b3-6229229e\t(none)\trpm\t(none)\n"
    )
    assert rpm == [{
        "name": "openssl-libs", "version": "1:3.0.7-27.el9", "arch": "x86_64", "type": "rpm",
        "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4&epoch=1",
        "source_package": "openssl", "distro": "rocky-9.4", "source": "ssh",
    }]  # fmt: skip
    deb = parse_packages(
        "os\tdebian\t12\n"
        "ii \tlibssl3\t3.0.11-1~deb12u2\tamd64\tdeb\topenssl\n"
        "ii \tbash\t5.2.15-2+b2\tamd64\tdeb\tbash (5.2.15-2)\n"
        "rc \told\t1.0\tamd64\tdeb\t\n"
    )
    assert [(c["name"], c["source_package"], c["distro"]) for c in deb] == [
        ("bash", "bash", "debian-12"),
        ("libssl3", "openssl", "debian-12"),
    ]
    old = parse_packages("bash\t0:5.1.8-9.el9\tx86_64\trpm\n")  # a v0.22.2 collector
    assert old[0]["source_package"] == "bash" and "distro" not in old[0]


# -- pillar 3: components per source, each with its age --------------------------------------------
def test_components_keep_each_source_with_its_age() -> None:
    from a2vm.models import AssetObservation
    from verdict.assets.build import consolidate_components

    def obs(source, at, comps):
        return AssetObservation(ref="web01", kind="host", source=source, observed_at=at, name="web01", components=comps)

    group = [
        obs("trivy", "2026-11-05T06:00:00+00:00", [{"name": "bash", "version": "5.1", "source": "ssh"}]),
        obs("dnf-updateinfo", "2026-11-06T06:00:00+00:00", [{"name": "bash", "version": "5.2", "source": "ssh"}]),
        obs("edr", "2026-11-04T06:00:00+00:00", [{"name": "bash", "version": "5.0", "source": "edr"}]),
    ]
    comps, seen = consolidate_components(group)
    assert [(c["source"], c["version"], c["seen"][:10]) for c in comps] == [
        ("edr", "5.0", "2026-11-04"),
        ("ssh", "5.2", "2026-11-06"),
    ]
    assert seen.startswith("2026-11-06")
    assert consolidate_components([obs("trivy", "2026-11-05T06:00:00+00:00", [])]) == ([], "")


def test_schemas_carry_the_new_component_fields() -> None:
    from a2vm.io import load_schema

    item = load_schema("assets")["$defs"]["asset"]["properties"]["components"]["items"]
    assert {"source_package", "distro", "source", "seen"} <= set(item["properties"])
    record = load_schema("vulnerability_records")["$defs"]["record"]["properties"]
    assert record["packages"]["items"]["properties"]["state"]["enum"] == [
        "fixed",
        "affected",
        "investigating",
        "not_affected",
    ]


# -- versions and distributions -------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1:3.0.7-27.el9", "1:3.0.7-28.el9_4", -1),
        ("3.0.7-27.el9", "1:3.0.7-1.el9", -1),
        ("8.7p1-38.el9_4.4", "8.7p1-38.el9_4.1", 1),
        ("1.0~rc1-1", "1.0-1", -1),
        ("2.0a-1", "2.0-1", 1),
        ("5.1.8-10.el9", "5.1.8-9.el9", 1),
        ("1.0.1-1.el9_4", "1.0.1-1.el9", 1),
    ],
)
def test_rpm_versions(a, b, expected) -> None:
    assert rpm_compare(a, b) == expected and rpm_compare(b, a) == -expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("3.0.11-1~deb12u2", "3.0.11-1~deb12u3", -1),
        ("3.0.11-1~deb12u2", "3.0.11-1", -1),
        ("1:1.0-1", "2.0-1", 1),
        ("3.0.13-0ubuntu3.16", "3.0.13-0ubuntu3.5", 1),
        ("1.0+b1", "1.0", 1),
        ("2.39-0ubuntu8.9", "2.39-0ubuntu8.10", -1),
    ],
)
def test_deb_versions(a, b, expected) -> None:
    assert deb_compare(a, b) == expected and compare("deb", b, a) == -expected


def test_families() -> None:
    assert family("rocky-9.4") == family("rocky 9.4") == family("almalinux-9.5") == "rhel:9"
    assert family("debian-12") == "debian:12" and family("ubuntu-22.04") == "ubuntu:22.04"
    assert family("fedora-40") == "" and family("") == ""


# -- pillar 1: package advisories of the distributions ---------------------------------------------
def test_red_hat_and_osv_advisories(sources) -> None:
    from via.intel.packages import parse_osv, parse_redhat

    rh = parse_redhat(sources.package_advisory("redhat", CVE))
    by = {(a["distro"], a["name"]): a for a in rh}
    assert by[("rhel:8", "openssl")]["fixed"] == "1:1.1.1k-5.el8_5"  # main stream only, no EUS
    assert by[("rhel:8", "openssl")]["url"].endswith("/errata/RHSA-2099:0001")
    assert by[("rhel:7", "openssl")]["state"] == "affected" and by[("rhel:7", "openssl")]["fixed"] == ""
    assert by[("rhel:9", "openssl")]["state"] == "not_affected"
    assert not any("/" in n or ":" in n for _, n in by)  # no module, no container
    deb = parse_osv(sources.package_advisory("debian", CVE))
    assert {(a["distro"], a["name"], a["fixed"]) for a in deb} == {
        ("debian:11", "openssl", "1.1.1k-1+deb11u1"),
        ("debian:12", "openssl", "1.1.1l-1"),
        ("debian:11", "edk2", ""),
    }
    assert sources.package_advisory("ubuntu", CVE) is None
    assert parse_osv({"id": "UBUNTU-CVE-1", "affected": [{"package": {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": "x"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}) == []  # fmt: skip


def test_a_cve_without_an_advisory_is_not_asked_again(settings) -> None:
    from via.intel.sources import Sources

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(404)

    src = Sources(settings.sources, transport=httpx.MockTransport(handler))
    assert src.package_advisory("ubuntu", CVE) is None
    assert src.package_advisory("ubuntu", CVE) is None
    src.close()
    assert calls == [f"https://api.osv.dev/v1/vulns/UBUNTU-{CVE}"]


def test_records_carry_the_advisories_only_when_asked(sources, tmp_path) -> None:
    from a2vm.io import read_records, write_records
    from via.intel.collect import collect

    plain = collect(sources, [CVE])
    assert plain.records[0].packages == []
    out = collect(sources, [CVE], packages=True)
    assert {a["source"] for a in out.records[0].packages} == {"redhat", "osv"}
    assert any(n.startswith("packages: advisories of redhat, debian, ubuntu for 1/1") for n in out.notes)
    write_records(tmp_path / "records.json", out.records, out.requested, out.errors)  # schema-checked
    _, back, _ = read_records(tmp_path / "records.json")
    assert back[CVE].packages == out.records[0].packages


def test_a_record_with_an_unknown_field_is_still_read() -> None:
    raw = {
        "cve_id": CVE, "state": "PUBLISHED", "published": None, "description": "", "cwes": [], "cvss": [],
        "affected": [], "adp_ssvc": None, "adp_kev": None, "references": [], "a_later_field": 1,
    }  # fmt: skip
    assert VulnRecord.from_dict(raw).cve_id == CVE


def test_the_shared_service_sends_the_advisories_on_request(settings) -> None:
    from via.intel.remote import IntelClient

    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"records": [], "errors": []})

    client = IntelClient("https://intel.example.org", "t", transport=httpx.MockTransport(handler))
    client.records([CVE])
    client.records([CVE], packages=True)
    client.close()
    assert bodies == [{"cves": [CVE]}, {"cves": [CVE], "packages": True}]


# -- matching ---------------------------------------------------------------------------------------
def _components(distro, *pkgs):
    return [{"name": n, "version": v, "type": t, "source_package": s, "distro": distro, "source": "ssh",
             "seen": "2026-11-07T05:00:00+00:00"} for n, v, t, s in pkgs]  # fmt: skip


def _advisories(sources):
    from via.intel.packages import parse_osv, parse_redhat

    return parse_redhat(sources.package_advisory("redhat", CVE)) + parse_osv(sources.package_advisory("debian", CVE))


def test_exposures_by_distribution_and_version(sources) -> None:
    adv = _advisories(sources)
    old = _components("rocky-8.4", ("openssl-libs", "1:1.1.1g-15.el8_3", "rpm", "openssl"))
    (hit,) = exposures(CVE, old, adv)
    assert (hit.component, hit.source_package, hit.fixed, hit.state) == (
        "openssl-libs",
        "openssl",
        "1:1.1.1k-5.el8_5",
        "fixed",
    )
    fixed = _components("rocky-8.5", ("openssl-libs", "1:1.1.1k-5.el8_5", "rpm", "openssl"))
    assert exposures(CVE, fixed, adv) == [] and covered(fixed, adv)
    rhel9 = _components("rocky-9.4", ("openssl", "1:3.0.7-27.el9", "rpm", "openssl"))
    assert exposures(CVE, rhel9, adv) == [] and covered(rhel9, adv)  # Red Hat: not affected
    nofix = _components("rhel-7.9", ("openssl", "1:1.0.2k-25.el7_9", "rpm", "openssl"))
    assert exposures(CVE, nofix, adv)[0].state == "affected"
    deb = _components("debian-11", ("libssl1.1", "1.1.1k-1", "deb", "openssl"))
    assert exposures(CVE, deb, adv)[0].fixed == "1.1.1k-1+deb11u1"
    ubuntu = _components("ubuntu-22.04", ("openssl", "3.0.2-0ubuntu1", "deb", "openssl"))
    assert exposures(CVE, ubuntu, adv) == [] and not covered(ubuntu, adv)
    assert [c["name"] for c in present("OpenSSL", ubuntu)] == ["openssl"]
    # a v0.22.2 listing: no distribution (the asset's OS instead), no source package (the binary name)
    legacy = [{"name": "openssl", "version": "1:1.1.1g-15.el8_3", "type": "rpm"}]
    assert exposures(CVE, legacy, adv, os_name="rocky 8.4")[0].fixed == "1:1.1.1k-5.el8_5"


def _asset(asset_id, name, comps, exposure="open"):
    return Asset(
        asset_id, "acme", "host", name, name, {"hostnames": [name]},
        {"exposure": Attribute(exposure, "external-scan"), "zone": Attribute("dmz", "rule"),
         "owner": Attribute("web-team", "declared")},
        ["trivy"], "2026-11-07T05:00:00+00:00", "2026-11-07T05:00:00+00:00",
        components=comps, components_seen="2026-11-07T05:00:00+00:00",
    )  # fmt: skip


def test_the_watch_names_the_hosts_with_a_level_of_proof(settings, sources, profile) -> None:
    from detect.inventory import InventoryScanner
    from via.alert.fiche import build, concerned_rows
    from via.alert.inventory import Inventory
    from via.alert.watch import EXPOSED, Item, relevant

    inv = Inventory(profile.id, {
        "host:web01": _asset("host:web01", "web01",
                             _components("rocky-8.4", ("openssl-libs", "1:1.1.1g-15.el8_3", "rpm", "openssl"))),
        "host:db01": _asset("host:db01", "db01",
                            _components("rocky-8.5", ("openssl-libs", "1:1.1.1k-5.el8_5", "rpm", "openssl"))),
        "host:app01": _asset("host:app01", "app01",
                             _components("ubuntu-22.04", ("openssl", "3.0.2-0ubuntu1", "deb", "openssl")), "small"),
    }, {}, "2026-11-07T05:00:00+00:00")  # fmt: skip
    item = Item(f"CVE:{CVE}", "cve", CVE, [CVE], "", source="CVE (cvelistV5)")
    profile.alerts["level"] = "all"
    [alert] = relevant([item], profile, sources, settings, InventoryScanner(settings), inventory=inv)
    assert [(a.id, h.component) for a, h in alert.exposed] == [("host:web01", "openssl-libs")]
    assert [(a.id, named) for a, named in alert.possible] == [("host:app01", "openssl 3.0.2-0ubuntu1")]
    assert EXPOSED == "exposed"

    rows, open_ = concerned_rows(alert, "CVE", "en")
    by = {r["nom"]: r for r in rows}
    assert open_ and set(by) >= {"web01", "app01"} and "db01" not in by
    assert by["web01"]["preuve"] == "exposed" and by["web01"]["version_corrigee"] == "1:1.1.1k-5.el8_5"
    assert by["web01"]["source"] == "packages listed (ssh, 2026-11-07)"
    assert by["app01"]["preuve"] == "possible"
    fr = {r["nom"]: r for r in concerned_rows(alert, "CVE", "fr")[0]}
    assert fr["web01"]["preuve"] == "exposition" and fr["app01"]["preuve"] == "possible"
    md = build(alert, settings).markdown()
    assert "| Proof |" in md and "| exposed |" in md


def test_without_listed_packages_the_watch_asks_no_advisory(settings, sources, profile, monkeypatch) -> None:
    from detect.inventory import InventoryScanner
    from via.alert import watch
    from via.alert.inventory import Inventory

    asked = []
    real = watch.collect
    monkeypatch.setattr(watch, "collect", lambda s, ids, packages=False: asked.append(packages) or real(s, ids))
    inv = Inventory(profile.id, {"host:web01": _asset("host:web01", "web01", [])}, {}, "")
    item = watch.Item(f"CVE:{CVE}", "cve", CVE, [CVE], "")
    watch.relevant([item], profile, sources, settings, InventoryScanner(settings), inventory=inv)
    assert asked == [False]


def test_neutral_word_templates_have_the_proof_column() -> None:
    from docx import Document

    for lang, head in (("en", "Proof"), ("fr", "Preuve")):
        doc = Document(str(ROOT / "via" / "src" / "via" / "alert" / "templates" / f"alert.{lang}.docx"))
        assert any(head in c.text for t in doc.tables for c in t.rows[0].cells)


def test_package_fixtures_hold_no_real_advisory_number() -> None:
    for path in (FIXTURES / "packages").rglob("*.json"):
        assert not re.search(r"RHSA-20[0-8]\d", path.read_text()), path  # invented numbers only (RHSA-2099:...)


def test_release_and_d20_recorded() -> None:
    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.0( \(current\))? \| D20, first step", hld, re.M)
    for version in ("v0.23.1", "v0.23.2", "v0.23.3"):
        assert re.search(rf"^\| {re.escape(version)} \((to confirm|current)\) \| D20", hld, re.M), version
    assert "| D20 | **In progress: first step in v0.23.0" in hld
    assert "## v0.23.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    lld = (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text(encoding="utf-8")
    assert "### 14.7 Components of an asset (v0.23.0, HLD D20)" in lld


def test_the_shared_service_answers_the_advisories_on_request(tmp_path) -> None:
    from .test_v0220 import READ, _service

    service = _service(tmp_path)
    plain = service.records(READ, {"cves": [CVE]})
    assert plain["records"][0]["packages"] == []
    asked = service.records(READ, {"cves": [CVE], "packages": True})
    assert {a["source"] for a in asked["records"][0]["packages"]} == {"redhat", "osv"}
