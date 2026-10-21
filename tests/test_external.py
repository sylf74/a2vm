# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""External scan: artifacts download, checks, `published` mapping and exposure precedence."""

from __future__ import annotations

import datetime as dt
import io
import json
import zipfile

import httpx
import pytest
import yaml

from a2vm.gitlab import ArtifactNotFound, GitLabError, download_artifacts
from a2vm.io import Detection, read_assets, read_findings, write_assets, write_detection, write_findings
from a2vm.models import AssetObservation, Finding, FindingObservation, Match
from a2vm.profile import load_profile
from detect.external import SOURCE, as_internal, pull
from verdict.assets.build import build_inventory

NOW = dt.datetime(2026, 10, 21, 8, 0, tzinfo=dt.UTC)
ENV = {"CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_JOB_TOKEN": "job-token"}


def _profile(tmp_path, **extra):
    data = {
        "schema_version": 2,
        "client": {"id": "acme", "name": "ACME", "updated": "2026-10-21"},
        "defaults": {"exposure": "controlled"},
        "rules": [{"ip": "10.0.0.0/16", "set": {"exposure": "controlled", "zone": "lan"}}],
        "assets": [],
        "external": {"client": "acme-external", "max_age_days": 8},
        "published": [
            {"endpoint": "www.example.org:443", "asset": "rproxy01", "behind": ["app01"], "zone": "dmz"},
        ],
        **extra,
    }
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    return load_profile(path)


def _host(ref, source, observed_at, hostname=None, fqdn=None, ips=()):
    ids = {}
    if hostname:
        ids["hostname"] = hostname
    if fqdn:
        ids["fqdn"] = fqdn
    if ips:
        ids["ips"] = list(ips)
    return AssetObservation(ref, "host", source, observed_at, hostname or ref, identifiers=ids)


def _finding(client, ref, cve, source, observed_at, version="1.0"):
    return Finding(
        Finding.make_id(client, ref, cve),
        client,
        ref,
        cve,
        "affected",
        [version],
        [FindingObservation(source, observed_at, Match("scanner", "", "pkg", 1.0), "pkg", version)],
    )


def _internal():
    seen = "2026-10-21T05:30:00+00:00"
    obs = [
        _host("rproxy01.lan.example", "trivy", seen, "rproxy01", "rproxy01.lan.example", ["10.0.2.4"]),
        _host("app01.lan.example", "trivy", seen, "app01", "app01.lan.example", ["10.0.10.5"]),
        _host("db01.lan.example", "trivy", seen, "db01", "db01.lan.example", ["10.0.10.6"]),
    ]
    return Detection("acme", "trivy", obs, [_finding("acme", "rproxy01.lan.example", "CVE-2026-0001", "trivy", seen)])


def _external(client="acme-external", seen="2026-10-20T22:00:00+00:00"):
    obs = [
        _host("203.0.113.10", "openvas", seen, fqdn="www.example.org", ips=["203.0.113.10"]),
        _host("198.51.100.7", "openvas", seen, ips=["198.51.100.7"]),
    ]
    findings = [
        _finding(client, "203.0.113.10", "CVE-2026-0001", "openvas", seen),
        _finding(client, "203.0.113.10", "CVE-2026-0002", "openvas", seen),
        _finding(client, "198.51.100.7", "CVE-2026-0003", "openvas", seen),
    ]
    return Detection(client, "openvas", obs, findings)


# -- checks and rewriting -------------------------------------------------------------------------
def test_external_detection_is_rewritten_for_the_internal_client(tmp_path):
    result = as_internal(_profile(tmp_path), [_external()], now=NOW)
    assert not result.problems
    d = result.detection
    assert (d.client_id, d.source) == ("acme", SOURCE)
    assert {o.source for o in d.observations} == {SOURCE}
    assert {f.client_id for f in d.findings} == {"acme"}
    assert {o.source for f in d.findings for o in f.observations} == {SOURCE}


def test_external_detection_of_another_client_or_too_old_is_left_out(tmp_path):
    profile = _profile(tmp_path)
    other = as_internal(profile, [_external(client="someone-else")], now=NOW)
    assert other.detection is None and "expected 'acme-external'" in other.problems[0]
    old = as_internal(profile, [_external(seen="2026-10-01T00:00:00+00:00")], now=NOW)
    assert old.detection is None and "20 days old (max 8)" in old.problems[0]


# -- published mapping and exposure ---------------------------------------------------------------
def test_published_endpoint_joins_its_internal_asset_and_raises_exposure(tmp_path):
    profile = _profile(tmp_path)
    external = as_internal(profile, [_external()], now=NOW).detection
    inv = build_inventory(profile, [_internal(), external])
    by_name = {a.name: a for a in inv.assets}

    rproxy = by_name["rproxy01"]
    exposure = rproxy.attributes["exposure"]
    assert (exposure.value, exposure.source) == ("open", "external-scan")
    assert "www.example.org:443" in exposure.note
    assert rproxy.identifiers["public"] == ["203.0.113.10", "www.example.org"]
    assert rproxy.identifiers["fqdns"] == ["rproxy01.lan.example"]  # the public name never names the asset
    assert rproxy.attributes["zone"].value == "lan"  # a rule wins over the published zone

    behind = by_name["app01"].attributes["exposure"]
    assert (behind.value, behind.source) == ("open", "external-scan") and "behind" in behind.note
    db = by_name["db01"].attributes["exposure"]
    assert (db.value, db.source) == ("controlled", "rule")  # not published: unchanged

    # One finding per asset and CVE, with the observations of both scans.
    found = {(f.asset_ref, f.cve_id): f for f in inv.findings}
    shared = found[(rproxy.id, "CVE-2026-0001")]
    assert shared.sources == ["external-scan", "trivy"]
    assert (rproxy.id, "CVE-2026-0002") in found

    # An external host no entry names stays an asset of its own, open from the external scan.
    stray = by_name["198.51.100.7"]
    assert (stray.attributes["exposure"].value, stray.attributes["exposure"].source) == ("open", "external-scan")

    # The exchange files accept the result.
    write_assets(tmp_path / "assets.json", inv.client_id, inv.assets)
    write_findings(tmp_path / "findings.json", inv.client_id, inv.findings, inv.not_affected)
    assert read_assets(tmp_path / "assets.json")
    assert read_findings(tmp_path / "findings.json")


def test_without_external_scan_published_changes_nothing(tmp_path):
    inv = build_inventory(_profile(tmp_path), [_internal()])
    rproxy = next(a for a in inv.assets if a.name == "rproxy01")
    assert (rproxy.attributes["exposure"].value, rproxy.attributes["exposure"].source) == ("controlled", "rule")
    assert "public" not in rproxy.identifiers


# -- GitLab artifacts -----------------------------------------------------------------------------
def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def test_download_extracts_only_the_prefix_and_never_outside(tmp_path):
    content = _zip(
        {
            "work/detect/acme-external/openvas.json": "{}",
            "work/scans/raw.xml": "x",
            "work/detect/acme-external/../../evil": "x",
        }
    )
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["token"] = str(request.url), request.headers.get("JOB-TOKEN")
        return httpx.Response(200, content=content)

    files = download_artifacts(
        "vulnops/clients/acme-external", "collect", "work/detect/acme-external", tmp_path / "out",
        environ=ENV, transport=httpx.MockTransport(handler),
    )  # fmt: skip
    assert [f.name for f in files] == ["openvas.json"]
    assert not (tmp_path / "evil").exists()
    assert seen["url"] == (
        "https://gitlab.example/api/v4/projects/vulnops%2Fclients%2Facme-external/jobs/artifacts/main/download?job=collect"
    )
    assert seen["token"] == "job-token"


def test_download_errors_are_explicit(tmp_path):
    def status(code):
        return httpx.MockTransport(lambda r: httpx.Response(code))

    with pytest.raises(ArtifactNotFound):
        download_artifacts("p", "collect", "work", tmp_path, environ=ENV, transport=status(404))
    with pytest.raises(GitLabError, match="Job token permissions"):
        download_artifacts("p", "collect", "work", tmp_path, environ=ENV, transport=status(403))
    with pytest.raises(GitLabError, match="credentials"):
        download_artifacts("p", "collect", "work", tmp_path, environ={"CI_API_V4_URL": "https://x/api/v4"})


def test_pull_end_to_end(tmp_path):
    profile = _profile(tmp_path)
    write_detection(tmp_path / "ext" / "openvas.json", _external(seen=dt.datetime.now(dt.UTC).isoformat()))
    payload = (tmp_path / "ext" / "openvas.json").read_text()
    content = _zip({"work/detect/acme-external/openvas.json": payload})
    result = pull(profile, "vulnops/clients/acme-external", environ=ENV,
                  transport=httpx.MockTransport(lambda r: httpx.Response(200, content=content)))  # fmt: skip
    assert not result.problems and result.detection is not None
    assert len(result.detection.findings) == 3
    assert json.loads(payload)["client_id"] == "acme-external"
