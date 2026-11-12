# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.11: the libraries (images, SBOMs, OSV), the libraries still in memory, the user forwarded.

D20 goes down to the libraries: Trivy lists those of an image with its digest, an SBOM gives those
of an application, OSV says every day which have a vulnerability known by a CVE, without touching
the hosts again. A library deleted on disk and still loaded by a process says a restart is needed.
The chat forwards the user to the tools and the LLM only when the tenant wants it."""

from __future__ import annotations

import json
import re
import subprocess

import httpx
import pytest

from a2vm.applications import is_application
from a2vm.io import read_detection, write_detection

from .conftest import ROOT

CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"name": "registry.example.org/shop/web:1.4"}},
    "components": [
        {"name": "jinja2", "version": "3.1.2", "purl": "pkg:pypi/jinja2@3.1.2"},
        {"name": "openssl", "version": "3.0.7", "purl": "pkg:deb/debian/openssl@3.0.7"},  # a distribution's
        {
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "components": [{"name": "minimist", "version": "1.2.5", "purl": "pkg:npm/minimist@1.2.5"}],
        },
    ],
}
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "name": "billing",
    "packages": [
        {
            "name": "log4j-core",
            "versionInfo": "2.14.1",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
            ],
        },
        {"name": "no-purl", "versionInfo": "1"},
    ],
}
TRIVY_IMAGE = {
    "SchemaVersion": 2,
    "CreatedAt": "2026-11-12T03:00:00Z",
    "Metadata": {
        "OS": {"Family": "debian", "Name": "12.7"},
        "RepoDigests": ["registry.example.org/shop/web@sha256:" + "a" * 64],
    },
    "Results": [
        {
            "Target": "debian",
            "Packages": [{"Name": "bash", "Version": "5.2", "Identifier": {"PURL": "pkg:deb/debian/bash@5.2"}}],
        },
        {
            "Target": "Python",
            "Packages": [{"Name": "jinja2", "Version": "3.1.2", "Identifier": {"PURL": "pkg:pypi/jinja2@3.1.2"}}],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-0101",
                    "PkgName": "jinja2",
                    "InstalledVersion": "3.1.2",
                    "FixedVersion": "3.1.3",
                    "Severity": "MEDIUM",
                }
            ],
        },
    ],
}


# -- SBOM ------------------------------------------------------------------------------------------
def test_cyclonedx_and_spdx_give_the_libraries_only() -> None:
    from detect.sbom import parse_sbom

    fmt, subject, libs = parse_sbom(CDX)
    assert fmt == "cyclonedx" and subject == "registry.example.org/shop/web:1.4"
    assert [c["purl"] for c in libs] == ["pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.5", "pkg:pypi/jinja2@3.1.2"]
    assert all(c["type"] == "library" and c["source"] == "sbom" for c in libs)
    fmt, subject, libs = parse_sbom(SPDX)
    assert (fmt, subject, [c["name"] for c in libs]) == ("spdx", "billing", ["log4j-core"])
    with pytest.raises(ValueError):
        parse_sbom({"hello": "world"})


def test_the_sbom_connector_reads_a_directory(tmp_path) -> None:
    from detect.sbom import SbomConfig, read

    (tmp_path / "web.cdx.json").write_text(json.dumps(CDX))
    (tmp_path / "billing.spdx.json").write_text(json.dumps(SPDX))
    (tmp_path / "broken.json").write_text("{")
    cfg = SbomConfig.from_dict(
        {"directory": str(tmp_path), "assets": [{"file": "billing.spdx.json", "kind": "host", "name": "app01"}]}
    )
    d = read(cfg, "lab", log=lambda _: None)
    refs = {o.ref: o for o in d.observations}
    assert set(refs) == {"host:app01", "image:registry.example.org/shop/web:1.4"}
    assert refs["host:app01"].identifiers == {"hostname": "app01"} and len(refs["host:app01"].components) == 1
    assert d.findings == [] and any("broken.json" in k for k in d.skipped)
    write_detection(tmp_path / "out.json", d)  # the schema takes libraries
    assert read_detection(tmp_path / "out.json").observations[0].components
    with pytest.raises(ValueError):
        SbomConfig.from_dict({"directory": "x", "assets": [{"file": "a", "kind": "router"}]})


def test_the_agent_knows_the_sbom_connector(tmp_path) -> None:
    from detect.agent import SbomConnector, load_config

    (tmp_path / "web.cdx.json").write_text(json.dumps(CDX))
    (tmp_path / "token").write_text("t")
    path = tmp_path / "collector.yaml"
    path.write_text(
        json.dumps(
            {
                "collector": "lan",
                "tenant": "lab",
                "service": "https://a2vm.example.org",
                "token_file": str(tmp_path / "token"),
                "connectors": [{"name": "apps", "type": "sbom", "directory": str(tmp_path)}],
            }
        )
    )
    cfg = load_config(path)
    connector = cfg.connectors[0]
    assert isinstance(connector, SbomConnector)
    detections, errors = connector.run("lab", tmp_path, log=lambda _: None)
    assert errors == [] and detections[0].source == "sbom"


# -- Trivy: the image's libraries and digest --------------------------------------------------------
def test_trivy_keeps_the_libraries_and_the_digest_of_an_image() -> None:
    from detect.collect import TRIVY_IMAGE as COMMAND
    from detect.scanners import Target, parse_trivy

    assert "--list-all-pkgs" in COMMAND
    d = parse_trivy(TRIVY_IMAGE, "lab", Target("web", kind="image", image="registry.example.org/shop/web:1.4"))
    o = d.observations[0]
    assert [c["purl"] for c in o.components] == ["pkg:pypi/jinja2@3.1.2"]  # bash: the distribution's advisories
    assert o.attributes["digest"].endswith("a" * 64) and len(d.findings) == 1
    host = parse_trivy(TRIVY_IMAGE, "lab", Target("web01", fqdn="web01.lab.example"))
    assert host.observations[0].components == [] and "digest" not in host.observations[0].attributes


def test_a_library_is_no_application() -> None:
    assert not is_application({"name": "jinja2", "version": "3.1.2", "type": "library"})
    assert not is_application({"name": "/usr/lib/libssl.so.3", "version": "", "type": "in-memory"})
    assert is_application({"name": "Jenkins", "version": "2.401", "type": "application"})


# -- the libraries still in memory ------------------------------------------------------------------
def test_a_deleted_library_still_loaded_is_found() -> None:
    from detect.collect import LOADED, parse_loaded

    assert "/proc/[0-9]*/maps" in LOADED and "(deleted)" in LOADED
    out = (
        "812\tnginx\t/usr/lib/x86_64-linux-gnu/libssl.so.3\n813\tnginx\t/usr/lib/x86_64-linux-gnu/libssl.so.3\nnoise\n"
    )
    assert parse_loaded(out) == [
        {
            "name": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "version": "",
            "type": "in-memory",
            "processes": "812 nginx, 813 nginx",
            "source": "ssh",
        },
    ]


def test_the_command_runs_in_a_shell(tmp_path) -> None:
    from detect.collect import LOADED

    proc = subprocess.run(
        LOADED.replace("nice -n 19 ionice -c3 ", ""), shell=True, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0  # nothing to find here, and no error: the processes of others are skipped


def test_collect_adds_the_loaded_libraries_to_the_host(tmp_path) -> None:
    from detect import collect as c

    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd[-1])
        if cmd[-1] == c.PACKAGES:
            return subprocess.CompletedProcess(cmd, 0, "openssl\t1:3.0.7-27.el9\tx86_64\trpm\n", "")
        if cmd[-1] == c.LOADED:
            return subprocess.CompletedProcess(cmd, 0, "812\tnginx\t/usr/lib64/libssl.so.3.0.7\n", "")
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"SchemaVersion": 2, "Results": []}), "")

    targets = tmp_path / "targets.yaml"
    targets.write_text(json.dumps({"client": "lab", "targets": [{"host": "web01.lab.example", "method": "trivy"}]}))
    detections, errors = c.collect(c.load_targets(targets), tmp_path / "raw", runner=runner, log=lambda _: None)
    assert errors == [] and c.LOADED in calls
    kinds = sorted(x["type"] for x in detections[0].observations[0].components)
    assert kinds == ["in-memory", "rpm"]


# -- OSV --------------------------------------------------------------------------------------------
def _osv_transport(fail: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(503)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-0000-0000-0001"}, {"id": "PYSEC-2099-1"}]}
                        if "jinja2" in q["package"]["purl"]
                        else {}
                        for q in queries
                    ]
                },
            )
        if request.url.path.endswith("GHSA-0000-0000-0001"):
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-0000-0000-0001",
                    "aliases": ["CVE-2099-0101"],
                    "affected": [
                        {
                            "package": {"purl": "pkg:pypi/jinja2"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}],
                        }
                    ],
                },
            )
        return httpx.Response(200, json={"id": "PYSEC-2099-1", "aliases": []})

    return httpx.MockTransport(handler)


def test_osv_finds_the_cves_of_the_libraries(tmp_path) -> None:
    from detect.osv import Osv, match

    detection = {
        "observations": [
            {
                "ref": "image:registry.example.org/shop/web:1.4",
                "kind": "image",
                "name": "web",
                "components": [
                    {"name": "jinja2", "version": "3.1.2", "type": "library", "purl": "pkg:pypi/jinja2@3.1.2"},
                    {"name": "lodash", "version": "4.17.21", "type": "library", "purl": "pkg:npm/lodash@4.17.21"},
                    {"name": "bash", "version": "5.2", "type": "deb"},
                ],
            }
        ]
    }
    osv = Osv(tmp_path / "cache", transport=_osv_transport())
    d = match([detection], "lab", osv, log=lambda _: None)
    assert [(f.cve_id, f.asset_ref) for f in d.findings] == [
        ("CVE-2099-0101", "image:registry.example.org/shop/web:1.4")
    ]
    fo = d.findings[0].observations[0]
    assert fo.source == "osv" and fo.fixed_version == "3.1.3" and fo.package == "jinja2"
    assert d.skipped == {"no CVE alias (PYSEC)": 1}
    assert (tmp_path / "cache" / "GHSA-0000-0000-0001.json").exists()  # kept for the next run
    write_detection(tmp_path / "osv.json", d)


def test_detect_osv_reads_the_work_directory_and_warns_offline(tmp_path, monkeypatch) -> None:
    from detect import osv as osv_module
    from detect.cli import main
    from detect.sbom import SbomConfig, read

    (tmp_path / "sbom").mkdir()
    (tmp_path / "sbom" / "web.cdx.json").write_text(json.dumps(CDX))
    work = tmp_path / "detect"
    write_detection(work / "lab" / "sbom.json", read(SbomConfig(str(tmp_path / "sbom")), "lab", log=lambda _: None))
    real = osv_module.Osv
    monkeypatch.setattr(osv_module, "Osv", lambda cache=None: real(cache, transport=_osv_transport()))
    assert main(["osv", "--mode", "api", "--detect", str(work), "--cache", str(tmp_path / "cache")]) == 0
    assert read_detection(work / "lab" / "osv.json").findings[0].cve_id == "CVE-2099-0101"
    monkeypatch.setattr(osv_module, "Osv", lambda cache=None: real(cache, transport=_osv_transport(fail=True)))
    assert main(["osv", "--mode", "api", "--detect", str(work)]) == 3  # a warning: the run goes on
    monkeypatch.setenv("A2VM_OSV_ENABLED", "false")
    assert main(["osv", "--detect", str(work)]) == 0


def test_osv_runs_every_day() -> None:
    daily = (ROOT / "deploy/charts/a2vm-tenant/templates/cronjob-daily.yaml").read_text()
    assert "step detect osv --detect /data/work/detect --cache /data/osv-cache" in daily
    assert "detect osv --detect work/detect || rc=$?" in (ROOT / "templates/client-pipeline.yml").read_text()


def test_sbom_and_osv_are_no_scans() -> None:
    from verdict.assets.build import NOT_SCANS

    assert {"sbom", "osv"} <= NOT_SCANS


# -- the forwarded user -----------------------------------------------------------------------------
def test_the_tenant_chooses_to_forward_the_user() -> None:
    chart = ROOT / "deploy/charts/a2vm-tenant"
    assert "forwardUserInfo: true" in (chart / "values.yaml").read_text()
    chat = (chart / "templates/chat.yaml").read_text()
    assert 'ENABLE_FORWARD_USER_INFO_HEADERS, value: {{ if eq (toString $chat.forwardUserInfo) "false" }}' in chat
    assert 'value: "true"}' not in chat.split("ENABLE_FORWARD_USER_INFO_HEADERS", 1)[1].split("\n", 1)[0]
    assert "forwardUserInfo" in (ROOT / "docs/llm.md").read_text()


def test_deploy_k8s_sets_it() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("chat_values", ROOT / "deploy/chat/chat_values.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = {
        "A2VM_CHAT_HOST": "chat.example.org",
        "A2VM_LLM_BASE_URL": "http://192.0.2.10:8000/v1",
        "A2VM_LLM_MODEL": "m",
    }
    assert "forwardUserInfo" not in mod.values(env)["chat"]
    assert mod.values({**env, "A2VM_CHAT_FORWARD_USER_INFO": "false"})["chat"]["forwardUserInfo"] is False
    with pytest.raises(ValueError):
        mod.values({**env, "A2VM_CHAT_FORWARD_USER_INFO": "maybe"})


def test_release_recorded() -> None:
    assert "## v0.23.11 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "| v0.23.11 " in (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(
        r"^version: 0\.(23\.(1[1-9]|[2-9]\d)|2[4-9]\.\d+)$",
        (ROOT / "deploy/charts/a2vm-tenant/Chart.yaml").read_text(),
        re.M,
    )
