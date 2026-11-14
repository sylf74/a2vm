# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.12: a copy of OSV, the tenants' libraries matched where they are.

The shared intelligence service rebuilds, every few hours, an index of each language ecosystem from
OSV's archive and serves it; the daily run matches its libraries against it. No library leaves the
tenant. Without the shared service, the run builds the index from the archive itself. The mode api
(each library sent to api.osv.dev) stays for a test, its pages now followed."""

from __future__ import annotations

import io
import json
import re
import threading
import zipfile

import httpx
import pytest

from ngvm import osvdb
from ngvm.config import load_settings
from ngvm.io import read_detection
from ngvm.service import TokenSet, digest

from .conftest import ROOT

READ = "r" * 40


def _archive(records: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


PYPI = [
    {"id": "GHSA-aaaa-0000-0001", "aliases": ["CVE-2099-0101"], "affected": [{
        "package": {"ecosystem": "PyPI", "name": "Jinja2"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}],
        "versions": ["3.1.0", "3.1.1", "3.1.2"]}]},
    {"id": "GHSA-aaaa-0000-0002", "aliases": ["CVE-2099-0102"], "affected": [{
        "package": {"ecosystem": "PyPI", "name": "requests"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.32.0"}]}]}]},
    {"id": "PYSEC-2099-9", "aliases": [], "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                                                         "versions": ["3.1.2"]}]},
    {"id": "GHSA-aaaa-0000-0003", "aliases": ["CVE-2099-0103"], "withdrawn": "2099-01-01T00:00:00Z",
     "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"}, "versions": ["3.1.2"]}]},
]  # fmt: skip
NPM = [
    {"id": "GHSA-bbbb-0000-0001", "aliases": ["CVE-2099-0201"], "affected": [{
        "package": {"ecosystem": "npm", "name": "@scope/lib"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]}]}]},
    {"id": "MAL-2099-1", "affected": [{"package": {"ecosystem": "npm", "name": "evil"}, "versions": ["1.0.0"]}]},
]  # fmt: skip


def _libs(*purls: str) -> list[dict]:
    comps = [{"name": p.split("/")[-1].split("@")[0], "version": p.rsplit("@", 1)[1], "type": "library", "purl": p}
             for p in purls]  # fmt: skip
    return [{"observations": [{"ref": "registry.example.org/shop/web:1.4", "kind": "image", "name": "web",
                               "components": comps}]}]  # fmt: skip


# -- versions -------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("a", "b", "order"),
    [("1.2.3", "1.2.10", -1), ("2.0.0rc1", "2.0.0", -1), ("2.0", "2.0.0", 0), ("1.0-SNAPSHOT", "1.0", -1),
     ("1.0.post1", "1.0", 1), ("1.0.dev0", "1.0a1", -1), ("1.0a1", "1.0b1", -1), ("2.17.1", "2.14.1", 1)],
)  # fmt: skip
def test_versions_in_order(a, b, order) -> None:
    assert osvdb.compare(a, b) == order and osvdb.compare(b, a) == -order


def test_semver_and_purls() -> None:
    assert osvdb.semver_compare("1.2.3-beta.1", "1.2.3") == -1 and osvdb.semver_compare("1.10.0", "1.9.9") == 1
    assert osvdb.from_purl("pkg:npm/%40scope/lib@1.4.0") == ("npm", "@scope/lib", "1.4.0")
    assert osvdb.from_purl("pkg:maven/org.example/core@2.14.1") == ("Maven", "org.example:core", "2.14.1")
    assert osvdb.from_purl("pkg:golang/github.com/example/mod@v1.9.0") == ("Go", "github.com/example/mod", "1.9.0")
    assert osvdb.from_purl("pkg:pypi/Jinja_2@3") == ("PyPI", "jinja-2", "3")
    assert osvdb.from_purl("pkg:deb/debian/bash@5.2") is None


# -- the index ------------------------------------------------------------------------------------
def test_the_index_keeps_the_records_with_a_cve() -> None:
    index = osvdb.load_index(osvdb.dump_index(osvdb.build_index(_archive(PYPI), "PyPI", "2099-01-01")))
    assert (index["records"], index["kept"]) == (4, 2)  # no CVE, withdrawn: left out
    assert set(index["packages"]) == {"jinja2", "requests"}
    assert osvdb.match(index, "jinja2", "3.1.2")[0] == [("GHSA-aaaa-0000-0001", ["CVE-2099-0101"], "3.1.3")]
    assert osvdb.match(index, "jinja2", "3.1.3")[0] == []  # not among the versions OSV enumerated
    assert osvdb.match(index, "requests", "2.31.0")[0][0][2] == "2.32.0"  # range, compared
    assert osvdb.match(index, "requests", "2.32.0")[0] == [] and osvdb.match(index, "requests", "1.9")[0] == []
    npm = osvdb.build_index(_archive(NPM), "npm")
    assert osvdb.match(npm, "@scope/lib", "1.4.1")[0] and not osvdb.match(npm, "@scope/lib", "1.4.2")[0]
    assert "evil" not in npm["packages"]  # malware records have no CVE
    git = {"packages": {"x": [["OSV-1", ["CVE-2099-1"], [], [["GIT", "abc", "def", ""]]]]}}
    assert osvdb.match(git, "x", "1.0") == ([], 1)  # undecided, counted
    with pytest.raises(osvdb.OsvDbError):
        osvdb.build_index(b"not a zip", "PyPI")


def test_the_mirror_downloads_only_a_changed_archive(tmp_path) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("If-None-Match", ""))
        if request.headers.get("If-None-Match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=_archive(PYPI), headers={"ETag": '"v1"'})

    mirror = osvdb.OsvMirror(tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert "2 with a CVE" in mirror.refresh("PyPI", client, "2099-01-01")
        assert "unchanged" in mirror.refresh("PyPI", client, "2099-01-02")
    assert calls == ["", '"v1"'] and mirror.load("PyPI")["kept"] == 2
    assert not list(tmp_path.glob(".*.zip"))  # the archive is not kept
    with pytest.raises(osvdb.OsvDbError):
        mirror.path("../etc")


# -- the daily run --------------------------------------------------------------------------------
def test_offline_matching_sends_no_library() -> None:
    from detect.osv import ecosystems_of, match_offline

    docs = _libs("pkg:pypi/jinja2@3.1.2", "pkg:npm/%40scope/lib@1.4.0", "pkg:cargo/serde@1.0.0", "pkg:hex/x@1")
    assert ecosystems_of(docs) == ["PyPI", "crates.io", "npm"]
    indexes = {"PyPI": osvdb.build_index(_archive(PYPI), "PyPI"), "npm": osvdb.build_index(_archive(NPM), "npm")}
    d = match_offline(docs, "lab", indexes, log=lambda _: None)
    assert sorted(f.cve_id for f in d.findings) == ["CVE-2099-0101", "CVE-2099-0201"]
    assert d.findings[0].observations[0].source == "osv"
    assert d.skipped == {"no index for crates.io": 1, "ecosystem not in the copy of OSV": 1}


def _intel(tmp_path):
    from via.intel.service import IntelService, IntelStore
    from via.intel.service import serve as http_serve

    digests = tmp_path / "digests"
    digests.write_text(f"read {digest(READ)}\n")
    settings = load_settings(ROOT / "config" / "settings.yaml")
    settings.sources.cache_dir = str(tmp_path / "cache")
    service = IntelService(TokenSet.load(digests, {"read", "radar"}), IntelStore(tmp_path / "store"), settings)
    archives = {"PyPI": _archive(PYPI), "npm": _archive(NPM)}
    service.transport = httpx.MockTransport(
        lambda r: httpx.Response(200, content=archives[r.url.path.split("/")[1]], headers={"ETag": '"a"'})
        if r.url.path.split("/")[1] in archives else httpx.Response(404)
    )  # fmt: skip
    httpd = http_serve(service, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return service, httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def test_the_shared_service_serves_the_indexes(tmp_path) -> None:
    from detect.osv import IndexSource

    service, httpd, url = _intel(tmp_path)
    try:
        lines = service.sync_osv(["PyPI", "npm", "Go"])
        assert lines[0].startswith("osv PyPI: 4 records") and lines[2].startswith("WARN osv Go: HTTP 404")
        assert httpx.get(f"{url}/v1/osv/PyPI").status_code == 401
        h = {"Authorization": f"Bearer {READ}"}
        assert httpx.get(f"{url}/v1/osv/Go", headers=h).status_code == 503  # not built yet
        assert httpx.get(f"{url}/v1/osv/Elixir", headers=h).status_code == 404
        source = IndexSource(tmp_path / "tenant-cache", url, READ)
        first = source.get("PyPI")
        assert first["kept"] == 2 and source.warnings == []
        etag = source.mirror.meta("PyPI")["etag"]
        assert httpx.get(f"{url}/v1/osv/PyPI", headers={**h, "If-None-Match": etag}).status_code == 304
        assert source.get("PyPI")["kept"] == 2  # 304: the copy kept
        source.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
    source = IndexSource(tmp_path / "tenant-cache", url, READ)  # the service is down
    assert source.get("PyPI")["kept"] == 2 and source.warnings  # yesterday's index, with a warning
    source.close()


def test_detect_osv_offline_from_the_shared_service(tmp_path, monkeypatch) -> None:
    from detect.cli import main
    from detect.sbom import SbomConfig, read
    from ngvm.io import write_detection

    service, httpd, url = _intel(tmp_path)
    try:
        service.sync_osv(["PyPI"])
        sbom = tmp_path / "sbom"
        sbom.mkdir()
        cdx = {"bomFormat": "CycloneDX", "metadata": {"component": {"name": "web"}},
               "components": [{"name": "jinja2", "version": "3.1.2", "purl": "pkg:pypi/jinja2@3.1.2"}]}  # fmt: skip
        (sbom / "web.cdx.json").write_text(json.dumps(cdx))
        work = tmp_path / "detect"
        write_detection(work / "lab" / "sbom.json", read(SbomConfig(str(sbom)), "lab", log=lambda _: None))
        (work / "lab" / "osv.json").write_text("{}")  # yesterday's, replaced
        (tmp_path / "intel-token").write_text(READ)
        monkeypatch.setenv("NGVM_INTEL_URL", url)
        monkeypatch.setenv("NGVM_INTEL_TOKEN_FILE", str(tmp_path / "intel-token"))
        monkeypatch.delenv("NGVM_OSV_MODE", raising=False)
        assert main(["osv", "--detect", str(work), "--cache", str(tmp_path / "osv-cache")]) == 0
        assert read_detection(work / "lab" / "osv.json").findings[0].cve_id == "CVE-2099-0101"
    finally:
        httpd.shutdown()
        httpd.server_close()
    monkeypatch.setenv("NGVM_OSV_MODE", "off")
    assert main(["osv", "--detect", str(work)]) == 0
    monkeypatch.setenv("NGVM_OSV_MODE", "everything")
    assert main(["osv", "--detect", str(work)]) == 2


# -- the mode api: the pages followed ---------------------------------------------------------------
def test_the_pages_of_an_answer_are_followed(tmp_path) -> None:
    from detect.osv import Osv

    def handler(request: httpx.Request) -> httpx.Response:
        q = json.loads(request.content)["queries"][0]
        if q.get("page_token") == "p2":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-0000-0000-0002"}]}]})
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-0000-0000-0001"}],
                                                      "next_page_token": "p2"}]})  # fmt: skip

    osv = Osv(tmp_path, transport=httpx.MockTransport(handler))
    assert osv.query(["pkg:pypi/old@1.0"]) == {"pkg:pypi/old@1.0": ["GHSA-0000-0000-0001", "GHSA-0000-0000-0002"]}
    osv.close()


def test_wiring() -> None:
    chart = ROOT / "deploy/charts/ngvm-tenant"
    assert "--osv-every-hours {{ $s.osvEveryHours | default 6 }}" in (chart / "templates/intel.yaml").read_text()
    assert "osvEveryHours: 6" in (chart / "values.yaml").read_text()
    assert "osv-vulnerabilities.storage.googleapis.com" in (ROOT / "deploy/relay/variables.tf").read_text()
    lld = (ROOT / "docs/lld/vulnerability-detection.md").read_text()
    assert "NGVM_OSV_MODE" in lld and "No library leaves the tenant" in lld


def test_release_recorded() -> None:
    assert "## v0.23.12 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[2-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
