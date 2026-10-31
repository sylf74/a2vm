# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.13.0 (HLD D15 step 2, LLD detection §8): the detection service, the collector agent that
pushes to it and the fetch of the daily run."""

from __future__ import annotations

import datetime as dt
import gzip
import http.client
import json
import threading
from pathlib import Path

import httpx
import pytest

from a2vm.io import read_detection, write_detection
from detect.agent import AgentError, FileImportConnector, RunReport, TargetsConnector, load_config, run
from detect.cli import main
from detect.intake.client import IntakeError, fetch, push
from detect.intake.registry import RegistryError, digest, load_collectors, load_registry
from detect.intake.server import Problem, Service, serve
from detect.intake.store import FileStore
from detect.scanners import load_trivy_file

from .conftest import FIXTURES

TRIVY = FIXTURES / "trivy"
NOW = dt.datetime(2026, 10, 24, 6, 0, tzinfo=dt.UTC)
LAN, DMZ, READER = "lan-token-0123456789abcdef", "dmz-token-0123456789abcdef", "read-token-0123456789abcdef"

COLLECTORS = """\
collectors:
  - id: lab-lan
    description: LAN collector
    sources: [trivy, dnf-updateinfo]
    max_age_hours: 30
  - id: lab-dmz
    sources: [trivy, openvas]
    max_age_hours: 12
"""


def _document(tmp_path: Path, source: str = "trivy", client: str = "lab", generated_at: dt.datetime = NOW) -> dict:
    d = load_trivy_file(TRIVY / "node00.lab.example.json", client)
    d.source = source
    path = write_detection(tmp_path / "doc" / f"{client}-{source}.json", d)
    doc = json.loads(path.read_text())
    doc["generated_at"] = generated_at.isoformat(timespec="seconds")
    return doc


def _body(doc: dict) -> bytes:
    return json.dumps(doc).encode()


@pytest.fixture
def declaration(tmp_path):
    collectors = tmp_path / "collectors.yaml"
    collectors.write_text(COLLECTORS)
    digests = tmp_path / "digests"
    digests.write_text(f"# comment\nlab-lan {digest(LAN)}\nlab-dmz {digest(DMZ)}\nread {digest(READER)}\n")
    return collectors, digests


def _store(tmp_path, dsn, keep):
    """The detection service's store: files, or the tenant's PostgreSQL (v0.18.0)."""
    if dsn is None:
        return FileStore(tmp_path / "store", keep=keep)
    from a2vm.db import Database
    from detect.intake.pgstore import MIGRATIONS, PgStore

    db = Database(dsn, "detect", MIGRATIONS)
    db.init()
    return PgStore(db, keep=keep)


@pytest.fixture
def service(tmp_path, declaration, backend):
    registry = load_registry("lab", *declaration)
    return Service(registry, _store(tmp_path, backend, 3), max_bytes=5 * 1024 * 1024)


# -- registry -------------------------------------------------------------------------------------


def test_registry_binds_each_token_to_its_collector_and_keeps_only_digests(declaration):
    registry = load_registry("lab", *declaration)
    assert registry.collector_for(LAN).id == "lab-lan"
    assert registry.collector_for(f"  {DMZ}\n").id == "lab-dmz"  # read from a file
    assert registry.collector_for("guess") is None and registry.collector_for(None) is None
    assert registry.collector_for(READER) is None  # the read token cannot push
    assert registry.may_read(READER) and not registry.may_read(LAN)
    assert registry.max_age("trivy") == 30 and registry.max_age("openvas") == 12
    assert LAN not in declaration[1].read_text()


def test_two_tokens_of_one_collector_are_valid_during_a_rotation(tmp_path, declaration):
    collectors, digests = declaration
    digests.write_text(digests.read_text() + f"lab-lan {digest('next-token-of-the-lan')}\n")
    registry = load_registry("lab", collectors, digests)
    assert registry.collector_for(LAN).id == registry.collector_for("next-token-of-the-lan").id == "lab-lan"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("collectors:\n  - {id: a, sources: [trivy]}\n  - {id: a, sources: [trivy]}\n", "duplicate"),
        ("collectors:\n  - {id: read, sources: [trivy]}\n", "invalid id"),
        ("collectors:\n  - {id: Bad_Id, sources: [trivy]}\n", "invalid id"),
        ("collectors:\n  - {id: a}\n", "sources"),
        ("collectors:\n  - {id: a, sources: trivy}\n", "sources"),
        ("collectors:\n  - {id: a, sources: [../x]}\n", "sources"),
        ("collectors:\n  - {id: a, sources: [trivy], max_age_hours: 0}\n", "positive"),
        ("collectors:\n  - {id: a, sources: [trivy], max_age_hours: soon}\n", "max_age_hours"),
        ("collectors: {id: a}\n", "a list"),
        ("collectors: [\n", "not YAML"),
    ],
)
def test_declaration_errors_are_named(tmp_path, text, message):
    path = tmp_path / "collectors.yaml"
    path.write_text(text)
    with pytest.raises(RegistryError, match=message):
        load_collectors("lab", path)


def test_digests_file_errors_and_tenant_id(tmp_path, declaration):
    collectors, digests = declaration
    with pytest.raises(RegistryError, match="invalid tenant"):
        load_registry("../lab", collectors, digests)
    digests.write_text(f"ghost {digest('x')}\n")
    with pytest.raises(RegistryError, match="unknown collector"):
        load_registry("lab", collectors, digests)
    digests.write_text("lab-lan not-a-digest\n")
    with pytest.raises(RegistryError, match="expected"):
        load_registry("lab", collectors, digests)
    # No digests file yet: the service starts, nobody can push or read.
    registry = load_registry("lab", collectors, tmp_path / "missing")
    assert registry.collector_for(LAN) is None and not registry.may_read(READER)


# -- store ----------------------------------------------------------------------------------------


def test_store_is_idempotent_keeps_the_last_n_per_collector_and_drops_their_keys(tmp_path, backend):
    store = _store(tmp_path, backend, 2)
    receipts = []
    for hour in range(4):
        doc = _document(tmp_path, generated_at=NOW + dt.timedelta(hours=hour))
        receipts.append(store.put("lab", "lab-lan", _body(doc), doc, f"run-{hour}", NOW + dt.timedelta(hours=hour)))
    again = store.put("lab", "lab-lan", b"ignored", _document(tmp_path), "run-3", NOW + dt.timedelta(hours=5))
    assert again.id == receipts[3].id and again.duplicate
    assert store.get("lab", receipts[0].id) is None and store.get("lab", receipts[2].id) is not None
    assert store.known("lab", "lab-lan", "run-1") is None  # the keys of the pruned ones are gone
    assert store.known("lab", "lab-lan", "run-2").id == receipts[2].id
    if backend is None:
        folder = tmp_path / "store" / "lab" / "trivy"
        assert len(list(folder.glob("*.meta.json"))) == 2
        assert len(list((tmp_path / "store" / "lab" / "_keys").iterdir())) == 2
    # A key whose detection was pruned stores the detection again.
    doc = _document(tmp_path, generated_at=NOW + dt.timedelta(hours=6))
    assert not store.put("lab", "lab-lan", _body(doc), doc, "run-0", NOW + dt.timedelta(hours=6)).duplicate
    receipt, stored = store.latest("lab", "trivy")[0]
    assert receipt.generated_at == stored["generated_at"] == doc["generated_at"]


def test_store_keeps_the_latest_of_each_collector_of_a_source(tmp_path, backend):
    store = _store(tmp_path, backend, 1)
    lan = _document(tmp_path, generated_at=NOW)
    dmz = _document(tmp_path, generated_at=NOW + dt.timedelta(hours=1))
    store.put("lab", "lab-lan", _body(lan), lan, "a", NOW)
    store.put("lab", "lab-dmz", _body(dmz), dmz, "b", NOW + dt.timedelta(hours=1))
    latest = store.latest("lab", "trivy")
    assert [r.collector for r, _ in latest] == ["lab-dmz", "lab-lan"]  # retention of one does not drop the other


@pytest.mark.parametrize("rid", ["../trivy/x", ".hidden", "20261024T060000000000Z-abc", "x\x00y", ""])
def test_store_reads_only_well_formed_ids(tmp_path, rid):
    assert FileStore(tmp_path).get("lab", rid) is None


# -- service --------------------------------------------------------------------------------------


def test_push_is_accepted_stored_and_read_back(tmp_path, service):
    doc = _document(tmp_path)
    receipt = service.push("lab", LAN, "run-1", gzip.compress(_body(doc)), True, NOW)
    assert receipt["collector"] == "lab-lan" and receipt["source"] == "trivy" and "duplicate" not in receipt
    assert service.push("lab", LAN, "run-1", gzip.compress(_body(doc)), True, NOW)["duplicate"] is True
    (entry,) = service.latest("lab", READER)
    assert entry["receipt"]["id"] == receipt["id"] and entry["detection"]["source"] == "trivy"
    assert service.one("lab", READER, receipt["id"])["detection"] == entry["detection"]
    with pytest.raises(Problem) as p:
        service.one("lab", READER, "20261024T060000000000Z-000000000000")
    assert p.value.status == 404


@pytest.mark.parametrize(
    ("change", "status", "detail"),
    [
        (lambda a: a.update(token=None), 401, "token"),
        (lambda a: a.update(token=READER), 401, "token"),
        (lambda a: a.update(tenant="other"), 404, "tenant"),
        (lambda a: a.update(key=None), 400, "Idempotency-Key"),
        (lambda a: a.update(key="k" * 129), 400, "Idempotency-Key"),
        (lambda a: a.update(body=b"not gzip", gzipped=True), 400, "gzip"),
        (lambda a: a.update(body=b"{not json"), 400, "JSON"),
        (lambda a: a.update(body=b'{"schema": "vulnops.detection/1"}'), 422, "body"),
        (lambda a: a.update(body=b'{"schema": "vulnops.assets/1"}'), 422, "expected"),
        (lambda a: a.update(doc={"client_id": "other"}), 422, "client_id"),
        (lambda a: a.update(doc={"source": "openvas"}), 403, "not declared"),
        (lambda a: a.update(doc={"generated_at": (NOW + dt.timedelta(hours=1)).isoformat()}), 422, "future"),
        (lambda a: a.update(doc={"generated_at": (NOW - dt.timedelta(hours=31)).isoformat()}), 422, "older"),
        (lambda a: a.update(body=gzip.compress(b" " * (6 * 1024 * 1024)), gzipped=True), 413, "larger"),
        (lambda a: a.update(body=b" " * (6 * 1024 * 1024)), 413, "larger"),
    ],
)
def test_a_refused_push_stores_nothing(tmp_path, service, change, status, detail):
    doc = _document(tmp_path)
    args = {"tenant": "lab", "token": LAN, "key": "run-1", "body": None, "gzipped": False, "doc": {}}
    change(args)
    doc.update(args.pop("doc"))
    body = args.pop("body") or _body(doc)
    with pytest.raises(Problem) as p:
        service.push(args["tenant"], args["token"], args["key"], body, args["gzipped"], NOW)
    assert int(p.value.status) == status and detail in p.value.detail
    assert not (tmp_path / "store" / "lab" / "trivy").exists()


def test_collector_status_shows_age_staleness_and_the_last_refusal(tmp_path, service):
    old = _document(tmp_path, generated_at=NOW - dt.timedelta(hours=40))
    with pytest.raises(Problem):
        service.push("lab", LAN, "run-0", _body(old), False, NOW)
    status = {c["id"]: {s["source"]: s for s in c["sources"]} for c in service.collectors("lab", READER)}
    assert status["lab-lan"]["trivy"]["stale"] and "older than 30 hours" in status["lab-lan"]["trivy"]["last_error"]
    assert "last_received_at" not in status["lab-lan"]["trivy"]
    doc = _document(tmp_path, generated_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1))
    service.push("lab", LAN, "run-1", _body(doc), False)
    status = {c["id"]: {s["source"]: s for s in c["sources"]} for c in service.collectors("lab", READER)}
    lan = status["lab-lan"]["trivy"]
    assert lan["last_received_at"] and not lan["stale"] and "last_error" not in lan
    assert status["lab-dmz"]["trivy"]["stale"]  # the other collector of trivy has pushed nothing
    with pytest.raises(Problem) as p:
        service.collectors("lab", LAN)  # a collector token does not read
    assert p.value.status == 401


def test_latest_refuses_a_source_that_is_not_a_name(service):
    with pytest.raises(Problem) as p:
        service.latest("lab", READER, "../../etc")
    assert p.value.status == 400


# -- over HTTP ------------------------------------------------------------------------------------


@pytest.fixture
def server(service):
    httpd = serve(service, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", httpd
    httpd.shutdown()
    httpd.server_close()


def _fresh(tmp_path, source="trivy", hours=1.0, client="lab"):
    return _document(tmp_path, source, client, dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours))


def test_push_and_fetch_over_http(tmp_path, server):
    url, _ = server
    receipt = push(url, "lab", LAN, _fresh(tmp_path), "lab-lan")
    assert push(url, "lab", LAN, read_json_again(tmp_path, receipt, url), "lab-lan")["duplicate"]
    push(url, "lab", LAN, _fresh(tmp_path, "dnf-updateinfo"), "lab-lan")
    result = fetch(url, "lab", READER, tmp_path / "out", ["trivy", "dnf-updateinfo", "openvas"], 30)
    assert sorted(p.name for p in result.written) == ["dnf-updateinfo.json", "trivy.json"]
    assert result.problems == ["openvas: nothing received yet"]
    d = read_detection(tmp_path / "out" / "lab" / "trivy.json")
    assert d.client_id == "lab" and d.observations and d.findings


def read_json_again(tmp_path, receipt, url):
    """The same detection again (a retry): fetched back from the service."""
    with httpx.Client(base_url=url, headers={"Authorization": f"Bearer {READER}"}) as c:
        return c.get(f"/v1/tenants/lab/detections/{receipt['id']}").json()["detection"]


def test_push_errors_say_whether_to_retry(tmp_path, server):
    url, _ = server
    with pytest.raises(IntakeError, match="401") as e:
        push(url, "lab", "stolen?", _fresh(tmp_path), "lab-lan")
    assert e.value.retry is False
    with pytest.raises(IntakeError, match="older") as e:
        push(url, "lab", LAN, _fresh(tmp_path, hours=31), "lab-lan")
    assert e.value.retry is False
    with pytest.raises(IntakeError, match="unreachable") as e:
        push("http://127.0.0.1:9", "lab", LAN, _fresh(tmp_path), "lab-lan")
    assert e.value.retry is True


def test_fetch_merges_the_collectors_of_a_source_and_applies_each_max_age(tmp_path, server):
    url, _ = server
    push(url, "lab", LAN, _fresh(tmp_path, hours=2), "lab-lan")
    push(url, "lab", DMZ, _fresh(tmp_path, hours=1), "lab-dmz")
    push(url, "lab", DMZ, _fresh(tmp_path, "openvas", hours=11), "lab-dmz")
    single = read_detection(tmp_path / "doc" / "lab-trivy.json")
    result = fetch(url, "lab", READER, tmp_path / "out", [], {"trivy": 30, "openvas": 6})
    assert [p.name for p in result.written] == ["trivy.json"]
    assert len(result.problems) == 1 and result.problems[0].startswith("openvas from lab-dmz: latest from")
    merged = read_detection(tmp_path / "out" / "lab" / "trivy.json")
    assert len(merged.findings) == 2 * len(single.findings)


def test_http_routes_health_and_malformed_requests(tmp_path, server, service, backend):
    url, httpd = server
    with httpx.Client(base_url=url) as c:
        assert c.get("/healthz").status_code == 200
        if backend is None:
            assert c.get("/readyz").status_code == 503  # the store volume is not there yet
            (tmp_path / "store").mkdir()
        assert c.get("/readyz").status_code == 200
        assert c.get("/v1/tenants/lab/detections/latest").status_code == 401
        r = c.get("/v1/tenants/lab/detections/latest?source=..%2F..", headers={"Authorization": f"Bearer {READER}"})
        assert r.status_code == 400 and r.headers["content-type"] == "application/problem+json"
        assert c.get("/v1/tenants/lab/nothing").status_code == 404
        assert c.get("/v1/tenants/LAB/collectors").status_code == 404
        assert c.post("/v1/tenants/lab/collectors", content=b"{}").status_code == 404
    host, port = httpd.server_address[:2]
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.putrequest("POST", "/v1/tenants/lab/detections")
    conn.putheader("Content-Length", "-1")
    conn.endheaders()
    assert conn.getresponse().status == 400
    conn.close()


def test_an_internal_error_answers_500_so_the_collector_retries(tmp_path, server, service, monkeypatch):
    url, _ = server

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(service.store, "put", broken)
    with pytest.raises(IntakeError, match="500") as e:
        push(url, "lab", LAN, _fresh(tmp_path), "lab-lan")
    assert e.value.retry is True


def test_fetch_never_writes_outside_its_folder(tmp_path):
    def answer(request):
        doc = _fresh(tmp_path)
        entry = {"receipt": {"source": "../../evil", "generated_at": doc["generated_at"]}, "age_hours": 1}
        return httpx.Response(200, json=[entry | {"detection": doc}])

    result = fetch("http://detect", "lab", READER, tmp_path / "out", [], 30, transport=httpx.MockTransport(answer))
    assert not result.written and "not a source name" in result.problems[0]
    assert not (tmp_path / "evil.json").exists()
    refused = httpx.MockTransport(lambda r: httpx.Response(401))
    with pytest.raises(IntakeError, match="refused"):
        fetch("http://detect", "lab", READER, tmp_path, [], 30, transport=refused)


def test_fetch_leaves_out_a_document_of_another_tenant(tmp_path):
    doc = _fresh(tmp_path, client="other")

    def answer(request):
        entry = {"receipt": {"source": "trivy", "collector": "x", "generated_at": doc["generated_at"]}, "age_hours": 1}
        return httpx.Response(200, json=[entry | {"detection": doc}])

    result = fetch("http://detect", "lab", READER, tmp_path / "out", [], 30, transport=httpx.MockTransport(answer))
    assert not result.written and "another tenant" in result.problems[0]


def test_cli_fetch_reads_sources_and_ages_from_the_declaration(tmp_path, server, declaration, capsys):
    url, _ = server
    push(url, "lab", LAN, _fresh(tmp_path), "lab-lan")
    token = tmp_path / "read-token"
    token.write_text(READER + "\n")
    args = ["fetch", "--url", url, "--tenant", "lab", "--token-file", str(token), "--out", str(tmp_path / "out")]
    assert main([*args, "--collectors", str(declaration[0])]) == 3  # dnf-updateinfo and openvas missing
    err = capsys.readouterr().err
    assert "dnf-updateinfo: nothing received yet" in err and "openvas: nothing received yet" in err
    assert main([*args, "--source", "trivy"]) == 0
    assert main([*args, "--source", "openvas"]) == 1  # nothing at all: the run stops
    assert READER not in capsys.readouterr().out


def test_cli_checks_the_declaration(tmp_path, declaration, capsys):
    assert main(["collectors", str(declaration[0]), "--tenant", "lab"]) == 0
    out = capsys.readouterr().out
    assert "collector lab-lan (trivy, dnf-updateinfo, max 30 h), token A2VM_COLLECTOR_TOKEN_LAB_LAN" in out
    empty = tmp_path / "empty.yaml"
    empty.write_text("collectors: []\n")
    assert main(["collectors", str(empty), "--tenant", "lab"]) == 2
    assert main(["collectors", str(declaration[0]), "--tenant", "Lab"]) == 2
    profile = tmp_path / "client.yaml"
    profile.write_text((FIXTURES.parent.parent / "examples" / "lab" / "client.yaml").read_text())
    assert main(["collectors", str(declaration[0]), "--tenant", "lab", "--profile", str(profile)]) == 0
    assert main(["collectors", str(declaration[0]), "--tenant", "lab-prod", "--profile", str(profile)]) == 2
    assert "is not the tenant" in capsys.readouterr().err


# -- agent ----------------------------------------------------------------------------------------


def _config(tmp_path, connectors: str = "  - {name: drop, type: file-import, source: trivy, folder: drop}\n") -> Path:
    token = tmp_path / "token"
    token.write_text(LAN + "\n")
    path = tmp_path / "collector.yaml"
    path.write_text(
        f"collector: lab-lan\ntenant: lab\nservice: https://detect.example.org\ntoken_file: {token}\n"
        f"work: {tmp_path / 'work'}\nspool: {tmp_path / 'spool'}\nconnectors:\n"
        + connectors.replace("folder: drop", f"folder: {tmp_path / 'drop'}")
    )
    return path


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("tenant: lab\n", "`collector` is required"),
        ("collector: a\ntenant: lab\nservice: ftp://x\ntoken_file: t\n", "http"),
        ("collector: a\ntenant: ../lab\nservice: https://x\ntoken_file: t\n", "tenant"),
        ("collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\n", "at least one connector"),
        ("collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\nconnectors: [{type: nmap}]\n", "unknown type"),
        ("collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\nconnectors: [{type: targets}]\n", "targets"),
        (
            "collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\n"
            "connectors: [{type: file-import, source: nessus, folder: /x}]\n",
            "source",
        ),
        (
            "collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\n"
            "connectors: [{name: ../x, type: targets, targets: t.yaml}]\n",
            "name",
        ),
        (
            "collector: a\ntenant: lab\nservice: https://x\ntoken_file: t\n"
            "connectors: [{name: a, type: targets, targets: t.yaml}, {name: a, type: targets, targets: u.yaml}]\n",
            "unique",
        ),
    ],
)
def test_agent_configuration_errors(tmp_path, text, message):
    path = tmp_path / "collector.yaml"
    path.write_text(text)
    with pytest.raises(AgentError, match=message):
        load_config(path)


def test_agent_refuses_an_empty_token_file(tmp_path):
    cfg = load_config(_config(tmp_path))
    cfg.token_file.write_text("\n")
    with pytest.raises(AgentError, match="empty"):
        run(cfg)


class FakeService:
    """Answers the pushes as the service would, or with the status given."""

    def __init__(self, tmp_path: Path, status: int | None = None):
        registry = load_registry("lab", *_declare(tmp_path))
        self.service = Service(registry, FileStore(tmp_path / "service"))
        self.status = status
        self.pushed: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.status is not None:
            return httpx.Response(self.status, json={"detail": "said no"})
        token = request.headers["authorization"][7:]
        try:
            body = request.read()
            receipt = self.service.push("lab", token, request.headers["idempotency-key"], body, True)
        except Problem as p:
            return httpx.Response(int(p.status), json={"detail": p.detail})
        self.pushed.append(json.loads(gzip.decompress(body)))
        return httpx.Response(202, json=receipt)


def _declare(tmp_path: Path) -> tuple[Path, Path]:
    collectors, digests = tmp_path / "declared.yaml", tmp_path / "declared.digests"
    collectors.write_text(COLLECTORS)
    digests.write_text(f"lab-lan {digest(LAN)}\n")
    return collectors, digests


def _drop(tmp_path: Path) -> Path:
    folder = tmp_path / "drop"
    folder.mkdir(exist_ok=True)
    target = folder / "node00.json"
    target.write_bytes((TRIVY / "node00.lab.example.json").read_bytes())
    return target


def test_agent_imports_dropped_exports_once_and_pushes_them(tmp_path):
    cfg = load_config(_config(tmp_path))
    dropped = _drop(tmp_path)
    fake = FakeService(tmp_path)
    report = run(cfg, transport=httpx.MockTransport(fake))
    assert report.status == 0 and report.pushed[0].startswith("trivy -> ")
    assert not dropped.exists() and dropped.with_name("node00.json.imported").exists()
    assert fake.pushed[0]["client_id"] == "lab" and fake.pushed[0]["findings"]
    assert (cfg.work / "detect" / "lab" / "trivy.json").exists()
    assert run(cfg, transport=httpx.MockTransport(fake)).pushed == []  # nothing new, nothing pushed


def test_agent_spools_what_it_cannot_push_and_pushes_it_at_the_next_run(tmp_path):
    cfg = load_config(_config(tmp_path))
    _drop(tmp_path)
    report = run(cfg, transport=httpx.MockTransport(FakeService(tmp_path, status=503)))
    assert report.status == 1 and report.spooled and (cfg.spool / "trivy.json").exists()
    fake = FakeService(tmp_path)
    report = run(cfg, transport=httpx.MockTransport(fake))
    assert report.status == 0 and len(fake.pushed) == 1 and not (cfg.spool / "trivy.json").exists()


def test_agent_sets_aside_a_spooled_detection_refused_for_good(tmp_path):
    cfg = load_config(_config(tmp_path))
    cfg.spool.mkdir(parents=True)
    (cfg.spool / "trivy.json").write_text(json.dumps(_document(tmp_path, generated_at=NOW - dt.timedelta(days=3))))
    (cfg.spool / "openvas.json").write_text(json.dumps({"source": "trivy"}))
    report = run(cfg, transport=httpx.MockTransport(FakeService(tmp_path)))
    assert report.status == 1 and any("older than" in e for e in report.errors)
    assert (cfg.spool / "trivy.json.rejected").exists() and not (cfg.spool / "trivy.json").exists()
    assert (cfg.spool / "openvas.json.rejected").exists()
    assert run(cfg, transport=httpx.MockTransport(FakeService(tmp_path))).errors == []


def test_agent_never_pushes_another_client_and_reports_a_bad_export(tmp_path):
    cfg = load_config(_config(tmp_path))

    class Other:
        name = "other"

        def run(self, tenant, work):
            return [load_trivy_file(TRIVY / "node00.lab.example.json", "someone-else")], []

    cfg.connectors = [Other(), FileImportConnector("drop", "trivy", tmp_path / "drop")]
    (tmp_path / "drop").mkdir()
    (tmp_path / "drop" / "broken.json").write_text("{")
    fake = FakeService(tmp_path)
    report = run(cfg, transport=httpx.MockTransport(fake))
    assert not fake.pushed and report.status == 1
    assert any("someone-else" in e for e in report.errors) and any("broken.json" in e for e in report.errors)
    with pytest.raises(AgentError, match="no connector named"):
        run(cfg, "nope", transport=httpx.MockTransport(fake))


def test_targets_connector_refuses_a_targets_file_of_another_client(tmp_path):
    targets = tmp_path / "targets.yaml"
    targets.write_text("client: other\ntargets:\n  - {host: node00.lab.example, method: trivy}\n")
    detections, errors = TargetsConnector("lan", targets).run("lab", tmp_path)
    assert detections == [] and "other" in errors[0]


def test_agent_exit_codes():
    assert RunReport(pushed=["a"]).status == 0
    assert RunReport(pushed=["a"], errors=["b"]).status == 3
    assert RunReport(pushed=["a"], spooled=["b"]).status == 3
    assert RunReport(spooled=["b"]).status == 1
    assert RunReport().status == 0
