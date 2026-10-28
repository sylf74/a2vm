# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.14.0 (HLD D15 step 3, read side; LLD triage-prioritization §15): the decision service of a
tenant, fed by the daily run's push, read through a short and paged API."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import threading
from pathlib import Path

import httpx
import pytest

from a2vm.io import ExchangeError, validate_triage
from a2vm.service import Problem, TokenSet, digest
from verdict.cli import main
from verdict.report import write_json
from verdict.service.server import Service, serve
from verdict.service.store import RunStore

from .test_pipeline import _run

PUBLISH, READ = "publish-token-0123456789abcdef0123", "read-token-0123456789abcdef01234567"


@pytest.fixture
def triage(settings, sources, profile, tmp_path):
    """A real run of the example client and its triage.json."""
    run = _run(settings, sources, profile, tmp=tmp_path)
    path = tmp_path / "triage.json"
    write_json(run, path)
    return run, path


def _service(tmp_path: Path, tenant: str, keep: int = 7) -> Service:
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    return Service(tenant, TokenSet.load(digests, {"publish", "read"}), RunStore(tmp_path / "store", keep))


def _push(service: Service, path: Path, key: str = "k1", **changes) -> dict:
    doc = json.loads(path.read_text())
    doc.update(changes)
    return service.push(service.tenant, PUBLISH, key, gzip.compress(json.dumps(doc).encode()), True)


def test_the_triage_of_a_run_is_a_versioned_exchange_file(triage):
    run, path = triage
    doc = json.loads(path.read_text())
    assert doc["schema"] == "a2vm.triage/1" and len(doc["rows"]) == len(run.rows) > 0
    validate_triage(doc)
    doc["rows"][0]["delivery_decision"] = "MAYBE"
    with pytest.raises(ExchangeError, match="delivery_decision"):
        validate_triage(doc)


def test_a_push_is_stored_once_and_answered_from_its_key(triage, tmp_path, monkeypatch):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    receipt = _push(service, path)
    counts = {lv: sum(r.delivery_decision == lv for r in run.rows) for lv in ("ACT", "ATTEND", "TRACK")}
    assert receipt["rows"] == len(run.rows) and receipt["counts"] == counts and "duplicate" not in receipt

    def never(*a, **k):
        raise AssertionError("a retry is not validated again")

    monkeypatch.setattr("verdict.service.server.validate_triage", never)
    again = service.push(run.client.id, PUBLISH, "k1", b"anything", True)
    assert again["id"] == receipt["id"] and again["duplicate"] is True


@pytest.mark.parametrize(
    ("args", "status", "detail"),
    [
        ({"token": READ}, 401, "publish token"),
        ({"token": None}, 401, "publish token"),
        ({"tenant": "other"}, 404, "tenant"),
        ({"key": None}, 400, "Idempotency-Key"),
        ({"body": b"not gzip"}, 400, "gzip"),
        ({"doc": {"schema": "a2vm.reporting/1"}}, 422, "a2vm.triage/1"),
        ({"doc": {"client": {"id": "someone-else"}}}, 422, "client id"),
        ({"doc": {"generated_at": "2099-01-01T00:00:00+00:00"}}, 422, "future"),
    ],
)
def test_a_refused_push_stores_nothing(triage, tmp_path, args, status, detail):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    doc = json.loads(path.read_text())
    doc.update(args.get("doc", {}))
    body = args.get("body") or gzip.compress(json.dumps(doc).encode())
    with pytest.raises(Problem) as p:
        service.push(args.get("tenant", run.client.id), args.get("token", PUBLISH), args.get("key", "k"), body, True)
    assert int(p.value.status) == status and detail in p.value.detail
    assert service.store.latest(run.client.id) is None


def test_reads_are_short_paged_and_cite_their_run(triage, tmp_path):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    receipt = _push(service, path)
    tenant = run.client.id
    summary = service.read(tenant, READ, "summary", {})
    assert summary["run"] == {"id": receipt["id"], "generated_at": receipt["generated_at"]}
    assert summary["findings"] == receipt["counts"]

    page = service.read(tenant, READ, "decisions", {"limit": "2"})
    assert page["total"] == len(run.rows) and len(page["items"]) == min(2, len(run.rows))
    assert set(page["items"][0]) >= {"id", "cve", "asset", "level", "ssvc", "kev", "epss", "due_date", "title"}
    assert "rationale" not in page["items"][0]  # a list stays short
    levels = [i["level"] for i in service.read(tenant, READ, "decisions", {"limit": "200"})["items"]]
    assert levels == sorted(levels, key=["ACT", "ATTEND", "TRACK"].index)
    if len(run.rows) > 2:
        assert page["next_offset"] == 2

    first = run.rows[0]
    only = service.read(tenant, READ, "decisions", {"cve": first.cve_id.lower()})
    assert {i["cve"] for i in only["items"]} == {first.cve_id}
    detail = service.read(tenant, READ, f"decisions/{only['items'][0]['id']}", {})
    assert detail["rationale"] and detail["reasons"] and detail["exploitation"]["source"]

    cve = service.read(tenant, READ, f"cves/{first.cve_id}", {})
    assert cve["cve"] == first.cve_id and cve["assets"]["total"] >= 1 and cve["description"]
    assets = service.read(tenant, READ, "assets", {})
    assert assets["total"] >= 1 and set(assets["items"][0]["counts"]) == {"ACT", "ATTEND", "TRACK"}
    one = service.read(tenant, READ, f"assets/{assets['items'][0]['asset']}", {"limit": "1"})
    assert one["decisions"]["limit"] == 1 and one["counts"] == assets["items"][0]["counts"]


@pytest.mark.parametrize(
    ("rest", "query", "status"),
    [
        ("decisions", {"level": "URGENT"}, 400),
        ("decisions", {"limit": "500"}, 400),
        ("decisions", {"sort": "random"}, 400),
        ("decisions", {"kev": "maybe"}, 400),
        ("decisions", {"run": "../../etc"}, 400),
        ("decisions/nothing-like-this", {}, 404),
        ("cves/CVE-1999-0001", {}, 404),
        ("whatever", {}, 404),
    ],
)
def test_bad_reads_are_problems(triage, tmp_path, rest, query, status):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    _push(service, path)
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, rest, dict(query))
    assert int(p.value.status) == status


def test_readers_need_the_read_token_and_a_run(triage, tmp_path):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, "summary", {})
    assert p.value.status == 404 and "no run" in p.value.detail
    for token in (None, PUBLISH):
        with pytest.raises(Problem) as p:
            service.read(run.client.id, token, "summary", {})
        assert p.value.status == 401


def test_the_latest_run_wins_and_the_last_ones_are_kept(triage, tmp_path):
    run, path = triage
    service = _service(tmp_path, run.client.id, keep=2)
    base = dt.datetime.now(dt.UTC) - dt.timedelta(days=3)
    ids = [
        _push(service, path, key=f"k{d}", generated_at=(base + dt.timedelta(days=d)).isoformat())["id"]
        for d in (0, 2, 1)
    ]
    runs = service.read(run.client.id, READ, "runs", {})["items"]
    assert [r["id"] for r in runs] == [ids[1], ids[2]]  # newest first, the oldest dropped
    assert service.read(run.client.id, READ, "summary", {})["run"]["id"] == ids[1]
    older = service.read(run.client.id, READ, "summary", {"run": ids[2]})
    assert older["run"]["id"] == ids[2]


def test_push_and_read_over_http_with_the_cli(triage, tmp_path, capsys):
    run, path = triage
    service = _service(tmp_path, run.client.id)
    httpd = serve(service, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    token = tmp_path / "publish-token"
    token.write_text(PUBLISH + "\n")
    try:
        args = ["push", str(path), "--url", url, "--tenant", run.client.id, "--token-file", str(token)]
        assert main(args) == 0
        assert "pushed to the decision service" in capsys.readouterr().out
        assert main(args) == 0
        assert "already received" in capsys.readouterr().out
        with httpx.Client(base_url=url, headers={"Authorization": f"Bearer {READ}"}) as c:
            assert c.get("/healthz").status_code == 200 and c.get("/readyz").status_code == 200
            r = c.get(f"/v1/tenants/{run.client.id}/decisions", params={"level": "ACT,ATTEND", "limit": 5})
            assert r.status_code == 200 and r.json()["limit"] == 5
            bad = c.get(f"/v1/tenants/{run.client.id}/decisions", params={"limit": 0})
            assert bad.status_code == 400 and bad.headers["content-type"] == "application/problem+json"
            assert c.post(f"/v1/tenants/{run.client.id}/runs", content=b"{}").status_code == 401
        assert main([*args[:3], "http://127.0.0.1:9", *args[4:]]) == 3  # unreachable: a warning
        token.write_text(READ)
        assert main(args) == 1  # refused: the read token cannot publish
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_token_file_errors(tmp_path):
    bad = tmp_path / "digests"
    bad.write_text("admin " + "0" * 64 + "\n")
    with pytest.raises(ValueError, match="publish|read"):
        TokenSet.load(bad, {"publish", "read"})
    assert TokenSet.load(tmp_path / "missing", {"read"}).role_of(READ) is None
