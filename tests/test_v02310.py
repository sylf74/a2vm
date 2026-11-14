# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.10: the chat acts and knows the next scans, and an audit journal imputable to an author.

An action is prepared by the chat, confirmed by a validator on the review page, taken and run by
the collector at its poll; every step, every tool call of the chat and every validation is in the
journal with who did it."""

from __future__ import annotations

import datetime as dt
import json

import httpx
import pytest

from ngvm.actions import MIGRATIONS as ACTION_MIGRATIONS
from ngvm.actions import ActionError, ActionStore
from ngvm.audit import MIGRATIONS as AUDIT_MIGRATIONS
from ngvm.audit import AuditLog
from ngvm.db import Database
from ngvm.schedule import ScheduleError, next_run
from ngvm.service import Problem

from .conftest import ROOT
from .test_v0232 import CHAT, _tools

T0 = dt.datetime.now(dt.UTC).replace(microsecond=0)  # requests expire against the clock


def _dbs(dsn):
    audit = Database(dsn, "audit", AUDIT_MIGRATIONS, size=2)
    audit.init()
    actions = Database(dsn, "actions", ACTION_MIGRATIONS, size=2)
    actions.init()
    return AuditLog("test", audit), ActionStore(actions)


# -- the journal ------------------------------------------------------------------------------------
def test_the_journal_in_a_file(tmp_path) -> None:
    log = AuditLog("via", path=tmp_path / "audit.jsonl")
    log.write("lab", "ana@example.org", "user", "alert:validated", "a1", {"to": ["x@example.org"]}, at=T0)
    log.write("lab", "lan", "collector", "push", "cmdb", at=T0 + dt.timedelta(minutes=5))
    log.write("other", "bob@example.org", "user", "alert:validated", "a2", at=T0)
    items, total = log.entries("lab")
    assert total == 2 and [i["action"] for i in items] == ["push", "alert:validated"]  # newest first
    assert items[1]["actor"] == "ana@example.org" and items[1]["service"] == "via"
    assert log.entries("lab", actor="ANA")[1] == 1 and log.entries("lab", action="push")[1] == 1
    assert log.entries("lab", since=T0 + dt.timedelta(minutes=1))[1] == 1


def test_the_journal_never_fails_the_request(tmp_path) -> None:
    (tmp_path / "file").write_text("x")
    log = AuditLog("via", path=tmp_path / "file" / "audit.jsonl")
    log.write("lab", "ana@example.org", "user", "alert:validated", "a1")  # a warning, no exception
    assert AuditLog("tools").entries("lab") == ([], 0)  # the log only: nothing to read


def test_the_journal_in_the_database(tenant_db) -> None:
    log, _ = _dbs(tenant_db)
    log.write("lab", "ana@example.org", "user", "chat:get_cve", "/cves/CVE-2099-0001", {"x": "y" * 5000}, at=T0)
    log.write("other", "bob@example.org", "user", "chat:get_cve", "/cves/x", at=T0)
    items, total = log.entries("lab")
    assert total == 1 and items[0]["actor"] == "ana@example.org" and "truncated" in items[0]["params"]
    assert log.entries("lab", until=T0)[1] == 0 and log.entries("lab", action="chat")[1] == 1


# -- the actions --------------------------------------------------------------------------------------
def test_an_action_from_the_chat_to_the_collector(tenant_db) -> None:
    _, store = _dbs(tenant_db)
    r = store.propose("lab", "run-connector", "lan", "lan-cmdb", "ana@example.org", now=T0)
    assert r["state"] == "proposed" and r["what"] == "run the connector lan-cmdb of the collector lan"
    with pytest.raises(ActionError, match="already open"):
        store.propose("lab", "run-connector", "lan", "lan-cmdb", "bob@example.org", now=T0)
    with pytest.raises(ActionError, match="unknown action"):
        store.propose("lab", "delete-everything", "lan", "lan-cmdb", "x", now=T0)
    with pytest.raises(ActionError, match="collector's id"):
        store.propose("lab", "run-connector", "lan; rm", "lan-cmdb", "x", now=T0)
    assert store.take("lab", "lan", T0) == []  # not confirmed: nothing to take
    done = store.decide("lab", r["id"], "val@example.org", True, T0)
    assert done["state"] == "confirmed" and done["decided_by"] == "val@example.org"
    with pytest.raises(ActionError, match="confirmed"):
        store.decide("lab", r["id"], "val@example.org", False, T0)
    assert store.take("lab", "dmz", T0) == []  # another collector
    (taken,) = store.take("lab", "lan", T0)
    assert taken["state"] == "taken"
    assert store.finish("lab", "dmz", r["id"], True, "x", T0) is None  # not its request
    end = store.finish("lab", "lan", r["id"], True, "pushed cmdb", T0)
    assert end["state"] == "done" and end["detail"] == "pushed cmdb"
    assert store.list("other") == []  # one tenant per transaction


def test_requests_expire(tenant_db) -> None:
    _, store = _dbs(tenant_db)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)
    r = store.propose("lab", "run-connector", "lan", "lan-ssh", "ana@example.org", now=old)
    assert store.get("lab", r["id"])["state"] == "expired"
    with pytest.raises(ActionError, match="expired"):
        store.decide("lab", r["id"], "val@example.org", True)


# -- the detection service: the poll --------------------------------------------------------------
def _service(tmp_path, actions=None, audit=None):
    from detect.intake.registry import load_registry
    from detect.intake.server import Service
    from detect.intake.store import FileStore
    from ngvm.service import digest

    (tmp_path / "collectors.yaml").write_text(
        "collectors:\n  - {id: lan, sources: [cmdb, openvas]}\n  - {id: dmz, sources: [trivy]}\n"
    )
    (tmp_path / "digests").write_text(f"lan {digest('lan-token')}\nread {digest('read')}\n")
    registry = load_registry("lab", tmp_path / "collectors.yaml", tmp_path / "digests")
    return Service(registry, FileStore(tmp_path / "store"), audit=audit, actions=actions)


def test_the_poll_reports_timers_and_hands_the_requests(tmp_path, tenant_db) -> None:
    audit, store = _dbs(tenant_db)
    from detect.intake.server import Problem as IntakeProblem

    svc = _service(tmp_path, store, audit)
    with pytest.raises(IntakeProblem):
        svc.poll("lab", "nope", {})
    timers = [{"connector": "lan-cmdb", "next_run": "2026-11-12T06:31:53+00:00", "last_run": ""},
              {"connector": "bad name!", "next_run": "x"}]  # fmt: skip
    assert svc.poll("lab", "lan-token", {"timers": timers}, T0) == {"actions": []}
    (lan,) = [c for c in svc.collectors("lab", "read") if c["id"] == "lan"]
    assert lan["timers"] == [{"connector": "lan-cmdb", "next_run": "2026-11-12T06:31:53+00:00", "last_run": ""}]
    r = store.propose("lab", "run-connector", "lan", "lan-cmdb", "ana@example.org")
    store.decide("lab", r["id"], "val@example.org", True)
    answer = svc.poll("lab", "lan-token", {})
    assert answer == {"actions": [{"id": r["id"], "action": "run-connector", "connector": "lan-cmdb"}]}
    svc.poll("lab", "lan-token", {"results": [{"id": r["id"], "outcome": "done", "detail": "pushed cmdb"}]})
    assert store.get("lab", r["id"])["state"] == "done"
    actions = [e["action"] for e in audit.entries("lab")[0]]
    assert actions[:2] == ["action:finished", "action:taken"]


def test_the_poll_without_the_database(tmp_path) -> None:
    svc = _service(tmp_path)
    assert svc.poll("lab", "lan-token", {"timers": []})["actions"] == []


# -- the agent ---------------------------------------------------------------------------------------
def test_the_agent_reads_systemd_timers(tmp_path) -> None:
    from detect.agent import read_timers

    usec = int(dt.datetime(2026, 11, 12, 6, 31, 53, tzinfo=dt.UTC).timestamp() * 1_000_000)
    (tmp_path / "t.json").write_text(json.dumps([
        {"next": usec, "left": 1, "last": None, "passed": None, "unit": "ngvm-collector@lan-cmdb.timer",
         "activates": "ngvm-collector@lan-cmdb.service"},
        {"next": usec, "unit": "apt-daily.timer"},
    ]))  # fmt: skip
    assert read_timers(tmp_path / "t.json") == [
        {"connector": "lan-cmdb", "next_run": "2026-11-12T06:31:53+00:00", "last_run": ""}
    ]
    assert read_timers(tmp_path / "missing.json") == [] and read_timers(None) == []


def test_the_agent_runs_what_was_confirmed(tmp_path, monkeypatch) -> None:
    from detect import agent

    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if "timers" in body:
            return httpx.Response(200, json={"actions": [
                {"id": "act-1", "action": "run-connector", "connector": "lan-cmdb"},
                {"id": "act-2", "action": "run-connector", "connector": "nope"},
            ]})  # fmt: skip
        return httpx.Response(200, json={"actions": []})

    cfg = agent.AgentConfig.__new__(agent.AgentConfig)
    cfg.service, cfg.tenant, cfg.collector, cfg.ca_file, cfg.timeout_seconds = (
        "https://d.example",
        "lab",
        "lan",
        None,
        60,
    )
    cfg.connectors = [type("C", (), {"name": "lan-cmdb"})()]
    monkeypatch.setattr(agent.AgentConfig, "token", lambda self: "t")
    ran = []

    def fake_run(c, only, transport=None, log=print):
        ran.append(only)
        report = agent.RunReport()
        report.pushed.append("cmdb")
        return report

    monkeypatch.setattr(agent, "run", fake_run)
    report = agent.poll(cfg, None, transport=httpx.MockTransport(handler), log=lambda line: None)
    assert ran == ["lan-cmdb"] and report.pushed == ["cmdb"]
    results = {r["id"]: r for r in calls[1]["results"]}
    assert results["act-1"]["outcome"] == "done" and "pushed cmdb" in results["act-1"]["detail"]
    assert results["act-2"]["outcome"] == "failed" and "no connector" in results["act-2"]["detail"]


# -- the chat ---------------------------------------------------------------------------------------
def _detect_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "detect.example":
        lan = {"id": "lan", "sources": [{"source": "cmdb", "connector": "lan-cmdb"}],
               "timers": [{"connector": "lan-openvas", "next_run": "2026-11-12T01:30:00+00:00"}]}  # fmt: skip
        return httpx.Response(200, json={"version": "0.23.10", "collectors": [lan]})
    return httpx.Response(200, json={})


def test_the_chat_prepares_never_runs(tmp_path, tenant_db) -> None:
    audit, store = _dbs(tenant_db)
    tools = _tools(tmp_path, _detect_handler, detect_url="http://detect.example", detect_token="d",
                   audit=audit, actions=store, review_url="https://review-lab.example.org")  # fmt: skip
    with pytest.raises(Problem) as p:
        tools.handle(CHAT, "/actions/run-connector", {"collector": "lan", "connector": "lan-cmdb"}, "ana@example.org")
    assert p.value.status == 405  # GET refused: a request is a POST
    out = tools.handle(CHAT, "/actions/run-connector", {"collector": "lan", "connector": "lan-cmdb"},
                       "ana@example.org", "POST")  # fmt: skip
    assert out["request"]["state"] == "proposed" and out["request"]["asked_by"] == "ana@example.org"
    assert out["confirm_at"] == "https://review-lab.example.org/actions" and "Nothing runs" in out["note"]
    for bad, text in (({"collector": "x", "connector": "lan-cmdb"}, "unknown collector"),
                      ({"collector": "lan", "connector": "x"}, "unknown connector")):  # fmt: skip
        with pytest.raises(Problem, match=text):
            tools.handle(CHAT, "/actions/run-connector", bad, "ana@example.org", "POST")
    listed = tools.handle(CHAT, "/actions", {"state": "proposed"}, "ana@example.org")
    assert listed["total"] == 1 and listed["counts"] == {"proposed": 1}
    journal = tools.handle(CHAT, "/audit", {"actor": "ana"}, "")
    acts = [i["action"] for i in journal["items"]]
    assert "chat:request_connector_run" in acts and "chat:list_actions" in acts
    refused = [i for i in journal["items"] if i["outcome"] == "400"]
    assert refused and refused[0]["detail"].startswith("unknown")
    anonymous = tools.handle(CHAT, "/audit", {"actor": "not forwarded"}, "")
    assert anonymous["total"] >= 1  # the journal call above, by a user Open WebUI did not name


def test_without_the_database_the_chat_says_so(tmp_path) -> None:
    tools = _tools(tmp_path, _detect_handler)
    with pytest.raises(Problem) as p:
        tools.handle(CHAT, "/actions/run-connector", {"collector": "lan", "connector": "lan-cmdb"}, "a", "POST")
    assert p.value.status == 503 and "database" in p.value.detail


def test_the_next_daily_run(tmp_path) -> None:
    tools = _tools(tmp_path, lambda r: httpx.Response(503), daily_schedule="45 5 * * *",
                   daily_timezone="Europe/Paris")  # fmt: skip
    out = tools.call(CHAT, "/platform", {})
    assert out["next_daily_run"].endswith("05:45+01:00") and "decisions are updated" in out["next_daily_run_note"]
    assert _tools(tmp_path, lambda r: httpx.Response(503)).call(CHAT, "/platform", {})["next_daily_run"] == "unknown"


@pytest.mark.parametrize(
    ("expr", "after", "expected"),
    [
        ("45 5 * * *", "2026-11-11T18:00", "2026-11-12T05:45"),
        ("45 5 * * *", "2026-11-12T05:44", "2026-11-12T05:45"),
        ("*/15 * * * *", "2026-11-11T18:07", "2026-11-11T18:15"),
        ("0 9 * * 1-5", "2026-11-13T10:00", "2026-11-16T09:00"),  # Friday -> Monday
        ("0 0 1 * *", "2026-11-11T00:00", "2026-12-01T00:00"),
        ("30 2 * * 0", "2026-11-11T00:00", "2026-11-15T02:30"),  # Sunday
        ("0 3 1 * 1", "2026-11-11T00:00", "2026-11-16T03:00"),  # the 1st or a Monday
    ],
)
def test_cron(expr, after, expected) -> None:
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("Europe/Paris")
    at = next_run(expr, dt.datetime.fromisoformat(after).replace(tzinfo=tz), "Europe/Paris")
    assert at.strftime("%Y-%m-%dT%H:%M") == expected


def test_cron_refuses_nonsense() -> None:
    for bad in ("* * * *", "61 * * * *", "a * * * *", "*/0 * * * *", "0 0 31 2 *"):
        with pytest.raises(ScheduleError):
            next_run(bad, T0)


# -- the review page ----------------------------------------------------------------------------------
def test_a_validator_confirms_on_the_review_page(tmp_path, tenant_db) -> None:
    from ngvm.service import TokenSet  # noqa: F401
    from via.service.review import Denied, Review
    from via.service.store import WatchStore

    audit, store = _dbs(tenant_db)
    review = Review("lab", WatchStore(tmp_path / "w"), b"k" * 32, {"readers"}, {"validators"},
                    "https://review-lab.example.org", audit=audit, actions=store)  # fmt: skip
    r = store.propose("lab", "run-connector", "lan", "lan-cmdb", "ana@example.org")
    page = review.actions_page("val@example.org", True)
    assert r["id"] in page and "Confirm" in page and "ana@example.org" in page
    assert "Confirm" not in review.actions_page("reader@example.org", False)
    headers = {"Origin": "https://review-lab.example.org"}
    tok = review.token("val@example.org", f"actions:{r['id']}")
    with pytest.raises(Denied):
        review.decide_action("val@example.org", {"id": [r["id"]], "decision": ["confirm"], "token": ["x"]}, headers)
    review.decide_action("val@example.org", {"id": [r["id"]], "decision": ["confirm"], "token": [tok]}, headers)
    assert store.get("lab", r["id"])["state"] == "confirmed"
    with pytest.raises(ValueError, match="confirmed"):
        review.decide_action("val@example.org", {"id": [r["id"]], "decision": ["cancel"], "token": [tok]}, headers)
    entries = audit.entries("lab", actor="val@example.org")[0]
    assert [e["action"] for e in entries] == ["action:cancel", "action:confirmed"]
    assert entries[0]["outcome"] == "refused" and entries[1]["params"]["asked_by"] == "ana@example.org"


def test_the_validations_are_journaled(tmp_path) -> None:
    import inspect

    from via.service import review

    source = inspect.getsource(review.Review)
    for action in ('"alert:edited"', '"alert:translation-edited"', '"alert:recipients-chosen"',
                   'f"alert:{event[\'event\']}"', 'f"application:{action}"'):  # fmt: skip
        assert action in source, action


# -- wiring -------------------------------------------------------------------------------------------
def test_wiring() -> None:
    charts = ROOT / "deploy" / "charts" / "ngvm-tenant" / "templates"
    chat = (charts / "chat.yaml").read_text()
    assert "ENABLE_FORWARD_USER_INFO_HEADERS" in chat and "--daily-schedule=" in chat and "--review-url=" in chat
    assert 'include "ngvm-tenant.dbEnv"' in chat and '(dict "root" . "component" "detect")' in chat
    assert '"tools" }}' in (charts / "database.yaml").read_text()
    intake = (charts / "intake.yaml").read_text()
    assert '"/v1/tenants/%s/poll"' in intake and '"component" "tools"' in intake
    script = (ROOT / "deploy" / "collector" / "install-collector.sh").read_text()
    assert "ngvm-collector-poll.timer" in script and "detect agent poll" in script and "list-timers" in script
