# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.21.0 (HLD D19): priorities and SLA per client. The level stays the SSVC decision; the client's
rules sort the decisions into priorities with their delays, counted from the day a decision enters its
priority, in calendar or business days; the rule applied and the BOD 26-04 due date are kept."""

from __future__ import annotations

import datetime as dt
import gzip
import json

import httpx
import pytest
import yaml

from a2vm import sla
from a2vm.io import read_reporting, validate_triage
from a2vm.profile import ProfileError, load_profile, validate_profile_data
from a2vm.service import TokenSet, digest
from verdict import priority
from verdict.report import render_markdown, write_all
from verdict.service.index import RunIndex

from .conftest import ROOT
from .test_pipeline import _run
from .test_restitution import ADMIN, _grafana, needs_db, reporting_db  # noqa: F401, F811 - the fixture

D = dt.date
PUBLISH, READ = "publish-token-0123456789abcdef0123", "read-token-0123456789abcdef01234567"
EXAMPLE = {  # the example of the documentation (docs/sla.md)
    "calendar": "business",
    "holidays": "FR",
    "timezone": "Europe/Paris",
    "rules": [
        {"priority": "P0", "days": 2, "calendar": "calendar", "when": {"kev": True}},
        {"priority": "P1", "days": 5, "when": {"level": "ACT", "exposure": "open"}},
        {"priority": "P2", "days": 10, "when": {"level": "ACT", "exposure": "controlled"}},
        {"priority": "P3", "days": 15, "when": {"level": "ACT"}},
        {"priority": "P4", "days": 30, "when": {"level": "ATTEND", "exposure": "open"}},
        {"priority": "P5", "days": 90, "when": {"level": "ATTEND"}},
    ],
}
FRIDAY = "2026-11-06T09:00:00+00:00"  # 11 November, a Wednesday, is a public holiday in France


# -- calendar --------------------------------------------------------------------------------------
def test_french_public_holidays():
    assert sla.easter(2026) == D(2026, 4, 5) and sla.easter(2027) == D(2027, 3, 28)
    days = sla.holidays_fr(2026)
    assert len(days) == 11
    assert {D(2026, 4, 6), D(2026, 5, 14), D(2026, 5, 25), D(2026, 11, 11), D(2026, 7, 14)} <= days


def test_business_days_skip_weekends_and_holidays():
    business = sla.Calendar("business", ("FR",))
    assert business.add(D(2026, 11, 6), 2) == D(2026, 11, 10)  # Friday + 2: Monday, Tuesday
    assert business.add(D(2026, 11, 6), 3) == D(2026, 11, 12)  # Wednesday 11 is left out
    assert business.add(D(2026, 11, 7), 1) == D(2026, 11, 9)  # from a Saturday: the Monday
    assert business.add(D(2026, 11, 6), 0) == D(2026, 11, 6)
    closed = sla.Calendar("business", (), frozenset({D(2026, 11, 9)}))
    assert closed.add(D(2026, 11, 6), 1) == D(2026, 11, 10)  # an extra day of the client
    assert sla.Calendar().add(D(2026, 11, 6), 2) == D(2026, 11, 8)  # 24/7


def test_the_day_of_a_run_is_the_clients():
    policy = sla.parse(EXAMPLE)
    assert policy.today("2026-11-06T23:30:00+00:00") == D(2026, 11, 7)  # already Saturday in Paris
    assert sla.parse({**EXAMPLE, "timezone": "UTC"}).today("2026-11-06T23:30:00Z") == D(2026, 11, 6)


# -- the profile's section ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "change, message",
    [
        ({"timezone": "Mars/Olympus"}, "time zone"),
        ({"holidays": "XX"}, "public holidays"),
        ({"rules": []}, "at least one rule"),
        ({"rules": [{"priority": "P1", "days": 5, "when": {"owner": "ops"}}]}, "unknown criterion"),
        ({"rules": [{"priority": "P1", "days": 5, "when": {"level": "URGENT"}}]}, "level"),
        ({"rules": [{"priority": "P 1", "days": 5}]}, "priority"),
        ({"rules": [{"priority": "P1", "days": -1}]}, "days"),
        ({"extra_holidays": ["2026-13-01"]}, "not a day"),
    ],
)
def test_bad_sla_sections_are_refused(change, message):
    with pytest.raises(sla.SlaError, match=message):
        sla.parse({**EXAMPLE, **change})


def _profile_with(tmp_path, section) -> object:
    data = yaml.safe_load((ROOT / "examples" / "example-client" / "client.yaml").read_text())
    data["sla"] = section
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


def test_the_profile_carries_its_sla(tmp_path):
    profile = load_profile(_profile_with(tmp_path, EXAMPLE))
    assert profile.sla.priorities == ["P0", "P1", "P2", "P3", "P4", "P5"]
    assert profile.sla.rules[0].calendar.kind == "calendar" and profile.sla.rules[1].calendar.kind == "business"
    assert profile.sla.rules[1].calendar.holidays == ("FR",)
    assert load_profile(ROOT / "examples" / "example-client" / "client.yaml").sla is None
    with pytest.raises(ProfileError, match="time zone"):
        load_profile(_profile_with(tmp_path, {**EXAMPLE, "timezone": "Nowhere/City"}))
    bad = yaml.safe_load(_profile_with(tmp_path, {**EXAMPLE, "calendar": "lunar"}).read_text())
    assert validate_profile_data(bad)  # the schema refuses it before the parser


def test_the_example_tenant_shows_the_section():
    profile = load_profile(ROOT / "examples" / "lab" / "client.yaml")
    assert profile.sla is not None and profile.sla.rules[0].when == {"kev": True}


# -- matching ----------------------------------------------------------------------------------------
def _facts(**kw):
    return {"level": "ACT", "kev": False, "exposure": "open", "zone": "", "epss": None, "cvss": None, "cmdb": {}, **kw}


def test_the_first_rule_that_matches_applies():
    policy = sla.parse(EXAMPLE)
    assert policy.classify(_facts(kev=True, level="TRACK")).priority == "P0"  # every KEV
    assert policy.classify(_facts()).priority == "P1"
    assert policy.classify(_facts(exposure="small")).priority == "P3"
    assert policy.classify(_facts(level="ATTEND", exposure="controlled")).priority == "P5"
    assert policy.classify(_facts(level="TRACK")) is None


def test_numbers_lists_and_cmdb_fields():
    when = {"epss": {"min": 0.1, "max": 0.5}, "zone": ["dmz", "lan"], "cmdb": {"criticality": ["high", "critical"]}}
    item = {"class": "Server", "criticality": "High", "status": "production"}
    assert sla.matches(when, _facts(epss=0.2, zone="DMZ", cmdb=item))
    assert not sla.matches(when, _facts(epss=0.6, zone="dmz", cmdb=item))
    assert not sla.matches(when, _facts(epss=None, zone="dmz", cmdb=item))  # unknown EPSS: no
    assert not sla.matches(when, _facts(epss=0.2, zone="dmz"))  # an asset without CMDB item: no
    assert sla.matches({"cvss": 9}, _facts(cvss=9.8)) and not sla.matches({"cvss": 9}, _facts(cvss=8.8))
    assert sla.matches({}, _facts())  # no criterion: every decision
    assert sla.matches({"cmdb": {"organization": "Lab"}}, _facts(cmdb={"organization": "lab"}))


# -- the delay of a decision -----------------------------------------------------------------------
P1 = sla.Rule(2, "P1", 5, {}, sla.Calendar("business", ("FR",)), 1)
P5 = sla.Rule(6, "P5", 90, {}, sla.Calendar("business", ("FR",)), 5)
P0 = sla.Rule(1, "P0", 2, {}, sla.Calendar(), 0)


def test_a_new_decision_starts_today_with_the_history_else_at_its_first_observation():
    today, first = D(2026, 11, 6), D(2026, 11, 2)
    s = sla.carry(P1, today, "ACT", first, None, history=True)
    assert (s["since"], s["since_source"], s["due"]) == ("2026-11-06", "run", "2026-11-16")
    assert (s["priority"], s["rule"], s["rank"], s["days"], s["calendar"]) == ("P1", 2, 1, 5, "business")
    s = sla.carry(P1, today, "ACT", first, None, history=False)
    assert (s["since"], s["since_source"], s["due"]) == ("2026-11-02", "first_seen", "2026-11-09")
    assert sla.carry(None, today, "TRACK", first, None, True) == {"priority": ""}


def test_a_decision_known_before_the_sla_keeps_the_day_of_its_level():
    before = sla.Previous("ACT", D(2026, 10, 20), None)
    s = sla.carry(P1, D(2026, 11, 6), "ACT", D(2026, 10, 1), before, True)
    assert (s["since"], s["since_source"], s["due"]) == ("2026-10-20", "level_since", "2026-10-27")
    other = sla.Previous("ATTEND", D(2026, 10, 20), None)  # its level changed with this run
    assert sla.carry(P1, D(2026, 11, 6), "ACT", None, other, True)["since"] == "2026-11-06"


def test_a_priority_kept_keeps_its_start_and_never_moves_its_due_date_later():
    known = {"priority": "P1", "since": "2026-11-02", "due": "2026-11-09"}
    s = sla.carry(P1, D(2026, 11, 6), "ACT", None, sla.Previous("ACT", D(2026, 11, 2), known), True)
    assert (s["since"], s["since_source"], s["due"]) == ("2026-11-02", "history", "2026-11-09")
    longer = sla.Rule(2, "P1", 10, {}, sla.Calendar("business", ("FR",)), 1)  # the client lengthened P1
    s = sla.carry(longer, D(2026, 11, 6), "ACT", None, sla.Previous("ACT", None, known), True)
    assert s["due"] == "2026-11-09"
    shorter = sla.Rule(2, "P1", 1, {}, sla.Calendar("business", ("FR",)), 1)
    assert sla.carry(shorter, D(2026, 11, 6), "ACT", None, sla.Previous("ACT", None, known), True)["due"] == (
        "2026-11-03"
    )


def test_a_priority_that_goes_up_gets_a_new_delay_never_beyond_the_due_date_set():
    p5 = {"priority": "P5", "since": "2026-10-01", "due": "2026-11-09"}
    s = sla.carry(P0, D(2026, 11, 6), "ACT", None, sla.Previous("ATTEND", None, p5), True)
    assert (s["priority"], s["since"], s["since_source"], s["due"]) == ("P0", "2026-11-06", "run", "2026-11-08")
    s = sla.carry(P1, D(2026, 11, 6), "ACT", None, sla.Previous("ATTEND", None, p5), True)
    assert s["due"] == "2026-11-09"  # 5 business days would be the 16th: the due date already set stays


def test_a_priority_that_goes_down_keeps_the_due_date_announced():
    p1 = {"priority": "P1", "since": "2026-11-02", "due": "2026-11-09"}
    s = sla.carry(P5, D(2026, 11, 4), "ATTEND", None, sla.Previous("ACT", None, p1), True)
    assert (s["priority"], s["since"], s["due"]) == ("P5", "2026-11-04", "2026-11-09")
    s = sla.carry(P5, D(2026, 11, 5), "ATTEND", None, sla.Previous("ATTEND", None, s), True)
    assert s["due"] == "2026-11-09"  # and the next day too
    out = {"priority": ""}  # back from no priority: a new entry
    assert sla.carry(P1, D(2026, 11, 6), "ACT", None, sla.Previous("TRACK", None, out), True)["due"] == "2026-11-16"


def test_respect_of_a_due_date():
    assert sla.status("2026-11-09", D(2026, 11, 9)) == "on-track"
    assert sla.status("2026-11-09", D(2026, 11, 10)) == "overdue"
    assert sla.status("2026-11-09", D(2026, 11, 12), fixed_on=D(2026, 11, 9)) == "met"
    assert sla.status("2026-11-09", D(2026, 11, 12), fixed_on=D(2026, 11, 10)) == "missed"
    assert sla.status(None, D(2026, 11, 9)) is None
    assert sla.deadline({"priority": "P1", "due": "2026-11-09"}, "2026-12-01") == "2026-11-09"
    assert sla.deadline({"priority": ""}, "2026-12-01") == "2026-12-01"
    assert sla.bod_due("14 days", "2026-11-01T06:00:00Z") == "2026-11-15"
    assert sla.bod_due("fix on system upgrade", "2026-11-01") is None


# -- on a run ---------------------------------------------------------------------------------------
def _sla_run(settings, sources, tmp_path, state=None, at=FRIDAY):
    profile = load_profile(_profile_with(tmp_path, EXAMPLE))
    run = _run(settings, sources, profile)
    run.generated_at = at
    for r in run.rows:
        r.first_seen = "2026-11-02T06:00:00+00:00"
    priority.apply(run, state)
    return run


def test_every_decision_gets_its_priority_and_the_bod_due_date_beside_it(settings, sources, tmp_path):
    run = _sla_run(settings, sources, tmp_path)
    by = {r.finding_id.rsplit(":", 1)[1]: r.sla for r in run.rows}
    assert by["CVE-2024-3400"]["priority"] == "P0" and by["CVE-2024-3400"]["rule"] == 1  # KEV, 2 calendar days
    assert by["CVE-2024-3400"]["due"] == "2026-11-04" and by["CVE-2024-3400"]["bod_due"] == "2026-11-05"
    assert by["CVE-2099-10002"]["priority"] == "P4" and by["CVE-2099-10001"]["priority"] == "P5"
    assert by["CVE-2099-10004"] == {"priority": "", "bod_due": "2027-01-01"}  # TRACK: BOD only
    assert {s.get("since_source") for s in by.values() if s["priority"]} == {"first_seen"}
    assert run.sla["history"] is False and run.sla["today"] == "2026-11-06"
    counts = priority.counts(run.rows, run.sla["today"])
    assert counts["P0"] == {"open": 1, "overdue": 1, "due_soon": 0, "rank": 0}
    with_history = _sla_run(settings, sources, tmp_path, state={})
    assert {r.sla.get("since_source") for r in with_history.rows if r.sla["priority"]} == {"run"}


def test_no_sla_section_changes_nothing(settings, sources, profile):
    run = _run(settings, sources, profile)
    priority.apply(run, {})
    assert run.sla == {} and all(r.sla == {} for r in run.rows)
    assert "Priorities and SLA" not in render_markdown(run)


def test_the_deliverables_show_the_priorities(settings, sources, tmp_path):
    run = _sla_run(settings, sources, tmp_path)
    target = write_all(run, tmp_path / "out", settings.policy)
    doc = json.loads((target / "triage.json").read_text())
    validate_triage(doc, "triage.json")
    assert doc["sla"]["priorities"][0] == "P0" and doc["rows"][0]["sla"]["priority"]
    report = (target / "report.md").read_text()
    assert "## Priorities and SLA" in report and "| P0 | 2 d | 1 | 1 | 0 |" in report
    assert "| Priority |" in report and "P0, 2026-11-04" in report
    assert "first observation" in report  # no history known
    csv = (target / "triage.csv").read_text()
    assert csv.splitlines()[0].endswith(";priority;sla_due;bod_due")
    data = read_reporting(target / "reporting.json")
    kev = next(d for d in data["decisions"] if d["kev"])
    assert (kev["priority"], kev["sla_due"], kev["due_date"], kev["sla_status"]) == (
        "P0", "2026-11-04", "2026-11-05", "overdue"
    )  # fmt: skip
    assert data["deadlines"]["sla"]["overdue"] == 1 and data["deadlines"]["sla"]["unclassified"] == 2
    assert data["run"]["sla"]["timezone"] == "Europe/Paris"
    assert "Priorités et SLA" in render_markdown(run, "fr")
    assert "Priorities and SLA" in (target / "dashboard.html").read_text()


def test_verdict_run_reads_the_state_and_warns_without_it(tmp_path):
    from verdict.cli import _sla_state

    profile = load_profile(_profile_with(tmp_path, EXAMPLE))
    assert _sla_state(None, profile) is None
    assert _sla_state(str(tmp_path / "missing.json"), profile) is None
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema": "a2vm.sla_state/1", "tenant": profile.id, "findings": [
        {"id": "f1", "level": "ACT", "level_since": "2026-10-20T06:00:00+00:00", "sla": None},
        {"id": "f2", "level": "ATTEND", "level_since": None, "sla": {"priority": "P5", "due": "2027-01-01"}},
    ]}))  # fmt: skip
    read = _sla_state(str(state), profile)
    late = priority.read_state_data(
        {"schema": "a2vm.sla_state/1", "tenant": "t", "findings": [{"id": "x", "level_since": "2026-10-20T23:30:00Z"}]},
        "t",
        "Europe/Paris",
    )
    assert late["x"].level_since == D(2026, 10, 21)  # the client's day
    assert read["f1"].level_since == D(2026, 10, 20) and read["f1"].sla is None and read["f2"].sla["priority"] == "P5"
    state.write_text(json.dumps({"schema": "a2vm.sla_state/1", "tenant": "another", "findings": []}))
    assert _sla_state(str(state), profile) is None


# -- the decision service ----------------------------------------------------------------------------
def _doc(run, tmp_path) -> dict:
    from verdict.report import write_json

    path = tmp_path / "triage.json"
    write_json(run, path)
    return json.loads(path.read_text())


def test_the_index_answers_by_priority(settings, sources, tmp_path):
    doc = _doc(_sla_run(settings, sources, tmp_path), tmp_path)
    idx = RunIndex({"id": "r", "generated_at": doc["generated_at"]}, doc)
    items = idx.decisions({"priority": "p0,P4", "limit": "50"})["items"]
    assert sorted(i["priority"] for i in items) == ["P0", "P4"] and items[0]["sla_due"]
    late = idx.decisions({"sla_overdue": "true", "today": "2026-11-06"})["items"]
    assert [i["priority"] for i in late] == ["P0"]
    ordered = idx.decisions({"sort": "priority", "limit": "50"})["items"]
    assert [i["priority"] for i in ordered] == ["P0", "P4", "P5", "", ""]
    assert idx.decisions({"sort": "sla_due", "limit": "1"})["items"][0]["priority"] == "P0"
    summary = idx.summary()["sla"]
    assert list(summary["by_priority"]) == ["P0", "P4", "P5"] and summary["unclassified"] == 2
    assert idx.sla_summary("2026-11-06")["by_priority"]["P0"]["overdue"] == 1
    full = idx.decision(items[0]["id"])
    assert full["sla"]["rule"] in (1, 5)


def test_the_sla_state_needs_the_database_and_the_publish_token(tmp_path):
    from a2vm.service import Problem
    from verdict.service.server import Service
    from verdict.service.store import RunStore

    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    service = Service("example-client", TokenSet.load(digests, {"publish", "read"}), RunStore(tmp_path / "runs"))
    with pytest.raises(Problem) as e:
        service.sla_state("example-client", PUBLISH)
    assert e.value.status == 404
    with pytest.raises(Problem) as e:
        service.sla_state("example-client", READ)
    assert e.value.status == 401


def test_the_cli_writes_the_state_only_when_complete(tmp_path, monkeypatch):
    from verdict.service import cli, client

    token = tmp_path / "token"
    token.write_text(PUBLISH)

    def answer(request):
        if request.url.path.endswith("/sla-state"):
            assert request.headers["authorization"] == f"Bearer {PUBLISH}"
            body = {"schema": "a2vm.sla_state/1", "tenant": "lab", "generated_at": "x", "findings": [{"id": "a",
                    "level": "ACT", "sla": None}]}  # fmt: skip
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"detail": "no such route"})

    real = client.sla_state
    monkeypatch.setattr(
        client, "sla_state", lambda *a, **kw: real(*a, **{**kw, "transport": httpx.MockTransport(answer)})
    )
    out = tmp_path / "work" / "sla-state.json"
    args = ["sla-state", "--url", "http://verdict", "--tenant", "lab", "--token-file", str(token), "--out", str(out)]
    assert cli.main(args) == 0 and json.loads(out.read_text())["findings"][0]["id"] == "a"
    out.unlink()
    monkeypatch.setattr(
        client,
        "sla_state",
        lambda *a, **kw: real(*a, **{**kw, "transport": httpx.MockTransport(lambda r: httpx.Response(404, json={}))}),
    )
    assert cli.main(args) == 3 and not out.exists()  # a service without the database: a warning


def test_the_database_keeps_the_entry_into_each_priority(settings, sources, tmp_path, tenant_db):
    from a2vm.db import Database
    from verdict.service.index import row_id
    from verdict.service.pgstore import MIGRATIONS, PgRunStore
    from verdict.service.server import Service

    db = Database(tenant_db, "verdict", MIGRATIONS)
    assert db.init() == len(MIGRATIONS)
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    run = _sla_run(settings, sources, tmp_path, state={}, at="2026-11-02T06:00:00+00:00")
    tenant = run.client.id
    service = Service(tenant, TokenSet.load(digests, {"publish", "read"}), PgRunStore(db))

    def push(doc, key):
        now = dt.datetime(2026, 11, 8, tzinfo=dt.UTC)
        return service.push(tenant, PUBLISH, key, gzip.compress(json.dumps(doc).encode()), True, now)

    push(_doc(run, tmp_path), "d1")
    state = service.sla_state(tenant, PUBLISH)
    assert state["schema"] == "a2vm.sla_state/1" and len(state["findings"]) == len(run.rows)
    known = priority.read_state_data(state, tenant, "Europe/Paris")
    # Four days later the ATTEND open finding becomes ACT: P4 -> P1, never beyond the P4 due date.
    later = _sla_run(settings, sources, tmp_path, state=known, at="2026-11-06T06:00:00+00:00")
    vpn = next(r for r in later.rows if r.finding_id.endswith("CVE-2099-10002"))
    assert vpn.sla["since_source"] == "history" and vpn.sla["since"] == "2026-11-02"
    vpn.delivery_decision = "ACT"
    priority.apply(later, known)
    vpn = next(r for r in later.rows if r.finding_id.endswith("CVE-2099-10002"))
    assert (vpn.sla["priority"], vpn.sla["since"], vpn.sla["due"]) == ("P1", "2026-11-06", "2026-11-16")
    push(_doc(later, tmp_path), "d2")
    life = service.read(tenant, READ, f"decisions/{row_id(_doc(later, tmp_path)['rows'][0])}", {})["lifecycle"]
    assert "sla" in life
    vpn_life = PgRunStore(db).lifecycle(tenant, vpn.finding_id)
    assert vpn_life["sla"]["priority"] == "P1" and [p["priority"] for p in vpn_life["priorities"]] == ["P4", "P1"]
    # A run without the history (decision service not reached) never replaces an unchanged priority.
    blind = _sla_run(settings, sources, tmp_path, state=None, at="2026-11-07T06:00:00+00:00")
    for r in blind.rows:
        if r.finding_id == vpn.finding_id:
            r.delivery_decision = "ACT"
    priority.apply(blind, None)
    push(_doc(blind, tmp_path), "d3")
    kept = PgRunStore(db).lifecycle(tenant, vpn.finding_id)["sla"]
    assert kept["since"] == "2026-11-06" and kept["since_source"] == "run"


# -- reporting database and dashboard ------------------------------------------------------------------
@needs_db
def test_the_sla_dashboard_reads_schema_5(settings, sources, tmp_path, reporting_db):  # noqa: F811
    import psycopg

    from verdict.reporting import build
    from verdict.restitution import db
    from verdict.restitution.cli import dashboard, main

    rdb = reporting_db
    run = _sla_run(settings, sources, tmp_path)
    day1 = {"schema": "a2vm.reporting/1", **build(run, settings.policy)}
    day2 = json.loads(json.dumps(day1))
    day2["generated_at"] = "2026-11-07T09:00:00+00:00"
    fixed = next(d for d in day2["decisions"] if d["priority"] == "P4")
    day2["decisions"] = [d for d in day2["decisions"] if d is not fixed]
    for a in day2["assets"]:
        if a["id"] == fixed["asset"]:
            a["scans"] = {k: "2100-01-01T00:00:00+00:00" for k in a["scans"]} or {"inventory": "2100-01-01T00:00:00Z"}
    for d in day2["decisions"]:
        d["seen_by"] = d.get("seen_by") or {}
    fixed["seen_by"] = fixed["seen_by"] or {"inventory": "2026-11-02T06:00:00Z"}
    for d in day1["decisions"]:
        if d["finding_id"] == fixed["finding_id"]:
            d["seen_by"] = fixed["seen_by"]
    for a in day2["assets"]:
        if a["id"] == fixed["asset"]:
            a["scans"] = {k: "2100-01-01T00:00:00+00:00" for k in fixed["seen_by"]}
    assert db.init(ADMIN, rdb["writer"]).startswith("schema a2vm version 5")
    for i, d in enumerate((day1, day2)):
        p = tmp_path / f"r{i}.json"
        p.write_text(json.dumps(d))
        assert main(["publish", str(p), "--dsn", rdb["as_writer"]]) == 0
    password = db.grant(ADMIN, rdb["reader"], ["*"])
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=rdb["reader"], password=password)
    results = {}
    with psycopg.connect(as_reader) as conn:
        for name in ("sla", "remediation"):
            for panel in json.loads(dashboard(name))["panels"]:
                for t in panel.get("targets", []):
                    cur = conn.execute(_grafana(t["rawSql"], {"tenant": [run.client.id]}))
                    results[(name, panel["title"])] = ([c.name for c in cur.description], cur.fetchall())
        row = conn.execute(
            "SELECT priority, sla_due, sla_status, deadline FROM a2vm.decision_facts WHERE kev ORDER BY day DESC"
        ).fetchone()
    assert row[0] == "P0" and row[1] == D(2026, 11, 4) and row[2] == "overdue" and row[3] == D(2026, 11, 4)
    assert results[("sla", "Past their SLA due date")][1] == [(1,)]
    assert results[("sla", "Fixed within the SLA")][1] == [(100,)]
    cols, rows = results[("sla", "By priority")]
    assert [r[cols.index("Priority")] for r in rows] == ["P0", "P4", "P5"]
    assert rows[1][cols.index("Fixed")] == 1 and rows[1][cols.index("Open")] == 0
    cols, rows = results[("sla", "Overdue decisions")]
    assert [r[cols.index("Priority")] for r in rows] == ["P0"] and rows[0][cols.index("Days late")] == 3
    cols, rows = results[("remediation", "Recently fixed")]
    assert rows[0][cols.index("Priority")] == "P4" and rows[0][cols.index("Within SLA")] is True


def test_the_sla_dashboard_has_its_french_and_rssi_versions():
    from verdict.restitution.cli import dashboard

    fr = json.loads(dashboard("sla", "fr"))
    assert fr["uid"] == "a2vm-sla-fr" and fr["title"] == "A2VM — priorités et SLA"
    rssi = json.loads(dashboard("sla", rssi=True))
    links = [o for p in rssi["panels"] for o in p.get("fieldConfig", {}).get("overrides", []) if "links" in str(o)]
    assert len(links) == 2 and "remediate?asset=" in json.dumps(links)
    chart = (ROOT / "deploy" / "charts" / "a2vm-portal" / "templates" / "grafana.yaml").read_text()
    assert '"coverage" "sla" }}' in chart
    for f in ("sla.json", "sla.fr.json", "sla.rssi.json", "sla.rssi.fr.json"):
        assert (ROOT / "deploy" / "charts" / "a2vm-portal" / "dashboards" / f).is_file()


# -- dispatch -----------------------------------------------------------------------------------------
def test_tickets_carry_the_priority_and_the_sla_due_date():
    from dispatch import tickets as tk
    from dispatch.connectors.itop import ItopConnector
    from dispatch.rules import Target

    decisions = [
        {"id": "a", "cve": "CVE-2024-0001", "asset": "host:web01", "level": "ATTEND", "due_date": "2026-12-01",
         "priority": "P4", "priority_rank": 4, "sla_due": "2026-11-20", "fixes": ["openssl 3.0.9"]},
        {"id": "b", "cve": "CVE-2024-0002", "asset": "host:web01", "level": "ACT", "due_date": "2026-11-20",
         "priority": "P1", "priority_rank": 1, "sla_due": "2026-11-13", "fixes": ["openssl 3.0.9"]},
        {"id": "c", "cve": "CVE-2024-0003", "asset": "host:web02", "level": "ACT", "due_date": "2026-11-20",
         "fixes": []},
    ]  # fmt: skip
    built = tk.build(decisions, "itsm")
    t = built["host:web01 / openssl 3.0.9"]
    assert (t.priority, t.due, t.bod_due) == ("P1", "2026-11-13", "2026-11-20")
    assert tk.title(t).startswith("[A2VM ACT P1] host:web01")
    text = tk.description(t)
    assert "<b>Priority</b>: P1" in text and "(SLA): 2026-11-13" in text and "for comparison): 2026-11-20" in text
    plain = built["host:web02 / no known fix"]
    assert (
        plain.priority == ""
        and tk.title(plain).startswith("[A2VM ACT] ")
        and "(BOD 26-04): 2026-11-20" in (tk.description(plain))
    )
    again = tk.Ticket.from_dict(json.loads(json.dumps(t.to_dict())))
    assert again.priority == "P1" and again.findings["a"].bod_due == "2026-12-01"
    t.findings["b"].refresh({**decisions[1], "priority": "P2", "priority_rank": 2, "sla_due": "2026-11-12"})
    assert t.priority == "P2" and t.due == "2026-11-12"

    sent = {}

    def itop(request):
        sent.update(json.loads(dict(httpx.QueryParams(request.content.decode()))["json_data"]))
        return httpx.Response(200, json={"code": 0, "objects": {"x": {"code": 0, "key": "7", "fields": {}}}})

    target = Target("itsm", "itop", {"url": "https://itop.example.org", "user": "u", "organization": "Lab",
                                     "caller": "A2VM", "priorities": {"P2": {"impact": 1, "urgency": 1}}})  # fmt: skip
    ItopConnector(target, "pw", transport=httpx.MockTransport(itop)).create(t, "x", "y")
    assert (sent["fields"]["impact"], sent["fields"]["urgency"]) == ("1", "1")
    ItopConnector(target, "pw", transport=httpx.MockTransport(itop)).create(plain, "x", "y")
    assert (sent["fields"]["impact"], sent["fields"]["urgency"]) == ("2", "1")  # by its level


def test_the_dispatch_rules_accept_the_priorities_of_itop():
    import jsonschema

    from a2vm.io import load_schema

    data = yaml.safe_load((ROOT / "examples" / "lab" / "dispatch.yaml").read_text())
    data["targets"]["itsm"]["priorities"] = {"P0": {"impact": 1, "urgency": 1}}
    jsonschema.validate(data, load_schema("dispatch"))


def test_the_requests_of_a_dashboard_may_name_a_priority():
    from dispatch.engine import REQUEST_FILTERS

    assert {"priority", "sla_overdue"} <= set(REQUEST_FILTERS)


# -- deployment ---------------------------------------------------------------------------------------
def test_the_daily_run_reads_the_state_before_deciding():
    daily = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "cronjob-daily.yaml").read_text()
    step = daily.split('define "a2vm-tenant.step.triage"')[1].split("{{- end -}}")[0]
    assert "verdict sla-state" in step and "--sla-state /data/work/sla-state.json" in step
    assert step.index("verdict sla-state") < step.index("verdict run")
    assert "/secrets/verdict-publish-token" in step and "WARN no SLA state" in step


def test_the_chat_documents_show_the_priority():
    from verdict.service import exports

    item = {"id": "a", "level": "ACT", "cve": "CVE-2024-0001", "asset": "host:web01", "priority": "P1",
            "sla_due": "2026-11-13", "due_date": "2026-11-20"}  # fmt: skip
    text = exports.build("csv", {"tenant": "lab", "run": {"id": "r", "generated_at": FRIDAY}}, [item], []).decode()
    assert text.splitlines()[0].endswith(";Priority;SLA due date") and ";P1;2026-11-13" in text
    detail = {"sla": {"priority": "P1", "due": "2026-11-13", "rule": 2, "days": 5, "calendar": "business",
                      "bod_due": "2026-11-20"}}  # fmt: skip
    lines = dict(exports._explanation(detail, "fr"))
    assert lines["Priorité"].startswith("Priorité P1 : échéance 2026-11-13 (règle 2, 5 jours ouvrés)")
    from verdict.service.tools import OPERATIONS

    search = next(op for op in OPERATIONS if op[1] == "search_decisions")
    assert {"priority", "sla_overdue", "sla_due_before"} <= {p["name"] for p in search[3]}


def test_decision_d19_and_the_release_are_recorded():
    import re

    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text()
    assert re.search(r"^\| D19 \| The client's priorities and SLA, within the levels", hld, re.M)
    assert "| v0.21.0 (current) | D19" in hld and "`a2vm.sla`" in hld
    assert "## 17. Priorities and SLA" in (ROOT / "docs" / "lld" / "triage-prioritization.md").read_text()
    assert (ROOT / "docs" / "sla.md").is_file()
