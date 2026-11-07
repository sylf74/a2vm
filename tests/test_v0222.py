# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.22.2: consolidation (radar precision, optional sharing of technologies, chat questions, full
package list, respect of the SLA measured on when a fix happened, radar proposals of the LLM)."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from via.alert import radar

NOW = dt.datetime(2026, 11, 7, 8, 0, tzinfo=dt.UTC)


def _item(title, cves=(), source="vendor-x", category="vendor", origin="rss", summary="", urgent=False):
    pub = SimpleNamespace(title=title, summary=summary, link=f"https://example.org/{source}", systems=[])
    return SimpleNamespace(
        title=title, cves=list(cves), source=source, category=category, origin=origin, publication=pub,
        facts={}, urgent_source=urgent,
    )  # fmt: skip


def test_markers_of_one_source_not_added_to_another() -> None:
    state: dict = {}
    cfg = radar.RadarConfig()
    a = _item("Product A flaw", ["CVE-2026-0001"], source="s1", summary="remote code execution")
    b = _item("Product A issue", ["CVE-2026-0001"], source="s2", summary="proof of concept available")
    radar.assess([a, b], {}, state, cfg, NOW)
    (event,) = state["events"].values()
    # best source 1 + 1 (rce), plus 2 for the other source; not 1 + 1 + 1 + 2
    assert event["score"] == 4
    assert sorted(event["markers"]) == ["poc", "rce"]


def test_bulletin_does_not_gather_by_cve() -> None:
    state: dict = {}
    cfg = radar.RadarConfig()
    cves = [f"CVE-2026-{1000 + i}" for i in range(20)]
    bulletin = _item(
        "Multiples vulnérabilités dans les produits Exemple", cves, source="certfr", category="institutional"
    )
    advisory = _item("SSA-1: remote code execution in Exemple Gateway", [cves[3]], source="vendor-exemple",
                     summary="unauthenticated remote code execution")  # fmt: skip
    radar.assess([bulletin, advisory], {}, state, cfg, NOW)
    assert len(state["events"]) == 2
    bulk = [e for e in state["events"].values() if e["bulk"]]
    assert len(bulk) == 1 and len(bulk[0]["cves"]) == 20


def test_old_sources_without_markers_take_the_event_markers() -> None:
    event = {"markers": ["rce"], "sources": [{"source": "s1", "base": 1}]}
    assert radar._score(event) == 2


def test_bulk_cves_in_profile_schema() -> None:
    from a2vm.io import load_schema

    radar_props = load_schema("client_profile")["properties"]["alerts"]["properties"]["radar"]["properties"]
    assert "bulk_cves" in radar_props
    assert radar.RadarConfig().bulk_cves == 10


def test_technologies_are_not_sent_unless_the_profile_shares_them(tmp_path) -> None:
    from pathlib import Path

    import httpx

    from a2vm.config import load_settings
    from a2vm.profile import load_profile
    from via.alert.cli import push_technologies
    from via.alert.watch import State

    root = Path(__file__).resolve().parents[1]
    sent = []
    token = tmp_path / "token"
    token.write_text("t" * 40)
    settings = load_settings(root / "config" / "settings.yaml")
    settings.sources.intel_url, settings.sources.intel_token_file = "http://intel.example", str(token)
    profile = load_profile(root / "examples" / "example-client" / "client.yaml")
    state = State.load(tmp_path / "state.json")
    transport = httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={"kept": 1}))
    assert push_technologies(settings, profile, state, transport) == "" and not sent


def _index_with_components():
    from verdict.service.index import RunIndex

    doc = {
        "rows": [],
        "assets": [
            {"id": "host:web01.lab.example", "name": "web01", "kind": "host", "zone": "dmz", "exposure": "open",
             "components": [{"name": "openssl", "version": "3.0.7-27.el9", "type": "rpm"},
                            {"name": "openssl-libs", "version": "3.0.7-27.el9", "type": "rpm"}],
             "components_seen": "2026-11-07T06:00:00+00:00"},
            {"id": "host:db01.lab.example", "name": "db01", "kind": "host",
             "components": [{"name": "openssl", "version": "3.2.2-6.el9", "type": "rpm"}],
             "components_seen": "2026-11-07T06:00:00+00:00"},
            {"id": "host:edge01.lab.example", "name": "edge01", "kind": "host"},
        ],
    }  # fmt: skip
    return RunIndex({"id": "r1", "generated_at": "2026-11-07T06:00:00+00:00"}, doc)


def test_find_component_counts_in_the_service() -> None:
    idx = _index_with_components()
    out = idx.components({"name": "openssl"})
    assert out["assets_with_it"] == 2 and out["assets_listed"] == 2 and out["hosts_not_listed"] == 1
    assert out["versions"] == {"openssl 3.0.7-27.el9": 1, "openssl-libs 3.0.7-27.el9": 1, "openssl 3.2.2-6.el9": 1}
    exact = idx.components({"name": "OpenSSL", "exact": "true", "version": "3.2"})
    assert [i["asset"] for i in exact["items"]] == ["host:db01.lab.example"]


def test_find_component_needs_a_name() -> None:
    import pytest

    from verdict.service.index import QueryError

    with pytest.raises(QueryError):
        _index_with_components().components({})


def test_find_component_is_a_tool_and_in_the_contract() -> None:
    from pathlib import Path

    import yaml

    from verdict.service.tools import OPERATIONS

    assert any(op[1] == "find_component" and op[4] == "components" for op in OPERATIONS)
    spec = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "a2vm/src/a2vm/schemas/openapi/verdict.v1.yaml").read_text()
    )
    assert spec["paths"]["/v1/tenants/{tenant}/components"]["get"]["operationId"] == "findComponent"


def test_components_reach_the_asset_and_the_triage() -> None:
    from a2vm.models import AssetObservation
    from verdict.assets.build import build_inventory  # noqa: F401 - imported for its module's use below
    from verdict.triage import run_asset

    obs_old = AssetObservation(
        ref="web01",
        kind="host",
        source="trivy",
        observed_at="2026-11-06T06:00:00+00:00",
        name="web01",
        components=[{"name": "bash", "version": "5.1"}],
    )
    obs_new = AssetObservation(ref="web01", kind="host", source="dnf-updateinfo",
                               observed_at="2026-11-07T06:00:00+00:00", name="web01",
                               components=[{"name": "bash", "version": "5.2"}])  # fmt: skip
    from pathlib import Path

    from a2vm.io import Detection
    from a2vm.profile import load_profile

    root = Path(__file__).resolve().parents[1]
    profile = load_profile(root / "examples" / "example-client" / "client.yaml")
    inv = build_inventory(profile, [Detection(profile.id, "trivy", [obs_old], []),
                                    Detection(profile.id, "dnf-updateinfo", [obs_new], [])])  # fmt: skip
    (asset,) = [a for a in inv.assets if a.name == "web01"]
    # since v0.23.0 each component carries its source and when it was seen
    assert [(c["name"], c["version"]) for c in asset.components] == [("bash", "5.2")]
    entry = run_asset(asset)
    assert entry["components"][0]["version"] == "5.2" and entry["components_seen"].startswith("2026-11-07")


def test_closed_findings_by_period_and_assets_with_counts(tenant_db, settings, sources, profile, tmp_path):
    import gzip
    import json

    from a2vm.db import Database
    from a2vm.service import TokenSet, digest
    from verdict.report import write_json
    from verdict.service.index import row_id
    from verdict.service.pgstore import MIGRATIONS, PgRunStore
    from verdict.service.server import Service

    from .test_pipeline import _run

    publish, read = "publish-token-0123456789abcdef0123", "read-token-0123456789abcdef01234567"
    path = tmp_path / "triage.json"
    write_json(_run(settings, sources, profile), path)
    doc = json.loads(path.read_text())
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(publish)}\nread {digest(read)}\n")
    db = Database(tenant_db, "verdict", MIGRATIONS)
    db.init()
    service = Service(doc["client"]["id"], TokenSet.load(digests, {"publish", "read"}), PgRunStore(db, keep=3))
    tenant = service.tenant

    def push(d, key):
        service.push(tenant, publish, key, gzip.compress(json.dumps(d).encode()), True)

    rescanned = [{**x, "scans": {k: "2100-01-01T00:00:00+00:00" for k in x["scans"]}} for x in doc["assets"]]
    push({**doc, "generated_at": "2026-10-01T06:00:00+00:00"}, "k1")
    rows = list(doc["rows"])
    first, second = rows[0], next(r for r in rows[1:] if r["asset_id"] != rows[0]["asset_id"])
    rows2 = [r for r in rows if r is not first]
    push({**doc, "generated_at": "2026-10-10T06:00:00+00:00", "rows": rows2, "assets": rescanned}, "k2")
    rows3 = [r for r in rows2 if r is not second]
    push({**doc, "generated_at": "2026-11-03T06:00:00+00:00", "rows": rows3, "assets": rescanned}, "k3")

    october = service.read(tenant, read, "findings/closed", {"since": "2026-10-01", "until": "2026-10-31"})
    assert october["total"] == 1 and october["items"][0]["id"] == row_id(first)
    assert october["until"] == "2026-10-31"
    assert sum(october["counts"]["by_level"].values()) == 1
    both = service.read(tenant, read, "findings/closed", {"since": "2026-09-01"})
    assert both["total"] == 2 and sum(sum(v.values()) for v in both["counts"]["by_asset"].values()) == 2
    name = second["asset_id"]
    one = service.read(tenant, read, "findings/closed", {"since": "2026-09-01", "asset": name})
    assert one["total"] == 1 and one["items"][0]["id"] == row_id(second)
    import pytest

    from a2vm.service import Problem

    with pytest.raises(Problem, match="no such asset"):
        service.read(tenant, read, "findings/closed", {"asset": "nowhere-host"})
    db.close()


def test_tickets_sent_over_a_period_with_their_itsm_number(tmp_path) -> None:

    import pytest

    from a2vm.service import Problem, TokenSet, digest
    from dispatch.rules import Rules
    from dispatch.service import Service
    from dispatch.store import FileStore

    from .test_v0200 import RULES, FakeDecisions, FakeTool, dec

    a = "host:web01.lab.example"
    tokens = TokenSet({"run": [digest("r" * 40)], "read": [digest("d" * 40)]})
    tool = FakeTool()
    decisions = FakeDecisions([dec(1, a, "ACT", ["openssl 3.0.15"]), dec(2, a, "ACT", ["bash 5.2"])])
    store = FileStore(tmp_path, "lab")
    svc = Service("lab", tokens, store, Rules.from_dict(RULES), lambda: decisions, connector_for=lambda name: tool)
    assert svc.process("lab", "r" * 40)["sent"] == 2
    tickets = store.tickets()
    tickets[0].created_at = "2026-10-05T06:00:00+00:00"  # one sent in October, the other in November
    tickets[1].created_at = "2026-11-02T06:00:00+00:00"
    for t in tickets:
        store.put(t)
    october = svc.read("lab", "d" * 40, "tickets", {"since": "2026-10-01", "until": "2026-10-31"})
    assert october["total"] == 1 and october["counts"]["with_itsm_ref"] == 1
    assert october["items"][0]["sent_at"].startswith("2026-10-05")
    assert october["items"][0]["external"]["ref"].startswith("UserRequest::")
    both = svc.read("lab", "d" * 40, "tickets", {"since": "2026-10-01", "limit": "1"})
    assert both["total"] == 2 and len(both["items"]) == 1 and both["next_offset"] == 1
    assert both["items"][0]["sent_at"].startswith("2026-11-02")  # newest first
    with pytest.raises(Problem, match="since"):
        svc.read("lab", "d" * 40, "tickets", {"since": "October"})


def test_the_chat_lists_the_tickets_through_dispatch() -> None:
    import json

    import httpx

    from a2vm.service import TokenSet, digest
    from verdict.service.tools import Tools

    seen = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "dispatch.example":
            body = {"mode": "live", "total": 1, "counts": {"by_state": {"sent": 1}}, "items": [
                {"key": "host:web01 / openssl", "external": {"ref": "R-000042"}, "sent_at": "2026-10-05"}]}  # fmt: skip
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"detail": "no"})

    chat = "c" * 40
    tools = Tools(
        "lab", TokenSet({"chat": [digest(chat)]}), "http://verdict.example", "v" * 40,
        transport=httpx.MockTransport(answer), dispatch_url="http://dispatch.example", dispatch_token="t" * 40,
    )  # fmt: skip
    out = tools.call(chat, "/tickets", {"since": "2026-10-01"})
    assert out["items"][0]["external"]["ref"] == "R-000042" and "dispatch" in out["source"]
    assert "since=2026-10-01" in seen[0] and "limit=10" in seen[0]
    assert json.dumps(out)


def test_the_tools_pod_reads_dispatch_when_it_runs() -> None:
    from pathlib import Path

    chat = (Path(__file__).resolve().parents[1] / "deploy/charts/a2vm-tenant/templates/chat.yaml").read_text()
    assert '--dispatch-url={{ include "a2vm-tenant.dispatchUrl" . }}' in chat
    assert "--dispatch-token-file=/secrets/dispatch-read-token" in chat
    assert chat.count("{{- if .Values.dispatch.enabled }}") >= 4  # label, args, secret item, egress
    values = (Path(__file__).resolve().parents[1] / "deploy/charts/a2vm-tenant/values.yaml").read_text()
    assert "list_tickets" in values and "find_component" in values and "never count a list yourself" in values


# -- respect of the SLA measured on when a fix happened (D19, v0.22.2) ---------------------------------
from .test_restitution import ADMIN, needs_db, reporting_db  # noqa: E402, F401, F811 - the fixture


@needs_db
def test_fix_status_from_the_interval_and_the_declared_date(settings, sources, tmp_path, reporting_db):  # noqa: F811
    import json

    import psycopg

    from verdict.reporting import build
    from verdict.restitution import db
    from verdict.restitution.cli import main

    from .test_v0210 import _sla_run

    rdb = reporting_db
    run = _sla_run(settings, sources, tmp_path)
    day1 = {"schema": "a2vm.reporting/1", **build(run, settings.policy)}
    fixed = next(d for d in day1["decisions"] if d["priority"] == "P4")
    other = next(d for d in day1["decisions"] if d["priority"] and d is not fixed and d["asset"] != fixed["asset"])
    seen = {"inventory": "2026-11-02T06:00:00+00:00"}
    for d in (fixed, other):
        d["seen_by"] = seen
    deadline = fixed.get("sla_due") or fixed["due_date"]
    day2 = json.loads(json.dumps(day1))
    day2["generated_at"] = "2026-11-07T09:00:00+00:00"
    day2["decisions"] = [
        d for d in day2["decisions"] if d["finding_id"] not in (fixed["finding_id"], other["finding_id"])
    ]
    for a in day2["assets"]:
        if a["id"] == fixed["asset"]:
            a["scans"] = {"inventory": "2100-01-01T00:00:00+00:00"}  # first clean scan long after the deadline
        if a["id"] == other["asset"]:
            a["scans"] = {"inventory": "2026-11-03T06:00:00+00:00"}  # the next day: on time
    assert db.init(ADMIN, rdb["writer"]).startswith("schema a2vm version 6")
    for i, d in enumerate((day1, day2)):
        p = tmp_path / f"r{i}.json"
        p.write_text(json.dumps(d))
        assert main(["publish", str(p), "--dsn", rdb["as_writer"]]) == 0

    def status(finding):
        with psycopg.connect(rdb["as_writer"]) as conn:
            return conn.execute(
                "SELECT fix_status, last_vulnerable::date, first_clean::date FROM a2vm.finding_closures "
                "WHERE finding_id = %s",
                (finding,),
            ).fetchone()

    assert status(other["finding_id"])[0] == "met (observed)"
    assert status(fixed["finding_id"])[0] == "to verify"
    declared = [{"finding": fixed["finding_id"], "declared_at": f"{deadline}T08:00:00+00:00", "ref": "R-000042"}]
    run2 = db.load(tmp_path / "r1.json")
    db.publish(rdb["as_writer"], run2, declared)
    assert status(fixed["finding_id"])[0] == "met (declared, verified)"
    too_late = [{"finding": fixed["finding_id"], "declared_at": "2099-01-01T08:00:00+00:00"}]
    db.publish(rdb["as_writer"], run2, too_late)
    assert status(fixed["finding_id"])[0] == "missed"  # declared in the interval, after the deadline
    outside = [{"finding": fixed["finding_id"], "declared_at": "2026-10-01T08:00:00+00:00"}]
    db.publish(rdb["as_writer"], run2, outside)
    assert status(fixed["finding_id"])[0] == "to verify"  # before the last scan that still saw it: not believed


# -- dispatch: the declared date of a fix, the due date in the ticket (v0.22.2) ------------------------
def test_dispatch_keeps_the_declared_date_and_writes_the_due_date(tmp_path) -> None:
    from a2vm.service import TokenSet, digest
    from dispatch.rules import Rules
    from dispatch.service import Service

    from .test_v0200 import RULES, FakeDecisions, FakeTool, dec, dispatcher

    class Tool(FakeTool):
        due_field = "a2vm_due_date"

        def __init__(self):
            super().__init__()
            self.dues, self.declared = [], {}

        def set_due(self, external, due):
            self.dues.append((external.ref, due))
            return True

        def declared_fix(self, external):
            return self.declared.get(external.ref, "")

    a = "host:web01.lab.example"
    tool = Tool()
    d, _ = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"], due="2026-11-20")], tool=tool)
    assert d.process_run()["sent"] == 1
    (t,) = d.store.tickets()
    assert t.due_pushed == "2026-11-20" and tool.dues == []  # written with the ticket
    d.decisions = FakeDecisions([dec(1, a, "ACT", ["openssl 3.0.15"], due="2026-11-12")], run="R2")
    d.process_run()
    assert tool.dues == [("UserRequest::1", "2026-11-12")]
    d.process_run()
    assert len(tool.dues) == 1  # unchanged: not written again
    tool.statuses["1"] = "resolved"  # the team says it fixed, the scan still sees it
    tool.declared["UserRequest::1"] = "2026-11-11T16:30:00"
    d.process_run()
    (t,) = d.store.tickets()
    assert t.declared_fixed_at == "2026-11-11T16:30:00" and t.state in ("claimed-fixed", "in-progress")
    tokens = TokenSet({"run": [digest("r" * 40)], "read": [digest("d" * 40)]})
    svc = Service("lab", tokens, d.store, Rules.from_dict(RULES), lambda: d.decisions, connector_for=lambda n: tool)
    fixes = svc.read("lab", "d" * 40, "fixes", {})
    assert fixes["items"] == [
        {"finding": "f1", "declared_at": "2026-11-11T16:30:00", "ref": "UserRequest::1", "ticket": t.key}
    ]


def test_itop_due_field_and_resolution_date() -> None:
    import json

    import httpx

    from dispatch.connectors import External
    from dispatch.connectors.itop import ItopConnector
    from dispatch.rules import Rules

    from .test_v0200 import RULES

    seen = []

    def handler(request):
        payload = json.loads(dict(httpx.QueryParams(request.content.decode()))["json_data"])
        seen.append(payload)
        if payload["operation"] == "core/get":
            fields = {"resolution_date": "2026-11-11 16:30:00"}
            return httpx.Response(200, json={"code": 0, "objects": {"UserRequest::42": {"code": 0, "fields": fields}}})
        return httpx.Response(200, json={"code": 0, "objects": {"x": {"code": 0, "key": "42", "fields": {"id": "42"}}}})

    rules = {**RULES, "targets": {"itsm": {**RULES["targets"]["itsm"], "due_field": "a2vm_due_date"}}}
    c = ItopConnector(Rules.from_dict(rules).targets["itsm"], "secret", transport=httpx.MockTransport(handler))
    ext = External(ref="UserRequest::42")
    assert c.set_due(ext, "2026-11-12") and seen[-1]["fields"] == {"a2vm_due_date": "2026-11-12"}
    assert c.declared_fix(ext) == "2026-11-11T16:30:00"
    plain = ItopConnector(Rules.from_dict(RULES).targets["itsm"], "secret", transport=httpx.MockTransport(handler))
    assert plain.set_due(ext, "2026-11-12") is False


# -- radar: proposals of the LLM (v0.22.2) ---------------------------------------------------------------
class _FakeLlm:
    model = "fake-model"

    def __init__(self, product=None, same=""):
        self.product, self.same, self.calls = product or {"vendor": "", "product": ""}, same, []

    def structured(self, system, user, name, schema):
        self.calls.append(name)
        if name == "radar_product":
            return dict(self.product)
        return {"event": self.same, "justification": "same flaw, French and English titles"}


def test_the_llm_proposes_a_product_and_a_same_event_but_decides_nothing() -> None:
    state: dict = {}
    cfg = radar.RadarConfig(info=1)
    first = _item("Exemple Gateway zero-day exploited in the wild", source="blog", summary="unauthenticated RCE")
    radar.assess([first], {}, state, cfg, NOW)
    second = _item("Vulnérabilité jour zéro dans Exemple Gateway", source="certfr", category="institutional")
    found = radar.assess([second], {}, state, cfg, NOW + dt.timedelta(hours=1))
    assert len(state["events"]) == 2  # the rules did not gather them (two languages)
    new = next(e for e, _ in found if e["sources"][0]["source"] == "certfr")
    old = next(e for e in state["events"].values() if e is not new)
    score_before = new["score"]
    llm = _FakeLlm({"vendor": "Exemple", "product": "Gateway"}, same=old["id"])
    since = (NOW - dt.timedelta(hours=72)).isoformat(timespec="seconds")
    new["alerts"] = 0
    assert radar.propose([new], state, llm, cfg, since) == 2
    assert new["proposals"]["product"] == {"vendor": "Exemple", "product": "Gateway", "model": "fake-model"}
    assert new["proposals"]["same_as"]["event"] == old["id"]
    assert new["score"] == score_before and new["products"] == [] and len(state["events"]) == 2


def test_an_unknown_event_id_from_the_llm_is_dropped_and_calls_are_capped() -> None:
    state: dict = {}
    cfg = radar.RadarConfig(llm_calls=1)
    a = _item("Exemple Gateway flaw", source="s1")
    radar.assess([a], {}, state, cfg, NOW)
    radar.assess([_item("Gateway Exemple advisory", ["CVE-2026-9"], source="s3")], {}, state, cfg, NOW)
    events = list(state["events"].values())
    llm = _FakeLlm(same="R-made-up")
    since = (NOW - dt.timedelta(hours=72)).isoformat(timespec="seconds")
    radar.propose(events, state, llm, cfg, since)
    assert len(llm.calls) == 1  # the cap
    assert all("same_as" not in (e.get("proposals") or {}) for e in events)


def test_the_sheet_shows_the_proposals_to_check() -> None:
    from via.alert.fiche import _radar_why

    alert = SimpleNamespace(radar={
        "why": "new", "score": 7, "cves": [], "markers": [], "sources": [],
        "proposals": {"product": {"vendor": "Exemple", "product": "Gateway", "model": "m"},
                      "same_as": {"event": "R20261107-0001", "why": "same flaw", "model": "m"}},
    })  # fmt: skip
    text = "\n".join(_radar_why(alert, "fr"))
    assert "produit proposé par le LLM, à vérifier : Exemple Gateway" in text
    assert "R20261107-0001" in text and "à vérifier" in text


def test_release_0222_recorded() -> None:
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    hld = (root / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.22\.2( \(current\))? \| Consolidation", hld, re.M)
    assert "## v0.22.2 — " in (root / "CHANGELOG.md").read_text(encoding="utf-8")
