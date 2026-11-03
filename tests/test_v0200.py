# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.20.0: pillar 4, dispatch: remediation tickets (asset x fix), the rules of the tenant, the
follow-up of the tickets, the requests of a person (D18), the iTop connector."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import httpx
import pytest

from a2vm.service import Problem, TokenSet, digest
from dispatch import tickets as tk
from dispatch.connectors import CLOSED, WORKING, ConnectorError, External
from dispatch.connectors.itop import ItopConnector
from dispatch.engine import Dispatcher
from dispatch.page import Denied, RequestPage
from dispatch.rules import Rules, RulesError, load_rules
from dispatch.service import Service
from dispatch.store import FileStore

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "schema_version": 1,
    "mode": "live",
    "targets": {
        "itsm": {
            "type": "itop",
            "url": "https://itop.example.org",
            "user": "a2vm-itsm",
            "organization": "Lab",
            "caller": "A2VM",
        }
    },
    "tickets": {"target": "itsm", "automatic": "act", "exclude_zones": ["lab"]},
    "requests": {"targets": ["itsm"], "max_tickets": 10},
}


def dec(i, asset, level, fixes, cve=None, zone="dmz", due="2026-11-10"):
    return {
        "id": f"f{i}",
        "cve": cve or f"CVE-2026-{1000 + i}",
        "asset": asset,
        "asset_name": asset.split(":")[-1].split(".")[0],
        "level": level,
        "kev": level == "ACT",
        "epss": 0.5,
        "cvss": 9.8,
        "due_date": due,
        "zone": zone,
        "product": "openssl",
        "title": "t",
        "fixes": fixes,
    }


class FakeDecisions:
    def __init__(self, items, closed=(), cards=None, run="R1"):
        self.items = list(items)
        self.closed = list(closed)
        self.cards = cards or {}
        self.run = {"id": run, "generated_at": "2026-11-03T06:00:00Z"}

    def latest_run(self):
        return self.run

    def decisions(self, filters=None, limit=None):
        f = filters or {}
        rows = self.items
        if "level" in f:
            levels = set(f["level"].split(","))
            rows = [d for d in rows if d["level"] in levels]
        if "asset" in f:
            rows = [d for d in rows if d["asset"] == f["asset"] or d["asset_name"] == f["asset"]]
        return self.run, list(rows)

    def asset(self, asset):
        return self.cards.get(asset, {})

    def closed_since(self, since):
        return self.closed

    def close(self):
        pass


class FakeTool:
    def __init__(self):
        self.created, self.comments, self.resolved, self.reopened = [], [], [], []
        self.statuses = {}

    def create(self, ticket, text, title):
        n = len(self.created) + 1
        self.created.append((ticket.key, title, ticket.cmdb))
        self.statuses[str(n)] = "new"
        return External(ref=f"UserRequest::{n}", url=f"https://itop.example.org/{n}", status="new")

    def comment(self, external, text):
        self.comments.append((external.ref, text))

    def resolve(self, external, text):
        self.resolved.append(external.ref)

    def reopen(self, external, text):
        self.reopened.append(external.ref)

    def status(self, external):
        s = self.statuses.get(external.ref.split("::")[1], "")
        return s, CLOSED if s in ("resolved", "closed") else WORKING

    def close(self):
        pass


def dispatcher(tmp_path, items, rules=None, tool=None, closed=(), cards=None):
    tool = tool or FakeTool()
    d = Dispatcher(
        "lab",
        rules or Rules.from_dict(RULES),
        FileStore(tmp_path, "lab"),
        FakeDecisions(items, closed, cards),
        lambda name: tool,
        clock=lambda: "2026-11-03T07:00:00+00:00",
    )
    return d, tool


# -- rules -------------------------------------------------------------------------------------
def test_rules_defaults_and_checks(tmp_path):
    assert load_rules(None).automatic_levels == () and load_rules(tmp_path / "none.yaml").request_targets == ()
    r = Rules.from_dict(RULES)
    assert r.live and r.automatic_levels == ("ACT",) and not r.dispatchable("lab")
    r2 = Rules.from_dict({**RULES, "mode": "dry-run", "tickets": {"target": "itsm", "automatic": "act-attend"}})
    assert r2.automatic_levels == ("ACT", "ATTEND") and not r2.live
    assert Rules.from_dict({**RULES, "tickets": {"target": "itsm", "automatic": "none"}}).automatic_levels == ()
    assert Rules.from_dict({k: v for k, v in RULES.items() if k != "mode"}).mode == "dry-run"
    with pytest.raises(RulesError, match="not declared"):
        Rules.from_dict({**RULES, "tickets": {"target": "soc"}})
    with pytest.raises(RulesError, match="password"):
        Rules.from_dict({**RULES, "targets": {"itsm": {**RULES["targets"]["itsm"], "password": "x"}}})


def test_tenant_example_is_valid():
    rules = load_rules(ROOT / "examples" / "lab" / "dispatch.yaml")
    assert rules.mode == "dry-run" and rules.request_targets


# -- grouping ----------------------------------------------------------------------------------
def test_one_ticket_per_asset_and_fix_each_decision_once():
    a = "host:web01.lab.example"
    items = [
        dec(1, a, "ACT", ["openssl 3.0.15"]),
        dec(2, a, "ATTEND", ["openssl 3.0.15", "libssl 3.1"]),
        dec(3, a, "TRACK", ["libssl 3.1"]),
        dec(4, a, "ACT", []),
        dec(5, "host:db01.lab.example", "ACT", ["openssl 3.0.15"]),
    ]
    built = tk.build(items, "itsm")
    assert set(built) == {
        f"{a} / openssl 3.0.15",
        f"{a} / libssl 3.1",
        f"{a} / no known fix",
        "host:db01.lab.example / openssl 3.0.15",
    }
    assert set(built[f"{a} / openssl 3.0.15"].findings) == {"f1", "f2"}  # f2: the fix with most ACT
    assert set(built[f"{a} / libssl 3.1"].findings) == {"f3"}
    t = built[f"{a} / openssl 3.0.15"]
    assert t.level == "ACT" and t.due == "2026-11-10"
    assert tk.title(t).startswith("[A2VM ACT] web01: apply openssl 3.0.15 (2 CVEs)")
    assert "<script" not in tk.description(tk.build([dec(9, a, "ACT", ["<script>"])], "x")[f"{a} / <script>"])


# -- after a run -------------------------------------------------------------------------------
def test_automatic_act_tickets_sent_once_with_the_cmdb_item(tmp_path):
    a = "host:web01.lab.example"
    items = [dec(1, a, "ACT", ["openssl 3.0.15"]), dec(2, a, "ATTEND", ["openssl 3.0.15"]),
             dec(3, "host:lab01.lab.example", "ACT", ["x 1"], zone="lab")]  # fmt: skip
    d, tool = dispatcher(tmp_path, items, cards={a: {"cmdb": [{"class": "VirtualMachine", "key": "12"}]}})
    s = d.process_run()
    assert s["sent"] == 1 and s["errors"] == 0
    assert tool.created == [(f"{a} / openssl 3.0.15", tool.created[0][1], {"class": "VirtualMachine", "key": "12"})]
    t = d.store.get(f"{a} / openssl 3.0.15")
    assert t.state == "sent" and set(t.findings) == {"f1"}  # ATTEND not automatic
    s = d.process_run()  # the same run again: nothing new
    assert s["sent"] == 0 and len(tool.created) == 1 and tool.comments == []


def test_dry_run_proposes_then_live_sends(tmp_path):
    a = "host:web01.lab.example"
    items = [dec(1, a, "ACT", ["openssl 3.0.15"])]
    d, tool = dispatcher(tmp_path, items, rules=Rules.from_dict({**RULES, "mode": "dry-run"}))
    assert d.process_run()["proposed"] == 1 and tool.created == []
    assert d.store.get(f"{a} / openssl 3.0.15").state == "proposed"
    d2, tool2 = dispatcher(tmp_path, items)
    assert d2.process_run()["sent"] == 1 and len(tool2.created) == 1


def test_new_findings_are_added_with_a_comment(tmp_path):
    a = "host:web01.lab.example"
    d, tool = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"])])
    d.process_run()
    d.decisions.items.append(dec(2, a, "ACT", ["openssl 3.0.15"]))
    s = d.process_run()
    assert s["updated"] == 1 and "CVE-2026-1002" in tool.comments[-1][1]
    assert set(d.store.get(f"{a} / openssl 3.0.15").findings) == {"f1", "f2"}


def test_fixed_only_when_a_scan_confirms_then_resolved(tmp_path):
    a = "host:web01.lab.example"
    d, tool = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"]), dec(2, a, "ACT", ["openssl 3.0.15"])])
    d.process_run()
    key = f"{a} / openssl 3.0.15"
    d.decisions.items = [dec(2, a, "ACT", ["openssl 3.0.15"])]  # f1 gone: not confirmed yet
    d.process_run()
    t = d.store.get(key)
    assert t.findings["f1"].state == "unverified" and t.is_open
    d.decisions.items = []
    d.decisions.closed = [{"id": f, "closed_at": "2026-11-04T06:00:00Z"} for f in ("f1", "f2")]
    s = d.process_run()
    t = d.store.get(key)
    assert s["fixed"] == 1 and t.state == "fixed" and tool.resolved == ["UserRequest::1"]
    assert any("fixed, confirmed by a scan" in c[1] for c in tool.comments)


def test_closed_in_the_tool_while_still_seen_is_reopened(tmp_path):
    a = "host:web01.lab.example"
    d, tool = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"])])
    d.process_run()
    tool.statuses["1"] = "resolved"
    s = d.process_run()
    assert s["claimed_fixed"] == 1 and s["reopened"] == 1 and tool.reopened == ["UserRequest::1"]
    assert d.store.get(f"{a} / openssl 3.0.15").state == "in-progress"


def test_a_refused_ticket_stays_proposed_and_is_retried(tmp_path):
    a = "host:web01.lab.example"

    class Refusing(FakeTool):
        def create(self, ticket, text, title):
            raise ConnectorError("iTop refused: code 100: no such Person")

    d, _ = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"])], tool=Refusing())
    assert d.process_run()["errors"] == 1
    t = d.store.get(f"{a} / openssl 3.0.15")
    assert t.state == "proposed" and "no such Person" in t.error
    d2, tool = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"])])
    assert d2.process_run()["sent"] == 1


# -- requests of a person ------------------------------------------------------------------------
def test_request_preview_writes_nothing_then_confirm_records_who(tmp_path):
    a = "host:web01.lab.example"
    rules = Rules.from_dict({**RULES, "tickets": {"target": "itsm", "automatic": "none"}})
    items = [dec(1, a, "ATTEND", ["openssl 3.0.15"]), dec(2, a, "TRACK", ["zlib 1.3"]),
             dec(3, "host:lab01", "ACT", [], zone="lab")]  # fmt: skip
    d, tool = dispatcher(tmp_path, items, rules=rules)
    view = d.preview({"asset": a})
    assert [t["key"] for t in view["tickets"]] == [f"{a} / openssl 3.0.15", f"{a} / zlib 1.3"]
    assert d.store.tickets() == [] and tool.created == []
    out = d.confirm({"asset": a}, [f"{a} / openssl 3.0.15"], "rssi@lab.example", comment="before Friday", run_id="R1")
    assert [r["state"] for r in out["results"]] == ["sent"] and len(tool.created) == 1
    t = d.store.get(f"{a} / openssl 3.0.15")
    assert t.origin == "request" and t.requested_by == "rssi@lab.example" and t.comment == "before Friday"
    assert d.store.requests()[0]["by"] == "rssi@lab.example"
    again = d.confirm({"asset": a}, [f"{a} / openssl 3.0.15"], "other@lab.example", run_id="R1")
    assert len(tool.created) == 1 and again["results"][0]["ref"] == "UserRequest::1"  # no duplicate
    assert d.confirm({"asset": a}, [f"{a} / zlib 1.3"], "x@lab.example", run_id="R0")["changed"] is True


def test_request_levels_and_cap(tmp_path):
    rules = Rules.from_dict({**RULES, "requests": {"targets": ["itsm"], "levels": ["ACT"], "max_tickets": 2}})
    items = [dec(i, f"host:h{i}", "ACT", ["p 1"]) for i in range(5)] + [dec(9, "host:h9", "TRACK", ["p 1"])]
    d, _ = dispatcher(tmp_path, items, rules=rules)
    view = d.preview({"level": "ACT,TRACK"})
    assert view["filters"]["level"] == "ACT" and len(view["tickets"]) == 2 and view["capped"] and view["total"] == 5


# -- page --------------------------------------------------------------------------------------
class H(dict):
    def get(self, k, default=None):
        return super().get(k, default)


def test_page_refuses_outside_the_group_and_checks_the_form(tmp_path):
    a = "host:web01.lab.example"
    rules = Rules.from_dict({**RULES, "tickets": {"target": "itsm", "automatic": "none"}})
    d, tool = dispatcher(tmp_path, [dec(1, a, "ACT", ["openssl 3.0.15"])], rules=rules)
    page = RequestPage("lab", b"k" * 32, {"A2VM-Remediation"}, "https://dispatch-lab.apps.example.org")
    with pytest.raises(Denied) as e:
        page.get(d, H(), {"asset": [a]})
    assert e.value.status == HTTPStatus.UNAUTHORIZED
    with pytest.raises(Denied) as e:
        page.get(d, H({"X-Forwarded-Email": "x@lab.example", "X-Forwarded-Groups": "A2VM-Analysts"}), {"asset": [a]})
    assert e.value.status == HTTPStatus.FORBIDDEN
    who = H({"X-Forwarded-Email": "rssi@lab.example", "X-Forwarded-Groups": "/A2VM-Remediation"})
    html_page = page.get(d, who, {"asset": [a]})
    assert "openssl 3.0.15" in html_page and "Send the tickets" in html_page and tool.created == []
    filters = d.selection({"asset": a})
    form = {"asset": [a], "level": [filters["level"]], "run": ["R1"], "key": [f"{a} / openssl 3.0.15"]}
    with pytest.raises(Denied, match="does not come"):
        good = [page.token("rssi@lab.example", filters, "R1")]
        page.post(d, H({**who, "Origin": "https://evil.example"}), {**form, "token": good})
    with pytest.raises(Denied, match="invalid token"):
        page.post(d, H({**who, "Origin": "https://dispatch-lab.apps.example.org"}), {**form, "token": ["0" * 64]})
    ok = H({**who, "Origin": "https://dispatch-lab.apps.example.org"})
    done = page.post(d, ok, {**form, "token": [page.token("rssi@lab.example", filters, "R1")]})
    assert "UserRequest::1" in done and len(tool.created) == 1


# -- service -----------------------------------------------------------------------------------
def test_service_roles_and_reads(tmp_path):
    a = "host:web01.lab.example"
    tokens = TokenSet({"run": [digest("r" * 40)], "read": [digest("d" * 40)]})
    tool = FakeTool()
    decisions = FakeDecisions([dec(1, a, "ACT", ["openssl 3.0.15"])])
    svc = Service("lab", tokens, FileStore(tmp_path, "lab"), Rules.from_dict(RULES), lambda: decisions,
                  connector_for=lambda name: tool)  # fmt: skip
    with pytest.raises(Problem) as e:
        svc.process("lab", "d" * 40)
    assert e.value.status == HTTPStatus.UNAUTHORIZED
    with pytest.raises(Problem):
        svc.process("other", "r" * 40)
    assert svc.process("lab", "r" * 40)["sent"] == 1
    listed = svc.read("lab", "d" * 40, "tickets", {"state": "open"})
    assert listed["total"] == 1 and listed["items"][0]["external"]["ref"] == "UserRequest::1"
    one = svc.read("lab", "d" * 40, f"tickets/{listed['items'][0]['id']}", {})
    assert one["findings"][0]["cve"] == "CVE-2026-1001"
    with pytest.raises(Problem):
        svc.read("lab", "r" * 40, "tickets", {})


# -- iTop --------------------------------------------------------------------------------------
def test_itop_connector_maps_the_ticket():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        payload = json.loads(form["json_data"])
        seen.append((form["auth_user"], payload))
        if payload["operation"] == "core/create":
            fields = {"id": "42", "ref": "R-000042", "status": "new"}
            obj = {"code": 0, "class": "UserRequest", "key": "42", "fields": fields}
            return httpx.Response(200, json={"code": 0, "objects": {"UserRequest::42": obj}})
        if payload["operation"] == "core/get":
            obj = {"fields": {"status": "resolved"}}
            return httpx.Response(200, json={"code": 0, "objects": {"UserRequest::42": obj}})
        return httpx.Response(200, json={"code": 0, "objects": {"UserRequest::42": {"code": 0}}})

    rules = Rules.from_dict({**RULES, "targets": {"itsm": {**RULES["targets"]["itsm"], "team": "Linux"}}})
    c = ItopConnector(rules.targets["itsm"], "secret", transport=httpx.MockTransport(handler))
    t = tk.build([dec(1, "host:web01", "ACT", ["openssl 3.0.15"])], "itsm")["host:web01 / openssl 3.0.15"]
    t.cmdb = {"class": "VirtualMachine", "key": "12"}
    ext = c.create(t, tk.description(t), tk.title(t))
    assert ext.ref == "UserRequest::42" and ext.url.endswith("class=UserRequest&id=42")
    user, p = seen[0]
    assert user == "a2vm-itsm" and p["class"] == "UserRequest"
    f = p["fields"]
    assert f["org_id"] == {"name": "Lab"} and f["caller_id"] == {"name": "A2VM"} and f["team_id"] == {"name": "Linux"}
    assert (f["impact"], f["urgency"]) == ("2", "1") and f["functionalcis_list"] == [{"functionalci_id": 12}]
    assert c.status(ext) == ("resolved", CLOSED)
    c.comment(ext, "hello")
    assert seen[-1][1]["fields"] == {"public_log": "hello"} and seen[-1][1]["key"] == 42
    c.resolve(ext, "done")
    assert seen[-1][1]["stimulus"] == "ev_resolve"


def test_itop_refusal_is_not_retried():
    c = ItopConnector(
        Rules.from_dict(RULES).targets["itsm"],
        "secret",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"code": 1, "message": "Invalid login"})),
    )
    with pytest.raises(ConnectorError, match="Invalid login") as e:
        c.status(External(ref="UserRequest::1"))
    assert e.value.retry is False


def test_decision_items_carry_their_fixes():
    from verdict.service.index import compact

    row = {"cve_id": "CVE-2026-1", "asset_id": "web01", "delivery_decision": "ACT", "ssvc_decision": "act",
           "fixes": ["openssl 3.0.15"]}  # fmt: skip
    assert compact(row)["fixes"] == ["openssl 3.0.15"]


# -- dashboards (D18) --------------------------------------------------------------------------
def test_rssi_dashboards_link_to_the_page_and_reading_ones_do_not():
    from verdict.restitution.cli import dashboard

    for name in ("remediation", "coverage"):
        for language, column in (("en", "Asset"), ("fr", "Actif")):
            reading = json.loads(dashboard(name, language))
            board = json.loads(dashboard(name, language, rssi=True))
            assert "remediate" not in json.dumps(reading)
            assert board["uid"] == reading["uid"] + "-rssi" and "rssi" in board["tags"]
            assert any(i["name"] == "VAR_DISPATCH_URL" and i["type"] == "constant" for i in board["__inputs"])
            assert any(v["name"] == "dispatch_url" for v in board["templating"]["list"])
            links = [
                o for p in board["panels"] if p.get("type") == "table" for o in p["fieldConfig"]["overrides"]
                if o["matcher"]["options"] == column and o["properties"][0]["id"] == "links"
            ]  # fmt: skip
            assert links and "${dispatch_url}/remediate?asset=${__value.raw:percentencode}" in json.dumps(links)
    with pytest.raises(ValueError):
        dashboard("overview", rssi=True)


def test_chart_and_pipeline_carry_the_dispatch_service():
    chart = ROOT / "deploy" / "charts" / "a2vm-tenant"
    tpl = (chart / "templates" / "dispatch.yaml").read_text()
    assert 'command: ["dispatch", "serve"]' in tpl and "--allowed-group={{ . }}" in tpl
    assert "never the tenant's other secrets" in tpl and "a2vm.io/verdict-reader" in tpl
    daily = (chart / "templates" / "cronjob-daily.yaml").read_text()
    assert '"name" "dispatch" "pillar" "dispatch"' in daily and "dispatch run --url" in daily
    pipeline = (ROOT / "templates" / "client-pipeline.yml").read_text()
    assert "dispatch check dispatch.yaml" in pipeline and "a2vm-dispatch" in pipeline
    assert "deploy/dispatch/dispatch_values.py" in pipeline


def test_dispatch_values_resolve_targets_and_need_the_credentials():
    import importlib.util

    spec = importlib.util.spec_from_file_location("dv", ROOT / "deploy" / "dispatch" / "dispatch_values.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    rules = {"targets": {"itsm": {"url": "https://192.0.2.10"}}}
    with pytest.raises(ValueError, match="A2VM_DISPATCH_ITSM_PASSWORD"):
        dv.values(rules, {})
    v, names = dv.values(rules, {"A2VM_DISPATCH_ITSM_PASSWORD": "x"})
    assert names == ["itsm"] and v["dispatch"]["egress"] == [{"cidr": "192.0.2.10/32", "port": 443}]
    with pytest.raises(ValueError, match="REMEDIATORS"):
        dv.values(rules, {"A2VM_DISPATCH_ITSM_PASSWORD": "x", "A2VM_DISPATCH_HOST": "d.example.org",
                          "A2VM_OIDC_ISSUER": "https://auth.example.org/realms/lab"})  # fmt: skip
    v, _ = dv.values(rules, {"A2VM_DISPATCH_ITSM_PASSWORD": "x", "A2VM_DISPATCH_HOST": "d.example.org",
                             "A2VM_OIDC_ISSUER": "https://auth.example.org/realms/lab",
                             "A2VM_OIDC_REMEDIATORS": "A2VM-Remediation"})  # fmt: skip
    assert v["dispatch"]["page"]["remediators"] == ["A2VM-Remediation"]


def test_tickets_and_requests_in_the_tenants_database(tenant_db):
    from a2vm.db import Database
    from dispatch.store import MIGRATIONS, PgStore

    db = Database(tenant_db, "dispatch", MIGRATIONS)
    assert db.init() == 1
    store, other = PgStore(db, "lab"), PgStore(db, "other")
    a = "host:web01.lab.example"
    d = Dispatcher("lab", Rules.from_dict(RULES), store, FakeDecisions([dec(1, a, "ACT", ["openssl 3.0.15"])]),
                   lambda name: FakeTool(), clock=lambda: "2026-11-03T07:00:00+00:00")  # fmt: skip
    assert d.process_run()["sent"] == 1
    t = store.get(f"{a} / openssl 3.0.15")
    assert t.state == "sent" and t.external["ref"] == "UserRequest::1"
    assert [x.key for x in store.tickets(open_only=True)] == [t.key] and other.tickets() == []
    store.add_request({"by": "rssi@lab.example", "tickets": []})
    assert store.requests()[0]["by"] == "rssi@lab.example" and other.requests() == []
    db.close()
