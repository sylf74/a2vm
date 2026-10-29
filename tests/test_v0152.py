# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.15.2: the analysts' daily questions. Dates of the facts behind a decision, what changed since
the run before and why, the fix plan of an asset, due dates, "are we concerned by this CVE"."""

from __future__ import annotations

import copy
import datetime as dt
import gzip
import json

import pytest

from a2vm.io import validate_triage
from a2vm.service import Problem
from via.intel.record import parse_record

from .test_v0150 import CHAT, tools  # noqa: F401 - fixture
from .test_verdict_service import PUBLISH, READ, _service, triage  # noqa: F401 - fixture


def _put(service, doc, key, generated_at):
    doc = {**doc, "generated_at": generated_at}
    return service.push(service.tenant, PUBLISH, key, gzip.compress(json.dumps(doc).encode()), True)


@pytest.fixture
def two_runs(triage, tmp_path):  # noqa: F811
    """Yesterday's run and today's, today's with one decision gone, one new, one moved to ACT by KEV."""
    run, path = triage
    service = _service(tmp_path, run.client.id)
    today = json.loads(path.read_text())
    rows = today["rows"]
    assert len(rows) >= 3
    yesterday = copy.deepcopy(today)
    now = dt.datetime.now(dt.UTC)
    before = (now - dt.timedelta(days=1)).isoformat()
    moved = next(r for r in yesterday["rows"] if r["delivery_decision"] != "ACT")
    moved_id = moved.get("finding_id")
    moved.update(delivery_decision="ATTEND", in_kev=False, kev_date_added="", epss=0.01)
    today_moved = next(r for r in rows if r.get("finding_id") == moved_id)
    today_moved.update(delivery_decision="ACT", in_kev=True, kev_date_added=now.date().isoformat(), epss=0.5)
    gone = rows.pop(next(i for i, r in enumerate(rows) if r.get("finding_id") != moved_id))
    new = copy.deepcopy(rows[-1])
    new.update(
        finding_id="lab:new-asset:CVE-2099-20001",
        cve_id="CVE-2099-20001",
        first_seen=now.isoformat(),
        seen_by={"trivy": now.isoformat()},
        cve_published=now.date().isoformat(),
    )
    rows.append(new)
    yesterday["rows"] = [r for r in yesterday["rows"] if r.get("finding_id") != new["finding_id"]]
    _put(service, yesterday, "y", before)
    receipt = _put(service, today, "t", (now - dt.timedelta(minutes=1)).isoformat())
    return run, service, receipt, {"moved": moved_id, "gone": gone["finding_id"], "new": new["finding_id"]}


def test_decisions_carry_the_dates_of_their_facts(triage):  # noqa: F811
    run, path = triage
    doc = json.loads(path.read_text())
    validate_triage(doc)
    kev = next(r for r in doc["rows"] if r["in_kev"])
    assert kev["kev_date_added"] and kev["epss_date"] == "2026-10-09"
    assert all("cve_published" in r and "cve_updated" in r for r in doc["rows"])
    record = parse_record(
        {
            "cveMetadata": {
                "cveId": "CVE-2099-1",
                "datePublished": "2026-01-02T00:00:00Z",
                "dateUpdated": "2026-10-27T08:00:00Z",
            },
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "x"}]}},
        }
    )
    assert record.updated == "2026-10-27T08:00:00Z" and record.published == "2026-01-02T00:00:00Z"


def test_what_changed_since_the_run_before_and_why(two_runs):
    run, service, receipt, ids = two_runs
    out = service.read(run.client.id, READ, "changes", {"limit": "200"})
    assert out["run"]["id"] == receipt["id"] and out["since"]["id"] != receipt["id"]
    by_id = {i["id"]: i for i in out["items"]}
    assert by_id[ids["moved"]]["change"] == "changed" and by_id[ids["moved"]]["from"] == "ATTEND"
    assert any(w.startswith("added to CISA KEV") for w in by_id[ids["moved"]]["why"])
    assert any(w == "EPSS 0.01 -> 0.5" for w in by_id[ids["moved"]]["why"])
    assert by_id[ids["new"]]["change"] == "new" and any(
        "first detected" in w and "trivy" in w for w in by_id[ids["new"]]["why"]
    )
    assert by_id[ids["gone"]]["change"] == "gone"
    assert out["counts"] == {"new": 1, "gone": 1, "changed": 1}
    only_new = service.read(run.client.id, READ, "changes", {"kind": "new"})
    assert [i["change"] for i in only_new["items"]] == ["new"]
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, "changes", {"kind": "everything"})
    assert p.value.status == 400


def test_nothing_to_compare_with_a_single_run(triage, tmp_path):  # noqa: F811
    run, path = triage
    service = _service(tmp_path, run.client.id)
    _put(service, json.loads(path.read_text()), "k", dt.datetime.now(dt.UTC).isoformat())
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, "changes", {})
    assert p.value.status == 404 and "nothing to compare" in p.value.detail


def test_fix_plan_puts_the_fix_that_clears_most_act_first(triage, tmp_path):  # noqa: F811
    run, path = triage
    service = _service(tmp_path, run.client.id)
    doc = json.loads(path.read_text())
    asset = doc["rows"][0]["asset_id_full"] or doc["rows"][0]["asset_id"]
    mine = [r for r in doc["rows"] if (r["asset_id_full"] or r["asset_id"]) == asset]
    for i, r in enumerate(mine):
        r["delivery_decision"] = "ACT" if i == 0 else "TRACK"
        r["fixes"] = ["kernel 5.14.0-611.el9"] if i == 0 else ["openssl 3.0.9"]
    extra = copy.deepcopy(mine[0])
    extra.update(
        finding_id="lab:x:CVE-2099-30001", cve_id="CVE-2099-30001", fixes=["kernel 5.14.0-611.el9"], in_kev=True
    )
    doc["rows"].append(extra)
    _put(service, doc, "k", dt.datetime.now(dt.UTC).isoformat())
    plan = service.read(run.client.id, READ, f"assets/{asset.split(':', 1)[-1]}/fixes", {})
    assert plan["asset"] == asset
    first = plan["plan"]["items"][0]
    assert first["fix"] == "kernel 5.14.0-611.el9" and first["clears"]["ACT"] == 2 and first["kev"] >= 1
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, "assets/nowhere/fixes", {})
    assert p.value.status == 404


def test_due_dates_this_week_and_overdue(triage, tmp_path):  # noqa: F811
    run, path = triage
    service = _service(tmp_path, run.client.id)
    doc = json.loads(path.read_text())
    _put(service, doc, "k", dt.datetime.now(dt.UTC).isoformat())
    every = service.read(run.client.id, READ, "decisions", {"limit": "200"})["items"]
    dues = sorted(i["due_date"] for i in every if i["due_date"])
    cut = dues[0]
    soon = service.read(run.client.id, READ, "decisions", {"due_before": cut, "limit": "200"})
    assert soon["total"] >= 1 and all(i["due_date"] <= cut for i in soon["items"])
    late = service.read(run.client.id, READ, "decisions", {"overdue": "true", "today": "2999-01-01", "limit": "200"})
    assert late["total"] == len(dues)
    assert service.read(run.client.id, READ, "decisions", {"overdue": "true", "today": "1970-01-01"})["total"] == 0
    with pytest.raises(Problem):
        service.read(run.client.id, READ, "decisions", {"due_before": "next week"})


def test_are_we_concerned_by_a_cve(triage, tmp_path):  # noqa: F811
    run, path = triage
    service = _service(tmp_path, run.client.id)
    doc = json.loads(path.read_text())
    doc["not_affected"] = [
        {
            "client_id": run.client.id,
            "cve_id": "CVE-2099-40001",
            "asset_id": "declared:web",
            "deployed_versions": ["3.0.8"],
            "source": "inventory",
        }
    ]
    _put(service, doc, "k", dt.datetime.now(dt.UTC).isoformat())
    spared = service.read(run.client.id, READ, "cves/CVE-2099-40001", {})
    assert spared["concerned"] is False and spared["not_affected"][0]["deployed_versions"] == ["3.0.8"]
    hit = service.read(run.client.id, READ, f"cves/{doc['rows'][0]['cve_id']}", {})
    assert hit["concerned"] is True and "updated" in hit and "kev_date_added" in hit
    with pytest.raises(Problem) as p:
        service.read(run.client.id, READ, "cves/CVE-1999-0001", {})
    assert p.value.status == 404 and "no asset of the tenant is concerned" in p.value.detail


def test_the_tools_answer_the_daily_questions(tools):  # noqa: F811
    run, t = tools
    ops = {o["operationId"] for item in t.spec["paths"].values() for o in item.values()}
    assert {"what_changed", "get_fix_plan"} <= ops
    with pytest.raises(Problem) as p:
        t.call(CHAT, "/changes", {})
    assert p.value.status == 404  # one run only: said, not guessed
    full = run.rows[0].asset_id_full or run.rows[0].asset_id
    plan = t.call(CHAT, f"/assets/{full.replace(':', '%3A').replace('/', '%2F')}/fixes", {})
    assert plan["asset"] == full and "without_known_fix" in plan
    page = t.call(CHAT, "/decisions", {"overdue": "false"})
    assert "first_seen" in page["items"][0] and "cve_updated" in page["items"][0]
