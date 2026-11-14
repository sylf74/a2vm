# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.18.1: an asset scanned without a finding stays known; a finding gone from a run is fixed only
when its asset was scanned again by the source that had seen it, else unverified; remediation KPIs."""

from __future__ import annotations

import gzip
import json

from ngvm.db import Database
from ngvm.service import TokenSet, digest
from verdict.report import write_json
from verdict.service.index import RunIndex, row_id
from verdict.service.pgstore import MIGRATIONS, PgRunStore, rescanned
from verdict.service.server import Service

from .conftest import ROOT
from .test_pipeline import _run
from .test_restitution import ADMIN, _grafana, needs_db, reporting_db  # noqa: F401, F811 - fixture

PUBLISH, READ = "publish-token-0123456789abcdef0123", "read-token-0123456789abcdef01234567"
LATER = "2100-01-01T00:00:00+00:00"


def _doc(settings, sources, profile, tmp_path) -> dict:
    run = _run(settings, sources, profile)
    path = tmp_path / "triage.json"
    write_json(run, path)
    return json.loads(path.read_text())


def test_every_asset_of_the_run_is_listed_with_its_scans(settings, sources, profile, tmp_path):
    doc = _doc(settings, sources, profile, tmp_path)
    assert doc["assets"] and all(a["scans"] for a in doc["assets"])
    with_findings = {r.get("asset_id_full") or r["asset_id"] for r in doc["rows"]}
    assert with_findings <= {a["id"] for a in doc["assets"]}
    # The asset is patched: its findings are gone, the scan still lists it.
    patched = sorted(with_findings)[0]
    clean = {**doc, "rows": [r for r in doc["rows"] if (r.get("asset_id_full") or r["asset_id"]) != patched]}
    idx = RunIndex({"id": "r", "generated_at": doc["generated_at"]}, clean)
    listed = {a["asset"]: a for a in idx.assets({"limit": "200"})["items"]}
    assert listed[patched]["counts"] == {"ACT": 0, "ATTEND": 0, "TRACK": 0} and listed[patched]["scans"]
    found = idx.asset(patched.split(":", 1)[1].split(".")[0], {})
    assert found is not None and found["asset"] == patched and found["decisions"]["total"] == 0
    assert idx.summary()["assets"] == len(doc["assets"])
    # A triage of an earlier version (no `assets`) still answers from its decisions.
    old = RunIndex({"id": "r", "generated_at": doc["generated_at"]}, {k: v for k, v in clean.items() if k != "assets"})
    assert old.asset(patched, {}) is None


def test_rescanned_needs_the_same_source_after_the_finding():
    seen = {"trivy": "2026-10-30T06:00:00+00:00"}
    assert rescanned(seen, {"trivy": "2026-10-31T06:00:00Z"})
    assert not rescanned(seen, {"trivy": "2026-10-30T06:00:00+00:00"})  # the same scan: not again
    assert not rescanned(seen, {"openvas": "2026-10-31T06:00:00Z"})  # another source does not say
    assert not rescanned({}, {"trivy": "2026-10-31T06:00:00Z"}) and not rescanned(seen, {})


def test_a_finding_gone_unchecked_is_unverified_not_fixed(tenant_db, settings, sources, profile, tmp_path):
    doc = _doc(settings, sources, profile, tmp_path)
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    db = Database(tenant_db, "verdict", MIGRATIONS)
    assert db.init() == len(MIGRATIONS)
    service = Service(doc["client"]["id"], TokenSet.load(digests, {"publish", "read"}), PgRunStore(db))
    tenant = service.tenant

    def push(d, key):
        return service.push(tenant, PUBLISH, key, gzip.compress(json.dumps(d).encode()), True)

    push({**doc, "generated_at": "2026-10-01T06:00:00+00:00"}, "d1")
    by_asset: dict[str, list] = {}
    for r in doc["rows"]:
        by_asset.setdefault(r.get("asset_id_full") or r["asset_id"], []).append(r)
    patched, down = sorted(by_asset)[:2]
    rows = [r for r in doc["rows"] if (r.get("asset_id_full") or r["asset_id"]) not in (patched, down)]
    assets = [{**a, "scans": {k: LATER for k in a["scans"]}} if a["id"] == patched else a for a in doc["assets"]]
    assets = [a for a in assets if a["id"] != down]  # its scan failed: not in the run
    push({**doc, "generated_at": "2026-10-02T06:00:00+00:00", "rows": rows, "assets": assets}, "d2")

    closed = service.read(tenant, READ, "findings/closed", {"since": "2026-09-01", "limit": "200"})
    unverified = service.read(tenant, READ, "findings/unverified", {"since": "2026-09-01", "limit": "200"})
    assert {i["asset"] for i in closed["items"]} == {patched} and closed["total"] == len(by_asset[patched])
    assert {i["asset"] for i in unverified["items"]} == {down} and unverified["total"] == len(by_asset[down])
    assert unverified["items"][0]["state"] == "unverified" and "closed_at" not in unverified["items"][0]
    # The scan comes back: the findings of the asset are open again, not reopened.
    push({**doc, "generated_at": "2026-10-03T06:00:00+00:00"}, "d3")
    life = service.read(tenant, READ, f"decisions/{row_id(by_asset[down][0])}", {})["lifecycle"]
    assert life["state"] == "open" and life["reopened"] == 0 and "unverified_since" not in life
    fixed_again = service.read(tenant, READ, f"decisions/{row_id(by_asset[patched][0])}", {})["lifecycle"]
    assert fixed_again["state"] == "open" and fixed_again["reopened"] == 1


@needs_db
def test_the_remediation_dashboard_counts_fixed_and_unverified(settings, sources, profile, tmp_path, reporting_db):  # noqa: F811, E501
    import psycopg

    from verdict.reporting import build
    from verdict.restitution import db
    from verdict.restitution.cli import dashboard, main

    rdb = reporting_db
    if rdb:
        run = _run(settings, sources, profile)
        data = {"schema": "ngvm.reporting/1", **build(run, settings.policy)}
        assert all("scans" in a for a in data["assets"]) and all("seen_by" in d for d in data["decisions"])
        by_asset: dict[str, list] = {}
        for d in data["decisions"]:
            by_asset.setdefault(d["asset"], []).append(d)
        patched, down = sorted(by_asset)[:2]
        day1 = {**data, "generated_at": "2026-10-01T06:00:00Z"}
        day2 = json.loads(json.dumps(data))
        day2["generated_at"] = "2026-10-02T06:00:00Z"
        day2["decisions"] = [d for d in day2["decisions"] if d["asset"] not in (patched, down)]
        for a in day2["assets"]:
            if a["id"] == patched:
                a["scans"] = {k: LATER for k in a["scans"]}
                a["counts"] = {"ACT": 0, "ATTEND": 0, "TRACK": 0}
        day2["assets"] = [a for a in day2["assets"] if a["id"] != down]
        db.init(ADMIN, rdb["writer"])
        for i, d in enumerate((day1, day2)):
            p = tmp_path / f"r{i}.json"
            p.write_text(json.dumps(d))
            assert main(["publish", str(p), "--dsn", rdb["as_writer"]]) == 0
        password = db.grant(ADMIN, rdb["reader"], ["*"])
        as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=rdb["reader"], password=password)
        dash = json.loads(dashboard("remediation"))
        values = {"tenant": [profile.id]}
        results = {}
        with psycopg.connect(as_reader) as conn:
            for panel in dash["panels"]:
                for t in panel.get("targets", []):
                    cur = conn.execute(_grafana(t["rawSql"], values))
                    results[panel["title"]] = ([c.name for c in cur.description], cur.fetchall())
        assert results["Fixed findings"][1] == [(len(by_asset[patched]),)]
        assert results["Gone without a new scan"][1] == [(len(by_asset[down]),)]
        cols, rows = results["Assets by last scan"]
        assert any(r[cols.index("Asset")] for r in rows) and len(rows) == len(day2["assets"])
        cols, rows = results["Time to fix per level"]
        assert sum(r[cols.index("Fixed")] for r in rows) == len(by_asset[patched])


def test_the_french_dashboards_follow_their_bar_charts_columns():
    for name in ("assets", "remediation"):
        from verdict.restitution.cli import dashboard

        fr = json.loads(dashboard(name, "fr"))
        for p in fr["panels"]:
            x = (p.get("options") or {}).get("xField")
            if x:
                assert x == "Zone · exposition"


def test_the_chat_tells_a_clean_asset_and_an_unchecked_one():
    import yaml

    values = yaml.safe_load((ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text())
    prompt = values["chat"]["systemPrompt"]
    assert "scanned clean" in prompt and "list_unverified_findings" in prompt and "another language" in prompt
    from verdict.service.tools import OPERATIONS

    ops = {op[1] for op in OPERATIONS}
    assert {"list_closed_findings", "list_unverified_findings"} <= ops
