# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Restitution (pillar 3): the reporting database. The database tests need a disposable PostgreSQL (16 or later):
A2VM_TEST_DSN = an administrator connection to an empty database; they are skipped without it."""

from __future__ import annotations

import json
import os
import uuid

import pytest

from verdict.restitution import db
from verdict.restitution.cli import dashboard, main

from .test_pipeline import _run

ADMIN = os.environ.get("A2VM_TEST_DSN", "")
needs_db = pytest.mark.skipif(not ADMIN, reason="A2VM_TEST_DSN not set (disposable PostgreSQL)")


def _params(conninfo: str) -> dict[str, str]:
    from psycopg.conninfo import conninfo_to_dict

    return conninfo_to_dict(conninfo)


def test_connection_string_is_encrypted_and_verified_when_a_certificate_is_given(tmp_path):
    assert _params(db.dsn("host=h dbname=a2vm user=w", environ={}))["sslmode"] == "require"
    ca = tmp_path / "server.crt"
    ca.write_text("x")
    full = _params(
        db.dsn(None, environ={"A2VM_REPORTING_DSN": "host=h dbname=a2vm user=w", "A2VM_REPORTING_CA": str(ca)})
    )
    assert full["sslrootcert"] == str(ca) and full["sslmode"] == "verify-full"
    stored = tmp_path / "dsn"
    stored.write_text("host=h user=w sslmode=verify-ca\n")
    assert _params(db.dsn(None, environ={"A2VM_REPORTING_DSN": str(stored)})) == {
        "host": "h",
        "user": "w",
        "sslmode": "verify-ca",
    }
    with pytest.raises(db.DatabaseError, match="A2VM_REPORTING_DSN"):
        db.dsn(None, environ={})


def test_connection_uri_and_pasted_certificate_are_accepted_and_errors_never_quote_the_string():
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    got = _params(db.dsn(None, environ={
        "A2VM_REPORTING_DSN": "postgresql://a2vm_writer:S3cret-pw@portal.example.org/a2vm",
        "A2VM_REPORTING_CA": pem,
    }))  # fmt: skip
    assert got["host"] == "portal.example.org" and got["user"] == "a2vm_writer" and got["dbname"] == "a2vm"
    assert got["password"] == "S3cret-pw" and got["sslmode"] == "verify-full"
    from pathlib import Path

    assert Path(got["sslrootcert"]).read_text().startswith("-----BEGIN CERTIFICATE-----")
    with pytest.raises(db.DatabaseError) as err:
        db.dsn("host=h password=S3cret-pw -----BEGIN", environ={})
    assert "S3cret" not in str(err.value) and "key=value" in str(err.value)
    with pytest.raises(db.DatabaseError, match="neither a file nor a PEM"):
        db.dsn("host=h", environ={"A2VM_REPORTING_CA": "not a certificate"})


@pytest.mark.parametrize("name", ["overview", "assets", "cves"])
def test_grafana_dashboards_read_the_reporting_database_only(capsys, name):
    assert main(["grafana", "dashboard", name]) == 0
    dash = json.loads(capsys.readouterr().out)
    panels = [p for p in dash["panels"] if p["type"] not in ("row", "text")]
    sql = " ".join(t["rawSql"] for p in panels for t in p["targets"])
    assert "a2vm." in sql and "gitlab" not in sql.lower()
    assert {p["datasource"]["uid"] for p in panels} == {"${DS_A2VM}"}


@pytest.fixture
def reporting_db():
    """A disposable a2vm schema: (writer connection string, administrator connection string, new
    reading role name); dropped afterwards with its roles."""
    import psycopg
    from psycopg import sql

    writer, reader = f"w_{uuid.uuid4().hex[:8]}", f"r_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        dbname = conn.info.dbname
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD 'w'").format(sql.Identifier(writer)))
        grant = sql.SQL("GRANT CONNECT, CREATE ON DATABASE {} TO {}")
        conn.execute(grant.format(sql.Identifier(dbname), sql.Identifier(writer)))
        conn.execute("DROP SCHEMA IF EXISTS a2vm CASCADE")
    as_writer = psycopg.conninfo.make_conninfo(ADMIN, user=writer, password="w", sslmode="disable")
    try:
        yield {"writer": writer, "as_writer": as_writer, "reader": reader}
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute("DROP SCHEMA IF EXISTS a2vm CASCADE")
            for role in (reader, writer):
                if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                    conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                    conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def _dataset(settings, sources, profile, tmp_path):
    from verdict.reporting import build

    run = _run(settings, sources, profile, tmp=tmp_path)
    data = {"schema": "a2vm.reporting/1", **build(run, settings.policy)}
    path = tmp_path / "reporting.json"
    path.write_text(json.dumps(data))
    return run, data, path


@needs_db
def test_publish_twice_keeps_one_run_and_readers_see_their_tenants_only(
    settings, sources, profile, tmp_path, reporting_db
):
    import psycopg

    run, data, path = _dataset(settings, sources, profile, tmp_path)
    as_writer, reader = reporting_db["as_writer"], reporting_db["reader"]
    assert db.init(ADMIN, reporting_db["writer"]).startswith("schema a2vm version 2")
    assert main(["publish", str(path), "--dsn", as_writer]) == 0
    assert main(["publish", str(path), "--dsn", as_writer]) == 0  # replaced, not doubled
    password = db.grant(ADMIN, reader, ["another-tenant"])
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=reader, password=password)
    with psycopg.connect(as_writer) as conn:
        assert conn.execute("SELECT count(*) FROM a2vm.runs").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM a2vm.decisions").fetchone()[0] == len(run.rows)
        facts = conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE severity IN ('Critical','High','Medium','Low','Unknown')),"
            " count(*) FILTER (WHERE cardinality(sources) > 0) FROM a2vm.decision_facts"
        ).fetchone()
        assert facts == (len(run.rows), len(run.rows), len(run.rows))
    with psycopg.connect(as_reader) as conn:  # another tenant only: nothing of this one
        assert conn.execute("SELECT count(*) FROM a2vm.latest_decisions").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM a2vm.decision_facts").fetchone()[0] == 0
    db.grant(ADMIN, reader, [profile.id])
    with psycopg.connect(as_reader) as conn:
        acts = conn.execute("SELECT act, attend, track FROM a2vm.latest_runs").fetchone()
        assert sum(acts) == len(run.rows)
        day = data["generated_at"][:10]
        snap = conn.execute("SELECT count(*) FROM a2vm.snapshot_runs(%s, %s)", ([profile.id], day)).fetchone()[0]
        assert snap == 1
        none = conn.execute("SELECT count(*) FROM a2vm.snapshot_runs(%s, NULL)", ([profile.id],)).fetchone()[0]
        assert none == 0
        with pytest.raises(psycopg.Error):
            conn.execute("DELETE FROM a2vm.runs")
    rotated = db.grant(ADMIN, reader, [profile.id], rotate=True)
    assert rotated and rotated != password
    with pytest.raises(psycopg.Error):
        psycopg.connect(as_reader)


@needs_db
def test_a_version_1_database_is_upgraded_in_place(settings, sources, profile, tmp_path, reporting_db):
    import psycopg
    from psycopg import sql

    from .conftest import FIXTURES

    _, data, path = _dataset(settings, sources, profile, tmp_path)
    as_writer, reader = reporting_db["as_writer"], reporting_db["reader"]
    with psycopg.connect(ADMIN) as conn:  # the schema as v0.11.5 created it, with one old run
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(reporting_db["writer"])))
        conn.execute((FIXTURES / "reporting-schema-v1.sql").read_text())
        conn.execute(
            "INSERT INTO a2vm.runs (tenant, tenant_name, generated_at, a2vm_version, policy_hash, cve_count, act,"
            " attend, track, assets_act, assets_attend, assets_track, needs_review, assumed_inputs, not_affected,"
            " errors, overdue, due_soon, exposure_gaps) VALUES (%s, 'Old', '2026-10-01T06:00:00Z', '0.11.5', 'x',"
            " 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)",
            (profile.id,),
        )
    password = db.grant(ADMIN, reader, ["*"])
    assert main(["publish", str(path), "--dsn", as_writer]) == 3  # refused: schema version 1
    assert db.init(ADMIN, reporting_db["writer"]).startswith("schema a2vm version 2")
    assert main(["publish", str(path), "--dsn", as_writer]) == 0
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=reader, password=password)
    with psycopg.connect(as_reader) as conn:  # granted before the upgrade, reads the new view
        assert conn.execute("SELECT count(*) FROM a2vm.runs").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM a2vm.decision_facts").fetchone()[0] == len(data["decisions"])


def _grafana(sql: str, values: dict[str, list[str]], texts: dict[str, str] | None = None) -> str:
    """The SQL Grafana sends: variables interpolated (`:sqlstring` lists, `:text`, raw), macros."""
    import re

    texts = texts or {}

    def quoted(name: str) -> str:
        return ",".join("'" + v.replace("'", "''") + "'" for v in values[name])

    sql = re.sub(r"\$\{(\w+):sqlstring\}", lambda m: quoted(m.group(1)), sql)
    sql = re.sub(r"\$\{(\w+):text\}", lambda m: texts.get(m.group(1), values[m.group(1)][0]), sql)
    sql = re.sub(r"\$\{(\w+)\}", lambda m: values[m.group(1)][0], sql)
    return re.sub(r"\$__timeFilter\((\w+)\)", r"\1 BETWEEN '1970-01-01' AND '2100-01-01'", sql)


@needs_db
@pytest.mark.parametrize("name", ["assets", "cves"])
def test_every_panel_of_the_dashboards_runs_and_counts_what_was_published(
    settings, sources, profile, tmp_path, reporting_db, name
):
    """Two clients, two days: the variables resolve, every panel query runs as a reading role,
    the counters of the snapshot match the dataset and the compared snapshot is the day before."""
    import psycopg

    _, data, path = _dataset(settings, sources, profile, tmp_path)
    as_writer = reporting_db["as_writer"]
    db.init(ADMIN, reporting_db["writer"])
    older = json.loads(json.dumps(data))
    older["generated_at"] = "2026-10-01T06:00:00Z"
    older["decisions"] = older["decisions"][:2]
    other = json.loads(json.dumps(data))
    other["run"]["tenant"] = {"id": "other", "name": "Other client"}
    for i, d in enumerate((older, other)):
        p = tmp_path / f"r{i}.json"
        p.write_text(json.dumps(d))
        assert main(["publish", str(p), "--dsn", as_writer]) == 0
    assert main(["publish", str(path), "--dsn", as_writer]) == 0
    password = db.grant(ADMIN, reporting_db["reader"], ["*"])
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=reporting_db["reader"], password=password)
    dash = json.loads(dashboard(name))
    variables = {v["name"]: v for v in dash["templating"]["list"]}
    values: dict[str, list[str]] = {}
    texts: dict[str, str] = {}
    with psycopg.connect(as_reader) as conn:
        for var in dash["templating"]["list"]:  # in order: later queries use earlier values
            if var["type"] == "custom":
                values[var["name"]] = var["query"].split(",")
                continue
            rows = conn.execute(_grafana(var["query"], values)).fetchall()
            cols = [c.name for c in conn.execute(_grafana(var["query"], values)).description]
            opts = [dict(zip(cols, r, strict=True)) for r in rows]
            if "__value" in cols:
                vals = [str(o["__value"]) for o in opts]
                texts[var["name"]] = str(opts[0]["__text"])
            else:
                vals = [str(r[0]) for r in rows]
            values[var["name"]] = vals if var["includeAll"] else vals[:1]
        assert set(values["tenant"]) == {profile.id, "other"}
        assert values["snapshot"] == [data["generated_at"][:10]]
        assert values["compare"] == ["2026-10-01"]  # the earlier snapshot is preselected
        results = {}
        for panel in dash["panels"]:
            for t in panel.get("targets", []):
                cur = conn.execute(_grafana(t["rawSql"], values, texts))
                results[panel["title"]] = (([c.name for c in cur.description]), cur.fetchall())
    n = len(data["decisions"])
    cves = {d["cve"] for d in data["decisions"]}
    if name == "assets":
        cols, rows = results["Exposures"]
        assert rows[-1][1] == 2 * n  # both clients today
        assert rows[0][1] == 2  # the day before: only the old run of one client
        cols, rows = results["SSVC decision × severity — exposures"]
        assert sum(sum(r[1:]) for r in rows) == 2 * n
        cols, rows = results["Assets to fix first"]
        assert sum(r[cols.index("ACT")] + r[cols.index("ATTEND")] + r[cols.index("TRACK")] for r in rows) == 2 * n
    else:
        cols, rows = results["Distinct CVEs"]
        assert rows[-1][1] == len(cves)
        cols, rows = results["SSVC decision × severity — CVEs"]
        assert sum(sum(r[1:]) for r in rows) == len(cves)
        cols, rows = results["CVEs to fix first"]
        assert {r[0] for r in rows} == cves and all(
            r[cols.index("Since")] in ("", "new") or r[cols.index("Since")].startswith("was ") for r in rows
        )
    assert variables["compare"]["multi"] is False
