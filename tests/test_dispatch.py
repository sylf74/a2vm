# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Pillar 4: the reporting database. The database tests need a disposable PostgreSQL (16 or later):
A2VM_TEST_DSN = an administrator connection to an empty database; they are skipped without it."""

from __future__ import annotations

import json
import os
import uuid

import pytest

from dispatch import db
from dispatch.cli import main

from .test_pipeline import _run

ADMIN = os.environ.get("A2VM_TEST_DSN", "")
needs_db = pytest.mark.skipif(not ADMIN, reason="A2VM_TEST_DSN not set (disposable PostgreSQL)")


def test_connection_string_is_encrypted_and_verified_when_a_certificate_is_given(tmp_path):
    assert db.dsn("host=h dbname=a2vm user=w", environ={}).endswith("sslmode=require")
    ca = tmp_path / "server.crt"
    ca.write_text("x")
    full = db.dsn(None, environ={"A2VM_REPORTING_DSN": "host=h dbname=a2vm user=w", "A2VM_REPORTING_CA": str(ca)})
    assert f"sslrootcert={ca}" in full and "sslmode=verify-full" in full
    stored = tmp_path / "dsn"
    stored.write_text("host=h user=w sslmode=verify-ca\n")
    assert db.dsn(None, environ={"A2VM_REPORTING_DSN": str(stored)}) == "host=h user=w sslmode=verify-ca"
    with pytest.raises(db.DatabaseError, match="A2VM_REPORTING_DSN"):
        db.dsn(None, environ={})


def test_grafana_dashboard_reads_the_reporting_database_only(capsys):
    assert main(["grafana", "dashboard"]) == 0
    dash = json.loads(capsys.readouterr().out)
    sql = " ".join(t["rawSql"] for p in dash["panels"] for t in p["targets"])
    assert "a2vm." in sql and "gitlab" not in sql.lower()
    assert {p["datasource"]["uid"] for p in dash["panels"]} == {"${DS_A2VM}"}


@needs_db
def test_publish_twice_keeps_one_run_and_readers_see_their_tenants_only(settings, sources, profile, tmp_path):
    import psycopg
    from psycopg import sql

    from verdict.reporting import build

    run = _run(settings, sources, profile, tmp=tmp_path)
    data = {"schema": "a2vm.reporting/1", **build(run, settings.policy)}
    path = tmp_path / "reporting.json"
    path.write_text(json.dumps(data))

    writer, reader = f"w_{uuid.uuid4().hex[:8]}", f"r_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        dbname = conn.info.dbname
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD 'w'").format(sql.Identifier(writer)))
        grant = sql.SQL("GRANT CONNECT, CREATE ON DATABASE {} TO {}")
        conn.execute(grant.format(sql.Identifier(dbname), sql.Identifier(writer)))
        conn.execute("DROP SCHEMA IF EXISTS a2vm CASCADE")
    as_writer = psycopg.conninfo.make_conninfo(ADMIN, user=writer, password="w")
    try:
        assert db.init(ADMIN, writer).startswith("schema a2vm version 1")
        assert main(["publish", str(path), "--dsn", as_writer + " sslmode=disable"]) == 0
        assert main(["publish", str(path), "--dsn", as_writer + " sslmode=disable"]) == 0  # replaced, not doubled
        password = db.grant(ADMIN, reader, ["another-tenant"])
        as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=reader, password=password)
        with psycopg.connect(as_writer) as conn:
            assert conn.execute("SELECT count(*) FROM a2vm.runs").fetchone()[0] == 1
            assert conn.execute("SELECT count(*) FROM a2vm.decisions").fetchone()[0] == len(run.rows)
        with psycopg.connect(as_reader) as conn:  # another tenant only: nothing of this one
            assert conn.execute("SELECT count(*) FROM a2vm.latest_decisions").fetchone()[0] == 0
        db.grant(ADMIN, reader, [profile.id])
        with psycopg.connect(as_reader) as conn:
            acts = conn.execute("SELECT act, attend, track FROM a2vm.latest_runs").fetchone()
            assert sum(acts) == len(run.rows)
            with pytest.raises(psycopg.Error):
                conn.execute("DELETE FROM a2vm.runs")
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute("DROP SCHEMA IF EXISTS a2vm CASCADE")
            for role in (reader, writer):
                if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                    conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                    conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
