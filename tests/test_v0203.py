# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.20.3: several portals: a run publishes into several reporting databases; the portal chart
(reporting database and Grafana on Kubernetes, dashboards provisioned)."""

from __future__ import annotations

import json

import pytest

from verdict.restitution import db

from .conftest import ROOT
from .test_restitution import reporting_db  # noqa: F401, F811 - the fixture

CHART = ROOT / "deploy" / "charts" / "a2vm-portal"


def test_every_reporting_database_of_a_run(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "reporting-dsn-client").write_text("postgresql://w:pw@portal.client.example/a2vm")
    (secrets / "reporting-ca-client").write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    (secrets / "reporting-dsn-empty").write_text("")
    env = {
        "A2VM_REPORTING_DSN": "host=ops.example.org dbname=a2vm user=w password=pw",
        "A2VM_REPORTING_DSN_LAB": "host=lab.example.org dbname=a2vm user=w password=pw",
        "A2VM_REPORTING_TARGETS_DIR": str(secrets),
    }
    found = dict(db.targets(env))
    assert list(found) == ["default", "client", "lab"]
    assert "sslmode=require" in found["default"] and "host=lab.example.org" in found["lab"]
    assert "sslmode=verify-full" in found["client"] and "sslrootcert=" in found["client"]
    assert db.targets({}) == []
    with pytest.raises(db.DatabaseError, match="reporting target bad") as e:
        db.targets({"A2VM_REPORTING_DSN_BAD": "not a connection string"})
    assert "not a connection" not in str(e.value)


def test_publish_goes_on_when_one_database_fails(monkeypatch, tmp_path, capsys):
    from verdict.restitution import cli

    dataset = tmp_path / "reporting.json"
    dataset.write_text("{}")
    monkeypatch.setattr(db, "load", lambda path: {"run": {"tenant": {"id": "lab"}}, "generated_at": "2026-11-04"})
    monkeypatch.setattr(db, "targets", lambda: [("default", "a"), ("client", "b")])

    def publish(conninfo, data):
        if conninfo == "b":
            raise db.DatabaseError("unreachable")
        return 7, {"decisions": 3}

    monkeypatch.setattr(db, "publish", publish)
    assert cli.main(["publish", str(dataset)]) == 3
    out = capsys.readouterr()
    assert "lab [default]: run 2026-11-04 published as #7" in out.out and "ERROR [client] unreachable" in out.err


def test_portal_chart_provisions_the_dashboards_of_the_version():
    for f in (ROOT / "verdict" / "src" / "verdict" / "restitution" / "grafana").glob("*.json"):
        assert (CHART / "dashboards" / f.name).read_text() == f.read_text(), f.name
    grafana = (CHART / "templates" / "grafana.yaml").read_text()
    assert 'replace "${DS_A2VM}" "a2vm-reporting"' in grafana and 'replace "${VAR_DISPATCH_URL}"' in grafana
    assert "uid: a2vm-reporting" in grafana and "sslmode: verify-full" in grafana
    assert "GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT" in grafana
    job = (CHART / "templates" / "schema-job.yaml").read_text()
    assert "verdict db init" in job and "--password-file /grafana/db-password" in job
    database = (CHART / "templates" / "database.yaml").read_text()
    assert "owner: a2vm_writer" in database and "writerNamespaces" in database
    assert "loadBalancerSourceRanges" in database
    chart = (CHART / "Chart.yaml").read_text()
    tenant = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "Chart.yaml").read_text()
    assert [line for line in chart.splitlines() if "ersion" in line and not line.startswith("#")] == [
        line for line in tenant.splitlines() if "ersion" in line and not line.startswith("#")
    ]
    json.loads((CHART / "dashboards" / "overview.json").read_text())


def test_grant_sets_a_given_password(reporting_db):  # noqa: F811 - the fixture
    import psycopg

    from .test_restitution import ADMIN

    db.init(ADMIN, reporting_db["writer"])
    role = reporting_db["reader"]
    assert db.grant(ADMIN, role, ["*"], password="kept-elsewhere-1") is None
    assert db.grant(ADMIN, role, ["*"], password="kept-elsewhere-2") is None
    as_reader = psycopg.conninfo.make_conninfo(ADMIN, user=role, password="kept-elsewhere-2", sslmode="disable")
    with psycopg.connect(as_reader) as conn:
        assert conn.execute("SELECT 1").fetchone() == (1,)
