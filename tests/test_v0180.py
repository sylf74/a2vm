# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.18.0: the services of a tenant keep their data in the tenant's PostgreSQL (CloudNativePG):
schema of each pillar created at start, row-level security per tenant, history of the findings."""

from __future__ import annotations

import gzip
import json
import threading
from pathlib import Path

import pytest
import yaml

from a2vm.db import Database, DatabaseError, Migration, dsn_from_env, rls
from a2vm.service import TokenSet, digest
from verdict.report import write_json
from verdict.service.index import row_id
from verdict.service.pgstore import MIGRATIONS, PgRunStore
from verdict.service.server import Service

from .conftest import ROOT
from .test_pipeline import _run

PUBLISH, READ = "publish-token-0123456789abcdef0123", "read-token-0123456789abcdef01234567"
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"


def test_the_connection_string_comes_from_a_file_and_is_never_printed(tmp_path):
    secret = tmp_path / "uri"
    secret.write_text("postgresql://app:s3cret-pw@a2vm-lab-db-rw.a2vm-lab:5432/app\n")
    dsn = dsn_from_env({"A2VM_DB_DSN_FILE": str(secret)})
    assert dsn == "postgresql://app:s3cret-pw@a2vm-lab-db-rw.a2vm-lab:5432/app"
    assert dsn_from_env({}) is None
    with pytest.raises(DatabaseError, match="A2VM_DB_DSN_FILE"):
        dsn_from_env({"A2VM_DB_DSN_FILE": str(tmp_path / "missing")})
    db = Database(dsn, "verdict", [], ca=str(tmp_path / "ca.crt"))
    assert "s3cret" not in db.describe() and "verify-full" not in db.describe()
    assert db.describe() == "postgresql a2vm-lab-db-rw.a2vm-lab/app (TLS verified)"


def test_a_tenant_sees_its_rows_only_even_as_owner(tenant_db):
    steps = [Migration(1, "CREATE TABLE t (tenant text NOT NULL, v integer);\n" + rls("t"))]
    db = Database(tenant_db, "test", steps)
    assert db.init() == 1 and db.init() == 1 and db.version() == 1
    with db.tx("a") as conn:
        conn.execute("INSERT INTO t VALUES ('a', 1)")
    with db.tx("b") as conn:
        conn.execute("INSERT INTO t VALUES ('b', 2)")
        assert conn.execute("SELECT v FROM t").fetchall() == [(2,)]
        import psycopg

        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO t VALUES ('a', 3)")  # another tenant's row: refused
    with db.tx("") as conn:
        assert conn.execute("SELECT count(*) FROM t").fetchone()[0] == 0
    db.close()


def test_replicas_starting_together_create_the_schema_once(tenant_db):
    errors = []

    def start():
        try:
            Database(tenant_db, "verdict", MIGRATIONS).init()
        except Exception as exc:  # noqa: BLE001 - collected for the assert
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and Database(tenant_db, "verdict", MIGRATIONS).version() == len(MIGRATIONS)


def _push(service, doc, key):
    return service.push(service.tenant, PUBLISH, key, gzip.compress(json.dumps(doc).encode()), True)


def test_the_findings_live_across_runs(tenant_db, settings, sources, profile, tmp_path):
    run = _run(settings, sources, profile)
    path = tmp_path / "triage.json"
    write_json(run, path)
    doc = json.loads(path.read_text())
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    db = Database(tenant_db, "verdict", MIGRATIONS)
    db.init()
    service = Service(doc["client"]["id"], TokenSet.load(digests, {"publish", "read"}), PgRunStore(db, keep=2))
    tenant = service.tenant

    _push(service, {**doc, "generated_at": "2026-10-01T06:00:00+00:00"}, "d1")
    first = service.read(tenant, READ, "decisions", {"limit": "1"})["items"][0]["id"]
    # Day 2: the first finding is gone (fixed), another one changes level.
    rows = [r for r in doc["rows"] if row_id(r) != first]
    moved = next(r for r in rows if r["delivery_decision"] != "ACT")
    rows = [{**r, "delivery_decision": "ACT"} if r is moved else r for r in rows]
    _push(service, {**doc, "generated_at": "2026-10-02T06:00:00+00:00", "rows": rows}, "d2")
    closed = service.read(tenant, READ, "findings/closed", {"since": "2026-09-01"})
    assert closed["total"] == 1 and closed["items"][0]["id"] == first
    assert closed["items"][0]["closed_at"].startswith("2026-10-02")
    moved_id = row_id(moved)
    life = service.read(tenant, READ, f"decisions/{moved_id}", {})["lifecycle"]
    assert life["opened_at"].startswith("2026-10-01") and life["level"] == "ACT"
    assert life["level_since"].startswith("2026-10-02") and [x["level"] for x in life["levels"]][-1] == "ACT"

    # A run pushed late (older than the newest) is kept, and moves no finding.
    _push(service, {**doc, "generated_at": "2026-09-30T06:00:00+00:00"}, "late")
    assert service.read(tenant, READ, "findings/closed", {"since": "2026-09-01"})["total"] == 1
    # Day 3: it comes back (reopened); only two runs are kept, the findings outlive them.
    _push(service, {**doc, "generated_at": "2026-10-03T06:00:00+00:00"}, "d3")
    assert service.read(tenant, READ, "findings/closed", {"since": "2026-09-01"})["total"] == 0
    back = service.read(tenant, READ, f"decisions/{first}", {})["lifecycle"]
    assert back["reopened"] == 1 and "closed_at" not in back
    assert len(service.read(tenant, READ, "runs", {})["items"]) == 2


def test_without_a_database_the_history_is_said_missing(tmp_path):
    from a2vm.service import Problem
    from verdict.service.store import RunStore

    digests = tmp_path / "digests"
    digests.write_text(f"read {digest(READ)}\n")
    service = Service("lab", TokenSet.load(digests, {"publish", "read"}), RunStore(tmp_path / "s"))
    with pytest.raises(Problem, match="database"):
        service.read("lab", READ, "findings/closed", {})


def test_the_contract_has_the_history():
    spec = yaml.safe_load((ROOT / "a2vm/src/a2vm/schemas/openapi/verdict.v1.yaml").read_text())
    assert "/v1/tenants/{tenant}/findings/closed" in spec["paths"]
    assert "lifecycle" in spec["components"]["schemas"]["Decision"]["properties"]


def test_the_chart_gives_each_tenant_its_cluster_and_the_services_its_secret(tmp_path):
    from .test_v0170 import _render

    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["database"]["enabled"] is False  # on only when the deploy job says so (A2VM_DATABASE)
    intake = {"enabled": True, "collectors": "schema_version: 1\ncollectors: []\n", "digestsSecret": "a2vm-intake"}
    docs = _render(tmp_path, {"database": {"enabled": True, "serviceReplicas": 2}, "intake": intake})
    cluster = next(d for d in docs if d["kind"] == "Cluster")
    assert cluster["apiVersion"] == "postgresql.cnpg.io/v1" and cluster["metadata"]["name"] == "a2vm-lab-db"
    assert cluster["spec"]["bootstrap"]["initdb"] == {"database": "app", "owner": "app"}
    assert cluster["spec"]["enableSuperuserAccess"] is False
    services = {"via", "detect", "verdict"}
    deployments = [
        d
        for d in docs
        if d["kind"] == "Deployment" and d["metadata"]["labels"]["app.kubernetes.io/component"] in services
    ]
    assert len(deployments) == 3
    for d in deployments:
        pod = d["spec"]["template"]["spec"]
        env = {e["name"]: e.get("value") for e in pod["containers"][0].get("env", [])}
        assert env["A2VM_DB_DSN_FILE"] == "/var/run/a2vm-db/uri" and env["A2VM_DB_CA"] == "/var/run/a2vm-db-ca/ca.crt"
        secrets = {v["secret"]["secretName"]: v["secret"].get("items") for v in pod["volumes"] if "secret" in v}
        assert secrets["a2vm-lab-db-ca"] == [{"key": "ca.crt", "path": "ca.crt"}]  # never the CA's key
        assert not any("persistentVolumeClaim" in v for v in pod["volumes"])  # no volume of its own
        assert d["spec"]["strategy"]["type"] == "RollingUpdate" and d["spec"]["replicas"] == 2
    claims = {d["metadata"]["name"] for d in docs if d["kind"] == "PersistentVolumeClaim"}
    assert claims == {"a2vm-lab-data", "a2vm-lab-chat"}  # the daily run's work files and Open WebUI's own
    policies = {d["metadata"]["name"]: d for d in docs if d["kind"] == "NetworkPolicy"}
    peers = policies["a2vm-lab-db"]["spec"]["ingress"][0]["from"]
    assert {p["podSelector"]["matchLabels"]["app.kubernetes.io/component"] for p in peers} == services
    for name in ("a2vm-lab-via", "a2vm-lab-detect", "a2vm-lab-verdict"):
        egress = policies[name]["spec"]["egress"]
        assert egress[0]["to"][0]["podSelector"]["matchLabels"] == {"cnpg.io/cluster": "a2vm-lab-db"}
    # Without the database: the volumes, one replica, no egress, as before.
    docs = _render(tmp_path, {"intake": intake})
    assert not any(d["kind"] == "Cluster" for d in docs)
    claims = {d["metadata"]["name"] for d in docs if d["kind"] == "PersistentVolumeClaim"}
    assert {"a2vm-lab-watch", "a2vm-lab-detections", "a2vm-lab-runs"} <= claims


def test_the_operator_is_documented_once_per_cluster():
    text = (ROOT / "docs" / "kubernetes.md").read_text()
    assert "cloudnative-pg" in text and "A2VM_DB" in text
    assert Path(ROOT / "deploy" / "cnpg" / "README.md").exists()


def _database_block(tmp_path: Path, operator: bool, **env) -> tuple[int, str]:
    import os
    import subprocess

    pipeline = yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())
    block = next(s for s in pipeline["deploy-k8s"]["script"] if 'DATABASE=""' in s)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    listed = "clusters.postgresql.cnpg.io\nbackups.postgresql.cnpg.io" if operator else ""
    (bin_dir / "kubectl").write_text(f'#!/bin/sh\nprintf "%s\\n" "{listed}"\n')
    (bin_dir / "kubectl").chmod(0o755)
    full = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CI_PROJECT_NAME": "Lab", **env}
    out = subprocess.run(["sh", "-ec", f'{block}\necho "DATABASE=$DATABASE"'], env=full, capture_output=True,
                         text=True, check=False)  # fmt: skip
    return out.returncode, out.stdout + out.stderr


def test_deploy_job_enables_the_database_only_with_the_operator(tmp_path):
    rc, out = _database_block(tmp_path, True)
    assert rc == 0 and out.strip().endswith("DATABASE=")  # not asked: nothing
    rc, out = _database_block(tmp_path, True, A2VM_DATABASE="true", A2VM_DATABASE_SIZE="10Gi")
    assert rc == 0 and "--set database.enabled=true" in out and "database.storage.size=10Gi" in out
    assert "a2vm-lab-db" in out
    rc, out = _database_block(tmp_path, False, A2VM_DATABASE="true")
    assert rc == 1 and "operator is not installed" in out
