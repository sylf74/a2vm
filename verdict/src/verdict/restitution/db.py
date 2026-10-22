# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The reporting database: connection, schema, reading roles, and loading a reporting dataset.

Two kinds of access:

- the operator (database administrator, from a workstation) creates the schema and the reading
  roles: `verdict db init`, `verdict db grant`;
- the A2VM jobs write with the writer role, which owns the tables: `verdict publish`.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from a2vm.config import env

SCHEMA_VERSION = 2
PEM = "-----BEGIN CERTIFICATE-----"


class DatabaseError(RuntimeError):
    """The reporting database could not be reached or refused the operation."""


def _ca_file(ca: str) -> str:
    """Path of the server's certificate: A2VM_REPORTING_CA is a File variable (a path), or the
    certificate pasted into a plain variable, written here to a private file."""
    if ca.lstrip().startswith(PEM):
        folder = tempfile.mkdtemp(prefix="a2vm-ca-")
        path = Path(folder) / "server.crt"
        path.write_text(ca.strip() + "\n", encoding="utf-8")
        return str(path)
    if not Path(ca).is_file():
        raise DatabaseError("A2VM_REPORTING_CA is neither a file nor a PEM certificate")
    return ca


def dsn(given: str | None = None, environ=None) -> str:
    """Connection string: `given`, else A2VM_REPORTING_DSN, a libpq string (`host=… user=…`) or a
    URI (`postgresql://user:password@host/a2vm`, which GitLab can mask), or a file holding one.
    With A2VM_REPORTING_CA (the server's certificate, file or text), the server is verified
    (verify-full); without, the connection is encrypted (require). Never in clear text. Errors
    never quote the string: it holds a password."""
    from psycopg import conninfo

    environ = os.environ if environ is None else environ
    value = (given or env("REPORTING_DSN", "", environ=environ)).strip()
    if value and "=" not in value and "://" not in value and Path(value).is_file():
        value = Path(value).read_text(encoding="utf-8").strip()
    if not value:
        raise DatabaseError("no reporting database: --dsn or the CI/CD variable A2VM_REPORTING_DSN")
    try:
        params = conninfo.conninfo_to_dict(value)
    except Exception:  # the message would quote the string, password included
        raise DatabaseError(
            "the reporting database connection string is not valid: key=value pairs "
            "(host=… dbname=… user=… password=…) or a URI (postgresql://user:password@host/dbname)"
        ) from None
    ca = env("REPORTING_CA", "", environ=environ)
    if ca and "sslrootcert" not in params:
        params["sslrootcert"] = _ca_file(ca)
        params.setdefault("sslmode", "verify-full")
    params.setdefault("sslmode", "require")
    return conninfo.make_conninfo(**params)


def connect(conninfo: str):
    import psycopg

    try:
        return psycopg.connect(conninfo, connect_timeout=15)
    except psycopg.Error as exc:
        raise DatabaseError(f"reporting database: {exc}".strip()) from exc


def _sql(name: str) -> str:
    return resources.files("verdict.restitution").joinpath("sql", name).read_text(encoding="utf-8")


def init(admin_dsn: str, writer: str = "a2vm_writer") -> str:
    """Create or update the schema, owned by `writer` (run as an administrator)."""
    import psycopg
    from psycopg import sql

    with connect(admin_dsn) as conn:
        try:
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(writer)))
            conn.execute(_sql("schema.sql"))
            conn.execute("RESET ROLE")
        except psycopg.Error as exc:
            raise DatabaseError(f"schema: {exc}") from exc
        version = conn.execute("SELECT max(version) FROM a2vm.schema_version").fetchone()[0]
    return f"schema a2vm version {version}, owned by {writer}"


def grant(
    admin_dsn: str, role: str, tenants: list[str], password: str | None = None, rotate: bool = False
) -> str | None:
    """Create (or update) a reading role limited to `tenants` ('*' = all); returns the password
    when one was generated (new role, or `rotate`), to give once to the tool that reads."""
    import psycopg
    from psycopg import sql

    generated = None
    with connect(admin_dsn) as conn:
        try:
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            if not exists or rotate:
                generated = password or secrets.token_urlsafe(24)
                verb = "ALTER ROLE {} PASSWORD {}" if exists else "CREATE ROLE {} LOGIN PASSWORD {}"
                conn.execute(sql.SQL(verb).format(sql.Identifier(role), sql.Literal(generated)))
            dbname = conn.info.dbname
            r = sql.Identifier(role)
            conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(dbname), r))
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA a2vm TO {}").format(r))
            conn.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA a2vm TO {}").format(r))
            conn.execute("DELETE FROM a2vm.tenant_roles WHERE role = %s", (role,))
            for t in tenants:
                conn.execute("INSERT INTO a2vm.tenant_roles (role, tenant) VALUES (%s, %s)", (role, t))
        except psycopg.Error as exc:
            raise DatabaseError(f"grant {role}: {exc}") from exc
    return generated


RUN_COLUMNS = (
    "tenant", "tenant_name", "generated_at", "a2vm_version", "policy_hash", "pipeline_id", "pipeline_url",
    "cve_count", "act", "attend", "track", "assets_act", "assets_attend", "assets_track", "needs_review",
    "assumed_inputs", "not_affected", "errors", "overdue", "due_soon", "exposure_gaps",
)  # fmt: skip
DECISION_COLUMNS = (
    "finding_id", "asset", "asset_name", "zone", "exposure", "exposure_source", "cve", "title", "level", "ssvc",
    "bod_timeline", "first_seen", "due_date", "kev", "epss", "needs_review", "rationale",
    "cvss_score", "cvss_version", "severity", "fix_available", "vendor", "product", "product_type", "sources",
)  # fmt: skip


def run_row(data: dict[str, Any]) -> dict[str, Any]:
    run, totals = data["run"], data["totals"]
    return {
        "tenant": run["tenant"]["id"],
        "tenant_name": run["tenant"]["name"],
        "generated_at": data["generated_at"],
        "a2vm_version": run["a2vm_version"],
        "policy_hash": run["policy_hash"],
        "pipeline_id": run.get("pipeline", {}).get("id") or None,
        "pipeline_url": run.get("pipeline", {}).get("url") or None,
        "cve_count": run["cve_count"],
        "act": totals["findings"]["ACT"],
        "attend": totals["findings"]["ATTEND"],
        "track": totals["findings"]["TRACK"],
        "assets_act": totals["assets"]["ACT"],
        "assets_attend": totals["assets"]["ATTEND"],
        "assets_track": totals["assets"]["TRACK"],
        "needs_review": totals["needs_review"],
        "assumed_inputs": totals["assumed_inputs"],
        "not_affected": totals["not_affected"],
        "errors": totals["errors"],
        "overdue": data["deadlines"]["overdue"],
        "due_soon": data["deadlines"]["due_soon"],
        "exposure_gaps": len(data.get("exposure_gaps", [])),
    }


def publish(conninfo: str, data: dict[str, Any]) -> tuple[int, dict[str, int]]:
    """Load one reporting dataset; a run already loaded (same tenant and time) is replaced, so a
    job run twice leaves one copy. Returns the run id and the rows written per table."""
    import psycopg

    row = run_row(data)
    tenant = row["tenant"]
    counts: dict[str, int] = {}
    with connect(conninfo) as conn:
        try:
            version = conn.execute("SELECT max(version) FROM a2vm.schema_version").fetchone()[0]
        except psycopg.Error as exc:
            raise DatabaseError(f"publish {tenant}: no A2VM schema, run `verdict db init` ({exc})".strip()) from exc
        if (version or 0) < SCHEMA_VERSION:
            raise DatabaseError(
                f"publish {tenant}: the reporting database is at schema version {version}, this A2VM needs "
                f"{SCHEMA_VERSION}: an administrator runs `verdict db init` once (docs/reporting.md)"
            )
        try:
            with conn.transaction():
                conn.execute(
                    "DELETE FROM a2vm.runs WHERE tenant = %s AND generated_at = %s", (tenant, row["generated_at"])
                )
                cols = ", ".join(RUN_COLUMNS)
                marks = ", ".join(f"%({c})s" for c in RUN_COLUMNS)
                run_id = conn.execute(
                    f"INSERT INTO a2vm.runs ({cols}) VALUES ({marks}) RETURNING run_id", row
                ).fetchone()[0]
                with conn.cursor() as cur:
                    decisions = [
                        (run_id, tenant, *[d.get(c) for c in DECISION_COLUMNS]) for d in data.get("decisions", [])
                    ]
                    cur.executemany(
                        f"INSERT INTO a2vm.decisions (run_id, tenant, {', '.join(DECISION_COLUMNS)}) "
                        f"VALUES (%s, %s, {', '.join(['%s'] * len(DECISION_COLUMNS))})",
                        decisions,
                    )
                    counts["decisions"] = len(decisions)
                    assets = [
                        (run_id, tenant, a["id"], a.get("name"), a.get("zone"), a.get("exposure"), a.get("owner"),
                         a["counts"]["ACT"], a["counts"]["ATTEND"], a["counts"]["TRACK"])
                        for a in data.get("assets", [])
                    ]  # fmt: skip
                    cur.executemany(
                        "INSERT INTO a2vm.assets (run_id, tenant, asset, name, zone, exposure, owner, act, attend,"
                        " track) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        assets,
                    )
                    counts["assets"] = len(assets)
                    gaps = [
                        (
                            run_id,
                            tenant,
                            g["kind"],
                            g["asset"],
                            g.get("name"),
                            g.get("declared") or None,
                            g.get("detail"),
                        )
                        for g in data.get("exposure_gaps", [])
                    ]
                    cur.executemany(
                        "INSERT INTO a2vm.exposure_gaps (run_id, tenant, kind, asset, name, declared, detail)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        gaps,
                    )
                    counts["exposure_gaps"] = len(gaps)
                    sources = [
                        (run_id, tenant, s["name"], s["findings"], s.get("last_observation") or None)
                        for s in data["run"].get("sources", [])
                    ]
                    cur.executemany(
                        "INSERT INTO a2vm.sources (run_id, tenant, name, findings, last_observation)"
                        " VALUES (%s, %s, %s, %s, %s)",
                        sources,
                    )
                    counts["sources"] = len(sources)
        except psycopg.Error as exc:
            raise DatabaseError(f"publish {tenant}: {exc}".strip()) from exc
    return run_id, counts


def load(path: str | Path) -> dict[str, Any]:
    """A reporting dataset, checked against its schema (a2vm.reporting/1)."""
    from a2vm.io import read_reporting

    data = read_reporting(path)
    json.dumps(data)  # plain JSON only
    return data
