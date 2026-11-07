# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Restitution commands of verdict (pillar 3): the reporting database and its dashboards.

  verdict publish reporting.json …          load a run's reporting dataset into the reporting database (jobs)
  verdict db init --dsn …                   create or update the schema (administrator, once per version)
  verdict db grant ROLE TENANT… --dsn …     reading role for a tool (Grafana, Qlik Sense), limited to tenants
  verdict grafana dashboard NAME            print a Grafana dashboard (JSON, to import): overview, assets, cves,
                                            remediation, coverage, sla;
                                            --language fr for its French version; --rssi (remediation,
                                            coverage, sla) for the version with the links "Remediate" (D18)

The jobs read the connection from A2VM_REPORTING_DSN and the server's certificate from
A2VM_REPORTING_CA. Exit codes: 0 done, 2 bad input, 3 database unreachable or refused (warning).
"""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from . import db


def cmd_publish(args: argparse.Namespace) -> int:
    """Each dataset into each reporting database (v0.20.3: several portals); one that fails does not
    stop the others. 0 done, 2 bad input, 3 a database unreachable or refused (warning)."""
    paths = [Path(p) for p in args.datasets]
    try:
        where = [("given", db.dsn(args.dsn))] if args.dsn else db.targets()
    except db.DatabaseError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not where:
        print("no reporting database: --dsn or the CI/CD variable A2VM_REPORTING_DSN", file=sys.stderr)
        return 2
    rc = 0
    for path in paths:
        try:
            data = db.load(path)
        except (OSError, ValueError) as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            rc = max(rc, 2)
            continue
        declared = _declared_fixes(args, data["run"]["tenant"]["id"])
        for name, conninfo in where:
            label = "" if len(where) == 1 else f" [{name}]"
            try:
                run_id, counts = db.publish(conninfo, data, declared)
            except db.DatabaseError as exc:
                print(f"ERROR{label} {exc}", file=sys.stderr)
                rc = max(rc, 3)
                continue
            written = ", ".join(f"{v} {k}" for k, v in counts.items())
            print(
                f"{data['run']['tenant']['id']}{label}: run {data['generated_at']} published as #{run_id} ({written})"
            )
    return rc


def cmd_db_init(args: argparse.Namespace) -> int:
    try:
        print(db.init(db.dsn(args.dsn), args.writer))
    except db.DatabaseError as exc:
        print(exc, file=sys.stderr)
        return 3
    return 0


def cmd_db_grant(args: argparse.Namespace) -> int:
    try:
        given = Path(args.password_file).read_text(encoding="utf-8").strip() if args.password_file else None
        if args.password_file and not given:
            raise db.DatabaseError(f"{args.password_file} is empty")
        password = db.grant(db.dsn(args.dsn), args.role, args.tenants, password=given, rotate=args.rotate)
    except (db.DatabaseError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 3
    scope = "all tenants" if "*" in args.tenants else ", ".join(args.tenants)
    print(f"{args.role}: reads {scope}")
    if password:
        print(f"password (shown once, store it in the tool that reads): {password}")
    return 0


DASHBOARDS = ("overview", "assets", "cves", "remediation", "coverage", "sla")


LANGUAGES = ("en", "fr")


RSSI_DASHBOARDS = ("remediation", "coverage", "sla")


def dashboard(name: str, language: str = "en", rssi: bool = False) -> str:
    """A dashboard in English, or its French version (v0.17.3: its own uid, `<uid>-fr`); `rssi`: the
    version with the links "Remediate" to the page of the requests of pillar 4 (v0.20.0, D18)."""
    if rssi and name not in RSSI_DASHBOARDS:
        raise ValueError(f"no RSSI version of {name}: {', '.join(RSSI_DASHBOARDS)} only")
    suffix = (".rssi" if rssi else "") + ("" if language == "en" else f".{language}")
    path = resources.files("verdict.restitution").joinpath("grafana", f"{name}{suffix}.json")
    return path.read_text(encoding="utf-8")


def cmd_grafana(args: argparse.Namespace) -> int:
    try:
        sys.stdout.write(dashboard(args.name, args.language, args.rssi))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


def _declared_fixes(args: argparse.Namespace, tenant: str) -> list[dict] | None:
    """The fixes the team declared in the ITSM, from the dispatch service (v0.22.2); None when it is
    not configured or cannot answer (said, the publication goes on)."""
    if not getattr(args, "dispatch_url", "") or not getattr(args, "dispatch_token_file", ""):
        return None
    import httpx

    try:
        token = Path(args.dispatch_token_file).read_text(encoding="utf-8").strip()
        r = httpx.get(
            f"{args.dispatch_url.rstrip('/')}/v1/tenants/{tenant}/fixes",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-publish"},
            timeout=30.0,
        )
        r.raise_for_status()
        return list(r.json().get("items") or [])
    except (OSError, httpx.HTTPError, ValueError) as exc:
        print(f"WARN declared fixes not read from the dispatch service: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verdict", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("publish", help="load reporting datasets into the reporting database")
    p.add_argument("datasets", nargs="+", help="reporting.json files (output/<tenant>/reporting.json)")
    p.add_argument("--dsn", help="connection string (default: A2VM_REPORTING_DSN)")
    p.add_argument("--dispatch-url", default="", help="dispatch service, for the fixes declared in the ITSM (v0.22.2)")
    p.add_argument("--dispatch-token-file", default="", help="read token of the dispatch service")
    p.set_defaults(func=cmd_publish)

    d = sub.add_parser("db", help="administration of the reporting database")
    dsub = d.add_subparsers(dest="action", required=True)
    i = dsub.add_parser("init", help="create or update the schema")
    i.add_argument("--dsn", help="administrator connection string")
    i.add_argument("--writer", default="a2vm_writer", help="role that owns the tables and the jobs write with")
    i.set_defaults(func=cmd_db_init)
    g = dsub.add_parser("grant", help="reading role for a dashboarding tool, limited to tenants")
    g.add_argument("role")
    g.add_argument("tenants", nargs="+", help="tenant ids, or * for all")
    g.add_argument("--dsn", help="administrator connection string")
    g.add_argument("--rotate", action="store_true", help="give an existing role a new password (printed once)")
    g.add_argument("--password-file", help="set this password (kept elsewhere, e.g. a Secret) instead of making one")
    g.set_defaults(func=cmd_db_grant)

    gr = sub.add_parser("grafana", help="Grafana resources")
    gr.add_argument("what", choices=["dashboard"])
    gr.add_argument("name", nargs="?", default="overview", choices=DASHBOARDS,
                    help="overview (default), assets, cves, remediation, coverage, sla (v0.21.0)")  # fmt: skip
    gr.add_argument("--language", default="en", choices=LANGUAGES,
                    help="language of the titles, descriptions and columns (default en)")  # fmt: skip
    gr.add_argument("--rssi", action="store_true",
                    help="remediation, coverage, sla: the version with the links to the remediation page")  # fmt: skip
    gr.set_defaults(func=cmd_grafana)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
