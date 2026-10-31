# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Restitution commands of verdict (pillar 3): the reporting database and its dashboards.

  verdict publish reporting.json …          load a run's reporting dataset into the reporting database (jobs)
  verdict db init --dsn …                   create or update the schema (administrator, once per version)
  verdict db grant ROLE TENANT… --dsn …     reading role for a tool (Grafana, Qlik Sense), limited to tenants
  verdict grafana dashboard NAME            print a Grafana dashboard (JSON, to import): overview, assets, cves;
                                            --language fr for its French version

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
    paths = [Path(p) for p in args.datasets]
    try:
        conninfo = db.dsn(args.dsn)
    except db.DatabaseError as exc:
        print(exc, file=sys.stderr)
        return 2
    rc = 0
    for path in paths:
        try:
            data = db.load(path)
        except (OSError, ValueError) as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            rc = max(rc, 2)
            continue
        try:
            run_id, counts = db.publish(conninfo, data)
        except db.DatabaseError as exc:
            print(f"ERROR {exc}", file=sys.stderr)
            rc = max(rc, 3)
            continue
        written = ", ".join(f"{v} {k}" for k, v in counts.items())
        print(f"{data['run']['tenant']['id']}: run {data['generated_at']} published as #{run_id} ({written})")
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
        password = db.grant(db.dsn(args.dsn), args.role, args.tenants, rotate=args.rotate)
    except db.DatabaseError as exc:
        print(exc, file=sys.stderr)
        return 3
    scope = "all tenants" if "*" in args.tenants else ", ".join(args.tenants)
    print(f"{args.role}: reads {scope}")
    if password:
        print(f"password (shown once, store it in the tool that reads): {password}")
    return 0


DASHBOARDS = ("overview", "assets", "cves")


LANGUAGES = ("en", "fr")


def dashboard(name: str, language: str = "en") -> str:
    """A dashboard in English, or its French version (v0.17.3: its own uid, `<uid>-fr`)."""
    suffix = "" if language == "en" else f".{language}"
    path = resources.files("verdict.restitution").joinpath("grafana", f"{name}{suffix}.json")
    return path.read_text(encoding="utf-8")


def cmd_grafana(args: argparse.Namespace) -> int:
    sys.stdout.write(dashboard(args.name, args.language))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verdict", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("publish", help="load reporting datasets into the reporting database")
    p.add_argument("datasets", nargs="+", help="reporting.json files (output/<tenant>/reporting.json)")
    p.add_argument("--dsn", help="connection string (default: A2VM_REPORTING_DSN)")
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
    g.set_defaults(func=cmd_db_grant)

    gr = sub.add_parser("grafana", help="Grafana resources")
    gr.add_argument("what", choices=["dashboard"])
    gr.add_argument("name", nargs="?", default="overview", choices=DASHBOARDS,
                    help="overview (default), assets (per asset), cves (per CVE)")  # fmt: skip
    gr.add_argument("--language", default="en", choices=LANGUAGES,
                    help="language of the titles, descriptions and columns (default en)")  # fmt: skip
    gr.set_defaults(func=cmd_grafana)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
