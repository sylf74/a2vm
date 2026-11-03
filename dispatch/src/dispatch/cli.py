# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Command `dispatch` (pillar 4):

dispatch serve   the dispatch service of one tenant, and its page of the requests for remediation
dispatch run     the daily run's step: the service processes the newest run of the decision service
dispatch check   check a tenant's dispatch.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path


def _read_secret(path: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"{path}: {exc}") from exc
    if not value:
        raise SystemExit(f"{path} is empty")
    return value


def cmd_serve(args: argparse.Namespace) -> int:
    from a2vm.db import DatabaseError, open_database
    from a2vm.service import TokenSet, serve

    from .decisions import Decisions
    from .page import RequestPage
    from .rules import RulesError, load_rules
    from .service import ROLES, Service, api_handler, page_handler
    from .store import MIGRATIONS, FileStore, PgStore

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        tokens = TokenSet.load(args.digests, ROLES)
        rules = load_rules(args.rules)
        db = open_database("dispatch", MIGRATIONS)
    except (ValueError, OSError, DatabaseError, RulesError) as exc:
        print(exc, file=sys.stderr)
        return 2
    store = PgStore(db, args.tenant) if db else FileStore(args.store, args.tenant)
    verdict_token = _read_secret(args.verdict_token_file)
    service = Service(
        args.tenant,
        tokens,
        store,
        rules,
        lambda: Decisions(args.verdict_url, args.tenant, verdict_token),
        secrets_dir=args.secrets,
    )
    roles = ", ".join(f"{r} {'set' if r in tokens.digests else 'MISSING'}" for r in sorted(ROLES))
    print(
        f"{args.tenant}: tokens {roles}; store {store.describe()}; mode {rules.mode}; targets "
        f"{', '.join(f'{t.name} ({t.type})' for t in rules.targets.values()) or 'none'}; automatic tickets "
        f"{', '.join(rules.automatic_levels) or 'none'}; requests to {', '.join(rules.request_targets) or 'none'}",
        flush=True,
    )
    servers = [serve(api_handler(service), args.host, args.port)]
    if args.page_port:
        groups = {g.strip() for g in (args.remediators or "").split(",") if g.strip()}
        try:
            page = RequestPage(args.tenant, _read_secret(args.page_key_file).encode(), groups, args.page_url)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        servers.append(serve(page_handler(service, page), args.host, args.page_port))
        print(f"{args.tenant}: page of the requests on :{args.page_port} for {', '.join(sorted(groups))}", flush=True)
    for httpd in servers[1:]:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for httpd in servers:
            httpd.server_close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """0 processed; 3 the service unreachable or refusing (a warning: the next run tries again)."""
    import httpx

    token = _read_secret(args.token_file)
    try:
        r = httpx.post(
            f"{args.url.rstrip('/')}/v1/tenants/{args.tenant}/runs",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "a2vm-dispatch"},
            timeout=httpx.Timeout(args.timeout_seconds, connect=15.0),
        )
    except httpx.HTTPError as exc:
        print(f"{args.tenant}: dispatch service unreachable: {exc}", file=sys.stderr)
        return 3
    if r.status_code != 200:
        try:
            detail = r.json().get("detail") or r.text[:200]
        except ValueError:
            detail = r.text[:200]
        print(f"{args.tenant}: dispatch refused ({r.status_code}): {detail}", file=sys.stderr)
        return 3
    s = r.json()
    run = s.get("run") or {}
    print(
        f"{args.tenant}: dispatch of run {run.get('id', 'none')} ({s.get('mode')}): proposed {s.get('proposed', 0)}, "
        f"sent {s.get('sent', 0)}, updated {s.get('updated', 0)}, fixed {s.get('fixed', 0)}, claimed fixed "
        f"{s.get('claimed_fixed', 0)}, reopened {s.get('reopened', 0)}, errors {s.get('errors', 0)}"
        + (f"; {s['detail']}" if s.get("detail") else "")
    )
    return 3 if s.get("errors") else 0


def cmd_check(args: argparse.Namespace) -> int:
    from .rules import RulesError, load_rules

    if not Path(args.rules).exists():
        print(f"{args.rules}: no such file", file=sys.stderr)
        return 2
    try:
        rules = load_rules(args.rules)
    except RulesError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(
        f"{args.rules}: mode {rules.mode}; targets {', '.join(rules.targets) or 'none'}; automatic tickets "
        f"{', '.join(rules.automatic_levels) or 'none'} to {rules.ticket_target or '-'}; requests to "
        f"{', '.join(rules.request_targets) or 'none'} ({', '.join(rules.request_levels)}, at most {rules.max_tickets})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    fmt = argparse.RawDescriptionHelpFormatter
    p = argparse.ArgumentParser(prog="dispatch", description=__doc__, formatter_class=fmt)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="the dispatch service of one tenant")
    s.add_argument("--tenant", required=True)
    s.add_argument("--digests", required=True, help="file of `<run|read> <sha256>` lines")
    s.add_argument("--rules", help="the tenant's dispatch.yaml (absent: nothing leaves)")
    s.add_argument("--verdict-url", required=True, help="the decision service")
    s.add_argument("--verdict-token-file", required=True, help="read token on the decision service")
    s.add_argument("--secrets", default="/secrets", help="directory of the connectors' credentials")
    s.add_argument("--store", default="/data/dispatch", help="files, without the tenant's database")
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104 - inside the pod, behind its NetworkPolicy
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--page-port", type=int, default=0, help="port of the page of the requests (0: none)")
    s.add_argument("--page-url", default="", help="public https URL of the page (origin of its forms)")
    s.add_argument("--page-key-file", default="/secrets/dispatch-page-key")
    s.add_argument("--remediators", default="", help="groups that may ask for remediation, comma-separated")
    s.set_defaults(func=cmd_serve)

    r = sub.add_parser("run", help="the daily run's step")
    r.add_argument("--url", required=True)
    r.add_argument("--tenant", required=True)
    r.add_argument("--token-file", required=True)
    r.add_argument("--timeout-seconds", type=float, default=1800)
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="check a dispatch.yaml")
    c.add_argument("rules")
    c.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
