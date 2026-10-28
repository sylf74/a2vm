# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`verdict serve` (the decision service of one tenant) and `verdict push` (the daily run's push)."""

from __future__ import annotations

import argparse
import logging
import sys
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
    from a2vm.service import TokenSet

    from .server import ROLES, Service, serve
    from .store import RunStore

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        tokens = TokenSet.load(args.digests, ROLES)
        Path(args.store).mkdir(parents=True, exist_ok=True)
    except (ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    store = RunStore(args.store, args.keep)
    latest = store.latest(args.tenant)
    roles = ", ".join(f"{r} {'set' if r in tokens.digests else 'MISSING'}" for r in sorted(ROLES))
    print(
        f"{args.tenant}: tokens {roles}; store {args.store}; latest run "
        f"{latest.id + ' of ' + latest.generated_at if latest else 'none yet'}",
        flush=True,
    )
    httpd = serve(Service(args.tenant, tokens, store, args.max_mb * 1024 * 1024), args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    """0 pushed (or already there); 3 the service unreachable or busy (a warning, the run goes on);
    1 refused."""
    from .client import PushError, push

    token = _read_secret(args.token_file)
    try:
        receipt = push(args.url, args.tenant, token, args.triage, args.ca_file, timeout=args.timeout_seconds)
    except PushError as exc:
        print(f"{args.tenant}: {exc}", file=sys.stderr)
        return 3 if exc.retry else 1
    except OSError as exc:
        print(f"{args.triage}: {exc}", file=sys.stderr)
        return 1
    counts = receipt.get("counts", {})
    print(
        f"{args.tenant}: run {receipt['id']} of {receipt['generated_at']} "
        f"{'already received' if receipt.get('duplicate') else 'pushed'} to the decision service "
        f"({receipt['rows']} decisions: ACT={counts.get('ACT', 0)} ATTEND={counts.get('ATTEND', 0)} "
        f"TRACK={counts.get('TRACK', 0)})"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="verdict")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve", help="the decision service of one tenant (read API on its latest runs)")
    s.add_argument("--tenant", required=True)
    s.add_argument("--digests", required=True, help="`<publish|read> <sha256>` per line")
    s.add_argument("--store", default="/data/runs")
    s.add_argument("--keep", type=int, default=7, help="runs kept")
    s.add_argument("--max-mb", type=int, default=400, help="largest triage accepted, uncompressed")
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a pod
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)
    p = sub.add_parser("push", help="push a run's triage.json to the decision service")
    p.add_argument("triage", help="triage.json written by verdict run")
    p.add_argument("--url", required=True, help="decision service, e.g. http://a2vm-lab-verdict:8080")
    p.add_argument("--tenant", required=True)
    p.add_argument("--token-file", required=True, help="the publish token")
    p.add_argument("--ca-file")
    p.add_argument("--timeout-seconds", type=float, default=600)
    p.set_defaults(func=cmd_push)
    args = parser.parse_args(argv)
    return args.func(args)
