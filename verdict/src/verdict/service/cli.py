# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`verdict serve` (the decision service of one tenant), `verdict push` (the daily run's push) and
`verdict tools` (the tool server of the conversational search)."""

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


def cmd_tools(args: argparse.Namespace) -> int:
    from a2vm.service import TokenSet

    from .tools import ROLES, Tools, serve

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        tokens = TokenSet.load(args.digests, ROLES)
    except (ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    read_token = _read_secret(args.read_token_file)
    tools = Tools(
        args.tenant,
        tokens,
        args.verdict_url,
        read_token,
        args.max_chars,
        public_url=args.public_url,
        export_ttl=args.export_minutes * 60,
    )
    print(
        f"{args.tenant}: tool server on {args.verdict_url}, "
        f"chat token {'set' if 'chat' in tokens.digests else 'MISSING'}, "
        f"answers up to {args.max_chars} characters",
        flush=True,
    )
    httpd = serve(tools, args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        tools.close()
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["chat-retention"]:
        from .retention import main as retention

        return retention(argv[1:])
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
    t = sub.add_parser("tools", help="tool server of the conversational search, on the decision service")
    t.add_argument("--tenant", required=True)
    t.add_argument("--verdict-url", required=True, help="decision service, e.g. http://a2vm-lab-verdict:8080")
    t.add_argument("--read-token-file", required=True, help="read token of the decision service")
    t.add_argument("--digests", required=True, help="`chat <sha256>`: the chat interface's token")
    t.add_argument("--max-chars", type=int, default=8000, help="longest answer, in characters of JSON")
    t.add_argument("--public-url", default="", help="address of the chat, for download links (https://chat-lab...)")
    t.add_argument("--export-minutes", type=int, default=60, help="how long a download link stays valid")
    t.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a pod
    t.add_argument("--port", type=int, default=8080)
    t.set_defaults(func=cmd_tools)
    args = parser.parse_args(argv)
    return args.func(args)
