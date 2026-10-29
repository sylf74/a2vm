# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`via serve` (the watch service of one tenant) and `via service …` (the tenant's jobs on Kubernetes):

  via serve                 keeps the watch's state, the last inventory, the alerts and their journal
  via service watch …       one passage of the watch: state and inventory from the service, `via watch`,
                            alerts, events and the new state back to it
  via service send …        the analyst's validation: the chosen alerts from the service, `via send`,
                            the events back to it
  via service push-inventory …   the daily run's assets and findings, for the watch

The watch and the send of the GitLab pipelines (`via watch`, `via send`) are unchanged; these commands
wrap them for a tenant that runs on Kubernetes (A2VM_RUN_MODE=kubernetes, LLD intelligence §3.7).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path

from a2vm.config import env

from .client import ServiceError, WatchClient

# Exit codes: 0 done; 1 refused or failed; 3 done with warnings (a source down, a mail failed).


def _secret(path: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"{path}: {exc}") from exc
    if not value:
        raise SystemExit(f"{path} is empty")
    return value


def _client(args: argparse.Namespace) -> WatchClient:
    return WatchClient(args.url, args.tenant, _secret(args.token_file))


def cmd_serve(args: argparse.Namespace) -> int:
    from a2vm.service import TokenSet

    from .server import ROLES, WatchService, serve
    from .store import WatchStore

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        tokens = TokenSet.load(args.digests, ROLES)
        Path(args.store).mkdir(parents=True, exist_ok=True)
    except (ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    store = WatchStore(args.store, args.keep_days)
    roles = ", ".join(f"{r} {'set' if r in tokens.digests else 'MISSING'}" for r in sorted(ROLES))
    kept = store.alerts(args.tenant)
    print(f"{args.tenant}: tokens {roles}; store {args.store}; {len(kept)} alert(s) kept", flush=True)
    httpd = serve(WatchService(args.tenant, tokens, store, args.max_mb * 1024 * 1024), args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def _new_events(path: Path) -> list[dict]:
    from via.alert import journal

    return journal.read(path)


def cmd_watch(args: argparse.Namespace) -> int:
    from via.alert.cli import cmd_watch as watch

    client = _client(args)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = client.state()
            if state is not None:
                (work / "state.json").write_bytes(state)
            has_inventory = client.inventory(work / "inventory")
            print(
                f"{args.tenant}: state {'from the service' if state else 'none yet (baseline)'}, "
                f"inventory {'from the last daily run' if has_inventory else 'none yet: declared assets only'}"
            )
            code = watch(
                argparse.Namespace(
                    profile=args.profile,
                    settings=args.settings,
                    sources=args.sources,
                    state=str(work / "state.json"),
                    out=str(work / "alerts"),
                    fixtures=args.fixtures,
                    no_llm=args.no_llm,
                    contacts=args.contacts,
                    journal=str(work / "events.jsonl"),
                    inventory=str(work / "inventory") if has_inventory else "none",
                )
            )
            if code not in (0, 3):
                return code
            new_state = json.loads((work / "state.json").read_text(encoding="utf-8"))
            out = client.put_run(new_state, _new_events(work / "events.jsonl"), work / "alerts")
            print(f"{args.tenant}: kept by the watch service: {out['alerts']} alert(s), {out['events']} event(s)")
            return code
    except ServiceError as exc:
        print(f"{args.tenant}: {exc}: the next passage sees the same items again", file=sys.stderr)
        return 1
    finally:
        client.close()


def cmd_send(args: argparse.Namespace) -> int:
    from via.alert.cli import cmd_send as send

    client = _client(args)
    try:
        wanted = [w for w in (args.only or env("SEND_ONLY").replace(",", " ").split()) if w]
        if wanted:
            chosen = []
            for w in wanted:
                a = client.alert(w)
                if a is None:
                    print(f"{w}: ERROR no such alert kept by the watch service", file=sys.stderr)
                    return 1  # never send a partial choice
                chosen.append(a)
        else:
            pending = client.alerts("pending")
            latest = pending[0]["run"] if pending else None
            chosen = [a for a in pending if a["run"] == latest]
            print(f"{args.tenant}: no alert named: the pending alerts of the latest watch ({len(chosen)})")
        already = [a["id"] for a in chosen if a["status"] == "sent"]
        if already and not args.again:
            print(
                f"{', '.join(already)}: ERROR already sent to the client (--again to send once more)", file=sys.stderr
            )
            return 1
        if not chosen:
            print(f"{args.tenant}: no alert to send")
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            alerts = Path(tmp) / "alerts"
            for a in chosen:
                client.fetch(a, alerts)
            index = [{k: v for k, v in a.items() if k not in ("run", "status", "events", "sheet")} for a in chosen]
            (alerts / "index.json").write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
            log = Path(tmp) / "events.jsonl"
            code = send(
                argparse.Namespace(
                    profile=args.profile,
                    contacts=args.contacts,
                    alerts=str(alerts),
                    only=None,
                    journal=str(log),
                    edits=args.edits,
                )
            )
            events = _new_events(log)
            if events:
                client.add_events(events)
            return code
    except ServiceError as exc:
        print(f"{args.tenant}: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


def cmd_push_inventory(args: argparse.Namespace) -> int:
    base = Path(args.assets_dir)
    try:
        assets = json.loads((base / "assets.json").read_text(encoding="utf-8"))
        findings = json.loads((base / "findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"{args.tenant}: no inventory to push ({exc})", file=sys.stderr)
        return 1
    client = _client(args)
    try:
        client.put_inventory(assets, findings)
    except ServiceError as exc:
        print(f"{args.tenant}: {exc}", file=sys.stderr)
        return 3 if exc.retry else 1
    finally:
        client.close()
    print(
        f"{args.tenant}: inventory pushed to the watch service ({len(assets.get('assets', []))} assets, "
        f"{len(findings.get('findings', []))} findings)"
    )
    return 0


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", required=True, help="watch service, e.g. http://a2vm-lab-via:8080")
    p.add_argument("--tenant", required=True)
    p.add_argument("--token-file", required=True, help="the run token of the watch service")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="via", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve", help="the watch service of one tenant")
    s.add_argument("--tenant", required=True)
    s.add_argument("--digests", required=True, help="`<run|read> <sha256>` per line")
    s.add_argument("--store", default="/data/watch")
    s.add_argument("--keep-days", type=int, default=30, help="days the alerts and their sheets are kept")
    s.add_argument("--max-mb", type=int, default=50)
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a pod
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    svc = sub.add_parser("service", help="the tenant's jobs on Kubernetes, with the watch service")
    ss = svc.add_subparsers(dest="job", required=True)
    w = ss.add_parser("watch", help="one passage of the watch")
    _common(w)
    w.add_argument("profile")
    w.add_argument("--settings", default="config/settings.yaml")
    w.add_argument("--sources", default="config/watch-sources.yaml")
    w.add_argument("--contacts", default="contacts.yaml")
    w.add_argument("--fixtures")
    w.add_argument("--no-llm", action="store_true")
    w.set_defaults(func=cmd_watch)
    d = ss.add_parser("send", help="send the alerts the analyst validated")
    _common(d)
    d.add_argument("profile")
    d.add_argument(
        "--only", nargs="*", help="alert ids (default: A2VM_SEND_ONLY, else the pending alerts of the latest watch)"
    )
    d.add_argument("--edits", help="the analysts' edited sheets (edits/<alert id>.md or .docx)")
    d.add_argument("--contacts", default="contacts.yaml")
    d.add_argument("--again", action="store_true", help="send an alert already sent once more")
    d.set_defaults(func=cmd_send)
    i = ss.add_parser("push-inventory", help="the daily run's assets and findings, for the watch")
    _common(i)
    i.add_argument("--assets-dir", required=True, help="work/assets/<client>, written by verdict assets")
    i.set_defaults(func=cmd_push_inventory)
    args = parser.parse_args(argv)
    return args.func(args)
