# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`via serve` (the watch service of one tenant) and `via service …` (the tenant's jobs on Kubernetes):

  via serve                 keeps the watch's state, the last inventory, the alerts and their journal;
                            with --review-port, the analysts' review page (behind oauth2-proxy)
  via service watch …       one passage of the watch: state and inventory from the service, `via watch`,
                            alerts, events and the new state back to it
  via service send …        the chosen alerts from the service, `via send`, the events back to it;
                            with --validated, the alerts validated on the review page (--every: a loop)
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
import threading
import time
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
    from a2vm.db import DatabaseError, open_database

    from .pgstore import MIGRATIONS, PgWatchStore

    try:
        tokens = TokenSet.load(args.digests, ROLES)
        db = open_database("via", MIGRATIONS)
        if db is None:
            Path(args.store).mkdir(parents=True, exist_ok=True)
    except (ValueError, OSError, DatabaseError) as exc:
        print(exc, file=sys.stderr)
        return 2
    store = PgWatchStore(db, args.keep_days) if db else WatchStore(args.store, args.keep_days)
    review_httpd = None
    if args.review_port:
        from a2vm.service import serve as plain_serve

        from .review import Review, make_handler

        try:
            key = Path(args.review_key).read_bytes().strip() if args.review_key else b""
            review = Review(
                args.tenant,
                store,
                key,
                {g for g in args.review_readers.split(",") if g.strip()},
                {g for g in args.review_validators.split(",") if g.strip()},
                args.review_url,
                contacts=args.review_contacts,
                profile=args.review_profile,
            )
        except (OSError, ValueError) as exc:
            print(f"review page: {exc}", file=sys.stderr)
            return 2
        review_httpd = plain_serve(make_handler(review), args.host, args.review_port)
        threading.Thread(target=review_httpd.serve_forever, daemon=True).start()
    roles = ", ".join(f"{r} {'set' if r in tokens.digests else 'MISSING'}" for r in sorted(ROLES))
    kept = store.alerts(args.tenant)
    page = f"; review page on port {args.review_port} ({args.review_url})" if review_httpd else ""
    print(f"{args.tenant}: tokens {roles}; store {store.describe()}; {len(kept)} alert(s) kept{page}", flush=True)
    httpd = serve(WatchService(args.tenant, tokens, store, args.max_mb * 1024 * 1024), args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if review_httpd:
            review_httpd.shutdown()
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
    if args.validated:
        return _send_validated(args)
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


def _send_validated(args: argparse.Namespace) -> int:
    """The sender of the review page, once (`--every 0`) or in a loop: the translations asked for,
    then the validated alerts, one mail per language (via.service.sender)."""
    from a2vm.config import load_settings
    from a2vm.llm import LlmClient
    from a2vm.profile import ProfileError, load_profile
    from via.alert.contacts import ContactsError, load_contacts

    from .sender import send_validated, translate_requested

    try:
        profile = load_profile(args.profile)
        contacts = load_contacts(args.contacts) if args.contacts and Path(args.contacts).exists() else []
        settings = load_settings(args.settings) if args.settings else None
    except (ProfileError, ContactsError, OSError, ValueError) as exc:
        print(f"{args.tenant}: {exc}", file=sys.stderr)
        return 2
    llm = LlmClient(settings.llm) if settings and settings.llm.enabled else None
    languages = sorted({c.language for c in contacts if c.active})
    how = f"by {settings.llm.model}" if llm else "not available (no LLM)"
    print(f"{args.tenant}: sender ready; contacts in {', '.join(languages) or 'en'}; translation {how}", flush=True)
    client = _client(args)
    code = 0
    try:
        while True:
            try:
                translate_requested(client, llm, args.tenant)
                _, failed = send_validated(client, profile, args.profile, contacts, args.tenant)
                code = 1 if failed else 0
            except ServiceError as exc:
                print(f"{args.tenant}: {exc}: tried again at the next pass", file=sys.stderr, flush=True)
                code = 1
            sys.stdout.flush()
            if args.every <= 0:
                return code
            time.sleep(args.every)
    finally:
        client.close()
        if llm:
            llm.close()


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
    s.add_argument("--review-port", type=int, default=0, help="serve the review page on this port (0: none)")
    s.add_argument("--review-url", default="", help="public https URL of the review page")
    s.add_argument("--review-key", help="file of the key that signs the page's forms (32 bytes at least)")
    s.add_argument("--review-readers", default="", help="groups that read the alerts, comma-separated")
    s.add_argument("--review-validators", default="", help="groups that also correct, validate and dismiss")
    s.add_argument("--review-contacts", help="contacts.yaml: the recipients a validator chooses from, their language")
    s.add_argument("--review-profile", help="client.yaml: its alerts.recipients also receive (in English)")
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
    d.add_argument("--validated", action="store_true", help="send the alerts validated on the review page")
    d.add_argument("--every", type=int, default=0, help="with --validated: seconds between passes (0: once)")
    d.add_argument("--settings", help="with --validated: settings of the LLM that translates (config/settings.yaml)")
    d.set_defaults(func=cmd_send)
    i = ss.add_parser("push-inventory", help="the daily run's assets and findings, for the watch")
    _common(i)
    i.add_argument("--assets-dir", required=True, help="work/assets/<client>, written by verdict assets")
    i.set_defaults(func=cmd_push_inventory)
    args = parser.parse_args(argv)
    return args.func(args)
