# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""via (alert): watch mode of a client project.

  watch   new CERT-FR publications, KEV additions and critical CVEs since the last run, matched to
          the client; each match becomes an alert sheet (Markdown + HTML) mailed to the analysts
          (A2VM_ANALYST_TO) for validation
  send    mail the validated alerts of a watch run to the client: contacts.yaml (by level), plus
          alerts.recipients of client.yaml
  contacts check a contacts.yaml and list who receives what
  check-sources  read every source of the watch catalogue once and say which ones work

The analysts validate by running the manual "send-alerts" job of the watch pipeline: the alert mail
links to it. Nothing reaches a client without that step.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from a2vm.config import describe_llm, env, load_settings
from a2vm.extensions import ExtensionMissing, asset_matcher
from a2vm.llm import LlmClient
from a2vm.profile import ProfileError, load_profile
from via.intel.sources import Sources

from . import journal
from .contacts import ContactsError, load_contacts, recipients
from .feeds import load_catalogue
from .fiche import build
from .inventory import Inventory, describe, fetch, load
from .mail import MailError, message, send
from .watch import State, discover, relevant


def _recipients(value: str) -> list[str]:
    return [a.strip() for a in value.replace(";", ",").split(",") if a.strip()]


LOCAL_INVENTORY = Path("work/assets")  # restored from the runner cache `inventory` (pipeline template)


def _inventory(how: str, client_id: str) -> Inventory | None:
    """The last daily inventory: `none`, a directory, or `auto`: the copy the daily triage job left in
    the runner cache, else the artifacts of the project's last triage job."""
    if how == "none":
        return None
    if how == "auto" and (LOCAL_INVENTORY / client_id / "assets.json").exists():
        how = str(LOCAL_INVENTORY)
    if how != "auto":
        inv = load(how, client_id)
        print(f"inventory: {how}: " + (describe(inv) if inv else f"no inventory of {client_id}: declared assets only"))
        return inv
    project = os.environ.get("CI_PROJECT_ID")
    if not project:
        print("inventory: not in a pipeline: declared assets only")
        return None
    with tempfile.TemporaryDirectory() as tmp:  # read into memory: nothing lands in the alerts artifacts
        inv, note = fetch(project, client_id, tmp, ref=os.environ.get("CI_DEFAULT_BRANCH", "main"))
    print(f"inventory: {note}")
    return inv


def cmd_watch(args: argparse.Namespace) -> int:
    settings = load_settings(args.settings)
    settings.sources.feed_cache_hours = min(settings.sources.feed_cache_hours, 0.1)
    if args.no_llm:
        settings.llm.enabled = False
    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(describe_llm(settings))
    state = State.load(args.state)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    llm = LlmClient(settings.llm) if settings.llm.enabled else None
    sources = Sources(settings.sources, fixtures_dir=args.fixtures)
    try:
        catalogue = load_catalogue(args.sources) if args.sources and Path(args.sources).exists() else None
        if catalogue:
            enabled = [c for c in catalogue if c.enabled]
            by_cat = {k: sum(c.category == k for c in enabled) for k in ("institutional", "vendor", "research")}
            print(f"sources: {args.sources}, {len(enabled)} enabled ({by_cat})")
        items, errors = discover(sources, state, catalogue=catalogue)
        if state.new:
            print(f"{profile.id}: first run, baseline recorded ({len(state.certfr)} CERT-FR, {len(state.kev)} KEV)")
            state.save()
            (out / "index.json").write_text("[]", encoding="utf-8")
            return 0
        try:
            matcher = asset_matcher(settings, llm)
        except ExtensionMissing as exc:
            print(exc, file=sys.stderr)
            return 2
        inventory = _inventory(args.inventory, profile.id)
        alerts = relevant(items, profile, sources, settings, matcher, state, catalogue, inventory)
        index = []
        for alert in alerts:
            fiche = build(alert, settings, llm)
            (out / f"{alert.id}.md").write_text(fiche.markdown(), encoding="utf-8")
            (out / f"{alert.id}.html").write_text(fiche.html(), encoding="utf-8")
            index.append(
                {
                    "id": alert.id,
                    "level": alert.level,
                    "title": fiche.title,
                    "prose": fiche.prose_source,
                    "cves": list(alert.item.cves),
                }
            )
        (out / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    finally:
        sources.close()
        if llm:
            llm.close()
    errors, warnings = state.count_failures(errors, int(env("SOURCE_FAILURES", "3") or 3))
    state.save()
    print(f"{profile.id}: {len(items)} new items, {len(index)} alerts -> {out}")
    for w in warnings:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}", file=sys.stderr)
    for a in index:
        print(f"  {a['level']:<6} {a['id']}: {a['title']} [{a['prose']}]")

    try:
        contacts = load_contacts(args.contacts) if args.contacts and Path(args.contacts).exists() else []
    except ContactsError as exc:
        print(exc, file=sys.stderr)
        contacts, errors = [], [*errors, "contacts.yaml invalid"]
    analysts = _recipients(env("ANALYST_TO"))
    pipeline = os.environ.get("CI_PIPELINE_URL", "")
    log_path = Path(args.journal) if args.journal else Path(args.state).parent / "alerts-log.jsonl"
    events = [journal.event("drafted", a, cves=a.get("cves")) for a in index]
    for number, a in enumerate(index, start=1):
        if not analysts:
            break
        fiche_html = (out / f"{a['id']}.html").read_text(encoding="utf-8")
        to = ", ".join(c.label() for c in recipients(a["level"], contacts, profile)) or "aucun destinataire configuré"
        how = (
            f'Pour l\'envoyer : <a href="{pipeline}">ouvrir le pipeline</a>, job « send-alerts », bouton ▶. '
            f"Pour n'envoyer que celle-ci : variable <code>A2VM_SEND_ONLY</code> = <code>{number}</code> "
            "dans le formulaire du job (sans variable, toutes les alertes du pipeline partent)."
            if pipeline
            else ""
        )
        note = (
            f'<p style="background:#fff4d6;padding:8px"><b>À valider avant envoi à {profile.name}</b> '
            f"(destinataires : {to}).<br>Alerte n° {number} sur {len(index)} de ce pipeline, "
            f"identifiant <code>{a['id']}</code>.<br>{how}</p>"
        )
        msg = message(
            f"[CERT Alert][{profile.id}] À valider — {a['title']}",
            note + fiche_html,
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            analysts,
        )
        try:
            result = send(msg, out / "outbox")
            print(f"  analysts: {result}")
            events.append(journal.event("analysts", a, to=analysts, result=result))
        except MailError as exc:
            print(f"  ERROR mail to analysts: {exc}", file=sys.stderr)
            errors.append(str(exc))
            events.append(journal.event("analysts", a, to=analysts, error=str(exc)))
    journal.append(log_path, events)
    journal.publish(log_path, out)
    return 3 if errors else 0


def cmd_send(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.profile)
        contacts = load_contacts(args.contacts) if args.contacts and Path(args.contacts).exists() else []
    except (ProfileError, ContactsError) as exc:
        print(exc, file=sys.stderr)
        return 2
    out = Path(args.alerts)
    index = json.loads((out / "index.json").read_text(encoding="utf-8")) if (out / "index.json").exists() else []
    wanted = list(args.only or []) or _recipients(env("SEND_ONLY").replace(" ", ","))
    if wanted:
        chosen, unknown = select(index, wanted)
        for w in unknown:
            print(
                f"{w}: ERROR no such alert in this pipeline (number 1 to {len(index)}, or an alert id)", file=sys.stderr
            )
        if unknown:
            return 1  # never send a partial choice: the analyst fixes the list and runs the job again
        index = chosen
        print(f"{profile.id}: sending {len(index)} chosen alert(s): {', '.join(a['id'] for a in index)}")
    if not index:
        print(f"{profile.id}: no alert to send (the watch of this pipeline drafted none)")
        return 0
    failed = 0
    sent_path = out / "sent.json"
    sent = json.loads(sent_path.read_text(encoding="utf-8")) if sent_path.exists() else []
    events = []
    for a in index:
        to = recipients(a["level"], contacts, profile)
        if not to:
            print(
                f"{a['id']}: ERROR no recipient for level {a['level']} (contacts.yaml, alerts.recipients)",
                file=sys.stderr,
            )
            failed += 1
            events.append(journal.event("send-failed", a, error="no recipient"))
            continue
        msg = message(
            f"[CERT Alert] {a['title']}",
            (out / f"{a['id']}.html").read_text(encoding="utf-8"),
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            [c.email for c in to],
        )
        emails = [c.email for c in to]
        try:
            result = send(msg, out / "outbox")
            print(f"{a['id']}: {result} — {', '.join(c.label() for c in to)}")
            entry = journal.event("sent", a, to=emails, result=result)
        except MailError as exc:
            print(f"{a['id']}: ERROR {exc}", file=sys.stderr)
            failed += 1
            entry = journal.event("send-failed", a, to=emails, error=str(exc))
        events.append(entry)
        sent.append({k: entry[k] for k in entry if k != "pipeline"})
    sent_path.write_text(json.dumps(sent, ensure_ascii=False, indent=1), encoding="utf-8")
    if args.journal:
        journal.append(args.journal, events)
        journal.publish(args.journal, out)
    return 1 if failed else 0


def select(index: list[dict], wanted: list[str]) -> tuple[list[dict], list[str]]:
    """The alerts named by number (position in this pipeline, from 1), full id or id suffix."""
    chosen, unknown = [], []
    for w in wanted:
        if w.isdigit() and 1 <= int(w) <= len(index):
            hits = [index[int(w) - 1]]
        else:
            hits = [a for a in index if a["id"] == w or a["id"].endswith("-" + w)]
        if len(hits) != 1:
            unknown.append(w)
        elif hits[0] not in chosen:
            chosen.append(hits[0])
    return chosen, unknown


def cmd_test_mail(args: argparse.Namespace) -> int:
    """Send one test message with the mail settings of this project, to check them."""
    to = list(args.to or []) or _recipients(env("ANALYST_TO"))
    if not to:
        print("no recipient: --to, or the CI/CD variable A2VM_ANALYST_TO", file=sys.stderr)
        return 2
    where = os.environ.get("CI_PROJECT_PATH", "local run")
    body = (
        f"Message de test A2VM ({where}).\n\nSi vous le lisez, les alertes de la veille arriveront par le même "
        "chemin : expéditeur, relais et destinataires sont corrects."
    )
    msg = message(f"[CERT Alert] Test d'envoi — {where}", f"<p>{body}</p>".replace("\n\n", "</p><p>"), body, to)
    print(f"From: {msg['From']}  To: {msg['To']}  transport: {env('MAIL_TRANSPORT', 'smtp')}")
    try:
        print(send(msg, Path(args.out) if args.out else None))
    except MailError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_check_sources(args: argparse.Namespace) -> int:
    """Read every source of the catalogue once (enabled or not) and report what came back."""
    from .certfr import parse_feed
    from .feeds import csaf_entries, csaf_index, parse_generic_feed

    settings = load_settings(args.settings)
    catalogue = load_catalogue(args.sources)
    sources = Sources(settings.sources, fixtures_dir=args.fixtures)
    bad = 0
    try:
        for src in catalogue:
            flag = "on " if src.enabled else "off"
            try:
                if src.kind == "certfr":
                    detail = f"{len(parse_feed(sources.certfr_feed(src.feed), src.feed))} publications"
                elif src.kind == "kev":
                    detail = f"{len(sources.kev())} entries"
                elif src.kind == "rss":
                    pubs = parse_generic_feed(sources.fetch_text(src.url), src)
                    if not pubs:
                        raise ValueError("no item")
                    detail = f"{len(pubs)} items, latest: {pubs[0].title[:60]}"
                elif src.kind == "csaf":
                    kind, index = csaf_index(sources, src.url)
                    entries = csaf_entries(kind, index, sources.fetch_text(index))
                    detail = f"{len(entries)} documents ({kind}), latest {entries[0][1] if entries else '-'}"
                else:
                    detail = "via cvelistV5" + (f" ({', '.join(src.vendors)})" if src.vendors else "")
                print(f"OK  {flag} {src.category:<13} {src.id:<18} {detail}")
            except Exception as exc:  # noqa: BLE001 - report every failure, whatever it is
                bad += 1
                print(f"KO  {flag} {src.category:<13} {src.id:<18} {type(exc).__name__}: {str(exc)[:150]}")
    finally:
        sources.close()
    return 3 if bad else 0


def cmd_contacts(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.profile)
        contacts = load_contacts(args.contacts)
    except (ProfileError, ContactsError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"{profile.id}: {len(contacts)} contacts in {args.contacts}")
    for c in contacts:
        state = "" if c.active else "  (inactif)"
        print(f"  {c.label():<45} {c.email:<35} {'/'.join(c.receive)}{state}")
    for level in ("urgent", "info"):
        print(f"  -> {level}: {', '.join(c.email for c in recipients(level, contacts, profile)) or 'personne'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="via", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("watch", help="draft alerts for what is new since the last run")
    w.add_argument("profile", help="client.yaml")
    w.add_argument("--settings", default="config/settings.yaml")
    w.add_argument("--state", default=".cache/watch-state.json", help="what was already seen (kept between runs)")
    w.add_argument("--out", default="alerts")
    w.add_argument("--fixtures", help="read sources from a fixtures directory (tests, demos)")
    w.add_argument("--no-llm", action="store_true")
    w.add_argument("--contacts", default="contacts.yaml", help="client contacts, named in the analysts' mail")
    w.add_argument("--journal", help="alerts journal (default: alerts-log.jsonl next to --state)")
    w.add_argument(
        "--sources",
        default="config/watch-sources.yaml",
        help="catalogue of watch sources (default without the file: CERT-FR, KEV, cvelistV5)",
    )
    w.add_argument(
        "--inventory",
        default="auto",
        help="last daily inventory: auto (runner cache work/assets, else the artifacts of the project's last "
        "triage job), none, or a directory",
    )
    w.set_defaults(func=cmd_watch)
    s = sub.add_parser("send", help="mail the alerts of a watch run to the client")
    s.add_argument("profile", help="client.yaml")
    s.add_argument("--alerts", default="alerts")
    s.add_argument(
        "--only",
        nargs="*",
        help="alerts to send, by number in this pipeline (1, 2…) or id (default: A2VM_SEND_ONLY, else all)",
    )
    s.add_argument("--journal", help="alerts journal to append to (e.g. .watch/alerts-log.jsonl)")
    s.add_argument("--contacts", default="contacts.yaml", help="client contacts (optional file)")
    s.set_defaults(func=cmd_send)

    m = sub.add_parser("test-mail", help="send one test message with this project's mail settings")
    m.add_argument("--to", nargs="*", help="recipients (default: A2VM_ANALYST_TO)")
    m.add_argument("--out", help="without A2VM_SMTP_HOST, write the message there instead")
    m.set_defaults(func=cmd_test_mail)
    k = sub.add_parser("check-sources", help="read every watch source once and report (enabled or not)")
    k.add_argument("--sources", default="config/watch-sources.yaml")
    k.add_argument("--settings", default="config/settings.yaml")
    k.add_argument("--fixtures", help="read sources from a fixtures directory")
    k.set_defaults(func=cmd_check_sources)
    c = sub.add_parser("contacts", help="check contacts.yaml and list who receives what")
    c.add_argument("profile", help="client.yaml")
    c.add_argument("--contacts", default="contacts.yaml")
    c.set_defaults(func=cmd_contacts)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
