# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""via (alert): watch mode of a client project.

  watch   new CERT-FR publications, KEV additions and critical CVEs since the last run, matched to
          the client; each match becomes an alert sheet (Markdown + HTML) mailed to the analysts
          (VULNOPS_ANALYST_TO) for validation
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
from pathlib import Path

from a2vm.config import describe_llm, load_settings
from a2vm.extensions import ExtensionMissing, asset_matcher
from a2vm.llm import LlmClient
from a2vm.profile import ProfileError, load_profile
from via.intel.sources import Sources

from .contacts import ContactsError, load_contacts, recipients
from .feeds import load_catalogue
from .fiche import build
from .mail import MailError, message, send
from .watch import State, discover, relevant


def _recipients(value: str) -> list[str]:
    return [a.strip() for a in value.replace(";", ",").split(",") if a.strip()]


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
        alerts = relevant(items, profile, sources, settings, matcher, state, catalogue)
        index = []
        for alert in alerts:
            fiche = build(alert, settings, llm)
            (out / f"{alert.id}.md").write_text(fiche.markdown(), encoding="utf-8")
            (out / f"{alert.id}.html").write_text(fiche.html(), encoding="utf-8")
            index.append({"id": alert.id, "level": alert.level, "title": fiche.title, "prose": fiche.prose_source})
        (out / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    finally:
        sources.close()
        if llm:
            llm.close()
    state.save()
    print(f"{profile.id}: {len(items)} new items, {len(index)} alerts -> {out}")
    for e in errors:
        print(f"  ERROR {e}", file=sys.stderr)
    for a in index:
        print(f"  {a['level']:<6} {a['id']}: {a['title']} [{a['prose']}]")

    try:
        contacts = load_contacts(args.contacts) if args.contacts and Path(args.contacts).exists() else []
    except ContactsError as exc:
        print(exc, file=sys.stderr)
        contacts, errors = [], [*errors, "contacts.yaml invalid"]
    analysts = _recipients(os.environ.get("VULNOPS_ANALYST_TO", ""))
    pipeline = os.environ.get("CI_PIPELINE_URL", "")
    for a in index:
        if not analysts:
            break
        fiche_html = (out / f"{a['id']}.html").read_text(encoding="utf-8")
        to = ", ".join(c.label() for c in recipients(a["level"], contacts, profile)) or "aucun destinataire configuré"
        note = (
            f'<p style="background:#fff4d6;padding:8px"><b>À valider avant envoi à {profile.name}</b> '
            f"(destinataires : {to}). "
            + (
                f'Pour l\'envoyer : <a href="{pipeline}">ouvrir le pipeline</a>, job « send-alerts », bouton ▶.'
                if pipeline
                else ""
            )
            + "</p>"
        )
        msg = message(
            f"[CERT Alert][{profile.id}] À valider — {a['title']}",
            note + fiche_html,
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            analysts,
        )
        try:
            print(f"  analysts: {send(msg, out / 'outbox')}")
        except MailError as exc:
            print(f"  ERROR mail to analysts: {exc}", file=sys.stderr)
            errors.append(str(exc))
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
    if args.only:
        index = [a for a in index if a["id"] in set(args.only)]
    if not index:
        print(f"{profile.id}: no alert to send")
        return 0
    failed = 0
    for a in index:
        to = recipients(a["level"], contacts, profile)
        if not to:
            print(
                f"{a['id']}: ERROR no recipient for level {a['level']} (contacts.yaml, alerts.recipients)",
                file=sys.stderr,
            )
            failed += 1
            continue
        msg = message(
            f"[Alerte vulnérabilité] {a['title']}",
            (out / f"{a['id']}.html").read_text(encoding="utf-8"),
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            [c.email for c in to],
        )
        try:
            print(f"{a['id']}: {send(msg, out / 'outbox')} — {', '.join(c.label() for c in to)}")
        except MailError as exc:
            print(f"{a['id']}: ERROR {exc}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


def cmd_check_sources(args: argparse.Namespace) -> int:
    """Read every source of the catalogue once (enabled or not) and report what came back."""
    from .certfr import parse_feed
    from .feeds import csaf_entries, csaf_index_url, parse_generic_feed

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
                    kind, index = csaf_index_url(sources.fetch_json(src.url) or {})
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
    w.add_argument(
        "--sources",
        default="config/watch-sources.yaml",
        help="catalogue of watch sources (default without the file: CERT-FR, KEV, cvelistV5)",
    )
    w.set_defaults(func=cmd_watch)
    s = sub.add_parser("send", help="mail the alerts of a watch run to the client")
    s.add_argument("profile", help="client.yaml")
    s.add_argument("--alerts", default="alerts")
    s.add_argument("--only", nargs="*", help="alert ids to send (default: all)")
    s.add_argument("--contacts", default="contacts.yaml", help="client contacts (optional file)")
    s.set_defaults(func=cmd_send)
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
