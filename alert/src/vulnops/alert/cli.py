"""vulnops-alert: watch mode of a client project.

  watch   new CERT-FR publications, KEV additions and critical CVEs since the last run, matched to
          the client; each match becomes an alert sheet (Markdown + HTML) mailed to the analysts
          (VULNOPS_ANALYST_TO) for validation
  send    mail the validated alerts of a watch run to the client (alerts.recipients of client.yaml)

The analysts validate by running the manual "send-alerts" job of the watch pipeline: the alert mail
links to it. Nothing reaches a client without that step.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from vulnops.core.config import describe_llm, load_settings
from vulnops.core.llm import LlmClient
from vulnops.core.profile import ProfileError, load_profile
from vulnops.detect.inventory import InventoryScanner
from vulnops.intel.sources import Sources

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
        items, errors = discover(sources, state)
        if state.new:
            print(f"{profile.id}: first run, baseline recorded ({len(state.certfr)} CERT-FR, {len(state.kev)} KEV)")
            state.save()
            (out / "index.json").write_text("[]", encoding="utf-8")
            return 0
        alerts = relevant(items, profile, sources, settings, InventoryScanner(settings, llm))
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

    analysts = _recipients(os.environ.get("VULNOPS_ANALYST_TO", ""))
    pipeline = os.environ.get("CI_PIPELINE_URL", "")
    for a in index:
        if not analysts:
            break
        fiche_html = (out / f"{a['id']}.html").read_text(encoding="utf-8")
        note = (
            f'<p style="background:#fff4d6;padding:8px"><b>À valider avant envoi à {profile.name}.</b> '
            + (
                f'Pour l\'envoyer : <a href="{pipeline}">ouvrir le pipeline</a>, job « send-alerts », bouton ▶.'
                if pipeline
                else ""
            )
            + "</p>"
        )
        msg = message(
            f"[vulnops][{profile.id}] À valider — {a['title']}",
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
    except ProfileError as exc:
        print(exc, file=sys.stderr)
        return 2
    out = Path(args.alerts)
    index = json.loads((out / "index.json").read_text(encoding="utf-8")) if (out / "index.json").exists() else []
    if args.only:
        index = [a for a in index if a["id"] in set(args.only)]
    if not index:
        print(f"{profile.id}: no alert to send")
        return 0
    to = profile.alerts.get("recipients", [])
    if not to:
        print(f"{profile.id}: no alerts.recipients in {args.profile}", file=sys.stderr)
        return 2
    failed = 0
    for a in index:
        msg = message(
            f"[Alerte vulnérabilité] {a['title']}",
            (out / f"{a['id']}.html").read_text(encoding="utf-8"),
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            to,
        )
        try:
            print(f"{a['id']}: {send(msg, out / 'outbox')}")
        except MailError as exc:
            print(f"{a['id']}: ERROR {exc}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnops-alert", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("watch", help="draft alerts for what is new since the last run")
    w.add_argument("profile", help="client.yaml")
    w.add_argument("--settings", default="config/settings.yaml")
    w.add_argument("--state", default=".cache/watch-state.json", help="what was already seen (kept between runs)")
    w.add_argument("--out", default="alerts")
    w.add_argument("--fixtures", help="read sources from a fixtures directory (tests, demos)")
    w.add_argument("--no-llm", action="store_true")
    w.set_defaults(func=cmd_watch)
    s = sub.add_parser("send", help="mail the alerts of a watch run to the client")
    s.add_argument("profile", help="client.yaml")
    s.add_argument("--alerts", default="alerts")
    s.add_argument("--only", nargs="*", help="alert ids to send (default: all)")
    s.set_defaults(func=cmd_send)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
