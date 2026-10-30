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
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

from a2vm.config import describe_llm, env, load_settings
from a2vm.declared import DeclaredMatcher
from a2vm.llm import LlmClient
from a2vm.profile import ProfileError, load_profile
from via.intel.sources import Sources

from . import journal, word
from .contacts import ContactsError, load_contacts, recipients
from .feeds import load_catalogue
from .fiche import build, markdown_html
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


def _edit_help(a: dict) -> str:
    """How to change the sheet before sending: a file named after the alert in edits/ of the project."""
    project, job = os.environ.get("CI_PROJECT_URL", ""), os.environ.get("CI_JOB_URL", "")
    branch = os.environ.get("CI_DEFAULT_BRANCH", "main")
    if not project or not job:
        return ""
    text = f"{job}/artifacts/raw/alerts/{a['id']}.md"
    new = f"{project}/-/new/{branch}?file_name=edits/{a['id']}.md"
    out = (
        f'<br>To change it before sending: copy <a href="{text}">the text of the sheet</a>, paste it into '
        f'<a href="{new}">edits/{a["id"]}.md</a>, correct it, commit on {branch}, then run send-alerts.'
    )
    if a.get("docx"):
        docx = f"{job}/artifacts/raw/alerts/{a['docx']}"
        out += (
            f' For the Word file: correct <a href="{docx}">{a["docx"]}</a> and put it under '
            f"<code>edits/{a['docx']}</code> of the project."
        )
    return out


def _today() -> str:
    import datetime as dt

    return dt.date.today().strftime("%d/%m/%Y")


def _word_template(profile, profile_path: str, lang: str = "en") -> Path | None:
    """The Word template of `lang` when the client wants the sheet attached (`alerts.attach`: docx
    and/or pdf): templates/alert.<lang>.docx of the project, else `alerts.word_template`, else
    templates/alert.docx, else the neutral template of the language."""
    if not {"docx", "pdf"} & set(profile.alerts.get("attach") or []):
        return None
    base = Path(profile_path).resolve().parent
    own = base / "templates" / f"alert.{lang}.docx"
    if own.exists():
        return own
    named = profile.alerts.get("word_template")
    if named:
        return base / named
    common = base / "templates" / "alert.docx"
    return common if common.exists() else word.default_template(lang)


def _send_link(alert_id: str) -> str:
    """On Kubernetes (no pipeline of the watch): a link to the alert on the review page
    (A2VM_REVIEW_URL, v0.17.0), else to a new pipeline of the tenant project, its variables filled in,
    that sends this alert (A2VM_SEND_PIPELINE_URL); both set by the chart."""
    review = env("REVIEW_URL").rstrip("/")
    if review:
        url = f"{review}/alerts/{quote(alert_id, safe='')}"
        return (
            f'To review, enrich, translate and send it: <a href="{url}">open the alert</a> (sign in with your '
            "account; validation by the validators only). Nothing is sent without it."
        )
    base = env("SEND_PIPELINE_URL")
    if not base:
        return ""
    ref = env("SEND_REF", "main")
    url = f"{base}?ref={quote(ref)}&var[A2VM_JOB]=send&var[A2VM_SEND_ONLY]={quote(alert_id)}"
    return (
        f'To send it: <a href="{url}">start the sending of this alert</a> (prefilled form, button '
        "\u201cRun pipeline\u201d). Nothing is sent without it."
    )


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
    sheet_errors: list[str] = []  # errors of this run, not of a source: reported at once
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
        matcher = DeclaredMatcher(settings, llm)
        inventory = _inventory(args.inventory, profile.id)
        alerts = relevant(items, profile, sources, settings, matcher, state, catalogue, inventory)
        index = []
        template = _word_template(profile, args.profile)
        try:
            contacts = load_contacts(args.contacts) if args.contacts and Path(args.contacts).exists() else []
        except ContactsError:
            contacts = []  # reported below, with the analysts' mail
        languages = sorted({c.language for c in contacts if c.active} | {"en"})
        for alert in alerts:
            fiche = build(alert, settings, llm)
            (out / f"{alert.id}.md").write_text(fiche.markdown(), encoding="utf-8")
            (out / f"{alert.id}.html").write_text(fiche.html(), encoding="utf-8")
            entry = {
                "id": alert.id,
                "level": alert.level,
                "title": fiche.title,
                "prose": fiche.prose_source,
                "cves": list(alert.item.cves),
            }
            if template:
                try:
                    path = word.render(template, word.context(fiche, today=_today()), out / word.filename(alert.id))
                    entry["docx"] = path.name
                    # The facts of the Word file in each language of the contacts; the sender adds the
                    # prose of the sheet validated in that language (word.with_text).
                    entry["ctx"] = {}
                    for lang in languages:
                        laid = fiche if lang == "en" else build(alert, settings, None, lang, fiche.facts["prose"])
                        name = f"{word.SAFE.sub('-', alert.id)}.ctx.{lang}.json"
                        ctx = word.context(laid, today=_today(), lang=lang)
                        (out / name).write_text(json.dumps(ctx, ensure_ascii=False), encoding="utf-8")
                        entry["ctx"][lang] = name
                except Exception as exc:  # a broken template must not stop the watch: mail without the file
                    sheet_errors.append(f"Word sheet of {alert.id} ({template}): {exc}")
            index.append(entry)
        (out / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    finally:
        sources.close()
        if llm:
            llm.close()
    errors, warnings = state.count_failures(errors, int(env("SOURCE_FAILURES", "3") or 3))
    errors += sheet_errors
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
        to = (
            ", ".join(f"{c.label()} [{c.language}]" for c in recipients(a["level"], contacts, profile))
            or "no recipient configured"
        )
        how = (
            f'To send it: <a href="{pipeline}">open the pipeline</a>, job \u201csend-alerts\u201d, button \u25b6. '
            f"To send this one only: variable <code>A2VM_SEND_ONLY</code> = <code>{number}</code> "
            "in the job's form (without it, every alert of the pipeline is sent)."
            if pipeline
            else _send_link(a["id"])
        )
        note = (
            f'<p style="background:#fff4d6;padding:8px"><b>To validate before sending to {profile.name}</b> '
            f"(recipients: {to}).<br>Alert {number} of {len(index)} of this run, "
            f"id <code>{a['id']}</code>.<br>{how}{_edit_help(a)}</p>"
        )
        attachments = [out / a["docx"]] if a.get("docx") else []
        msg = message(
            f"[CERT Alert][{profile.id}] To validate — {a['title']}",
            note + fiche_html,
            (out / f"{a['id']}.md").read_text(encoding="utf-8"),
            analysts,
            attachments=attachments,
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
        try:
            html_body, text_body, files, edited = _final_content(
                a, out, Path(args.edits) if args.edits else None, profile.alerts.get("attach")
            )
        except ValueError as exc:
            print(f"{a['id']}: ERROR {exc}", file=sys.stderr)
            failed += 1
            events.append(journal.event("send-failed", a, error=str(exc)))
            continue
        if edited:
            print(f"{a['id']}: edited by the analyst ({', '.join(edited)})")
        msg = message(f"[CERT Alert] {a['title']}", html_body, text_body, [c.email for c in to], attachments=files)
        emails = [c.email for c in to]
        try:
            result = send(msg, out / "outbox")
            print(f"{a['id']}: {result} — {', '.join(c.label() for c in to)}")
            entry = journal.event("sent", a, to=emails, result=result, edited=edited, files=[f.name for f in files])
        except MailError as exc:
            print(f"{a['id']}: ERROR {exc}", file=sys.stderr)
            failed += 1
            entry = journal.event("send-failed", a, to=emails, error=str(exc), edited=edited)
        events.append(entry)
        sent.append({k: entry[k] for k in entry if k != "pipeline"})
    sent_path.write_text(json.dumps(sent, ensure_ascii=False, indent=1), encoding="utf-8")
    if args.journal:
        journal.append(args.journal, events)
        journal.publish(args.journal, out)
    return 1 if failed else 0


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _final_content(
    a: dict, out: Path, edits: Path | None, attach: list[str] | None = None
) -> tuple[str, str, list[Path], list[str]]:
    """Mail body (HTML, text), attachments and what the analyst edited: `edits/<id>.md` replaces the
    sheet, `edits/<id>.docx` the Word file. An edited sheet may not cite a CVE the alert does not.
    The client gets the Word file (`docx`) and/or a PDF made from it now (`pdf`)."""
    attach = list(attach if attach is not None else ["docx"])
    text = (out / f"{a['id']}.md").read_text(encoding="utf-8")
    html_body = (out / f"{a['id']}.html").read_text(encoding="utf-8")
    sheet = out / a["docx"] if a.get("docx") else None
    edited = []
    if edits and (edits / f"{a['id']}.md").exists():
        new = (edits / f"{a['id']}.md").read_text(encoding="utf-8")
        foreign = sorted(set(CVE_RE.findall(new)) - set(CVE_RE.findall(text)) - set(a.get("cves", [])))
        if foreign:
            raise ValueError(f"edits/{a['id']}.md cites {', '.join(foreign)}, which this alert does not: not sent")
        if not new.strip():
            raise ValueError(f"edits/{a['id']}.md is empty: not sent")
        text, html_body = new, markdown_html(new)
        edited.append("text")
    if edits and sheet and (edits / sheet.name).exists():
        sheet = edits / sheet.name
        edited.append("docx")
    files = []
    if sheet and "docx" in attach:
        files.append(sheet)
    if sheet and "pdf" in attach:
        try:
            files.append(word.to_pdf(sheet, out / "pdf"))
        except word.ConversionError as exc:
            raise ValueError(f"PDF of {sheet.name}: {exc}: not sent") from exc
    return html_body, text, files, edited


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


def cmd_check_template(args: argparse.Namespace) -> int:
    problems = word.check_template(args.template)
    for p in problems:
        print(f"FAIL  {p}", file=sys.stderr)
    if not problems:
        print(f"OK    {args.template} (Word template of the alert sheet)")
    return 1 if problems else 0


def cmd_test_mail(args: argparse.Namespace) -> int:
    """Send one test message with the mail settings of this project, to check them."""
    to = list(args.to or []) or _recipients(env("ANALYST_TO"))
    if not to:
        print("no recipient: --to, or the CI/CD variable A2VM_ANALYST_TO", file=sys.stderr)
        return 2
    where = os.environ.get("CI_PROJECT_PATH", "local run")
    body = (
        f"A2VM test message ({where}).\n\nIf you read it, the watch's alerts will come the same way: "
        "sender, relay and recipients are right."
    )
    msg = message(f"[CERT Alert] Sending test — {where}", f"<p>{body}</p>".replace("\n\n", "</p><p>"), body, to)
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
    s.add_argument("--edits", help="directory of the analysts' edited sheets (edits/<alert id>.md or .docx)")
    s.add_argument("--contacts", default="contacts.yaml", help="client contacts (optional file)")
    s.set_defaults(func=cmd_send)

    t = sub.add_parser("check-template", help="check a Word template of the alert sheet (tags A2VM fills)")
    t.add_argument("template", nargs="?", default="templates/alert.docx")
    t.set_defaults(func=cmd_check_template)

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
