# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The sender of the review page (LLD vulnerability-intelligence §3.8, §3.9): one replica, in a loop.

Each pass:
1. translations: for each alert whose recipients were chosen, each language they need that has no
   translation of the current English reference yet is translated by the tenant's LLM
   (`via.alert.translate`) and given to the watch service, or the reason it was refused; an analyst
   checks and corrects it on the page, then validates;
2. sending: each validated alert is mailed to the chosen recipients, one mail per language: the
   reference in English, the validated translation otherwise, with the Word file filled in that
   language. A translation no longer made from the current reference is never sent.
The sender holds the mail secrets and reaches the LLM; `via serve` and the page hold neither.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from via.alert import journal, word
from via.alert.contacts import Contact, recipients
from via.alert.fiche import markdown_html
from via.alert.mail import MailError, message, send
from via.alert.translate import TranslationError, text_hash, translate

from .client import WatchClient


def reference(client: WatchClient, alert: dict[str, Any]) -> str:
    """The English reference, as enriched on the page, else as the watch wrote it."""
    edited = client.edit(alert["id"])
    if edited is not None:
        return edited
    with tempfile.TemporaryDirectory() as tmp:
        client.fetch({"id": alert["id"]}, Path(tmp))
        return (Path(tmp) / f"{alert['id']}.md").read_text(encoding="utf-8")


def translate_requested(client: WatchClient, llm: Any, tenant: str) -> int:
    """Translate what the analysts asked for; the number of translations given back."""
    done = 0
    for a in client.alerts("translating"):
        detail = client.alert(a["id"])
        if not detail:
            continue
        waiting = [lang for lang, m in (detail.get("translations") or {}).items() if m.get("state") == "waiting"]
        if not waiting:
            continue
        ref = reference(client, a)
        ref_hash = text_hash(ref)
        if ref_hash != detail.get("reference_hash"):
            continue  # changed meanwhile: the next pass sees the new request
        for lang in waiting:
            try:
                text, source = translate(llm, ref, lang)
                client.put_translation(a["id"], lang, ref_hash, source, text=text)
                print(f"{tenant}: {a['id']}: translated into {lang} ({source})", flush=True)
            except TranslationError as exc:
                client.put_translation(a["id"], lang, ref_hash, "llm", error=str(exc))
                print(f"{tenant}: {a['id']}: translation into {lang} refused: {exc}", file=sys.stderr, flush=True)
            done += 1
    return done


def send_validated(
    client: WatchClient, profile: Any, profile_path: str, contacts: list[Contact], tenant: str
) -> tuple[int, int]:
    """Mail the validated alerts, one mail per language; (mails sent, failures)."""
    from via.alert.cli import _today, _word_template

    sent = failed = 0
    attach = list(profile.alerts.get("attach") or ["docx"])
    for listed in client.alerts("validated"):
        detail = client.alert(listed["id"])
        if not detail:
            continue
        a = {k: v for k, v in detail.items() if k != "sheet"}  # the full entry: Word file, its contexts
        request = detail.get("request") or {}
        known = {c.email.lower(): c for c in recipients(a.get("level", ""), contacts, profile)}
        groups: dict[str, list[str]] = {}
        missing = []
        for email in request.get("to") or []:
            c = known.get(email.lower())
            if c is None:
                missing.append(email)
            else:
                groups.setdefault(c.language, []).append(c.email)
        if missing:
            print(f"{tenant}: {a['id']}: no longer a recipient, left out: {', '.join(missing)}", file=sys.stderr)
        events = []
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            client.fetch(a, work)
            ref = reference(client, a)
            for lang, emails in sorted(groups.items()):
                state = (detail.get("translations") or {}).get(lang, {}).get("state")
                try:
                    if lang == "en":
                        text = ref
                    elif state != "fresh":
                        raise ValueError(f"translation into {lang} {state or 'missing'}: not sent")
                    else:
                        text = client.translation(a["id"], lang) or ""
                    if text_hash(ref) != detail.get("reference_hash"):
                        raise ValueError("the reference changed after the validation: not sent")
                    files = _word(a, work, lang, text, profile, profile_path, attach, _word_template, _today)
                    title = next((line[2:] for line in text.splitlines() if line.startswith("# ")), a.get("title", ""))
                    msg = message(f"[CERT Alert] {title}", markdown_html(text), text, emails, attachments=files)
                    result = send(msg, work / "outbox")
                    print(f"{tenant}: {a['id']}: {result} — {', '.join(emails)} [{lang}]", flush=True)
                    events.append(journal.event("sent", a, to=emails, result=result, language=lang,
                                                files=[f.name for f in files]))  # fmt: skip
                    sent += 1
                except (ValueError, MailError, word.ConversionError) as exc:
                    print(f"{tenant}: {a['id']}: ERROR [{lang}] {exc}", file=sys.stderr, flush=True)
                    events.append(journal.event("send-failed", a, to=emails, language=lang, error=str(exc)))
                    failed += 1
            if not groups:
                events.append(journal.event("send-failed", a, error="no recipient left"))
                failed += 1
        for e in events:
            e.pop("pipeline", None)
        # Failures last: an alert with one language failed stays `failed` until validated again.
        client.add_events(sorted(events, key=lambda e: e["event"] == "send-failed"))
    return sent, failed


def _word(a, work: Path, lang: str, text: str, profile, profile_path: str, attach, template_of, today) -> list[Path]:
    """The Word file (and PDF) of the alert in `lang`: the facts of that language (the watch's
    context file), the prose of the sheet validated in it, the template of that language."""
    ctx_files = a.get("ctx") or {}
    if not a.get("docx") or not ctx_files or not {"docx", "pdf"} & set(attach):
        return [work / a["docx"]] if a.get("docx") and "docx" in attach and not ctx_files else []
    name = ctx_files.get(lang) or ctx_files.get("en")
    ctx = json.loads((work / name).read_text(encoding="utf-8"))
    ctx = word.with_text(ctx, text, lang if name == ctx_files.get(lang) else "en")
    ctx["date"] = today()
    template = template_of(profile, profile_path, lang)
    out = word.render(template, ctx, work / lang / a["docx"])
    files = [out] if "docx" in attach else []
    if "pdf" in attach:
        files.append(word.to_pdf(out, work / lang / "pdf"))
    return files
