# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The review page of the alerts (LLD vulnerability-intelligence §3.8 and §3.9): the analysts read
the alerts of the watch; a validator enriches the English reference, chooses the recipients,
checks and corrects the translation for each language of those recipients, then validates the
alert for sending, or dismisses it.

Served by `via serve` on a port of its own (8081), reached only through oauth2-proxy, which signs the
analyst in with the tenant's identity provider (OIDC) and passes who it is: X-Forwarded-Email (or
X-Forwarded-User) and X-Forwarded-Groups. The NetworkPolicy lets only oauth2-proxy reach this port,
so these headers are trusted here and nowhere else. Rights from the groups:

  readers      read the alerts, their reference and their translations
  validators   also enrich, choose the recipients, correct a translation, validate, dismiss

Nothing is sent and nothing is translated from here: a request of translations and a validation are
events of the journal; the sender (`via service send --validated`) translates (the tenant's LLM)
and mails. Every action is journaled with who did it. Forms carry a token bound to the analyst and
the alert (HMAC) and must come from the page's own origin.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from via.alert import journal
from via.alert.contacts import Contact, ContactsError, load_contacts
from via.alert.fiche import markdown_html
from via.alert.i18n import name as language_name
from via.alert.translate import text_hash

from .store import ALERT_ID, EDIT_MAX, LANG, STATUSES, WatchStore

log = logging.getLogger("via.review")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
STATUS_TEXT = {
    "pending": "to review",
    "translating": "recipients chosen, translations to check",
    "validated": "validated, waiting for the sender",
    "dismissed": "dismissed",
    "sent": "sent to the client",
    "failed": "sending failed",
}
EVENT_TEXT = {
    "drafted": "drafted by the watch",
    "analysts": "mailed to the analysts",
    "edited": "reference enriched",
    "translation-requested": "recipients chosen, translations requested",
    "translated": "translated",
    "translation-failed": "translation refused",
    "translation-edited": "translation corrected",
    "validated": "validated for sending",
    "dismissed": "dismissed",
    "sent": "sent to the client",
    "send-failed": "sending failed",
}
STATE_TEXT = {
    "waiting": "waiting for the sender's translation (within a minute)",
    "fresh": "ready to check",
    "outdated": "outdated: the reference changed, choose the recipients again",
    "failed": "refused",
}
CAN_PREPARE = ("pending", "translating", "failed", "dismissed", "validated")
CAN_VALIDATE = ("translating",)
CAN_DISMISS = ("pending", "translating", "failed", "validated")
CAN_EDIT = ("pending", "translating", "failed", "validated", "dismissed")
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; img-src 'none'"
)
STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;color:#1a1a1a;background:#f7f7f5}
header{background:#1f2933;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;text-decoration:none;font-weight:600}
main{max-width:1100px;margin:0 auto;padding:16px 24px}
h2{margin-top:28px;font-size:18px}
table.list{border-collapse:collapse;width:100%;background:#fff}
.list th,.list td{border-bottom:1px solid #e3e3e0;padding:8px;text-align:left;vertical-align:top;font-size:14px}
.list th{background:#eeeeea}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#e3e3e0}
.urgent{background:#fde2e1;color:#8a1c14}.validated,.translating{background:#e1effd;color:#0b4a8a}
.sent,.fresh{background:#e2f5e6;color:#1d5b2c}.failed,.outdated{background:#fde2e1;color:#8a1c14}.dismissed{color:#666}
.sheet{background:#fff;border:1px solid #e3e3e0;padding:16px 20px;margin:12px 0}
.actions form{display:inline-block;margin-right:8px}
.box{background:#fff;border:1px solid #e3e3e0;padding:12px 16px;margin:12px 0}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer}
button.primary{background:#0b4a8a;color:#fff;border-color:#0b4a8a}
textarea{width:100%;min-height:480px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.note{color:#555;font-size:13px}.error{color:#8a1c14;font-weight:600}
nav a{margin-right:12px}
label{display:block;margin:4px 0}
"""


class Denied(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _groups(header: str) -> set[str]:
    """Group names as oauth2-proxy passes them, comma-separated; a Keycloak full path keeps its last part."""
    return {g.strip().strip("/").rsplit("/", 1)[-1] for g in header.split(",") if g.strip().strip("/")}


class Review:
    """The page's logic, free of HTTP (tested directly)."""

    def __init__(
        self,
        tenant: str,
        store: WatchStore,
        key: bytes,
        readers: set[str],
        validators: set[str],
        public_url: str,
        contacts: str | Path | None = None,
        profile: str | Path | None = None,
    ):
        if len(key) < 32:
            raise ValueError("review key: 32 bytes at least")
        if not validators:
            raise ValueError("review: a validators group is required")
        self.tenant = tenant
        self.store = store
        self.key = key
        self.readers = readers
        self.validators = validators
        self.contacts_path = Path(contacts) if contacts else None
        self.profile_path = Path(profile) if profile else None
        u = urlsplit(public_url)
        if u.scheme != "https" or not u.netloc:
            raise ValueError("review: public URL https://<host> expected")
        self.origin = f"{u.scheme}://{u.netloc}"

    # -- who -----------------------------------------------------------------------------------
    def who(self, headers: Any) -> tuple[str, bool]:
        """(the analyst, whether a validator); Denied when not signed in or in no group of the tenant."""
        user = (headers.get("X-Forwarded-Email") or headers.get("X-Forwarded-User") or "").strip()
        if not user:
            raise Denied(HTTPStatus.UNAUTHORIZED, "Sign-in required.")
        groups = _groups(headers.get("X-Forwarded-Groups") or "")
        validator = bool(groups & self.validators)
        if not validator and not groups & self.readers:
            raise Denied(HTTPStatus.FORBIDDEN, "Your account is in no group of the analysts of this tenant.")
        return user[:200], validator

    def token(self, user: str, alert_id: str) -> str:
        return hmac.new(self.key, f"{user}|{alert_id}".encode(), hashlib.sha256).hexdigest()

    def check_form(self, headers: Any, user: str, alert_id: str, form: dict[str, list[str]]) -> None:
        origin = headers.get("Origin") or ""
        referer = headers.get("Referer") or ""
        if origin != self.origin and not (not origin and referer.startswith(self.origin + "/")):
            raise Denied(HTTPStatus.FORBIDDEN, "Form refused: it does not come from this page.")
        if not hmac.compare_digest((form.get("token") or [""])[0], self.token(user, alert_id)):
            raise Denied(HTTPStatus.FORBIDDEN, "Form refused: invalid token, reload the page.")

    # -- what ----------------------------------------------------------------------------------
    def alert(self, alert_id: str) -> dict[str, Any]:
        a = self.store.alert(self.tenant, alert_id) if ALERT_ID.match(alert_id) else None
        if a is None:
            raise Denied(HTTPStatus.NOT_FOUND, "Unknown alert (or no longer kept).")
        return self.store.detail(self.tenant, a)

    def original(self, a: dict[str, Any]) -> str:
        return (self.store.file(self.tenant, a["run"], f"{a['id']}.md") or b"").decode("utf-8", "replace")

    def current(self, a: dict[str, Any]) -> str:
        return self.store.reference(self.tenant, a)

    def eligible(self, a: dict[str, Any]) -> list[Contact]:
        """The contacts that may receive this alert (its level), with their language; the profile's
        plain recipients in English."""
        contacts: list[Contact] = []
        if self.contacts_path and self.contacts_path.exists():
            try:
                contacts = load_contacts(self.contacts_path)
            except ContactsError as exc:
                log.warning("contacts: %s", exc)
        out = [c for c in contacts if c.active and a.get("level") in c.receive]
        if self.profile_path and self.profile_path.exists():
            from a2vm.profile import ProfileError, load_profile
            from via.alert.contacts import recipients

            try:
                out = recipients(a.get("level", ""), contacts, load_profile(self.profile_path))
            except ProfileError as exc:
                log.warning("profile: %s", exc)
        return out

    def _event(self, kind: str, a: dict[str, Any], user: str, **extra: Any) -> dict:
        e = journal.event(kind, a, by=user, **extra)
        e.pop("pipeline", None)
        return e

    def _check_text(self, a: dict[str, Any], text: str) -> str:
        text = text.replace("\r\n", "\n").strip() + "\n"
        if not text.strip():
            raise ValueError("The sheet is empty.")
        if len(text) > EDIT_MAX:
            raise ValueError(f"The sheet is longer than {EDIT_MAX} characters.")
        original = self.original(a)
        foreign = sorted(set(CVE_RE.findall(text)) - set(CVE_RE.findall(original)) - set(a.get("cves") or []))
        if foreign:
            raise ValueError(f"The sheet names {', '.join(foreign)}, which this alert does not concern.")
        return text

    def save_edit(self, a: dict[str, Any], user: str, text: str) -> None:
        """The English reference, enriched: the translations made before are outdated."""
        if a["status"] not in CAN_EDIT:
            raise Denied(HTTPStatus.CONFLICT, "This alert is sent: its sheet no longer changes.")
        text = self._check_text(a, text)
        self.store.put_edit(self.tenant, a["id"], text, self._event("edited", a, user))
        log.info("review tenant=%s alert=%s edited by=%s", self.tenant, a["id"], user)

    def save_translation(self, a: dict[str, Any], user: str, lang: str, text: str) -> None:
        """A translation corrected (or written) by a validator, for the current reference."""
        if a["status"] != "translating" or lang not in (a.get("translations") or {}):
            raise Denied(HTTPStatus.CONFLICT, "Choose the recipients first: no translation is requested in it.")
        text = self._check_text(a, text)
        meta = {"source": f"edited by {user}", "source_hash": a["reference_hash"], "by": user}
        event = self._event("translation-edited", a, user, language=lang)
        self.store.put_translation(self.tenant, a["id"], lang, text, meta, event)
        log.info("review tenant=%s alert=%s translation %s edited by=%s", self.tenant, a["id"], lang, user)

    def prepare(self, a: dict[str, Any], user: str, emails: list[str]) -> None:
        """The recipients chosen; the languages of the translations they need (English: none)."""
        if a["status"] not in CAN_PREPARE:
            raise Denied(HTTPStatus.CONFLICT, f"Not possible: the alert is {STATUS_TEXT[a['status']]}.")
        eligible = {c.email.lower(): c for c in self.eligible(a)}
        chosen = [eligible[e.lower()] for e in dict.fromkeys(emails) if e.lower() in eligible]
        if not chosen:
            raise ValueError("Choose at least one recipient.")
        languages = sorted({c.language for c in chosen} - {"en"})
        event = self._event(
            "translation-requested", a, user, to=[c.email for c in chosen], languages=languages,
            reference=a["reference_hash"],
        )  # fmt: skip
        self.store.add_events(self.tenant, [event])
        log.info("review tenant=%s alert=%s recipients %d, languages %s by=%s", self.tenant, a["id"], len(chosen),
                 languages or "en", user)  # fmt: skip

    def act(self, a: dict[str, Any], user: str, action: str) -> None:
        if action == "validate":
            if a["status"] not in CAN_VALIDATE or not a.get("ready"):
                raise Denied(HTTPStatus.CONFLICT, "Not ready: choose the recipients and check every translation.")
            request = a["request"] or {}
            event = self._event("validated", a, user, to=request.get("to"), languages=request.get("languages"),
                                reference=a["reference_hash"])  # fmt: skip
        else:
            if a["status"] not in CAN_DISMISS:
                raise Denied(HTTPStatus.CONFLICT, f"Not possible: the alert is {STATUS_TEXT[a['status']]}.")
            event = self._event("dismissed", a, user)
        self.store.add_events(self.tenant, [event])
        log.info("review tenant=%s alert=%s %s by=%s", self.tenant, a["id"], event["event"], user)

    # -- pages ---------------------------------------------------------------------------------
    def page(self, title: str, body: str, user: str) -> str:
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body>"
            f'<header><a href="/">A2VM alerts — {html.escape(self.tenant)}</a>'
            f"<span>{html.escape(user)}</span></header><main>{body}</main></body></html>"
        )

    def list_page(self, user: str, status: str) -> str:
        items = self.store.alerts(self.tenant)
        if status == "todo":
            items = [a for a in items if a["status"] in ("pending", "translating", "validated", "failed")]
        elif status in STATUSES:
            items = [a for a in items if a["status"] == status]
        filters = [("todo", "To process"), *((s, STATUS_TEXT[s].capitalize()) for s in STATUSES), ("all", "All")]
        nav = "".join(
            f'<a href="/?status={s}">{"<b>" + html.escape(label) + "</b>" if s == status else html.escape(label)}</a>'
            for s, label in filters
        )
        rows = "".join(
            "<tr>"
            f"<td>{_run_date(a['run'])}</td>"
            f'<td><span class="badge {"urgent" if a.get("level") == "urgent" else ""}">'
            f"{html.escape(a.get('level', ''))}</span></td>"
            f'<td><a href="/alerts/{quote(a["id"], safe="")}">{html.escape(a.get("title", a["id"]))}</a></td>'
            f"<td>{html.escape(', '.join((a.get('cves') or [])[:4]))}</td>"
            f'<td><span class="badge {a["status"]}">{STATUS_TEXT[a["status"]]}</span>'
            f"{' · enriched' if a.get('edited') else ''}</td>"
            "</tr>"
            for a in items[:300]
        )
        table = (
            '<table class="list"><tr><th>Date</th><th>Level</th><th>Alert</th><th>CVE</th><th>Status</th></tr>'
            f"{rows}</table>"
            if rows
            else '<p class="note">No alert.</p>'
        )
        return self.page("Alerts", f"<nav>{nav}</nav><p></p>{table}", user)

    def _form(self, action: str, tok: str, label: str, primary: bool = False, extra: str = "") -> str:
        cls = ' class="primary"' if primary else ""
        return (
            f'<form method="post" action="{action}"><input type="hidden" name="token" value="{tok}">'
            f"{extra}<button{cls}>{html.escape(label)}</button></form>"
        )

    def alert_page(self, user: str, validator: bool, a: dict[str, Any], error: str = "") -> str:
        aid = a["id"]
        q = quote(aid, safe="")
        tok = self.token(user, aid)
        events = "".join(
            f"<li>{html.escape(str(e.get('at', ''))[:16].replace('T', ' '))} — "
            f"{html.escape(EVENT_TEXT.get(e.get('event', ''), e.get('event', '')))}"
            f"{' (' + html.escape(language_name(e['language'])) + ')' if e.get('language') else ''}"
            f"{' by ' + html.escape(e['by']) if e.get('by') else ''}"
            f"{' to ' + html.escape(', '.join(e['to'])) if e.get('to') else ''}"
            f"{': ' + html.escape(str(e['error'])[:200]) if e.get('error') else ''}</li>"
            for e in a.get("events", [])
        )
        err = f'<p class="error">{html.escape(error)}</p>' if error else ""
        head = (
            f"<h1>{html.escape(a.get('title', aid))}</h1>"
            f'<p><span class="badge {a["status"]}">{STATUS_TEXT[a["status"]]}</span> '
            f"level {html.escape(a.get('level', ''))} · {html.escape(', '.join(a.get('cves') or []))}"
            f"{' · reference enriched' if a.get('edited') else ''}</p>{err}"
        )
        if not validator:
            steps = '<p class="note">Read only: enrichment, translation and validation are for the validators.</p>'
        else:
            steps = self._steps(a, q, tok)
        word = ""
        if a.get("docx"):
            word = (
                '<p class="note">The Word file is filled from the facts and from the title, main impact and '
                "description of the sheet validated in each language.</p>"
            )
        body = (
            f"{head}{steps}{word}<h2>Reference (English)</h2>"
            f'<div class="sheet">{markdown_html(self.current(a))}</div>'
            f"{self._translations(a)}<h2>History</h2><ul>{events}</ul>"
        )
        return self.page(a.get("title", aid), body, user)

    def _steps(self, a: dict[str, Any], q: str, tok: str) -> str:
        status = a["status"]
        parts = []
        if status in CAN_EDIT:
            parts.append(f'<a href="/alerts/{q}/edit"><button type="button">1. Enrich the reference</button></a>')
        actions = f'<div class="actions">{"".join(parts)}</div>'
        if status in CAN_PREPARE:
            chosen = {e.lower() for e in ((a.get("request") or {}).get("to") or [])}
            boxes = (
                "".join(
                    f'<label><input type="checkbox" name="to" value="{html.escape(c.email)}"'
                    f"{' checked' if not chosen or c.email.lower() in chosen else ''}> {html.escape(c.label())} "
                    f"&lt;{html.escape(c.email)}&gt; — {html.escape(language_name(c.language))}</label>"
                    for c in self.eligible(a)
                )
                or '<p class="note">No contact receives this level of alert (contacts.yaml).</p>'
            )
            actions += (
                '<div class="box"><b>2. Recipients</b> — a translation is prepared for each language other than '
                f'English.<form method="post" action="/alerts/{q}/prepare"><input type="hidden" name="token" '
                f'value="{tok}">{boxes}<p><button>Choose these recipients and translate</button></p></form></div>'
            )
        if status in CAN_VALIDATE:
            ready = a.get("ready")
            note = (
                "Every translation is checked against the current reference."
                if ready
                else "Waiting: each translation must be ready (refresh the page)."
            )
            to = ", ".join((a.get("request") or {}).get("to") or [])
            actions += (
                f'<div class="box"><b>3. Validate</b> — to {html.escape(to)}. <span class="note">{note}</span>'
                + (self._form(f"/alerts/{q}/validate", tok, "Validate and send", primary=True) if ready else "")
                + "</div>"
            )
        if status == "validated":
            actions += '<p class="note">Sent within a minute by the sender.</p>'
        if status in CAN_DISMISS:
            actions += f'<div class="actions">{self._form(f"/alerts/{q}/dismiss", tok, "Dismiss")}</div>'
        return actions

    def _translations(self, a: dict[str, Any]) -> str:
        out = []
        q = quote(a["id"], safe="")
        for lang, meta in sorted((a.get("translations") or {}).items()):
            state = meta.get("state", "waiting")
            text, _ = self.store.translation(self.tenant, a["id"], lang)
            why = f" — {html.escape(meta.get('error', ''))}" if state == "failed" else ""
            source = f" · {html.escape(meta.get('source', ''))}" if meta.get("source") else ""
            edit = (
                f' <a href="/alerts/{q}/translations/{lang}/edit">correct or write it</a>'
                if a["status"] == "translating" and state in ("fresh", "failed")
                else ""
            )
            out.append(
                f"<h2>{html.escape(language_name(lang))}</h2>"
                f'<p><span class="badge {state}">{STATE_TEXT[state]}</span>{why}{source}{edit}</p>'
                + (f'<div class="sheet">{markdown_html(text)}</div>' if text and state != "failed" else "")
            )
        return "".join(out)

    def edit_page(self, user: str, a: dict[str, Any], text: str | None = None, error: str = "", lang: str = "") -> str:
        q = quote(a["id"], safe="")
        action = f"/alerts/{q}/translations/{lang}/edit" if lang else f"/alerts/{q}/edit"
        if text is None:
            text = (
                (self.store.translation(self.tenant, a["id"], lang)[0] or self.current(a))
                if lang
                else (self.current(a))
            )
        what = f"translation into {language_name(lang)}" if lang else "English reference"
        err = f'<p class="error">{html.escape(error)}</p>' if error else ""
        body = (
            f"<h1>{html.escape(what.capitalize())}: {html.escape(a.get('title', a['id']))}</h1>{err}"
            '<p class="note">The watch\'s format: "# title", "## section", "- " lists, "|" tables. '
            "No CVE the alert does not concern."
            + (" Enriching the reference outdates its translations." if not lang else "")
            + "</p>"
            f'<form method="post" action="{action}"><input type="hidden" name="token" '
            f'value="{self.token(user, a["id"])}"><textarea name="text">{html.escape(text)}</textarea>'
            f'<p><button class="primary">Save</button> <a href="/alerts/{q}">Cancel</a></p></form>'
        )
        return self.page("Edit", body, user)


def _run_date(run: str) -> str:
    return f"{run[0:4]}-{run[4:6]}-{run[6:8]} {run[9:11]}:{run[11:13]}" if len(run) >= 13 else html.escape(run)


def make_handler(review: Review) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "a2vm-via-review"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            path = urlsplit(self.path).path
            status = str(args[1]) if len(args) > 1 else ""
            if path == "/healthz" and status == "200":
                return
            log.info("%s %s %s", self.command, path, status)

        def _send(self, status: HTTPStatus, body: str = "", location: str = "") -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _denied(self, d: Denied, user: str = "") -> None:
            self._send(d.status, review.page("Access", f'<p class="error">{html.escape(d.message)}</p>', user))

        def _parts(self) -> tuple[list[str], dict[str, str]]:
            url = urlsplit(self.path)
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            return [unquote(p) for p in url.path.strip("/").split("/") if p], query

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if urlsplit(self.path).path == "/healthz":
                self._send(HTTPStatus.OK, "ok")
                return
            user = ""
            try:
                user, validator = review.who(self.headers)
                parts, query = self._parts()
                if not parts:
                    self._send(HTTPStatus.OK, review.list_page(user, query.get("status", "todo")))
                elif len(parts) == 2 and parts[0] == "alerts":
                    self._send(HTTPStatus.OK, review.alert_page(user, validator, review.alert(parts[1])))
                elif len(parts) in (3, 5) and parts[0] == "alerts" and parts[-1] == "edit":
                    if not validator:
                        raise Denied(HTTPStatus.FORBIDDEN, "Editing is for the validators.")
                    lang = parts[3] if len(parts) == 5 and parts[2] == "translations" else ""
                    if len(parts) == 5 and (not lang or not LANG.match(lang)):
                        raise Denied(HTTPStatus.NOT_FOUND, "Unknown page.")
                    self._send(HTTPStatus.OK, review.edit_page(user, review.alert(parts[1]), lang=lang))
                else:
                    raise Denied(HTTPStatus.NOT_FOUND, "Unknown page.")
            except Denied as d:
                self._denied(d, user)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", urlsplit(self.path).path)
                self._denied(Denied(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal error."), user)

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            user = ""
            try:
                user, validator = review.who(self.headers)
                parts, _ = self._parts()
                translation = len(parts) == 5 and parts[2] == "translations" and parts[4] == "edit"
                simple = len(parts) == 3 and parts[2] in ("edit", "prepare", "validate", "dismiss")
                if parts[:1] != ["alerts"] or not (translation or simple):
                    raise Denied(HTTPStatus.NOT_FOUND, "Unknown page.")
                if not validator:
                    raise Denied(HTTPStatus.FORBIDDEN, "Action for the validators only.")
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError as exc:
                    raise Denied(HTTPStatus.LENGTH_REQUIRED, "Form without a length.") from exc
                if not 0 <= length <= EDIT_MAX * 6 + 4096:
                    raise Denied(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Form too long.")
                raw = self.rfile.read(length).decode("utf-8", "replace")
                form = parse_qs(raw, keep_blank_values=True)
                a = review.alert(parts[1])
                review.check_form(self.headers, user, a["id"], form)
                q = quote(a["id"], safe="")
                text = (form.get("text") or [""])[0]
                try:
                    if translation:
                        if not LANG.match(parts[3]):
                            raise Denied(HTTPStatus.NOT_FOUND, "Unknown page.")
                        review.save_translation(a, user, parts[3], text)
                    elif parts[2] == "edit":
                        review.save_edit(a, user, text)
                    elif parts[2] == "prepare":
                        review.prepare(a, user, form.get("to") or [])
                    else:
                        review.act(a, user, parts[2])
                except ValueError as exc:
                    if parts[2] == "prepare":
                        page = review.alert_page(user, validator, a, str(exc))
                    else:
                        page = review.edit_page(user, a, text, str(exc), lang=parts[3] if translation else "")
                    self._send(HTTPStatus.UNPROCESSABLE_ENTITY, page)
                    return
                self._send(HTTPStatus.SEE_OTHER, location=f"/alerts/{q}")
            except Denied as d:
                self._denied(d, user)
            except Exception:  # noqa: BLE001
                log.exception("POST %s failed", urlsplit(self.path).path)
                self._denied(Denied(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal error."), user)

    return Handler


__all__ = ["Denied", "Review", "make_handler", "text_hash"]
