# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The review page of the alerts (LLD vulnerability-intelligence §3.8, v0.17.0): the analysts read
the alerts of the watch, a validator corrects a sheet, validates it for sending or dismisses it.

Served by `via serve` on a port of its own (8081), reached only through oauth2-proxy, which signs the
analyst in with the tenant's identity provider (OIDC) and passes who it is: X-Forwarded-Email (or
X-Forwarded-User) and X-Forwarded-Groups. The NetworkPolicy lets only oauth2-proxy reach this port,
so these headers are trusted here and nowhere else. Rights from the groups:

  analysts     read the alerts and their sheets
  validators   also correct a sheet, validate an alert for sending, dismiss it

Nothing is sent from here: a validation is an event in the journal; the sender (`via service send
--validated`) mails the validated alerts. Every action is journaled with who did it. Forms carry a
token bound to the analyst and the alert (HMAC) and must come from the page's own origin.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from via.alert import journal
from via.alert.fiche import markdown_html

from .store import ALERT_ID, EDIT_MAX, STATUSES, WatchStore

log = logging.getLogger("via.review")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
STATUS_FR = {
    "pending": "à valider",
    "validated": "validée, en attente d'envoi",
    "dismissed": "écartée",
    "sent": "envoyée au client",
    "failed": "envoi en échec",
}
EVENT_FR = {
    "drafted": "rédigée par la veille",
    "analysts": "transmise aux analystes",
    "edited": "fiche corrigée",
    "validated": "validée pour envoi",
    "dismissed": "écartée",
    "sent": "envoyée au client",
    "send-failed": "envoi en échec",
}
CAN_VALIDATE = ("pending", "failed", "dismissed")
CAN_DISMISS = ("pending", "failed", "validated")
CAN_EDIT = ("pending", "failed", "validated", "dismissed")
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; img-src 'none'"
)
STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;color:#1a1a1a;background:#f7f7f5}
header{background:#1f2933;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;text-decoration:none;font-weight:600}
main{max-width:1100px;margin:0 auto;padding:16px 24px}
table.list{border-collapse:collapse;width:100%;background:#fff}
.list th,.list td{border-bottom:1px solid #e3e3e0;padding:8px;text-align:left;vertical-align:top;font-size:14px}
.list th{background:#eeeeea}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#e3e3e0}
.urgent{background:#fde2e1;color:#8a1c14}.validated{background:#e1effd;color:#0b4a8a}
.sent{background:#e2f5e6;color:#1d5b2c}.failed{background:#fde2e1;color:#8a1c14}.dismissed{color:#666}
.sheet{background:#fff;border:1px solid #e3e3e0;padding:16px 20px;margin:16px 0}
.actions form{display:inline-block;margin-right:8px}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer}
button.primary{background:#0b4a8a;color:#fff;border-color:#0b4a8a}
textarea{width:100%;min-height:480px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.note{color:#555;font-size:13px}.error{color:#8a1c14;font-weight:600}
nav a{margin-right:12px}
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
        analysts: set[str],
        validators: set[str],
        public_url: str,
    ):
        if len(key) < 32:
            raise ValueError("review key: 32 bytes at least")
        if not validators:
            raise ValueError("review: a validators group is required")
        self.tenant = tenant
        self.store = store
        self.key = key
        self.analysts = analysts
        self.validators = validators
        u = urlsplit(public_url)
        if u.scheme != "https" or not u.netloc:
            raise ValueError("review: public URL https://<host> expected")
        self.origin = f"{u.scheme}://{u.netloc}"

    # -- who -----------------------------------------------------------------------------------
    def who(self, headers: Any) -> tuple[str, bool]:
        """(the analyst, whether a validator); Denied when not signed in or in no group of the tenant."""
        user = (headers.get("X-Forwarded-Email") or headers.get("X-Forwarded-User") or "").strip()
        if not user:
            raise Denied(HTTPStatus.UNAUTHORIZED, "Connexion requise.")
        groups = _groups(headers.get("X-Forwarded-Groups") or "")
        validator = bool(groups & self.validators)
        if not validator and not groups & self.analysts:
            raise Denied(HTTPStatus.FORBIDDEN, "Votre compte n'appartient à aucun groupe d'analystes de ce tenant.")
        return user[:200], validator

    def token(self, user: str, alert_id: str) -> str:
        return hmac.new(self.key, f"{user}|{alert_id}".encode(), hashlib.sha256).hexdigest()

    def check_form(self, headers: Any, user: str, alert_id: str, form: dict[str, str]) -> None:
        origin = headers.get("Origin") or ""
        referer = headers.get("Referer") or ""
        if origin != self.origin and not (not origin and referer.startswith(self.origin + "/")):
            raise Denied(HTTPStatus.FORBIDDEN, "Formulaire refusé : il ne vient pas de cette page.")
        if not hmac.compare_digest(form.get("token", ""), self.token(user, alert_id)):
            raise Denied(HTTPStatus.FORBIDDEN, "Formulaire refusé : jeton invalide, rechargez la page.")

    # -- what ----------------------------------------------------------------------------------
    def alert(self, alert_id: str) -> dict[str, Any]:
        a = self.store.alert(self.tenant, alert_id) if ALERT_ID.match(alert_id) else None
        if a is None:
            raise Denied(HTTPStatus.NOT_FOUND, "Alerte inconnue (ou plus conservée).")
        return a

    def original(self, a: dict[str, Any]) -> str:
        return (self.store.file(self.tenant, a["run"], f"{a['id']}.md") or b"").decode("utf-8", "replace")

    def current(self, a: dict[str, Any]) -> str:
        return self.store.edit(self.tenant, a["id"]) or self.original(a)

    def _event(self, kind: str, a: dict[str, Any], user: str) -> dict:
        e = journal.event(kind, a, by=user)
        e.pop("pipeline", None)
        return e

    def save_edit(self, a: dict[str, Any], user: str, text: str) -> None:
        if a["status"] not in CAN_EDIT:
            raise Denied(HTTPStatus.CONFLICT, "Cette alerte est déjà envoyée : la fiche ne change plus.")
        text = text.replace("\r\n", "\n").strip() + "\n"
        if not text.strip():
            raise ValueError("La fiche est vide.")
        if len(text) > EDIT_MAX:
            raise ValueError(f"La fiche dépasse {EDIT_MAX} caractères.")
        original = self.original(a)
        foreign = sorted(set(CVE_RE.findall(text)) - set(CVE_RE.findall(original)) - set(a.get("cves") or []))
        if foreign:
            raise ValueError(f"La fiche cite {', '.join(foreign)}, que cette alerte ne concerne pas.")
        self.store.put_edit(self.tenant, a["id"], text, self._event("edited", a, user))
        log.info("review tenant=%s alert=%s edited by=%s", self.tenant, a["id"], user)

    def act(self, a: dict[str, Any], user: str, action: str) -> None:
        allowed = {"validate": CAN_VALIDATE, "dismiss": CAN_DISMISS}[action]
        if a["status"] not in allowed:
            raise Denied(HTTPStatus.CONFLICT, f"Impossible : l'alerte est {STATUS_FR[a['status']]}.")
        kind = "validated" if action == "validate" else "dismissed"
        self.store.add_events(self.tenant, [self._event(kind, a, user)])
        log.info("review tenant=%s alert=%s %s by=%s", self.tenant, a["id"], kind, user)

    # -- pages ---------------------------------------------------------------------------------
    def page(self, title: str, body: str, user: str) -> str:
        return (
            '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body>"
            f'<header><a href="/">Alertes A2VM — {html.escape(self.tenant)}</a>'
            f"<span>{html.escape(user)}</span></header><main>{body}</main></body></html>"
        )

    def list_page(self, user: str, status: str) -> str:
        items = self.store.alerts(self.tenant)
        if status == "todo":
            items = [a for a in items if a["status"] in ("pending", "validated", "failed")]
        elif status in STATUSES:
            items = [a for a in items if a["status"] == status]
        filters = [("todo", "À traiter"), *((s, STATUS_FR[s].capitalize()) for s in STATUSES), ("all", "Toutes")]
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
            f'<td><span class="badge {a["status"]}">{STATUS_FR[a["status"]]}</span>'
            f"{' · corrigée' if a.get('edited') else ''}</td>"
            "</tr>"
            for a in items[:300]
        )
        table = (
            '<table class="list"><tr><th>Date</th><th>Niveau</th><th>Alerte</th><th>CVE</th><th>Statut</th></tr>'
            f"{rows}</table>"
            if rows
            else '<p class="note">Aucune alerte.</p>'
        )
        return self.page("Alertes", f"<nav>{nav}</nav><p></p>{table}", user)

    def alert_page(self, user: str, validator: bool, a: dict[str, Any], error: str = "") -> str:
        aid = a["id"]
        q = quote(aid, safe="")
        events = "".join(
            f"<li>{html.escape(str(e.get('at', ''))[:16].replace('T', ' '))} — "
            f"{html.escape(EVENT_FR.get(e.get('event', ''), e.get('event', '')))}"
            f"{' par ' + html.escape(e['by']) if e.get('by') else ''}"
            f"{' à ' + html.escape(', '.join(e['to'])) if e.get('to') else ''}"
            f"{' : ' + html.escape(str(e['error'])[:200]) if e.get('error') else ''}</li>"
            for e in a.get("events", [])
        )
        actions = ""
        if validator:
            tok = self.token(user, aid)
            buttons = []
            if a["status"] in CAN_EDIT:
                buttons.append(f'<a href="/alerts/{q}/edit"><button type="button">Corriger la fiche</button></a>')
            if a["status"] in CAN_VALIDATE:
                buttons.append(
                    f'<form method="post" action="/alerts/{q}/validate"><input type="hidden" name="token" '
                    f'value="{tok}"><button class="primary">Valider et envoyer au client</button></form>'
                )
            if a["status"] in CAN_DISMISS:
                buttons.append(
                    f'<form method="post" action="/alerts/{q}/dismiss"><input type="hidden" name="token" '
                    f'value="{tok}"><button>Écarter</button></form>'
                )
            actions = f'<div class="actions">{"".join(buttons)}</div>'
            if a["status"] == "validated":
                actions += '<p class="note">Envoi au client dans la minute par le service d\'envoi.</p>'
        else:
            actions = '<p class="note">Lecture seule : la validation est réservée aux valideurs.</p>'
        word = ""
        if a.get("docx") and a.get("edited"):
            word = (
                '<p class="note">Le Word joint reste celui de la veille : la correction porte sur le texte du mail.</p>'
            )
        err = f'<p class="error">{html.escape(error)}</p>' if error else ""
        body = (
            f"<h1>{html.escape(a.get('title', aid))}</h1>"
            f'<p><span class="badge {a["status"]}">{STATUS_FR[a["status"]]}</span> '
            f"niveau {html.escape(a.get('level', ''))} · {html.escape(', '.join(a.get('cves') or []))}"
            f"{' · fiche corrigée' if a.get('edited') else ''}</p>{err}{actions}{word}"
            f'<div class="sheet">{markdown_html(self.current(a))}</div>'
            f"<h3>Historique</h3><ul>{events}</ul>"
        )
        return self.page(a.get("title", aid), body, user)

    def edit_page(self, user: str, a: dict[str, Any], text: str | None = None, error: str = "") -> str:
        q = quote(a["id"], safe="")
        err = f'<p class="error">{html.escape(error)}</p>' if error else ""
        body = (
            f"<h1>Corriger : {html.escape(a.get('title', a['id']))}</h1>{err}"
            '<p class="note">Format de la veille : « # titre », « ## section », listes « - », tableaux « | ». '
            "Aucune CVE que l'alerte ne concerne pas.</p>"
            f'<form method="post" action="/alerts/{q}/edit"><input type="hidden" name="token" '
            f'value="{self.token(user, a["id"])}"><textarea name="text">'
            f"{html.escape(text if text is not None else self.current(a))}</textarea>"
            f'<p><button class="primary">Enregistrer</button> <a href="/alerts/{q}">Annuler</a></p></form>'
        )
        return self.page("Corriger", body, user)


def _run_date(run: str) -> str:
    return f"{run[6:8]}/{run[4:6]}/{run[0:4]} {run[9:11]}:{run[11:13]}" if len(run) >= 13 else html.escape(run)


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
            self._send(d.status, review.page("Accès", f'<p class="error">{html.escape(d.message)}</p>', user))

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
                elif len(parts) == 3 and parts[0] == "alerts" and parts[2] == "edit":
                    if not validator:
                        raise Denied(HTTPStatus.FORBIDDEN, "La correction est réservée aux valideurs.")
                    self._send(HTTPStatus.OK, review.edit_page(user, review.alert(parts[1])))
                else:
                    raise Denied(HTTPStatus.NOT_FOUND, "Page inconnue.")
            except Denied as d:
                self._denied(d, user)
            except Exception:  # noqa: BLE001 - answer rather than drop the connection
                log.exception("GET %s failed", urlsplit(self.path).path)
                self._denied(Denied(HTTPStatus.INTERNAL_SERVER_ERROR, "Erreur interne."), user)

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            user = ""
            try:
                user, validator = review.who(self.headers)
                parts, _ = self._parts()
                if len(parts) != 3 or parts[0] != "alerts" or parts[2] not in ("edit", "validate", "dismiss"):
                    raise Denied(HTTPStatus.NOT_FOUND, "Page inconnue.")
                if not validator:
                    raise Denied(HTTPStatus.FORBIDDEN, "Action réservée aux valideurs.")
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError as exc:
                    raise Denied(HTTPStatus.LENGTH_REQUIRED, "Formulaire sans longueur.") from exc
                if not 0 <= length <= EDIT_MAX * 6 + 4096:
                    raise Denied(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Formulaire trop long.")
                raw = self.rfile.read(length).decode("utf-8", "replace")
                form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
                a = review.alert(parts[1])
                review.check_form(self.headers, user, a["id"], form)
                q = quote(a["id"], safe="")
                if parts[2] == "edit":
                    try:
                        review.save_edit(a, user, form.get("text", ""))
                    except ValueError as exc:
                        self._send(
                            HTTPStatus.UNPROCESSABLE_ENTITY, review.edit_page(user, a, form.get("text"), str(exc))
                        )
                        return
                else:
                    review.act(a, user, parts[2])
                self._send(HTTPStatus.SEE_OTHER, location=f"/alerts/{q}")
            except Denied as d:
                self._denied(d, user)
            except Exception:  # noqa: BLE001
                log.exception("POST %s failed", urlsplit(self.path).path)
                self._denied(Denied(HTTPStatus.INTERNAL_SERVER_ERROR, "Erreur interne."), user)

    return Handler
