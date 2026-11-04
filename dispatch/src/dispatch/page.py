# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The page of the requests for remediation (LLD dispatch §3.2, D18).

A dashboard's link "Remediate" opens `/remediate?asset=...&level=...`. The page is served on a port
of its own, reached only through oauth2-proxy, which signs the person in with the tenant's identity
provider and passes who it is (X-Forwarded-Email or X-Forwarded-User, X-Forwarded-Groups); the
NetworkPolicy lets only the proxy reach this port, so these headers are trusted here only.

  GET   what would be sent: the tickets of the selection, by the grouping of the tickets; nothing
        is written. Shown only to a member of a group of `remediators`.
  POST  the chosen tickets sent (or proposed in dry-run), the request recorded with who asked.
        The form carries a token bound to the person, the selection and the run (HMAC), and must
        come from the page's own origin; a newer run in between: nothing sent, the page again.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
from http import HTTPStatus
from typing import Any
from urllib.parse import urlencode, urlsplit

from .engine import REQUEST_FILTERS, Dispatcher, DispatchError

STATUS_TEXT = {
    "new": "new ticket",
    "proposed": "proposed (dry run), not sent yet",
    "sent": "already sent",
    "in-progress": "already sent, in progress",
    "claimed-fixed": "closed in the tool, still seen by the scans",
}


class Denied(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _groups(value: str) -> set[str]:
    return {g.strip().lstrip("/") for g in value.split(",") if g.strip()}


class RequestPage:
    def __init__(self, tenant: str, key: bytes, remediators: set[str], public_url: str):
        if len(key) < 32:
            raise ValueError("page key: 32 bytes at least")
        if not remediators:
            raise ValueError("page: a group of remediators is required")
        u = urlsplit(public_url)
        if u.scheme != "https" or not u.netloc:
            raise ValueError("page: public URL https://<host> expected")
        self.tenant = tenant
        self.key = key
        self.remediators = remediators
        self.origin = f"{u.scheme}://{u.netloc}"

    # -- who ---------------------------------------------------------------------------------------
    def who(self, headers: Any) -> str:
        user = (headers.get("X-Forwarded-Email") or headers.get("X-Forwarded-User") or "").strip()
        if not user:
            raise Denied(HTTPStatus.UNAUTHORIZED, "Sign-in required.")
        if not _groups(headers.get("X-Forwarded-Groups") or "") & self.remediators:
            raise Denied(HTTPStatus.FORBIDDEN, "Your account may not ask for remediation for this tenant.")
        return user[:200]

    def token(self, user: str, filters: dict[str, str], run_id: str) -> str:
        msg = json.dumps([user, sorted(filters.items()), run_id], ensure_ascii=False)
        return hmac.new(self.key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def check_form(self, headers: Any, user: str, filters: dict[str, str], run_id: str, form: dict) -> None:
        origin = headers.get("Origin") or ""
        referer = headers.get("Referer") or ""
        if origin != self.origin and not (not origin and referer.startswith(self.origin + "/")):
            raise Denied(HTTPStatus.FORBIDDEN, "Form refused: it does not come from this page.")
        if not hmac.compare_digest((form.get("token") or [""])[0], self.token(user, filters, run_id)):
            raise Denied(HTTPStatus.FORBIDDEN, "Form refused: invalid token, reload the page.")

    # -- pages -------------------------------------------------------------------------------------
    @staticmethod
    def query_of(form_or_query: dict[str, list[str]]) -> dict[str, str]:
        return {k: v[0] for k, v in form_or_query.items() if k in REQUEST_FILTERS and v and v[0].strip()}

    def get(self, d: Dispatcher, headers: Any, query: dict[str, list[str]]) -> str:
        user = self.who(headers)
        try:
            view = d.preview(self.query_of(query), (query.get("target") or [None])[0])
        except DispatchError as exc:
            return _page("Remediation", f"<p class='err'>{html.escape(str(exc))}</p>")
        return self._view(d, user, view)

    def post(self, d: Dispatcher, headers: Any, form: dict[str, list[str]]) -> str:
        user = self.who(headers)
        query = self.query_of(form)
        filters = d.selection(query)
        run_id = (form.get("run") or [""])[0]
        self.check_form(headers, user, filters, run_id, form)
        try:
            out = d.confirm(
                query,
                form.get("key") or [],
                user,
                target=(form.get("target") or [None])[0],
                comment=(form.get("comment") or [""])[0],
                run_id=run_id,
            )
        except DispatchError as exc:
            return _page("Remediation", f"<p class='err'>{html.escape(str(exc))}</p>")
        if out["changed"]:
            note = "A newer run arrived: nothing was sent. Check the tickets again."
            return self._view(d, user, out["view"], note=note)
        if not out["results"]:
            return self._view(d, user, out["view"], note="No ticket chosen: nothing was sent.")
        rows = []
        for r in out["results"]:
            ref = r["ref"] or "—"
            link = f"<a href='{html.escape(r['url'])}'>{html.escape(ref)}</a>" if r["url"] else html.escape(ref)
            err = f" <span class='err'>{html.escape(r['error'])}</span>" if r["error"] else ""
            rows.append(
                f"<tr><td>{html.escape(r['key'])}</td><td>{html.escape(r['state'])}</td><td>{link}{err}</td></tr>"
            )
        mode = "<p class='warn'>Dry run: nothing was sent to the tool.</p>" if out.get("mode") != "live" else ""
        body = (
            f"{mode}<p>Recorded, asked by {html.escape(user)}.</p>"
            "<table><tr><th>Ticket</th><th>State</th><th>Reference</th></tr>" + "".join(rows) + "</table>"
            f"<p><a href='/remediate?{html.escape(urlencode(query))}'>Back to the selection</a></p>"
        )
        return _page("Remediation requested", body)

    def _view(self, d: Dispatcher, user: str, view: dict[str, Any], note: str = "") -> str:
        e = html.escape
        filters = view["filters"]
        run = view.get("run") or {}
        shown = ", ".join(f"{k} = {v}" for k, v in filters.items()) or "everything"
        parts = [f"<p>Selection: <b>{e(shown)}</b>, run {e(run.get('generated_at', '—'))}.</p>"]
        if note:
            parts.append(f"<p class='warn'>{e(note)}</p>")
        if d.rules.mode != "live":
            parts.append("<p class='warn'>Dry run: the tickets are proposed and recorded, none reaches the tool.</p>")
        if view.get("excluded"):
            parts.append(f"<p>{view['excluded']} decision(s) left out: their zone is not dispatched.</p>")
        if view.get("capped"):
            parts.append(
                f"<p class='warn'>{view['total']} tickets: only the first {len(view['tickets'])} are shown."
                " Narrow the selection.</p>"
            )
        if not view["tickets"]:
            parts.append("<p>Nothing to send for this selection.</p>")
            return _page("Remediation", "".join(parts))
        rows = []
        for t in view["tickets"]:
            sendable = t["status"] in ("new", "proposed")
            box = f"<input type='checkbox' name='key' value='{e(t['key'])}'{' checked' if sendable else ''}>"
            ref = f" <a href='{e(t['url'])}'>{e(t['ref'])}</a>" if t["url"] else (f" {e(t['ref'])}" if t["ref"] else "")
            cves = ", ".join(t["cves"][:12]) + (f" (+{len(t['cves']) - 12})" if len(t["cves"]) > 12 else "")
            rows.append(
                f"<tr><td>{box}</td><td>{e(t['asset_name'])}</td><td>{e(t['fix'])}</td>"
                f"<td>{e(t['level'])}{(' ' + e(t['priority'])) if t.get('priority') else ''}</td>"
                f"<td>{e(t['due'] or '')}</td><td>{e(cves)}</td>"
                f"<td>{e(STATUS_TEXT.get(t['status'], t['status']))}{ref}</td></tr>"
            )
        hidden = "".join(f"<input type='hidden' name='{e(k)}' value='{e(v)}'>" for k, v in filters.items())
        targets = "".join(
            f"<option value='{e(name)}'{' selected' if name == view['target'] else ''}>{e(name)}</option>"
            for name in d.rules.request_targets
        )
        token = self.token(user, filters, run.get("id", ""))
        button = "Record the request (dry run)" if d.rules.mode != "live" else "Send the tickets"
        parts.append(
            "<form method='post' action='/remediate'>"
            f"{hidden}<input type='hidden' name='run' value='{e(run.get('id', ''))}'>"
            f"<input type='hidden' name='token' value='{token}'>"
            "<table><tr><th></th><th>Asset</th><th>Fix</th><th>Level</th><th>Due</th><th>CVEs</th><th>State</th></tr>"
            + "".join(rows)
            + "</table>"
            f"<p><label>To <select name='target'>{targets}</select></label></p>"
            "<p><label>Comment for the team<br><textarea name='comment' rows='3' cols='80' maxlength='2000'>"
            "</textarea></label></p>"
            f"<p><button type='submit'>{button}</button> as {e(user)}</p></form>"
        )
        return _page("Remediation", "".join(parts))


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)} — A2VM</title><style>"
        "body{font-family:system-ui,sans-serif;margin:1.5rem;max-width:72rem;color:#1d2433}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border-bottom:1px solid #d7dbe3;padding:.35rem;text-align:left;vertical-align:top;font-size:.92rem}"
        ".warn{background:#fff4d6;padding:.5rem}.err{color:#a4161a}"
        "button{padding:.45rem 1rem}"
        "</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}</body></html>"
    )
