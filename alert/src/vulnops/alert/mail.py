# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Send mail, configured by CI/CD variables. Set on the group, they apply to every client; set on a
client project, they override the group's for that client (e.g. one client through its own tenant).

  VULNOPS_MAIL_TRANSPORT   smtp (default) | graph
  VULNOPS_MAIL_FROM        sender address (and display name)

  smtp:  VULNOPS_SMTP_HOST, VULNOPS_SMTP_PORT (587), VULNOPS_SMTP_TLS (starttls | ssl | none),
         VULNOPS_SMTP_USER, VULNOPS_SMTP_PASSWORD
  graph: Microsoft 365 through Microsoft Graph (sendMail), with an app registration that has the
         Mail.Send application permission, restricted to the sending mailbox:
         VULNOPS_GRAPH_TENANT_ID, VULNOPS_GRAPH_CLIENT_ID, VULNOPS_GRAPH_CLIENT_SECRET,
         VULNOPS_GRAPH_SENDER (mailbox that sends, e.g. veille@client-or-provider.example)

Without VULNOPS_SMTP_HOST (smtp) nothing is sent: the message is written as a .eml file (dry run).
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path

import httpx


class MailError(RuntimeError):
    pass


def message(subject: str, html: str, text: str, to: list[str], sender: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender or os.environ.get("VULNOPS_MAIL_FROM", "vulnops@localhost")
    msg["To"] = ", ".join(to)
    msg["Message-ID"] = make_msgid(domain=msg["From"].split("@")[-1].strip("> "))
    msg.set_content(text)
    msg.add_alternative(f"<!doctype html><html><body>{html}</body></html>", subtype="html")
    return msg


GRAPH_LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SEND = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"


def _graph_send(msg: EmailMessage, transport: httpx.BaseTransport | None = None) -> str:
    env = {k: os.environ.get(f"VULNOPS_GRAPH_{k}", "") for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "SENDER")}
    missing = [f"VULNOPS_GRAPH_{k}" for k, v in env.items() if not v]
    if missing:
        raise MailError("missing " + ", ".join(missing))
    html_part = msg.get_body(("html",))
    text_part = msg.get_body(("plain",))
    body = html_part.get_content() if html_part else (text_part.get_content() if text_part else "")
    recipients = [{"emailAddress": {"address": a.strip()}} for a in str(msg["To"]).split(",") if a.strip()]
    payload = {
        "message": {
            "subject": str(msg["Subject"]),
            "body": {"contentType": "HTML" if html_part else "Text", "content": body},
            "toRecipients": recipients,
        },
        "saveToSentItems": True,
    }
    try:
        with httpx.Client(timeout=30, transport=transport) as client:
            token = client.post(
                GRAPH_LOGIN.format(tenant=env["TENANT_ID"]),
                data={
                    "grant_type": "client_credentials",
                    "client_id": env["CLIENT_ID"],
                    "client_secret": env["CLIENT_SECRET"],
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            if token.status_code != 200:
                raise MailError(f"Microsoft login: HTTP {token.status_code} {token.text[:200]}")
            resp = client.post(
                GRAPH_SEND.format(sender=env["SENDER"]),
                json=payload,
                headers={"Authorization": f"Bearer {token.json()['access_token']}"},
            )
    except httpx.HTTPError as exc:
        raise MailError(f"Microsoft Graph: {exc}") from exc
    if resp.status_code != 202:
        raise MailError(f"Microsoft Graph sendMail: HTTP {resp.status_code} {resp.text[:300]}")
    return f"sent to {msg['To']} (Microsoft Graph, from {env['SENDER']})"


def send(msg: EmailMessage, dry_run_dir: str | Path | None = None, transport: httpx.BaseTransport | None = None) -> str:
    """Send `msg`; return a short description of what happened."""
    if os.environ.get("VULNOPS_MAIL_TRANSPORT", "smtp").lower() == "graph":
        return _graph_send(msg, transport)
    host = os.environ.get("VULNOPS_SMTP_HOST", "")
    if not host:
        if dry_run_dir is None:
            raise MailError("VULNOPS_SMTP_HOST is not set")
        path = Path(dry_run_dir) / (msg["Message-ID"].strip("<>").split("@")[0] + ".eml")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(msg))
        return f"not sent (no VULNOPS_SMTP_HOST): written to {path}"
    port = int(os.environ.get("VULNOPS_SMTP_PORT", "587"))
    mode = os.environ.get("VULNOPS_SMTP_TLS", "starttls").lower()
    user, password = os.environ.get("VULNOPS_SMTP_USER", ""), os.environ.get("VULNOPS_SMTP_PASSWORD", "")
    context = ssl.create_default_context()
    try:
        if mode == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, context=context, timeout=30)
        else:
            server = smtplib.SMTP(host, port, timeout=30)
            if mode == "starttls":
                server.starttls(context=context)
        with server:
            if user:
                server.login(user, password)
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"SMTP {host}:{port}: {exc}") from exc
    return f"sent to {msg['To']}"
