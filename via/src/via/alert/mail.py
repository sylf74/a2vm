# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Send mail, configured by CI/CD variables. Set on the group, they apply to every client; set on a
client project, they override the group's for that client (e.g. one client through its own tenant).

  NGVM_MAIL_TRANSPORT   smtp (default) | graph
  NGVM_MAIL_FROM        sender address (and display name)

  smtp:  NGVM_SMTP_HOST, NGVM_SMTP_PORT (587), NGVM_SMTP_TLS (starttls | ssl | none),
         NGVM_SMTP_USER, NGVM_SMTP_PASSWORD
  graph: Microsoft 365 through Microsoft Graph (sendMail), with an app registration that has the
         Mail.Send application permission, restricted to the sending mailbox:
         NGVM_GRAPH_TENANT_ID, NGVM_GRAPH_CLIENT_ID, NGVM_GRAPH_CLIENT_SECRET,
         NGVM_GRAPH_SENDER (mailbox that sends, e.g. veille@client-or-provider.example)

Without NGVM_SMTP_HOST (smtp) nothing is sent: the message is written as a .eml file (dry run).
"""

from __future__ import annotations

import base64
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path

import httpx

from ngvm.config import env


class MailError(RuntimeError):
    pass


TYPES = {
    ".docx": ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".pdf": ("application", "pdf"),
}


def message(
    subject: str,
    html: str,
    text: str,
    to: list[str],
    sender: str | None = None,
    attachments: list[Path] | None = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender or env("MAIL_FROM", "ngvm@localhost")
    msg["To"] = ", ".join(to)
    msg["Message-ID"] = make_msgid(domain=msg["From"].split("@")[-1].strip("> "))
    msg.set_content(text)
    msg.add_alternative(f"<!doctype html><html><body>{html}</body></html>", subtype="html")
    for path in attachments or []:
        maintype, subtype = TYPES.get(path.suffix, ("application", "octet-stream"))
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)
    return msg


GRAPH_LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SEND = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"


def _graph_send(msg: EmailMessage, transport: httpx.BaseTransport | None = None) -> str:
    graph = {k: env(f"GRAPH_{k}") for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "SENDER")}
    missing = [f"NGVM_GRAPH_{k}" for k, v in graph.items() if not v]
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
            "attachments": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": part.get_filename(),
                    "contentType": part.get_content_type(),
                    "contentBytes": base64.b64encode(part.get_content()).decode(),
                }
                for part in msg.iter_attachments()
            ],
        },
        "saveToSentItems": True,
    }
    try:
        with httpx.Client(timeout=30, transport=transport) as client:
            token = client.post(
                GRAPH_LOGIN.format(tenant=graph["TENANT_ID"]),
                data={
                    "grant_type": "client_credentials",
                    "client_id": graph["CLIENT_ID"],
                    "client_secret": graph["CLIENT_SECRET"],
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            if token.status_code != 200:
                raise MailError(f"Microsoft login: HTTP {token.status_code} {token.text[:200]}")
            resp = client.post(
                GRAPH_SEND.format(sender=graph["SENDER"]),
                json=payload,
                headers={"Authorization": f"Bearer {token.json()['access_token']}"},
            )
    except httpx.HTTPError as exc:
        raise MailError(f"Microsoft Graph: {exc}") from exc
    if resp.status_code != 202:
        raise MailError(f"Microsoft Graph sendMail: HTTP {resp.status_code} {resp.text[:300]}")
    return f"sent to {msg['To']} (Microsoft Graph, from {graph['SENDER']})"


def send(msg: EmailMessage, dry_run_dir: str | Path | None = None, transport: httpx.BaseTransport | None = None) -> str:
    """Send `msg`; return a short description of what happened."""
    if env("MAIL_TRANSPORT", "smtp").lower() == "graph":
        return _graph_send(msg, transport)
    host = env("SMTP_HOST", "")
    if not host:
        if dry_run_dir is None:
            raise MailError("NGVM_SMTP_HOST is not set")
        path = Path(dry_run_dir) / (msg["Message-ID"].strip("<>").split("@")[0] + ".eml")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(msg))
        return f"not sent (no NGVM_SMTP_HOST): written to {path}"
    port = int(env("SMTP_PORT", "587"))
    mode = env("SMTP_TLS", "starttls").lower()
    user, password = env("SMTP_USER", ""), env("SMTP_PASSWORD", "")
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
