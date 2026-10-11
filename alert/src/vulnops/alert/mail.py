"""Send mail through an SMTP relay configured by CI/CD variables.

  VULNOPS_SMTP_HOST, VULNOPS_SMTP_PORT (587), VULNOPS_SMTP_TLS (starttls | ssl | none),
  VULNOPS_SMTP_USER, VULNOPS_SMTP_PASSWORD, VULNOPS_MAIL_FROM

Without VULNOPS_SMTP_HOST nothing is sent: the message is written as a .eml file instead (dry run).
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path


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


def send(msg: EmailMessage, dry_run_dir: str | Path | None = None) -> str:
    """Send `msg`; return a short description of what happened."""
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
