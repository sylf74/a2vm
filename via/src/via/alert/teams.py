# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The analysts' Teams channel (v0.22.0): each alert to validate is also posted to a Teams webhook.

The webhook's address is a secret (it carries its signature): the file named by
NGVM_TEAMS_WEBHOOK_FILE (Kubernetes: a key of the tenant's secret), or the masked CI/CD variable
NGVM_TEAMS_WEBHOOK (GitLab). Without either, nothing is posted. The message is an Adaptive Card,
which both the Workflows of Teams ("When a Teams webhook request is received") and the older
incoming webhooks accept: the level, the title, the CVE ids, the tenant, and a button to the review
page (or the pipeline). It carries no sheet: the analysts read and validate on the page.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from ngvm.config import env

TIMEOUT = 20.0


class TeamsError(RuntimeError):
    pass


def webhook() -> str:
    path = env("TEAMS_WEBHOOK_FILE")
    if path and Path(path).exists():  # Kubernetes: an optional key of the tenant's secret
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise TeamsError(f"Teams webhook: {exc}") from exc
    return env("TEAMS_WEBHOOK").strip()


def card(profile: Any, alert: dict[str, Any], number: int, total: int, link: str) -> dict[str, Any]:
    level = str(alert.get("level", "")).upper()
    facts = [{"title": "Tenant", "value": profile.id}, {"title": "Level", "value": level or "-"}]
    if alert.get("cves"):
        facts.append({"title": "CVE", "value": ", ".join(alert["cves"][:8])})
    radar = alert.get("radar") or {}
    if radar:
        facts.append({"title": "Magnitude", "value": str(radar.get("score", ""))})
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": f"NGVM — alert {number}/{total} to validate", "weight": "Bolder",
         "color": "Attention" if level == "URGENT" else "Default"},
        {"type": "TextBlock", "text": str(alert.get("title", ""))[:300], "wrap": True, "size": "Medium"},
        {"type": "FactSet", "facts": facts},
    ]  # fmt: skip
    content: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if link:
        content["actions"] = [{"type": "Action.OpenUrl", "title": "Open the alert", "url": link}]
    return {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}],
    }


def notify(
    profile: Any,
    alert: dict[str, Any],
    number: int,
    total: int,
    link: str,
    transport: httpx.BaseTransport | None = None,
) -> str:
    """Post one alert; "" when no webhook is set. Raises TeamsError."""
    url = webhook()
    if not url:
        return ""
    if not url.startswith("https://"):
        raise TeamsError("Teams webhook: an https:// address expected")
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
            r = c.post(url, json=card(profile, alert, number, total, link))
    except httpx.HTTPError as exc:
        raise TeamsError(f"Teams webhook unreachable ({type(exc).__name__})") from None  # never its address
    if r.status_code >= 300:
        raise TeamsError(f"Teams webhook answered {r.status_code}")
    return f"posted to Teams ({r.status_code})"
