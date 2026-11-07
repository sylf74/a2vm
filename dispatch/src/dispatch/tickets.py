# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Tickets of remediation (LLD dispatch §2.1): one per asset and fix, with the decisions it clears.

A decision is cleared by the fixes the scanners reported for it (`<package> <fixed version>`); it
goes to one ticket only: the fix of its asset that clears the most ACT, then ATTEND, then KEV,
then by name. Decisions without a known fix make one ticket per asset, `no known fix`. The key of
a ticket is stable from run to run: `<asset id> / <fix>`.

The title and the text come from templates; the facts from the decisions (D11: no LLM here).
"""

from __future__ import annotations

import hashlib
import html
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

LEVEL_RANK = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
NO_FIX = "no known fix"
STATES = ("proposed", "sent", "in-progress", "claimed-fixed", "fixed", "dropped", "lost")
OPEN_STATES = ("sent", "in-progress", "claimed-fixed")
UNSENT_STATES = ("proposed", "fixed", "dropped", "lost")  # a ticket in these is (re)created when wanted


@dataclass
class Finding:
    id: str
    cve: str
    level: str
    kev: bool = False
    epss: float | None = None
    cvss: float | None = None
    due: str | None = None
    product: str = ""
    title: str = ""
    state: str = "open"  # open, fixed (closed by a scan), unverified, gone (absent, not dispatched again)
    fixed_at: str | None = None
    # The client's SLA (v0.21.0, D19): `due` is its SLA due date when the decision has a priority, else
    # the BOD 26-04 one, which `bod_due` always keeps.
    priority: str = ""
    priority_rank: int | None = None
    bod_due: str | None = None

    @classmethod
    def from_decision(cls, d: dict[str, Any]) -> Finding:
        return cls(
            id=d["id"],
            cve=d["cve"],
            level=d["level"],
            kev=bool(d.get("kev")),
            epss=d.get("epss"),
            cvss=d.get("cvss"),
            due=deadline(d),
            product=d.get("product") or "",
            title=d.get("title") or "",
            priority=d.get("priority") or "",
            priority_rank=d.get("priority_rank"),
            bod_due=d.get("due_date"),
        )

    def refresh(self, d: dict[str, Any]) -> None:
        """Bring the finding up to date with a decision of a newer run."""
        self.level, self.due, self.kev, self.epss = d["level"], deadline(d), bool(d.get("kev")), d.get("epss")
        self.priority, self.priority_rank, self.bod_due = (
            d.get("priority") or "",
            d.get("priority_rank"),
            d.get("due_date"),
        )


def deadline(d: dict[str, Any]) -> str | None:
    """The due date a decision must meet: its SLA due date when it has a priority, else BOD 26-04."""
    return d.get("sla_due") if d.get("priority") and d.get("sla_due") else d.get("due_date")


@dataclass
class Ticket:
    key: str
    asset: str
    asset_name: str
    fix: str
    target: str
    findings: dict[str, Finding] = field(default_factory=dict)
    zone: str = ""
    cmdb: dict[str, Any] = field(default_factory=dict)  # {class, key} of the CMDB item, when known
    origin: str = "rule"  # rule | request
    requested_by: str = ""
    requested_at: str = ""
    comment: str = ""
    state: str = "proposed"
    external: dict[str, str] = field(default_factory=dict)  # {ref, url, status}
    created_at: str = ""
    updated_at: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    # v0.22.2: the date the team resolved the ticket in the ITSM (a declaration, verified by a scan
    # before it counts), and the due date last written into the ticket.
    declared_fixed_at: str = ""
    due_pushed: str = ""

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings.values() if f.state in ("open", "unverified")]

    @property
    def level(self) -> str:
        levels = [f.level for f in self.open_findings] or [f.level for f in self.findings.values()]
        return min(levels, key=lambda lv: LEVEL_RANK.get(lv, 9)) if levels else "TRACK"

    @property
    def due(self) -> str | None:
        dues = sorted(f.due for f in self.open_findings if f.due)
        return dues[0] if dues else None

    @property
    def priority(self) -> str:
        """The most urgent priority of the client's SLA among the open findings; "" without one."""
        ranked = [f for f in self.open_findings if f.priority] or [f for f in self.findings.values() if f.priority]
        if not ranked:
            return ""
        return min(
            ranked, key=lambda f: (f.priority_rank if f.priority_rank is not None else 9999, f.priority)
        ).priority

    @property
    def bod_due(self) -> str | None:
        dues = sorted(f.bod_due for f in self.open_findings if f.bod_due)
        return dues[0] if dues else None

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_STATES

    def event(self, at: str, what: str, **extra: Any) -> None:
        self.history.append({"at": at, "what": what, **extra})
        del self.history[:-100]  # the last 100 events
        self.updated_at = at

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["findings"] = [asdict(f) for f in self.findings.values()]
        out["level"] = self.level
        out["due"] = self.due
        out["priority"] = self.priority
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Ticket:
        d = dict(data)
        d.pop("level", None)
        d.pop("due", None)
        d.pop("priority", None)
        findings = {f["id"]: Finding(**f) for f in d.pop("findings", [])}
        return cls(**d, findings=findings)


def ticket_key(asset: str, fix: str) -> str:
    return f"{asset} / {fix}"


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def assign_fixes(decisions: list[dict[str, Any]]) -> dict[str, str]:
    """Decision id -> the fix of its ticket, per asset (see the module's docstring)."""
    by_asset: dict[str, list[dict[str, Any]]] = {}
    for d in decisions:
        by_asset.setdefault(d["asset"], []).append(d)
    out: dict[str, str] = {}
    for rows in by_asset.values():
        groups: dict[str, list[dict[str, Any]]] = {}
        for d in rows:
            for fix in d.get("fixes") or []:
                groups.setdefault(fix, []).append(d)

        def weight(fix: str, groups: dict[str, list[dict[str, Any]]] = groups) -> tuple:
            counts = Counter(d["level"] for d in groups[fix])
            kev = sum(1 for d in groups[fix] if d.get("kev"))
            return (-counts["ACT"], -counts["ATTEND"], -kev, fix)

        order = sorted(groups, key=weight)
        for d in rows:
            fixes = set(d.get("fixes") or [])
            out[d["id"]] = next((f for f in order if f in fixes), NO_FIX)
    return out


def build(
    decisions: list[dict[str, Any]],
    target: str,
    cards: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Ticket]:
    """The tickets of these decisions, by key; `cards`: asset id -> its card (`cmdb`), when read."""
    cards = cards or {}
    fixes = assign_fixes(decisions)
    out: dict[str, Ticket] = {}
    for d in decisions:
        fix = fixes[d["id"]]
        key = ticket_key(d["asset"], fix)
        t = out.get(key)
        if t is None:
            items = (cards.get(d["asset"]) or {}).get("cmdb") or []
            item = items[0] if items else {}
            t = out[key] = Ticket(
                key=key,
                asset=d["asset"],
                asset_name=d.get("asset_name") or d["asset"],
                fix=fix,
                target=target,
                zone=d.get("zone") or "",
                cmdb={k: item[k] for k in ("class", "key") if item.get(k)},
            )
        t.findings[d["id"]] = Finding.from_decision(d)
    return out


# -- texts -------------------------------------------------------------------------------------
def title(t: Ticket) -> str:
    what = f"apply {t.fix}" if t.fix != NO_FIX else "mitigate, no known fix"
    cves = len(t.open_findings) or len(t.findings)
    tag = f"{t.level} {t.priority}" if t.priority else t.level
    return f"[A2VM {tag}] {t.asset_name}: {what} ({cves} CVE{'s' if cves > 1 else ''})"[:250]


def description(t: Ticket, base_url: str = "") -> str:
    """The ticket's text (HTML, which iTop and ServiceNow render)."""
    e = html.escape
    rows = sorted(t.findings.values(), key=lambda f: (LEVEL_RANK.get(f.level, 9), f.due or "9999", f.cve))
    if t.priority:  # the client's SLA (v0.21.0)
        due = (
            f"<br><b>Priority</b>: {e(t.priority)}<br><b>Due date</b> (SLA): {e(t.due or 'none')}"
            f"<br><b>Due date</b> (BOD 26-04, for comparison): {e(t.bod_due or 'none')}"
        )
    else:
        due = f"<br><b>Due date</b> (BOD 26-04): {e(t.due or 'none')}"
    lines = [
        f"<p><b>Asset</b>: {e(t.asset)}<br><b>Fix</b>: {e(t.fix)}<br><b>Level</b>: {e(t.level)}{due}</p>",
        "<p>This ticket was opened by A2VM"
        + (f" at the request of {e(t.requested_by)}" if t.origin == "request" and t.requested_by else "")
        + ". It is closed when a new scan no longer sees these vulnerabilities: closing it here does not"
        " close them in A2VM.</p>",
    ]
    if t.comment:
        lines.append(f"<p><b>Comment</b>: {e(t.comment)}</p>")
    lines.append(
        "<table><tr><th>CVE</th><th>Level</th>"
        + ("<th>Priority</th>" if t.priority else "")
        + "<th>KEV</th><th>EPSS</th><th>CVSS</th><th>Due</th><th>Product</th><th>State</th></tr>"
    )
    for f in rows:
        lines.append(
            f"<tr><td>{e(f.cve)}</td><td>{e(f.level)}</td>"
            + (f"<td>{e(f.priority)}</td>" if t.priority else "")
            + f"<td>{'yes' if f.kev else ''}</td>"
            f"<td>{'' if f.epss is None else f'{f.epss:.3f}'}</td><td>{'' if f.cvss is None else f.cvss}</td>"
            f"<td>{e(f.due or '')}</td><td>{e(f.product)}</td><td>{e(f.state)}</td></tr>"
        )
    lines.append("</table>")
    if base_url:
        lines.append(f"<p>Details: {e(base_url)}</p>")
    return "\n".join(lines)
