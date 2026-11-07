# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""What pillar 4 does with a run and with a request (LLD dispatch §3).

After each run (`process_run`):
  1. the decisions the rules send by themselves (`tickets.automatic`) are grouped into tickets;
     a new ticket is sent, a known one gets the findings it did not have;
  2. every open ticket is followed: its findings closed by a scan are written into it; when none is
     left open, it is fixed (and resolved in the tool by `resolve_when_fixed`); closed in the tool
     while a finding is still seen, it is "claimed fixed" (and reopened by `reopen_when_still_seen`).

On a request of a person (`preview`, then `confirm`): the decisions of the selection, grouped the
same way, shown, then sent on confirmation, recorded with who asked.

In dry-run nothing reaches a tool: the tickets stay `proposed`, and are sent by the first run in
live mode. A2VM never takes the tool's word for a fix: only the decision service's closed findings
(a scan confirmed) close a finding.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from typing import Any

from . import tickets as tk
from .connectors import CLOSED, GONE, Connector, ConnectorError, External
from .decisions import Decisions, DecisionsError
from .rules import Rules
from .store import TicketStore

log = logging.getLogger("dispatch.engine")
REQUEST_FILTERS = ("asset", "cve", "level", "zone", "exposure", "kev", "product", "q", "overdue")
REQUEST_FILTERS += ("priority", "sla_overdue")  # the client's SLA (v0.21.0)


class DispatchError(RuntimeError):
    pass


def _today(at: str) -> str:
    return at[:10]


class Dispatcher:
    def __init__(
        self,
        tenant: str,
        rules: Rules,
        store: TicketStore,
        decisions: Decisions,
        connector_for: Callable[[str], Connector],
        clock: Callable[[], str] | None = None,
    ):
        self.tenant = tenant
        self.rules = rules
        self.store = store
        self.decisions = decisions
        self._connector_for = connector_for
        self._connectors: dict[str, Connector] = {}
        self.clock = clock or (lambda: dt.datetime.now(dt.UTC).isoformat(timespec="seconds"))

    # -- tools -------------------------------------------------------------------------------------
    def connector(self, target: str) -> Connector:
        if target not in self._connectors:
            self._connectors[target] = self._connector_for(target)
        return self._connectors[target]

    def close(self) -> None:
        for c in self._connectors.values():
            c.close()
        self._connectors.clear()

    def _send(self, t: tk.Ticket, at: str, summary: dict[str, int]) -> None:
        """Create the ticket in its tool (live), or leave it proposed (dry-run)."""
        if not self.rules.live:
            t.state = "proposed"
            summary["proposed"] += 1
            return
        try:
            ext = self.connector(t.target).create(t, tk.description(t), tk.title(t))
        except ConnectorError as exc:
            t.state, t.error = "proposed", str(exc)
            t.event(at, "send failed", error=str(exc))
            summary["errors"] += 1
            log.warning("tenant=%s ticket %r not sent: %s", self.tenant, t.key, exc)
            return
        t.external = ext.to_dict()
        if getattr(self.connector(t.target), "due_field", "") and t.due:
            t.due_pushed = t.due  # written with the ticket (v0.22.2)
        t.state, t.error = "sent", ""
        t.created_at = t.created_at or at
        t.event(at, "sent", ref=ext.ref)
        summary["sent"] += 1

    def _write(self, t: tk.Ticket, text: str, at: str, summary: dict[str, int], what: str) -> None:
        """A comment in the tool; the event is kept either way."""
        t.event(at, what, text=text)
        if not self.rules.live or not t.external.get("ref"):
            return
        try:
            self.connector(t.target).comment(External(**t.external), text)
        except ConnectorError as exc:
            t.error = str(exc)
            summary["errors"] += 1

    # -- after a run -------------------------------------------------------------------------------
    def process_run(self) -> dict[str, Any]:
        at = self.clock()
        summary = {"proposed": 0, "sent": 0, "updated": 0, "fixed": 0, "claimed_fixed": 0, "reopened": 0, "errors": 0}
        try:
            run = self.decisions.latest_run()
            if run is None:
                return {"run": None, "mode": self.rules.mode, **summary, "detail": "no run in the decision service"}
            self._automatic(at, summary)
            self._follow(at, summary)
        except DecisionsError as exc:
            raise DispatchError(str(exc)) from exc
        finally:
            self.close()
        log.info("tenant=%s run=%s mode=%s %s", self.tenant, run.get("id"), self.rules.mode, summary)
        return {"run": run, "mode": self.rules.mode, **summary}

    def _link_cmdb(self, wanted: dict[str, tk.Ticket], known: dict[str, tk.Ticket | None]) -> None:
        """The CMDB item of the asset of each ticket about to be sent (one read per asset)."""
        sending = [t for k, t in wanted.items() if known.get(k) is None or known[k].state in tk.UNSENT_STATES]
        cards = {a: self.decisions.asset(a) or {} for a in sorted({t.asset for t in sending})}
        for t in sending:
            items = cards[t.asset].get("cmdb") or []
            if items:
                t.cmdb = {k: items[0][k] for k in ("class", "key") if items[0].get(k)}

    def _automatic(self, at: str, summary: dict[str, int]) -> None:
        levels = self.rules.automatic_levels
        if not levels:
            return
        _, items = self.decisions.decisions({"level": ",".join(levels)})
        items = [d for d in items if self.rules.dispatchable(d.get("zone") or "")]
        wanted = tk.build(items, self.rules.ticket_target or "")
        known = {k: self.store.get(k) for k in wanted}
        self._link_cmdb(wanted, known)
        for key, t in wanted.items():
            self._apply(known[key], t, at, summary)

    def _apply(self, old: tk.Ticket | None, new: tk.Ticket, at: str, summary: dict[str, int]) -> tk.Ticket:
        """Send a new ticket, or bring a known one up to date with the findings of `new`."""
        if old is None or old.state in ("fixed", "dropped", "lost"):  # sent again, as a new ticket
            if old is not None:
                new.history = old.history
                new.event(at, f"new findings after {old.state}")
            self._send(new, at, summary)
            self.store.put(new)
            return new
        added = [f for fid, f in new.findings.items() if fid not in old.findings]
        for f in new.findings.values():
            mine = old.findings.get(f.id)
            if mine is not None:
                mine.level, mine.due, mine.kev, mine.epss = f.level, f.due, f.kev, f.epss
                mine.priority, mine.priority_rank, mine.bod_due = f.priority, f.priority_rank, f.bod_due
        for f in added:
            old.findings[f.id] = f
        if new.origin == "request" and new.requested_by:
            old.event(at, "requested", by=new.requested_by, comment=new.comment)
        if old.state == "proposed":
            if new.origin == "request":
                old.origin, old.requested_by, old.requested_at = "request", new.requested_by, new.requested_at
                old.comment = new.comment or old.comment
            self._send(old, at, summary)
        elif added:
            text = "A2VM: new findings for this fix: " + ", ".join(f"{f.cve} ({f.level})" for f in added)
            self._write(old, text, at, summary, "findings added")
            summary["updated"] += 1
        self.store.put(old)
        return old

    def _follow(self, at: str, summary: dict[str, int]) -> None:
        open_tickets = self.store.tickets(open_only=True)
        if not open_tickets:
            return
        since = min((t.created_at or at) for t in open_tickets)[:10]
        closed = {c["id"]: c for c in self.decisions.closed_since(since)}
        current: dict[str, dict[str, dict[str, Any]]] = {}
        for t in open_tickets:
            if t.asset not in current:
                _, items = self.decisions.decisions({"asset": t.asset})
                current[t.asset] = {d["id"]: d for d in items}
            self._follow_one(t, current[t.asset], closed, at, summary)
            self.store.put(t)

    def _follow_one(
        self,
        t: tk.Ticket,
        seen: dict[str, dict[str, Any]],
        closed: dict[str, dict[str, Any]],
        at: str,
        summary: dict[str, int],
    ) -> None:
        fixed_now = []
        for f in t.findings.values():
            if f.state == "fixed":
                continue
            if f.id in seen:
                d = seen[f.id]
                f.state = "open"
                f.refresh(d)
            elif f.id in closed:
                f.state, f.fixed_at = "fixed", (closed[f.id].get("closed_at") or at)[:10]
                fixed_now.append(f)
            else:
                f.state = "unverified"  # absent, its asset not scanned again: not a fix
        if fixed_now:
            text = "A2VM: fixed, confirmed by a scan: " + ", ".join(f"{f.cve} ({f.fixed_at})" for f in fixed_now)
            self._write(t, text, at, summary, "findings fixed")
        if not t.open_findings:
            t.state = "fixed"
            summary["fixed"] += 1
            t.event(at, "fixed")
            if self.rules.live and self.rules.resolve_when_fixed and t.external.get("ref"):
                try:
                    status, view = self.connector(t.target).status(External(**t.external))
                    if view == CLOSED:  # the team had resolved it: its date, now confirmed by the scan
                        self._declared(t, at)
                    if view != CLOSED:
                        text = "A2VM: every vulnerability of this ticket is fixed, a scan confirmed."
                        self.connector(t.target).resolve(External(**t.external), text)
                except ConnectorError as exc:
                    t.error = str(exc)
                    summary["errors"] += 1
            return
        if not self.rules.live or not t.external.get("ref"):
            return
        try:
            status, view = self.connector(t.target).status(External(**t.external))
        except ConnectorError as exc:
            t.error = str(exc)
            summary["errors"] += 1
            return
        t.external["status"] = status
        if view == CLOSED:
            self._declared(t, at)
        elif view != GONE:
            self._push_due(t, at, summary)
        if view == GONE:
            t.state = "lost"
            t.event(at, "lost", detail="the tool no longer knows this ticket")
        elif view == CLOSED and t.state != "claimed-fixed":
            still = ", ".join(f.cve for f in t.open_findings)
            t.state = "claimed-fixed"
            summary["claimed_fixed"] += 1
            text = f"A2VM: closed here, but the last scan still sees {still}."
            t.event(at, "claimed fixed", text=text)
            if self.rules.reopen_when_still_seen:
                try:
                    self.connector(t.target).reopen(External(**t.external), text)
                    t.state = "in-progress"
                    summary["reopened"] += 1
                    t.event(at, "reopened")
                except ConnectorError as exc:
                    t.error = str(exc)
                    self._write(t, text, at, summary, "comment")
        elif view != CLOSED and t.state in ("sent", "claimed-fixed"):
            t.state = "in-progress" if status not in ("", "new") else t.state

    def _declared(self, t: tk.Ticket, at: str) -> None:
        """The date the team says it fixed (v0.22.2): kept as a declaration, which the reporting
        database counts only when it lies between the last scan that still saw the flaw and the first
        that no longer did (D11: a declaration alone never closes a finding)."""
        read = getattr(self.connector(t.target), "declared_fix", None)
        if read is None:
            return
        try:
            when = read(External(**t.external))
        except ConnectorError as exc:
            t.error = str(exc)
            return
        if when and when != t.declared_fixed_at:
            t.declared_fixed_at = when
            t.event(at, "declared fixed", declared=when)

    def _push_due(self, t: tk.Ticket, at: str, summary: dict[str, int]) -> None:
        """A2VM's due date into the ticket's field, when the target has one and it changed (v0.22.2)."""
        write = getattr(self.connector(t.target), "set_due", None)
        if write is None or not t.due or t.due == t.due_pushed:
            return
        try:
            if write(External(**t.external), t.due):
                t.due_pushed = t.due
                t.event(at, "due date written", due=t.due)
        except ConnectorError as exc:
            t.error = str(exc)
            summary["errors"] += 1

    # -- requests of a person ---------------------------------------------------------------------
    def selection(self, query: dict[str, str]) -> dict[str, str]:
        filters = {k: str(v).strip() for k, v in query.items() if k in REQUEST_FILTERS and str(v).strip()}
        allowed = set(self.rules.request_levels)
        asked = {lv.strip().upper() for lv in filters.get("level", "").split(",") if lv.strip()} or allowed
        filters["level"] = ",".join(sorted(asked & allowed, key=lambda lv: tk.LEVEL_RANK[lv])) or "none"
        return filters

    def preview(self, query: dict[str, str], target: str | None = None) -> dict[str, Any]:
        """What a request would send: the tickets of the selection, nothing written."""
        if not self.rules.request_targets:
            raise DispatchError("this tenant has no target for requests (dispatch.yaml `requests`)")
        target = target if target in self.rules.request_targets else self.rules.request_targets[0]
        filters = self.selection(query)
        if filters["level"] == "none":
            return {"run": None, "filters": filters, "target": target, "tickets": [], "excluded": 0, "capped": False}
        cap = self.rules.max_tickets
        run, items = self.decisions.decisions(filters)
        excluded = [d for d in items if not self.rules.dispatchable(d.get("zone") or "")]
        items = [d for d in items if self.rules.dispatchable(d.get("zone") or "")]
        built = tk.build(items, target, {})
        keys = sorted(built, key=lambda k: (tk.LEVEL_RANK.get(built[k].level, 9), built[k].due or "9999", k))
        out = []
        for key in keys[:cap]:
            t = built[key]
            old = self.store.get(key)
            out.append(
                {
                    "key": key,
                    "asset": t.asset,
                    "asset_name": t.asset_name,
                    "fix": t.fix,
                    "level": t.level,
                    "priority": t.priority,
                    "due": t.due,
                    "cves": sorted(f.cve for f in t.findings.values()),
                    "status": "new" if old is None or old.state in ("fixed", "dropped", "lost") else old.state,
                    "ref": (old.external.get("ref") if old else "") or "",
                    "url": (old.external.get("url") if old else "") or "",
                }
            )
        return {
            "run": run,
            "filters": filters,
            "target": target,
            "tickets": out,
            "excluded": len(excluded),
            "capped": len(keys) > cap,
            "total": len(keys),
        }

    def confirm(
        self,
        query: dict[str, str],
        keys: list[str],
        user: str,
        target: str | None = None,
        comment: str = "",
        run_id: str = "",
    ) -> dict[str, Any]:
        """Send the chosen tickets of the selection, recorded with who asked. When a newer run came
        between the page and the confirmation, nothing is sent: the person checks again."""
        at = self.clock()
        view = self.preview(query, target)
        if run_id and (view.get("run") or {}).get("id") != run_id:
            return {"changed": True, "view": view, "results": []}
        summary = {"proposed": 0, "sent": 0, "updated": 0, "errors": 0}
        wanted = set(keys) & {t["key"] for t in view["tickets"]}
        if not wanted:
            return {"changed": False, "view": view, "results": []}
        _, items = self.decisions.decisions(view["filters"])
        items = [d for d in items if self.rules.dispatchable(d.get("zone") or "")]
        built = {k: t for k, t in tk.build(items, view["target"]).items() if k in wanted}
        known = {k: self.store.get(k) for k in built}
        self._link_cmdb(built, known)
        results = []
        try:
            for key in sorted(built):
                t = built[key]
                t.origin, t.requested_by, t.requested_at, t.comment = "request", user, at, comment[:2000]
                t.event(at, "requested", by=user, comment=comment[:2000])
                kept = self._apply(known[key], t, at, summary)
                results.append({"key": key, "state": kept.state, "ref": kept.external.get("ref", ""),
                                "url": kept.external.get("url", ""), "error": kept.error})  # fmt: skip
        finally:
            self.close()
        self.store.add_request(
            {
                "by": user,
                "filters": view["filters"],
                "target": view["target"],
                "run": (view.get("run") or {}).get("id"),
                "comment": comment[:2000],
                "mode": self.rules.mode,
                "tickets": [{"key": r["key"], "state": r["state"], "ref": r["ref"]} for r in results],
            }
        )
        log.info(
            "tenant=%s request by=%s tickets=%d mode=%s %s", self.tenant, user, len(results), self.rules.mode, summary
        )
        return {"changed": False, "view": view, "results": results, "mode": self.rules.mode}
