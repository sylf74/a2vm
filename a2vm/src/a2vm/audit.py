# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The audit journal of a tenant, imputable to an author (v0.23.10, traceability: the T of DICT).

Every service writes here what a person or a machine did through it: the chat's tool calls (who
asked what), the actions asked and confirmed, the validations of alerts and applications on the
review pages, the pushes of the collectors. One entry says who (`actor`, and what kind of actor:
`user` for a person the chat or the sign-in names, `collector`, `token` for a job), when, through
which service, what (`action`, its `target` and parameters) and the outcome.

With the tenant's database the journal is one table, `audit.entries`, shared by the services, one
tenant per transaction (row-level security), kept `keep_days` days. Without it, each service
appends to `audit.jsonl` in its own data directory. Every entry is also a log line of the service
(`audit actor=… action=…`), so that the cluster's log collection keeps a copy. Writing never
fails the request it records: a journal that cannot be written is a warning in the log.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path
from typing import Any

from .db import Database, Migration, rls

log = logging.getLogger("a2vm.audit")

ACTOR_KINDS = ("user", "collector", "token", "service")
MAX_PARAMS = 4000  # characters of the parameters kept per entry

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS audit;
CREATE TABLE audit.entries (
    tenant text NOT NULL,
    id bigserial NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    actor_kind text NOT NULL,
    service text NOT NULL,
    action text NOT NULL,
    target text NOT NULL DEFAULT '',
    params jsonb NOT NULL DEFAULT '{}'::jsonb,
    outcome text NOT NULL DEFAULT 'ok',
    detail text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id)
);
CREATE INDEX entries_at ON audit.entries (tenant, at);
"""
        + rls("audit.entries"),
    ),
]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _params(params: dict[str, Any] | None) -> dict[str, Any]:
    clean = {k: v for k, v in (params or {}).items() if v not in (None, "", [], {})}
    text = json.dumps(clean, ensure_ascii=False, default=str)
    return clean if len(text) <= MAX_PARAMS else {"truncated": text[:MAX_PARAMS]}


class AuditLog:
    """The journal as one service writes and reads it."""

    def __init__(self, service: str, db: Database | None = None, path: str | Path | None = None, keep_days: int = 365):
        self.service = service
        self.db = db
        self.path = Path(path) if path else None
        self.keep_days = max(1, keep_days)
        self._lock = threading.Lock()
        self._pruned = ""

    def write(
        self,
        tenant: str,
        actor: str,
        actor_kind: str,
        action: str,
        target: str = "",
        params: dict[str, Any] | None = None,
        outcome: str = "ok",
        detail: str = "",
        at: dt.datetime | None = None,
    ) -> None:
        at = at or _now()
        entry = {
            "at": at.isoformat(timespec="seconds"), "actor": (actor or "unknown")[:200],
            "actor_kind": actor_kind if actor_kind in ACTOR_KINDS else "token", "service": self.service,
            "action": action[:100], "target": target[:300], "params": _params(params),
            "outcome": outcome[:40], "detail": detail[:1000],
        }  # fmt: skip
        log.info(
            "audit tenant=%s actor=%s kind=%s action=%s target=%s outcome=%s",
            tenant, entry["actor"], entry["actor_kind"], entry["action"], entry["target"], entry["outcome"],
        )  # fmt: skip
        try:
            if self.db is not None:
                with self.db.tx(tenant) as conn:
                    conn.execute(
                        "INSERT INTO audit.entries (tenant, at, actor, actor_kind, service, action, target, params, "
                        "outcome, detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)",
                        (tenant, at, entry["actor"], entry["actor_kind"], self.service, entry["action"],
                         entry["target"], json.dumps(entry["params"]), entry["outcome"], entry["detail"]),
                    )  # fmt: skip
                    self._prune(conn, tenant, at)
            elif self.path is not None:
                with self._lock:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with self.path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps({"tenant": tenant, **entry}, ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001 - the journal never fails the request it records
            log.warning("audit journal not written (%s): %s", type(exc).__name__, exc)

    def _prune(self, conn, tenant: str, at: dt.datetime) -> None:
        day = at.date().isoformat()
        if self._pruned == day:
            return
        conn.execute(
            "DELETE FROM audit.entries WHERE tenant = %s AND at < %s",
            (tenant, at - dt.timedelta(days=self.keep_days)),
        )
        self._pruned = day

    def entries(
        self,
        tenant: str,
        since: dt.datetime | None = None,
        until: dt.datetime | None = None,
        actor: str = "",
        action: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """The entries newest first, filtered (actor and action: a part of them, case ignored); the total."""
        limit = max(1, min(limit, 200))
        if self.db is not None:
            where, args = ["tenant = %s"], [tenant]
            if since:
                where.append("at >= %s")
                args.append(since)
            if until:
                where.append("at < %s")
                args.append(until)
            if actor:
                where.append("actor ILIKE %s")
                args.append(f"%{actor}%")
            if action:
                where.append("action ILIKE %s")
                args.append(f"%{action}%")
            sql = " AND ".join(where)
            with self.db.tx(tenant) as conn:
                total = conn.execute(f"SELECT count(*) FROM audit.entries WHERE {sql}", args).fetchone()[0]  # noqa: S608
                rows = conn.execute(
                    "SELECT at, actor, actor_kind, service, action, target, params, outcome, detail "  # noqa: S608
                    f"FROM audit.entries WHERE {sql} ORDER BY at DESC, id DESC LIMIT %s OFFSET %s",
                    [*args, limit, offset],
                ).fetchall()
            keys = ("at", "actor", "actor_kind", "service", "action", "target", "params", "outcome", "detail")
            items = [dict(zip(keys, r, strict=True)) for r in rows]
            for i in items:
                i["at"] = i["at"].isoformat(timespec="seconds")
            return items, int(total)
        items = []
        if self.path is not None and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                at = dt.datetime.fromisoformat(e["at"])
                if e.get("tenant") != tenant or (since and at < since) or (until and at >= until):
                    continue
                if actor and actor.lower() not in e["actor"].lower():
                    continue
                if action and action.lower() not in e["action"].lower():
                    continue
                e.pop("tenant", None)
                items.append(e)
        items.reverse()
        return items[offset : offset + limit], len(items)


def open_audit(service: str, directory: str | Path | None = None, keep_days: int = 365) -> AuditLog:
    """The journal in the tenant's database when there is one, else `audit.jsonl` in `directory`
    (or the log only, without a directory)."""
    from .db import open_database

    db = open_database("audit", MIGRATIONS, size=2)
    path = None if db or not directory else Path(directory) / "audit.jsonl"
    return AuditLog(service, db, path, keep_days)
