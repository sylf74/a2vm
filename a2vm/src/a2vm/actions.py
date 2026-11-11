# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Actions asked to A2VM, confirmed by a person (v0.23.10, LLD triage §16.6).

The chat may prepare an action; it never runs it on the model's word alone: what the chat reads
(a CVE record, an advisory, a ticket) is written by others and could ask for anything. A request is
`proposed` by the chat (with who asked), then `confirmed` or `cancelled` by a validator on the
review page, signed in by the tenant's identity provider. A confirmed request waits for the one
that carries it out: a collector asks for its requests when it polls the detection service (no
inbound connection to a collector), takes them, runs them and says how it went.

  proposed --confirm--> confirmed --take--> taken --finish--> done | failed
     |                      |
     +--cancel--> cancelled  +--(24 h)--> expired
     +--(1 h)--> expired

The list of actions is closed:

  run-connector   run one connector of a collector now (« lance une synchro CMDB »)

The requests live in the tenant's database (`actions.requests`, row-level security), shared by the
tool server that proposes, the review page that confirms and the detection service that hands
them to the collectors: without the database there are no actions.
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
from typing import Any

from .db import Database, Migration, rls

ACTIONS = {"run-connector": "run one connector of a collector now"}
STATES = ("proposed", "confirmed", "taken", "done", "failed", "cancelled", "expired")
OPEN = ("proposed", "confirmed", "taken")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROPOSED_FOR = dt.timedelta(hours=1)
CONFIRMED_FOR = dt.timedelta(hours=24)

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS actions;
CREATE TABLE actions.requests (
    tenant text NOT NULL,
    id text NOT NULL,
    action text NOT NULL,
    collector text NOT NULL DEFAULT '',
    connector text NOT NULL DEFAULT '',
    state text NOT NULL,
    asked_by text NOT NULL,
    asked_at timestamptz NOT NULL,
    decided_by text NOT NULL DEFAULT '',
    decided_at timestamptz,
    taken_at timestamptz,
    finished_at timestamptz,
    detail text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id)
);
CREATE INDEX requests_open ON actions.requests (tenant, state, collector);
"""
        + rls("actions.requests"),
    ),
]

COLUMNS = ("id", "action", "collector", "connector", "state", "asked_by", "asked_at", "decided_by", "decided_at",
           "taken_at", "finished_at", "detail")  # fmt: skip


class ActionError(ValueError):
    """A request that cannot be made or changed; the message says why, for the person."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _row(r: tuple) -> dict[str, Any]:
    out = dict(zip(COLUMNS, r, strict=True))
    for k in ("asked_at", "decided_at", "taken_at", "finished_at"):
        out[k] = out[k].isoformat(timespec="seconds") if out[k] else ""
    out["what"] = f"run the connector {out['connector']} of the collector {out['collector']}"
    return out


class ActionStore:
    def __init__(self, db: Database):
        self.db = db

    def _expire(self, conn, tenant: str, now: dt.datetime) -> None:
        conn.execute(
            "UPDATE actions.requests SET state = 'expired', detail = 'not confirmed within the hour' "
            "WHERE tenant = %s AND state = 'proposed' AND asked_at < %s",
            (tenant, now - PROPOSED_FOR),
        )
        conn.execute(
            "UPDATE actions.requests SET state = 'expired', detail = 'the collector did not ask for it within 24 h' "
            "WHERE tenant = %s AND state = 'confirmed' AND decided_at < %s",
            (tenant, now - CONFIRMED_FOR),
        )

    def propose(self, tenant: str, action: str, collector: str, connector: str, asked_by: str,
                now: dt.datetime | None = None) -> dict[str, Any]:  # fmt: skip
        if action not in ACTIONS:
            raise ActionError(f"unknown action {action!r}: {', '.join(ACTIONS)}")
        if not NAME.match(collector or "") or not NAME.match(connector or ""):
            raise ActionError("a collector's id and a connector's name are required (letters, digits, . _ -)")
        now = now or _now()
        rid = f"act-{now:%Y%m%d}-{secrets.token_hex(4)}"
        with self.db.tx(tenant) as conn:
            self._expire(conn, tenant, now)
            same = conn.execute(
                "SELECT id FROM actions.requests WHERE tenant = %s AND action = %s AND collector = %s "
                "AND connector = %s AND state IN ('proposed', 'confirmed', 'taken')",
                (tenant, action, collector, connector),
            ).fetchone()
            if same:
                raise ActionError(f"the same request is already open: {same[0]}")
            conn.execute(
                "INSERT INTO actions.requests (tenant, id, action, collector, connector, state, asked_by, asked_at) "
                "VALUES (%s, %s, %s, %s, %s, 'proposed', %s, %s)",
                (tenant, rid, action, collector, connector, asked_by[:200], now),
            )
        return self.get(tenant, rid)

    def get(self, tenant: str, rid: str) -> dict[str, Any]:
        with self.db.tx(tenant) as conn:
            self._expire(conn, tenant, _now())
            r = conn.execute(
                f"SELECT {', '.join(COLUMNS)} FROM actions.requests WHERE tenant = %s AND id = %s",  # noqa: S608
                (tenant, rid),
            ).fetchone()
        if r is None:
            raise ActionError(f"unknown request {rid}")
        return _row(r)

    def list(self, tenant: str, states: tuple[str, ...] = (), limit: int = 50) -> list[dict[str, Any]]:
        with self.db.tx(tenant) as conn:
            self._expire(conn, tenant, _now())
            sql = f"SELECT {', '.join(COLUMNS)} FROM actions.requests WHERE tenant = %s"  # noqa: S608
            args: list[Any] = [tenant]
            if states:
                sql += " AND state = ANY(%s)"
                args.append(list(states))
            rows = conn.execute(sql + " ORDER BY asked_at DESC LIMIT %s", [*args, max(1, min(limit, 200))]).fetchall()
        return [_row(r) for r in rows]

    def decide(self, tenant: str, rid: str, by: str, confirm: bool, now: dt.datetime | None = None) -> dict[str, Any]:
        now = now or _now()
        with self.db.tx(tenant) as conn:
            self._expire(conn, tenant, now)
            done = conn.execute(
                "UPDATE actions.requests SET state = %s, decided_by = %s, decided_at = %s "
                "WHERE tenant = %s AND id = %s AND state = 'proposed' RETURNING id",
                ("confirmed" if confirm else "cancelled", by[:200], now, tenant, rid),
            ).fetchone()
        if done is None:
            state = self.get(tenant, rid)["state"]
            raise ActionError(f"the request is {state}: it can no longer be confirmed or cancelled")
        return self.get(tenant, rid)

    def take(self, tenant: str, collector: str, now: dt.datetime | None = None) -> list[dict[str, Any]]:
        """The confirmed requests of a collector, now taken by it."""
        now = now or _now()
        with self.db.tx(tenant) as conn:
            self._expire(conn, tenant, now)
            rows = conn.execute(
                f"UPDATE actions.requests SET state = 'taken', taken_at = %s WHERE tenant = %s "  # noqa: S608
                f"AND collector = %s AND state = 'confirmed' RETURNING {', '.join(COLUMNS)}",
                (now, tenant, collector),
            ).fetchall()
        return [_row(r) for r in rows]

    def finish(self, tenant: str, collector: str, rid: str, ok: bool, detail: str,
               now: dt.datetime | None = None) -> dict[str, Any] | None:  # fmt: skip
        now = now or _now()
        with self.db.tx(tenant) as conn:
            done = conn.execute(
                "UPDATE actions.requests SET state = %s, finished_at = %s, detail = %s WHERE tenant = %s "
                "AND id = %s AND collector = %s AND state = 'taken' RETURNING id",
                ("done" if ok else "failed", now, detail[:1000], tenant, rid, collector),
            ).fetchone()
        return self.get(tenant, rid) if done else None


def open_actions() -> ActionStore | None:
    """The requests in the tenant's database, or None (no database: no actions)."""
    from .db import open_database

    db = open_database("actions", MIGRATIONS, size=2)
    return ActionStore(db) if db else None
