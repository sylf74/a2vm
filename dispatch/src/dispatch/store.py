# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Where the dispatch service keeps its tickets and the requests of the persons (LLD dispatch §6):
the tenant's PostgreSQL (schema `dispatch`, row-level security on the tenant, as `verdict`), or
files on the service's volume without it.

  dispatch.tickets    one row per ticket: its key, state, target, external reference, document
  dispatch.requests   one row per request of a person: who, when, what, the tickets it touched
"""

from __future__ import annotations

import datetime as dt
import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol

from ngvm.db import Database, Migration, rls

from .tickets import OPEN_STATES, Ticket, key_digest

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS dispatch;
CREATE TABLE dispatch.tickets (
    tenant text NOT NULL,
    key text NOT NULL,
    state text NOT NULL,
    target text NOT NULL,
    asset text NOT NULL,
    external_ref text,
    updated_at timestamptz NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant, key)
);
CREATE INDEX tickets_state ON dispatch.tickets (tenant, state);
CREATE INDEX tickets_asset ON dispatch.tickets (tenant, asset);
CREATE TABLE dispatch.requests (
    tenant text NOT NULL,
    id bigserial,
    at timestamptz NOT NULL,
    by_user text NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant, id)
);
"""
        + rls("dispatch.tickets")
        + rls("dispatch.requests"),
    ),
]


class TicketStore(Protocol):
    def get(self, key: str) -> Ticket | None: ...
    def put(self, ticket: Ticket) -> None: ...
    def tickets(self, open_only: bool = False, asset: str | None = None) -> list[Ticket]: ...
    def add_request(self, record: dict[str, Any]) -> None: ...
    def requests(self, limit: int = 50) -> list[dict[str, Any]]: ...
    def describe(self) -> str: ...
    def ready(self) -> bool: ...


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class FileStore:
    """One JSON file per ticket under `<root>/<tenant>/tickets/`, requests in `requests.jsonl`."""

    def __init__(self, root: str | Path, tenant: str):
        self.dir = Path(root) / tenant
        (self.dir / "tickets").mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def describe(self) -> str:
        return f"files {self.dir}"

    def ready(self) -> bool:
        return self.dir.is_dir()

    def _path(self, key: str) -> Path:
        return self.dir / "tickets" / f"{key_digest(key)}.json"

    def get(self, key: str) -> Ticket | None:
        p = self._path(key)
        return Ticket.from_dict(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else None

    def put(self, ticket: Ticket) -> None:
        p = self._path(ticket.key)
        tmp = p.with_name(f".{p.name}.tmp")
        with self._lock:
            tmp.write_text(json.dumps(ticket.to_dict(), ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, p)

    def tickets(self, open_only: bool = False, asset: str | None = None) -> list[Ticket]:
        out = []
        for p in sorted((self.dir / "tickets").glob("*.json")):
            t = Ticket.from_dict(json.loads(p.read_text(encoding="utf-8")))
            if (not open_only or t.state in OPEN_STATES) and (asset is None or t.asset == asset):
                out.append(t)
        return sorted(out, key=lambda t: t.key)

    def add_request(self, record: dict[str, Any]) -> None:
        with self._lock, (self.dir / "requests.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": _now(), **record}, ensure_ascii=False) + "\n")

    def requests(self, limit: int = 50) -> list[dict[str, Any]]:
        p = self.dir / "requests.jsonl"
        if not p.exists():
            return []
        lines = p.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in reversed(lines)]


class PgStore:
    """The same in the tenant's PostgreSQL."""

    def __init__(self, db: Database, tenant: str):
        self.db = db
        self.tenant = tenant

    def describe(self) -> str:
        return self.db.describe()

    def ready(self) -> bool:
        return self.db.ready()

    def get(self, key: str) -> Ticket | None:
        with self.db.tx(self.tenant) as conn:
            row = conn.execute(
                "SELECT document FROM dispatch.tickets WHERE tenant = %s AND key = %s", (self.tenant, key)
            ).fetchone()
        return Ticket.from_dict(row[0]) if row else None

    def put(self, ticket: Ticket) -> None:
        from psycopg.types.json import Jsonb

        doc = ticket.to_dict()
        with self.db.tx(self.tenant) as conn:
            conn.execute(
                "INSERT INTO dispatch.tickets (tenant, key, state, target, asset, external_ref, updated_at, document) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (tenant, key) DO UPDATE SET "
                "state = EXCLUDED.state, target = EXCLUDED.target, external_ref = EXCLUDED.external_ref, "
                "updated_at = EXCLUDED.updated_at, document = EXCLUDED.document",
                (
                    self.tenant,
                    ticket.key,
                    ticket.state,
                    ticket.target,
                    ticket.asset,
                    ticket.external.get("ref"),
                    ticket.updated_at or _now(),
                    Jsonb(doc),
                ),
            )

    def tickets(self, open_only: bool = False, asset: str | None = None) -> list[Ticket]:
        sql = "SELECT document FROM dispatch.tickets WHERE tenant = %s"
        args: list[Any] = [self.tenant]
        if open_only:
            sql += " AND state = ANY(%s)"
            args.append(list(OPEN_STATES))
        if asset is not None:
            sql += " AND asset = %s"
            args.append(asset)
        with self.db.tx(self.tenant) as conn:
            rows = conn.execute(sql + " ORDER BY key", args).fetchall()
        return [Ticket.from_dict(r[0]) for r in rows]

    def add_request(self, record: dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb

        with self.db.tx(self.tenant) as conn:
            conn.execute(
                "INSERT INTO dispatch.requests (tenant, at, by_user, document) VALUES (%s, now(), %s, %s)",
                (self.tenant, record.get("by", ""), Jsonb(record)),
            )

    def requests(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.tx(self.tenant) as conn:
            rows = conn.execute(
                "SELECT at, document FROM dispatch.requests WHERE tenant = %s ORDER BY id DESC LIMIT %s",
                (self.tenant, limit),
            ).fetchall()
        return [{"at": at.isoformat(timespec="seconds"), **doc} for at, doc in rows]
