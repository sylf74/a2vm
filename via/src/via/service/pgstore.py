# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""What the watch service keeps, in the tenant's PostgreSQL (v0.18.0, LLD vulnerability-intelligence
§3.7): the same interface as the files of `WatchStore`.

  via.state          what the watch has already seen (opaque to the service)
  via.inventory      the last daily inventory of each client (assets.json, findings.json)
  via.runs           the passages of the watch that drafted alerts
  via.files          their files: index.json and the alert sheets (Markdown, HTML, Word, contexts)
  via.events         the journal of the alerts, in order
  via.edits          the English reference as a validator enriched it
  via.translations   a translation of the reference and its metadata

A passage of the watch (state, journal events, files) is written in one transaction, so several
replicas of the service never see half of one.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
from typing import Any

from a2vm.db import Database, Migration, rls
from via.alert import journal

from .store import ALERT_ID, FILE_NAME, INVENTORY_FILES, LANG, RUN_ID, WatchStore, _now

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS via;
CREATE TABLE via.state (tenant text PRIMARY KEY, data bytea NOT NULL, at timestamptz NOT NULL);
CREATE TABLE via.inventory (
    tenant text NOT NULL,
    client text NOT NULL,
    name text NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (tenant, client, name)
);
CREATE TABLE via.inventory_meta (
    tenant text NOT NULL,
    client text NOT NULL,
    meta jsonb NOT NULL,
    PRIMARY KEY (tenant, client)
);
CREATE TABLE via.runs (
    tenant text NOT NULL,
    id text NOT NULL,
    at timestamptz NOT NULL,
    alerts integer NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE TABLE via.files (
    tenant text NOT NULL,
    run text NOT NULL,
    name text NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (tenant, run, name),
    FOREIGN KEY (tenant, run) REFERENCES via.runs (tenant, id) ON DELETE CASCADE
);
CREATE TABLE via.events (
    tenant text NOT NULL,
    seq bigserial,
    event jsonb NOT NULL,
    PRIMARY KEY (tenant, seq)
);
CREATE TABLE via.edits (
    tenant text NOT NULL,
    alert text NOT NULL,
    text text NOT NULL,
    PRIMARY KEY (tenant, alert)
);
CREATE TABLE via.translations (
    tenant text NOT NULL,
    alert text NOT NULL,
    lang text NOT NULL,
    text text,
    meta jsonb NOT NULL,
    PRIMARY KEY (tenant, alert, lang)
);
"""
        + "".join(
            rls(f"via.{t}")
            for t in ("state", "inventory", "inventory_meta", "runs", "files", "events", "edits", "translations")
        ),
    ),
]


class PgWatchStore(WatchStore):
    """`WatchStore` in PostgreSQL: the reads built on `file`, `events` and `translation` are shared."""

    def __init__(self, db: Database, keep_days: int = 30):  # noqa: D107 - no root: no files
        self.db = db
        self.keep_days = keep_days

    def describe(self) -> str:
        return self.db.describe()

    def ready(self) -> bool:
        return self.db.ready()

    # -- state -----------------------------------------------------------------------------------
    def state(self, tenant: str) -> bytes | None:
        with self.db.tx(tenant) as conn:
            row = conn.execute("SELECT data FROM via.state WHERE tenant = %s", (tenant,)).fetchone()
        return bytes(row[0]) if row else None

    # -- inventory -------------------------------------------------------------------------------
    def put_inventory(self, tenant: str, client: str, docs: dict[str, bytes]) -> dict[str, Any]:
        meta = {"client": client, "received_at": _now().isoformat(), "files": sorted(docs)}
        with self.db.tx(tenant) as conn:
            for name, data in docs.items():
                conn.execute(
                    "INSERT INTO via.inventory (tenant, client, name, data) VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (tenant, client, name) DO UPDATE SET data = EXCLUDED.data",
                    (tenant, client, name, data),
                )
            conn.execute(
                "INSERT INTO via.inventory_meta (tenant, client, meta) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant, client) DO UPDATE SET meta = EXCLUDED.meta",
                (tenant, client, json.dumps(meta)),
            )
        return meta

    def inventory(self, tenant: str, client: str, name: str) -> bytes | None:
        if name not in INVENTORY_FILES:
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT data FROM via.inventory WHERE tenant = %s AND client = %s AND name = %s", (tenant, client, name)
            ).fetchone()
        return bytes(row[0]) if row else None

    def inventory_meta(self, tenant: str, client: str) -> dict[str, Any] | None:
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT meta FROM via.inventory_meta WHERE tenant = %s AND client = %s", (tenant, client)
            ).fetchone()
        return row[0] if row else None

    # -- watch runs ------------------------------------------------------------------------------
    @staticmethod
    def _append(conn, tenant: str, events: list[dict]) -> None:
        if not events:
            return
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO via.events (tenant, event) VALUES (%s, %s)",
                [(tenant, json.dumps(e, ensure_ascii=False)) for e in events],
            )
        conn.execute(
            "DELETE FROM via.events WHERE tenant = %s AND seq < (SELECT min(seq) FROM (SELECT seq FROM via.events "
            "WHERE tenant = %s ORDER BY seq DESC LIMIT %s) last)",
            (tenant, tenant, journal.MAX_LINES),
        )

    def put_run(
        self, tenant: str, state: bytes, events: list[dict], files: dict[str, bytes], now: dt.datetime | None = None
    ) -> dict[str, Any]:
        now = now or _now()
        rid = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
        index = json.loads(files["index.json"]) if "index.json" in files else []
        with self.db.tx(tenant) as conn:
            if index:
                conn.execute(
                    "INSERT INTO via.runs (tenant, id, at, alerts) VALUES (%s, %s, %s, %s)",
                    (tenant, rid, now, len(index)),
                )
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO via.files (tenant, run, name, data) VALUES (%s, %s, %s, %s)",
                        [(tenant, rid, name, data) for name, data in files.items()],
                    )
            conn.execute(
                "INSERT INTO via.state (tenant, data, at) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant) DO UPDATE SET data = EXCLUDED.data, at = EXCLUDED.at",
                (tenant, state, now),
            )
            self._append(conn, tenant, events)
            conn.execute(
                "DELETE FROM via.runs WHERE tenant = %s AND at < %s", (tenant, now - dt.timedelta(days=self.keep_days))
            )
        return {"run": rid if index else None, "alerts": len(index), "events": len(events)}

    def add_events(self, tenant: str, events: list[dict]) -> int:
        with self.db.tx(tenant) as conn:
            self._append(conn, tenant, events)
        return len(events)

    def runs(self, tenant: str) -> list[str]:
        with self.db.tx(tenant) as conn:
            rows = conn.execute("SELECT id FROM via.runs WHERE tenant = %s ORDER BY id DESC", (tenant,)).fetchall()
        return [r[0] for r in rows]

    # -- alerts ----------------------------------------------------------------------------------
    def events(self, tenant: str) -> list[dict]:
        with self.db.tx(tenant) as conn:
            rows = conn.execute("SELECT event FROM via.events WHERE tenant = %s ORDER BY seq", (tenant,)).fetchall()
        return [r[0] for r in rows]

    def edit(self, tenant: str, alert_id: str) -> str | None:
        if not ALERT_ID.match(alert_id):
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT text FROM via.edits WHERE tenant = %s AND alert = %s", (tenant, alert_id)
            ).fetchone()
        return row[0] if row else None

    def put_edit(self, tenant: str, alert_id: str, text: str, event: dict) -> None:
        if not ALERT_ID.match(alert_id):
            raise ValueError("invalid alert id")
        with self.db.tx(tenant) as conn:
            conn.execute(
                "INSERT INTO via.edits (tenant, alert, text) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant, alert) DO UPDATE SET text = EXCLUDED.text",
                (tenant, alert_id, text),
            )
            self._append(conn, tenant, [event])

    def translation(self, tenant: str, alert_id: str, lang: str) -> tuple[str | None, dict[str, Any] | None]:
        if not ALERT_ID.match(alert_id) or not LANG.match(lang):
            return None, None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT text, meta FROM via.translations WHERE tenant = %s AND alert = %s AND lang = %s",
                (tenant, alert_id, lang),
            ).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def put_translation(
        self, tenant: str, alert_id: str, lang: str, text: str | None, meta: dict[str, Any], event: dict
    ) -> None:
        if not ALERT_ID.match(alert_id) or not LANG.match(lang):
            raise ValueError("invalid alert id or language")
        with self.db.tx(tenant) as conn:
            conn.execute(
                "INSERT INTO via.translations (tenant, alert, lang, text, meta) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (tenant, alert, lang) DO UPDATE SET "
                "text = COALESCE(EXCLUDED.text, via.translations.text), meta = EXCLUDED.meta",
                (tenant, alert_id, lang, text, json.dumps(meta, ensure_ascii=False)),
            )
            self._append(conn, tenant, [event])

    def file(self, tenant: str, run: str, name: str) -> bytes | None:
        if not RUN_ID.match(run) or not FILE_NAME.match(name) or name == "meta.json":
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT data FROM via.files WHERE tenant = %s AND run = %s AND name = %s", (tenant, run, name)
            ).fetchone()
        return bytes(row[0]) if row else None
