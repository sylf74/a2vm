# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The detection service's detections in the tenant's PostgreSQL (v0.18.0, LLD detection §8.2):
the same interface as `FileStore`.

  detect.detections   one row per detection accepted: its receipt and the document (gzip)
  detect.push_keys    idempotency: collector and key -> detection

Retention and "latest" are per source and collector, as with the files.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from typing import Any

from a2vm.db import Database, Migration, rls

from .store import RID, Receipt, parse_time

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS detect;
CREATE TABLE detect.detections (
    tenant text NOT NULL,
    id text NOT NULL,
    collector text NOT NULL,
    source text NOT NULL,
    generated_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    receipt jsonb NOT NULL,
    document bytea NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX detections_latest ON detect.detections (tenant, source, collector, generated_at, received_at);
CREATE TABLE detect.push_keys (
    tenant text NOT NULL,
    key_hash text NOT NULL,
    detection_id text NOT NULL,
    PRIMARY KEY (tenant, key_hash)
);
"""
        + rls("detect.detections")
        + rls("detect.push_keys"),
    ),
]


class PgStore:
    def __init__(self, db: Database, keep: int = 14):
        self.db = db
        self.keep = max(1, keep)

    def describe(self) -> str:
        return self.db.describe()

    def ready(self) -> bool:
        return self.db.ready()

    @staticmethod
    def _key(collector: str, key: str) -> str:
        return hashlib.sha256(f"{collector}\0{key}".encode()).hexdigest()

    def _known(self, conn, tenant: str, collector: str, key: str) -> Receipt | None:
        row = conn.execute(
            "SELECT d.receipt FROM detect.push_keys k JOIN detect.detections d ON d.tenant = k.tenant "
            "AND d.id = k.detection_id WHERE k.tenant = %s AND k.key_hash = %s",
            (tenant, self._key(collector, key)),
        ).fetchone()
        if row is None:
            return None
        receipt = Receipt(**row[0])
        receipt.duplicate = True
        return receipt

    def known(self, tenant: str, collector: str, key: str) -> Receipt | None:
        with self.db.tx(tenant) as conn:
            return self._known(conn, tenant, collector, key)

    def put(
        self,
        tenant: str,
        collector: str,
        body: bytes,
        document: dict[str, Any],
        key: str,
        now: dt.datetime | None = None,
        gzipped: bytes | None = None,
    ) -> Receipt:
        now = now or dt.datetime.now(dt.UTC)
        source = document["source"]
        sha = hashlib.sha256(body).hexdigest()
        rid = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{sha[:12]}"
        receipt = Receipt(
            rid, tenant, collector, source, document["generated_at"], now.isoformat(timespec="seconds"), sha
        )
        with self.db.tx(tenant) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('detect.push:' || %s))", (tenant,))
            known = self._known(conn, tenant, collector, key)
            if known is not None:
                return known
            conn.execute(
                "INSERT INTO detect.detections (tenant, id, collector, source, generated_at, received_at, receipt, "
                "document) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    tenant,
                    rid,
                    collector,
                    source,
                    parse_time(receipt.generated_at),
                    now,
                    json.dumps(receipt.to_dict()),
                    gzipped if gzipped is not None else gzip.compress(body, 6),
                ),
            )
            conn.execute(
                "INSERT INTO detect.push_keys (tenant, key_hash, detection_id) VALUES (%s, %s, %s)",
                (tenant, self._key(collector, key), rid),
            )
            dropped = [
                r[0]
                for r in conn.execute(
                    "SELECT id FROM detect.detections WHERE tenant = %s AND source = %s AND collector = %s "
                    "ORDER BY generated_at DESC, received_at DESC OFFSET %s",
                    (tenant, source, collector, self.keep),
                ).fetchall()
            ]
            if dropped:
                conn.execute(
                    "DELETE FROM detect.push_keys WHERE tenant = %s AND detection_id = ANY(%s)", (tenant, dropped)
                )
                conn.execute("DELETE FROM detect.detections WHERE tenant = %s AND id = ANY(%s)", (tenant, dropped))
        return receipt

    def receipt(self, tenant: str, rid: str) -> Receipt | None:
        if not RID.match(rid):
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT receipt FROM detect.detections WHERE tenant = %s AND id = %s", (tenant, rid)
            ).fetchone()
        return Receipt(**row[0]) if row else None

    def sources(self, tenant: str) -> list[str]:
        with self.db.tx(tenant) as conn:
            rows = conn.execute(
                "SELECT DISTINCT source FROM detect.detections WHERE tenant = %s ORDER BY source", (tenant,)
            ).fetchall()
        return [r[0] for r in rows]

    def latest(self, tenant: str, source: str | None = None) -> list[tuple[Receipt, dict[str, Any]]]:
        """The latest detection of each source and collector (the newest generated_at wins)."""
        with self.db.tx(tenant) as conn:
            rows = conn.execute(
                "SELECT DISTINCT ON (source, collector) receipt, document FROM detect.detections "
                "WHERE tenant = %s AND (%s::text IS NULL OR source = %s) "
                "ORDER BY source, collector, generated_at DESC, received_at DESC",
                (tenant, source, source),
            ).fetchall()
        return [(Receipt(**r), json.loads(gzip.decompress(bytes(d)))) for r, d in rows]

    def get(self, tenant: str, rid: str, source: str | None = None) -> tuple[Receipt, dict[str, Any]] | None:
        if not RID.match(rid):
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT receipt, document FROM detect.detections WHERE tenant = %s AND id = %s "
                "AND (%s::text IS NULL OR source = %s)",
                (tenant, rid, source, source),
            ).fetchone()
        return (Receipt(**row[0]), json.loads(gzip.decompress(bytes(row[1])))) if row else None
