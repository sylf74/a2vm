# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The decision service's runs in the tenant's PostgreSQL (v0.18.0, LLD triage-prioritization §15.8):
the same interface as the files of `RunStore`, plus the life of each finding across runs.

  verdict.runs       one row per run received: its receipt and the triage document (gzip)
  verdict.push_keys  idempotency: key of the push -> run
  verdict.findings   one row per finding (CVE on asset) ever decided: opened, last seen, closed
                     (absent from a newer run: fixed or no longer detected), its level and the
                     changes of its level

The last `keep` runs are kept; the findings outlive them. Only the newest run moves the findings:
a run pushed late (older than the newest) is kept and readable, and changes no finding.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from typing import Any

from a2vm.db import Database, Migration, rls

from .index import row_id
from .store import RID, RunReceipt, parse_time

LEVELS_KEPT = 50  # changes of level kept per finding

MIGRATIONS = [
    Migration(
        1,
        """
CREATE SCHEMA IF NOT EXISTS verdict;
CREATE TABLE verdict.runs (
    tenant text NOT NULL,
    id text NOT NULL,
    generated_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    receipt jsonb NOT NULL,
    document bytea NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX runs_generated ON verdict.runs (tenant, generated_at, received_at);
CREATE TABLE verdict.push_keys (
    tenant text NOT NULL,
    key_hash text NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (tenant, key_hash)
);
CREATE TABLE verdict.findings (
    tenant text NOT NULL,
    finding text NOT NULL,
    cve text NOT NULL,
    asset text NOT NULL,
    opened_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    last_run text NOT NULL,
    closed_at timestamptz,
    closed_run text,
    reopened integer NOT NULL DEFAULT 0,
    level text NOT NULL,
    level_since timestamptz NOT NULL,
    levels jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (tenant, finding)
);
CREATE INDEX findings_closed ON verdict.findings (tenant, closed_at);
"""
        + rls("verdict.runs")
        + rls("verdict.push_keys")
        + rls("verdict.findings"),
    ),
]


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, dt.datetime) else str(value)


class PgRunStore:
    """`RunStore` in PostgreSQL; `lifecycle` and `closed` read the findings' history."""

    history = True

    def __init__(self, db: Database, keep: int = 30):
        self.db = db
        self.keep = max(1, keep)

    def describe(self) -> str:
        return self.db.describe()

    def ready(self) -> bool:
        return self.db.ready()

    @staticmethod
    def _key(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    def known(self, tenant: str, key: str) -> RunReceipt | None:
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT r.receipt FROM verdict.push_keys k JOIN verdict.runs r ON r.tenant = k.tenant "
                "AND r.id = k.run_id WHERE k.tenant = %s AND k.key_hash = %s",
                (tenant, self._key(key)),
            ).fetchone()
        if row is None:
            return None
        receipt = RunReceipt(**row[0])
        receipt.duplicate = True
        return receipt

    def put(
        self,
        tenant: str,
        body: bytes,
        document: dict[str, Any],
        key: str,
        now: dt.datetime | None = None,
        gzipped: bytes | None = None,
    ) -> RunReceipt:
        now = now or dt.datetime.now(dt.UTC)
        sha = hashlib.sha256(body).hexdigest()
        counts = {level: 0 for level in ("ACT", "ATTEND", "TRACK")}
        for row in document["rows"]:
            counts[row["delivery_decision"]] += 1
        rid = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{sha[:12]}"
        receipt = RunReceipt(
            rid, tenant, document["generated_at"], now.isoformat(timespec="seconds"), sha, len(document["rows"]), counts
        )
        with self.db.tx(tenant) as conn:
            # One push at a time per tenant: the key, the run and the findings move together.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('verdict.runs:' || %s))", (tenant,))
            found = conn.execute(
                "SELECT r.receipt FROM verdict.push_keys k JOIN verdict.runs r ON r.tenant = k.tenant "
                "AND r.id = k.run_id WHERE k.tenant = %s AND k.key_hash = %s",
                (tenant, self._key(key)),
            ).fetchone()
            if found is not None:
                known = RunReceipt(**found[0])
                known.duplicate = True
                return known
            newest = conn.execute("SELECT max(generated_at) FROM verdict.runs WHERE tenant = %s", (tenant,)).fetchone()[
                0
            ]
            conn.execute(
                "INSERT INTO verdict.runs (tenant, id, generated_at, received_at, receipt, document) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    tenant,
                    rid,
                    parse_time(receipt.generated_at),
                    now,
                    json.dumps(receipt.to_dict()),
                    gzipped if gzipped is not None else gzip.compress(body, 6),
                ),
            )
            conn.execute(
                "INSERT INTO verdict.push_keys (tenant, key_hash, run_id) VALUES (%s, %s, %s)",
                (tenant, self._key(key), rid),
            )
            at = parse_time(receipt.generated_at)
            if newest is None or at > newest:
                self._findings(conn, tenant, rid, at, document["rows"])
            self._prune(conn, tenant)
        return receipt

    def _findings(self, conn, tenant: str, rid: str, at: dt.datetime, rows: list[dict[str, Any]]) -> None:
        """Open, keep or close each finding from the newest run."""
        current: dict[str, dict[str, Any]] = {}
        for r in rows:
            current[row_id(r)] = r
        known = {
            f: (level, closed, levels)
            for f, level, closed, levels in conn.execute(
                "SELECT finding, level, closed_at, levels FROM verdict.findings WHERE tenant = %s", (tenant,)
            ).fetchall()
        }
        stamp = at.isoformat()
        with conn.cursor() as cur:
            for fid, r in current.items():
                level = r["delivery_decision"]
                asset = r.get("asset_id_full") or r["asset_id"]
                if fid not in known:
                    cur.execute(
                        "INSERT INTO verdict.findings (tenant, finding, cve, asset, opened_at, last_seen_at, "
                        "last_run, level, level_since, levels) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (tenant, fid, r["cve_id"], asset, at, at, rid, level, at,
                         json.dumps([{"at": stamp, "level": level, "run": rid}])),
                    )  # fmt: skip
                    continue
                old_level, closed, levels = known[fid]
                changed = old_level != level or closed is not None
                if changed:
                    levels = (levels + [{"at": stamp, "level": level, "run": rid}])[-LEVELS_KEPT:]
                cur.execute(
                    "UPDATE verdict.findings SET last_seen_at = %s, last_run = %s, closed_at = NULL, "
                    "closed_run = NULL, reopened = reopened + %s, level = %s, "
                    "level_since = CASE WHEN %s THEN %s ELSE level_since END, levels = %s "
                    "WHERE tenant = %s AND finding = %s",
                    (at, rid, 1 if closed is not None else 0, level, changed, at, json.dumps(levels), tenant, fid),
                )
            gone = [f for f, (_, closed, _) in known.items() if closed is None and f not in current]
            for fid in gone:
                cur.execute(
                    "UPDATE verdict.findings SET closed_at = %s, closed_run = %s WHERE tenant = %s AND finding = %s",
                    (at, rid, tenant, fid),
                )

    def _prune(self, conn, tenant: str) -> None:
        ids = [
            r[0]
            for r in conn.execute(
                "SELECT id FROM verdict.runs WHERE tenant = %s ORDER BY generated_at DESC, received_at DESC OFFSET %s",
                (tenant, self.keep),
            ).fetchall()
        ]
        if ids:
            conn.execute("DELETE FROM verdict.push_keys WHERE tenant = %s AND run_id = ANY(%s)", (tenant, ids))
            conn.execute("DELETE FROM verdict.runs WHERE tenant = %s AND id = ANY(%s)", (tenant, ids))

    def receipts(self, tenant: str) -> list[RunReceipt]:
        with self.db.tx(tenant) as conn:
            rows = conn.execute(
                "SELECT receipt FROM verdict.runs WHERE tenant = %s ORDER BY generated_at, received_at", (tenant,)
            ).fetchall()
        return [RunReceipt(**r[0]) for r in rows]

    def receipt(self, tenant: str, rid: str) -> RunReceipt | None:
        if not RID.match(rid):
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT receipt FROM verdict.runs WHERE tenant = %s AND id = %s", (tenant, rid)
            ).fetchone()
        return RunReceipt(**row[0]) if row else None

    def latest(self, tenant: str) -> RunReceipt | None:
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT receipt FROM verdict.runs WHERE tenant = %s ORDER BY generated_at DESC, received_at DESC "
                "LIMIT 1",
                (tenant,),
            ).fetchone()
        return RunReceipt(**row[0]) if row else None

    def load(self, tenant: str, rid: str) -> dict[str, Any] | None:
        if not RID.match(rid):
            return None
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                "SELECT document FROM verdict.runs WHERE tenant = %s AND id = %s", (tenant, rid)
            ).fetchone()
        return json.loads(gzip.decompress(bytes(row[0]))) if row else None

    # -- life of the findings ----------------------------------------------------------------------
    @staticmethod
    def _finding(row: tuple) -> dict[str, Any]:
        fid, cve, asset, opened, last, last_run, closed, closed_run, reopened, level, since, levels = row
        out = {
            "id": fid,
            "cve_id": cve,
            "asset": asset,
            "opened_at": _iso(opened),
            "last_seen_at": _iso(last),
            "last_run": last_run,
            "closed_at": _iso(closed),
            "closed_run": closed_run,
            "reopened": reopened,
            "level": level,
            "level_since": _iso(since),
            "levels": levels,
        }
        if closed is None:
            out.pop("closed_at")
            out.pop("closed_run")
        return out

    _COLUMNS = (
        "finding, cve, asset, opened_at, last_seen_at, last_run, closed_at, closed_run, reopened, level, "
        "level_since, levels"
    )

    def lifecycle(self, tenant: str, finding: str) -> dict[str, Any] | None:
        with self.db.tx(tenant) as conn:
            row = conn.execute(
                f"SELECT {self._COLUMNS} FROM verdict.findings WHERE tenant = %s AND finding = %s",  # noqa: S608
                (tenant, finding),
            ).fetchone()
        return self._finding(row) if row else None

    def closed(self, tenant: str, since: dt.datetime, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        """Findings closed since `since` (absent from the newest runs), most recent first."""
        with self.db.tx(tenant) as conn:
            total = conn.execute(
                "SELECT count(*) FROM verdict.findings WHERE tenant = %s AND closed_at >= %s", (tenant, since)
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT {self._COLUMNS} FROM verdict.findings WHERE tenant = %s AND closed_at >= %s "  # noqa: S608
                "ORDER BY closed_at DESC, finding LIMIT %s OFFSET %s",
                (tenant, since, limit, offset),
            ).fetchall()
        return total, [self._finding(r) for r in rows]
