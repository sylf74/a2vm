# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""PostgreSQL of a tenant's services (v0.18.0, HLD D15): `via serve`, `detect serve` and
`verdict serve` keep what they receive in the tenant's database instead of files on a volume.

On Kubernetes each tenant has its own PostgreSQL cluster (CloudNativePG, in its namespace); its
application role owns one database. Each pillar keeps its tables in a schema of its own (`via`,
`detect`, `verdict`) and creates them itself at start (`Database.init`, under an advisory lock so
that several replicas start together). Every table carries the tenant and is under row-level
security: a transaction sees and writes the rows of the tenant it names (`Database.tx(tenant)`),
nothing else, even for the owner of the tables (FORCE ROW LEVEL SECURITY).

The connection string is read from a file (`A2VM_DB_DSN_FILE`, the CloudNativePG secret's `uri`)
or from `A2VM_DB_DSN`; with `A2VM_DB_CA` (the cluster's CA) the server is verified
(`sslmode=verify-full`). No password is ever printed: `describe()` gives host and database only.
"""

from __future__ import annotations

import contextlib
import os
import queue
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

DSN_FILE_ENV = "A2VM_DB_DSN_FILE"
DSN_ENV = "A2VM_DB_DSN"
CA_ENV = "A2VM_DB_CA"
LOCK_KEY = 0x4132564D  # "A2VM": the advisory lock of the schema changes


class DatabaseError(Exception):
    """The database is unreachable, refused or misconfigured."""


@dataclass
class Migration:
    """One step of a pillar's schema: the SQL run once, in order, by `Database.init`."""

    version: int
    sql: str


def rls(table: str) -> str:
    """Row-level security of a table with a `tenant` column: one tenant per transaction."""
    name = table.split(".")[-1]
    check = "tenant = current_setting('a2vm.tenant', true)"
    return (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n"
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {name}_tenant ON {table} USING ({check}) WITH CHECK ({check});\n"
    )


def dsn_from_env(environ: dict[str, str] | None = None) -> str | None:
    """The connection string of the tenant's database, or None (the service keeps its files)."""
    env = os.environ if environ is None else environ
    path = env.get(DSN_FILE_ENV, "")
    if path:
        try:
            value = open(path, encoding="utf-8").read().strip()  # noqa: SIM115 - read once at start
        except OSError as exc:
            raise DatabaseError(f"{DSN_FILE_ENV}: {exc}") from exc
        if not value:
            raise DatabaseError(f"{DSN_FILE_ENV}: {path} is empty")
        return value
    return env.get(DSN_ENV) or None


class Database:
    """A small pool of connections to one database, and the schema of one component."""

    def __init__(
        self,
        dsn: str,
        component: str,
        migrations: list[Migration],
        size: int = 8,
        ca: str | None = None,
        connect_timeout: int = 5,
    ):
        import psycopg

        extra: dict[str, Any] = {"connect_timeout": connect_timeout, "application_name": f"a2vm-{component}"}
        ca = ca if ca is not None else os.environ.get(CA_ENV, "")
        if ca:
            extra.update(sslmode="verify-full", sslrootcert=ca)
        try:
            self.dsn = psycopg.conninfo.make_conninfo(dsn, **extra)
        except psycopg.ProgrammingError as exc:
            raise DatabaseError("invalid connection string") from None if "password" in str(exc) else exc
        self.component = component
        self.migrations = sorted(migrations, key=lambda m: m.version)
        self.size = max(1, size)
        self._pool: queue.LifoQueue = queue.LifoQueue()
        self._open = 0
        self._lock = threading.Lock()

    def describe(self) -> str:
        """Host and database, never the password."""
        import psycopg

        info = psycopg.conninfo.conninfo_to_dict(self.dsn)
        tls = "verified" if info.get("sslmode") == "verify-full" else info.get("sslmode", "default")
        return f"postgresql {info.get('host', 'local')}/{info.get('dbname', '')} (TLS {tls})"

    # -- connections -----------------------------------------------------------------------------
    def _connect(self):
        import psycopg

        try:
            return psycopg.connect(self.dsn)
        except psycopg.Error as exc:
            raise DatabaseError(f"{self.describe()}: {type(exc).__name__}: {str(exc).splitlines()[0]}") from None

    def _get(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._open < self.size:
                self._open += 1
                try:
                    return self._connect()
                except DatabaseError:
                    self._open -= 1
                    raise
        try:
            return self._pool.get(timeout=30)
        except queue.Empty:
            raise DatabaseError("no free connection to the database") from None

    def _put(self, conn) -> None:
        import psycopg

        if conn.closed or conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            with contextlib.suppress(Exception):
                conn.close()
            with self._lock:
                self._open -= 1
            return
        self._pool.put(conn)

    @contextlib.contextmanager
    def tx(self, tenant: str) -> Iterator[Any]:
        """One transaction that sees the rows of `tenant` only; committed when the block ends."""
        import psycopg

        conn = self._get()
        try:
            with conn.transaction():
                conn.execute("SELECT set_config('a2vm.tenant', %s, true)", (tenant,))
                yield conn
        except psycopg.OperationalError as exc:
            with contextlib.suppress(Exception):
                conn.close()
            raise DatabaseError(f"{self.describe()}: {str(exc).splitlines()[0] if str(exc) else 'lost'}") from None
        finally:
            self._put(conn)

    def close(self) -> None:
        while True:
            try:
                self._pool.get_nowait().close()
            except queue.Empty:
                break
        with self._lock:
            self._open = 0

    def ready(self) -> bool:
        try:
            with self.tx("") as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001 - /readyz answers no, the log has the reason
            return False

    # -- schema ----------------------------------------------------------------------------------
    def version(self) -> int:
        with self.tx("") as conn:
            exists = conn.execute("SELECT to_regclass('a2vm_meta.versions') IS NOT NULL").fetchone()[0]
            if not exists:
                return 0
            row = conn.execute("SELECT version FROM a2vm_meta.versions WHERE component = %s", (self.component,))
            found = row.fetchone()
            return int(found[0]) if found else 0

    def init(self) -> int:
        """Create or update the component's tables; the version reached. Safe to run from several
        replicas at once: one applies the changes, the others wait and find them done."""
        with self.tx("") as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))
            conn.execute("CREATE SCHEMA IF NOT EXISTS a2vm_meta")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS a2vm_meta.versions (component text PRIMARY KEY, "
                "version integer NOT NULL, at timestamptz NOT NULL DEFAULT now())"
            )
            row = conn.execute("SELECT version FROM a2vm_meta.versions WHERE component = %s", (self.component,))
            found = row.fetchone()
            current = int(found[0]) if found else 0
            for m in self.migrations:
                if m.version > current:
                    conn.execute(m.sql)
                    current = m.version
            conn.execute(
                "INSERT INTO a2vm_meta.versions (component, version) VALUES (%s, %s) "
                "ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, at = now()",
                (self.component, current),
            )
        return current


def open_database(component: str, migrations: list[Migration], size: int = 8) -> Database | None:
    """The tenant's database when one is configured (created or updated), else None."""
    dsn = dsn_from_env()
    if not dsn:
        return None
    db = Database(dsn, component, migrations, size=size)
    db.init()
    return db
