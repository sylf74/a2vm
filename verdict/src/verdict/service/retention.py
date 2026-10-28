# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Retention of the analysts' chats (HLD §8, LLD triage-prioritization §16.7), `verdict chat-retention`.

Runs next to Open WebUI, in its pod, on its database (SQLite on the chat's volume): every hour,
the chats not changed for `--days` days are deleted the way Open WebUI deletes a chat (its runs of
automations detached, its messages, its shared copies and its file links removed, then the chat),
in one transaction. Open WebUI has no setting for it. The tables are those of the Open WebUI version
of the chart (`chat.image.tag`); a table that does not exist is skipped, a `chat` table without its
columns stops the retention with an error rather than deleting blindly.
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import time
from pathlib import Path

log = logging.getLogger("verdict.chat-retention")
# (table, statement) in the order of Open WebUI's delete_chat_by_id, then the chat itself.
DEPENDENTS = (
    ("automation_run", "UPDATE automation_run SET chat_id = NULL WHERE chat_id IN ({ids})"),
    ("chat_message", "DELETE FROM chat_message WHERE chat_id IN ({ids})"),
    ("shared_chat", "DELETE FROM shared_chat WHERE chat_id IN ({ids})"),
    ("chat_file", "DELETE FROM chat_file WHERE chat_id IN ({ids})"),
)
BATCH = 200


def _tables(db: sqlite3.Connection) -> set[str]:
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def purge(path: str | Path, days: int, now: float | None = None) -> int:
    """Delete the chats not updated for `days` days; return how many."""
    if days <= 0:
        return 0
    cutoff = int((now or time.time()) - days * 86400)
    db = sqlite3.connect(str(path), timeout=30)
    try:
        tables = _tables(db)
        if "chat" not in tables:
            return 0  # Open WebUI has not created its database yet
        columns = {r[1] for r in db.execute("PRAGMA table_info(chat)")}
        if not {"id", "updated_at"} <= columns:
            raise RuntimeError("table chat without id and updated_at: Open WebUI changed, retention stopped")
        deleted = 0
        while True:
            ids = [r[0] for r in db.execute("SELECT id FROM chat WHERE updated_at < ? LIMIT ?", (cutoff, BATCH))]
            if not ids:
                return deleted
            marks = ",".join("?" * len(ids))
            with db:  # one transaction per batch
                for table, statement in DEPENDENTS:
                    if table in tables:
                        db.execute(statement.format(ids=marks), ids)
                db.execute(f"DELETE FROM chat WHERE id IN ({marks})", ids)  # noqa: S608 - placeholders only
            deleted += len(ids)
    finally:
        db.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="verdict chat-retention")
    parser.add_argument("--db", required=True, help="Open WebUI's database, e.g. /app/backend/data/webui.db")
    parser.add_argument("--days", type=int, required=True, help="chats unchanged for longer are deleted; 0 keeps all")
    parser.add_argument("--every", type=int, default=3600, help="seconds between two passes; 0: one pass")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("chats unchanged for %d days are deleted, every %d s", args.days, args.every)
    while True:
        try:
            if Path(args.db).exists():
                n = purge(args.db, args.days)
                if n:
                    log.info("deleted %d chat(s) unchanged for %d days", n, args.days)
        except (sqlite3.Error, RuntimeError) as exc:
            log.error("retention pass failed: %s", exc)
            if isinstance(exc, RuntimeError):
                return 2
        if args.every <= 0:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
