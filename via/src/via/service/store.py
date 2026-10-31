# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""What the watch service keeps for its tenant (LLD vulnerability-intelligence §3.7), on its volume:

  <root>/<tenant>/state.json                 what the watch has already seen (opaque to the service)
  <root>/<tenant>/inventory/<client>/assets.json, findings.json   the last daily inventory
  <root>/<tenant>/runs/<id>/                 one passage of the watch that drafted alerts: index.json
                                             and the alert sheets (Markdown, HTML, Word)
  <root>/<tenant>/edits/<alert id>.md        the English reference as a validator enriched it (review page)
  <root>/<tenant>/translations/<alert id>.<lang>.md, .json   a translation of the reference and its
                                             metadata (source, reference hash, who edited it)
  <root>/<tenant>/alerts-log.jsonl           the journal of the alerts (drafted, analysts, edited,
                                             validated, dismissed, sent, send-failed)

One writer (the service), each file written to a temporary name then renamed. Runs older than
`keep_days` are removed; the journal keeps its last lines (via.alert.journal). Since v0.18.0 the
tenant's PostgreSQL replaces these files when the tenant has one (`pgstore.PgWatchStore`, same
interface: the methods below that read through `file`, `events` and `translation` serve both).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import shutil
import threading
from pathlib import Path
from typing import Any

from via.alert import journal

RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$")
ALERT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,150}$")
INVENTORY_FILES = ("assets.json", "findings.json")
STATUSES = ("pending", "translating", "validated", "dismissed", "sent", "failed")
# The events that set the status of an alert; the last one wins (none: pending). A change of the
# English reference (`edited`) takes the alert back to pending: its translations are outdated.
STATUS_OF = {
    "edited": "pending",
    "translation-requested": "translating",
    "validated": "validated",
    "dismissed": "dismissed",
    "sent": "sent",
    "send-failed": "failed",
}
LANG = re.compile(r"^[a-z]{2}$")
EDIT_MAX = 100_000  # characters of a corrected sheet


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


class WatchStore:
    def __init__(self, root: str | Path, keep_days: int = 30):
        self.root = Path(root)
        self.keep_days = keep_days
        self._lock = threading.Lock()

    def describe(self) -> str:
        return f"files {self.root}"

    def ready(self) -> bool:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            probe = self.root / ".ready"
            probe.write_text("ok")
            probe.unlink()
            return True
        except OSError:
            return False

    def _t(self, tenant: str) -> Path:
        return self.root / tenant

    # -- state -----------------------------------------------------------------------------------
    def state(self, tenant: str) -> bytes | None:
        path = self._t(tenant) / "state.json"
        return path.read_bytes() if path.exists() else None

    # -- inventory -------------------------------------------------------------------------------
    def put_inventory(self, tenant: str, client: str, docs: dict[str, bytes]) -> dict[str, Any]:
        base = self._t(tenant) / "inventory" / client
        with self._lock:
            for name, data in docs.items():
                _atomic(base / name, data)
            meta = {"client": client, "received_at": _now().isoformat(), "files": sorted(docs)}
            _atomic(base / "meta.json", json.dumps(meta).encode())
        return meta

    def inventory(self, tenant: str, client: str, name: str) -> bytes | None:
        if name not in INVENTORY_FILES:
            return None
        path = self._t(tenant) / "inventory" / client / name
        return path.read_bytes() if path.exists() else None

    def inventory_meta(self, tenant: str, client: str) -> dict[str, Any] | None:
        path = self._t(tenant) / "inventory" / client / "meta.json"
        return json.loads(path.read_text()) if path.exists() else None

    # -- watch runs ------------------------------------------------------------------------------
    def put_run(
        self, tenant: str, state: bytes, events: list[dict], files: dict[str, bytes], now: dt.datetime | None = None
    ) -> dict[str, Any]:
        """One passage of the watch: its new state, its journal events and, when it drafted alerts,
        their files (index.json and the sheets)."""
        now = now or _now()
        rid = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
        with self._lock:
            index = json.loads(files["index.json"]) if "index.json" in files else []
            if index:
                run_dir = self._t(tenant) / "runs" / rid
                for name, data in files.items():
                    _atomic(run_dir / name, data)
                _atomic(
                    run_dir / "meta.json", json.dumps({"id": rid, "at": now.isoformat(), "alerts": len(index)}).encode()
                )
            _atomic(self._t(tenant) / "state.json", state)
            if events:
                journal.append(self._t(tenant) / "alerts-log.jsonl", events)
            self._prune(tenant, now)
        return {"run": rid if index else None, "alerts": len(index), "events": len(events)}

    def add_events(self, tenant: str, events: list[dict]) -> int:
        with self._lock:
            journal.append(self._t(tenant) / "alerts-log.jsonl", events)
        return len(events)

    def _prune(self, tenant: str, now: dt.datetime) -> None:
        cutoff = (now - dt.timedelta(days=self.keep_days)).strftime("%Y%m%dT%H%M%SZ")
        runs = self._t(tenant) / "runs"
        if runs.exists():
            for d in runs.iterdir():
                if RUN_ID.match(d.name) and d.name < cutoff:
                    shutil.rmtree(d, ignore_errors=True)

    def runs(self, tenant: str) -> list[str]:
        """Ids of the runs kept that drafted alerts, newest first."""
        base = self._t(tenant) / "runs"
        if not base.exists():
            return []
        return sorted((d.name for d in base.iterdir() if RUN_ID.match(d.name)), reverse=True)

    # -- alerts ----------------------------------------------------------------------------------
    def events(self, tenant: str) -> list[dict]:
        return journal.read(self._t(tenant) / "alerts-log.jsonl")

    # -- corrected sheets ------------------------------------------------------------------------
    def edit(self, tenant: str, alert_id: str) -> str | None:
        if not ALERT_ID.match(alert_id):
            return None
        path = self._t(tenant) / "edits" / f"{alert_id}.md"
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def put_edit(self, tenant: str, alert_id: str, text: str, event: dict) -> None:
        """The sheet a validator corrected, and its journal event, together."""
        if not ALERT_ID.match(alert_id):
            raise ValueError("invalid alert id")
        with self._lock:
            _atomic(self._t(tenant) / "edits" / f"{alert_id}.md", text.encode("utf-8"))
            journal.append(self._t(tenant) / "alerts-log.jsonl", [event])

    # -- translations --------------------------------------------------------------------------
    def reference(self, tenant: str, alert: dict[str, Any]) -> str:
        """The English reference of an alert: as enriched by a validator, else as the watch wrote it."""
        edited = self.edit(tenant, alert["id"])
        if edited is not None:
            return edited
        return (self.file(tenant, alert["run"], f"{alert['id']}.md") or b"").decode("utf-8", "replace")

    def translation(self, tenant: str, alert_id: str, lang: str) -> tuple[str | None, dict[str, Any] | None]:
        if not ALERT_ID.match(alert_id) or not LANG.match(lang):
            return None, None
        base = self._t(tenant) / "translations"
        meta_path, text_path = base / f"{alert_id}.{lang}.json", base / f"{alert_id}.{lang}.md"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else None
        text = text_path.read_text(encoding="utf-8") if text_path.is_file() else None
        return text, meta

    def put_translation(
        self, tenant: str, alert_id: str, lang: str, text: str | None, meta: dict[str, Any], event: dict
    ) -> None:
        """A translation (or why it failed: `meta["error"]`, no text) and its journal event, together."""
        if not ALERT_ID.match(alert_id) or not LANG.match(lang):
            raise ValueError("invalid alert id or language")
        base = self._t(tenant) / "translations"
        with self._lock:
            if text is not None:
                _atomic(base / f"{alert_id}.{lang}.md", text.encode("utf-8"))
            _atomic(base / f"{alert_id}.{lang}.json", json.dumps(meta, ensure_ascii=False).encode("utf-8"))
            journal.append(self._t(tenant) / "alerts-log.jsonl", [event])

    def detail(self, tenant: str, alert: dict[str, Any]) -> dict[str, Any]:
        """An alert with its reference hash, its last request of translations (recipients, languages)
        and the state of each translation: fresh (made from the current reference), outdated, failed."""
        from via.alert.translate import text_hash

        ref_hash = text_hash(self.reference(tenant, alert))
        evs = [e for e in self.events(tenant) if e.get("alert") == alert["id"]]
        request = next((e for e in reversed(evs) if e.get("event") == "translation-requested"), None)
        langs = list((request or {}).get("languages") or [])
        asked_now = bool(request) and request.get("reference") == ref_hash  # asked for the current reference
        translations = {}
        for lang in langs:
            _, meta = self.translation(tenant, alert["id"], lang)
            if meta is None:
                translations[lang] = {"state": "waiting"}
            elif meta.get("error"):
                retried = asked_now and str(request.get("at", "")) > str(meta.get("at", ""))
                state = "failed" if meta.get("source_hash") == ref_hash and not retried else "waiting"
                translations[lang] = {**meta, "state": state}
            else:
                fresh = meta.get("source_hash") == ref_hash
                state = "fresh" if fresh else "waiting" if asked_now else "outdated"
                translations[lang] = {**meta, "state": state}
        ready = request is not None and all(v["state"] == "fresh" for v in translations.values())
        return {
            **alert,
            "reference_hash": ref_hash,
            "request": {k: request[k] for k in ("to", "languages", "by", "at") if k in request} if request else None,
            "translations": translations,
            "ready": ready,
        }

    def alerts(self, tenant: str) -> list[dict[str, Any]]:
        """Every alert of the runs kept, newest first, with its status from the journal (STATUS_OF:
        the last of validated, dismissed, sent, send-failed; none: pending)."""
        by_alert: dict[str, list[dict]] = {}
        for e in self.events(tenant):
            by_alert.setdefault(e.get("alert", ""), []).append(e)
        out, seen = [], set()
        for rid in self.runs(tenant):
            try:
                index = json.loads(self.file(tenant, rid, "index.json") or b"[]")
            except ValueError:
                continue
            for entry in index:
                aid = entry.get("id", "")
                if not aid or aid in seen:
                    continue
                seen.add(aid)
                evs = by_alert.get(aid, [])
                marks = [e for e in evs if e.get("event") in STATUS_OF]
                status = STATUS_OF[marks[-1]["event"]] if marks else "pending"
                edited = any(e.get("event") == "edited" for e in evs)
                out.append({**entry, "run": rid, "status": status, "edited": edited, "events": evs[-10:]})
        return out

    def alert(self, tenant: str, alert_id: str) -> dict[str, Any] | None:
        if not ALERT_ID.match(alert_id):
            return None
        return next((a for a in self.alerts(tenant) if a["id"] == alert_id), None)

    def file(self, tenant: str, run: str, name: str) -> bytes | None:
        if not RUN_ID.match(run) or not FILE_NAME.match(name) or name == "meta.json":
            return None
        path = self._t(tenant) / "runs" / run / name
        return path.read_bytes() if path.is_file() else None

    @staticmethod
    def files_of(entry: dict[str, Any]) -> list[str]:
        """The files of one alert, as the watch names them: its sheet in Markdown and HTML, its Word file."""
        names = [f"{entry['id']}.md", f"{entry['id']}.html"]
        if entry.get("docx"):
            names.append(entry["docx"])
        names += [n for n in (entry.get("ctx") or {}).values() if isinstance(n, str)]
        return names
