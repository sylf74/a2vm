# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The LLM's answers kept from one run to the next (v0.23.7).

The daily run asks the same questions every morning: the rationale of a CVE whose facts did not
change, the SSVC inputs of a record without CVSS. A question is the model, the prompts and the
schema; its digest is the key. An answer comes back as long as the question is the same: a fact
that changes (KEV, EPSS rounded to 2 decimals, a new fix, another decision) makes a new question.
Answers not used for `days` days are forgotten when the file is saved. A file that cannot be read
is an empty cache: the run asks again, it does not fail.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("a2vm.llm")


def question_key(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class LlmCache:
    def __init__(self, path: str | Path, days: int = 30, today: str | None = None):
        self.path = Path(path)
        self.days = days
        self.today = today or dt.date.today().isoformat()
        self._lock = threading.Lock()
        self.entries: dict[str, dict[str, Any]] = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("answers"), dict):
                self.entries = data["answers"]
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.warning("LLM cache %s not read (%s): starting empty", self.path, exc)

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self.entries.get(key)
            if entry is None:
                return None
            entry["used"] = self.today
            return entry["answer"]

    def put(self, key: str, answer: dict[str, Any]) -> None:
        with self._lock:
            self.entries[key] = {"answer": answer, "used": self.today}

    def save(self) -> None:
        limit = (dt.date.fromisoformat(self.today) - dt.timedelta(days=self.days)).isoformat()
        with self._lock:
            self.entries = {k: v for k, v in self.entries.items() if str(v.get("used", "")) >= limit}
            data = {"answers": self.entries}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("LLM cache %s not saved: %s", self.path, exc)
