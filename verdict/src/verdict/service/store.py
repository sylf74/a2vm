# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Where the decision service keeps the runs it received (LLD triage-prioritization §15).

Files on the service's volume until PostgreSQL (D15), one folder per tenant:

  <root>/<tenant>/runs/<id>.json.gz     the triage document as received (gzip)
  <root>/<tenant>/runs/<id>.meta.json   its receipt: generated_at, received_at, digest, counts
  <root>/<tenant>/_keys/<sha256>        idempotency: key of the push -> id

The last `keep` runs by generated_at are kept. Writes go to a temporary file renamed into place.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

RID = re.compile(r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12}$")


@dataclass
class RunReceipt:
    id: str
    tenant: str
    generated_at: str
    received_at: str
    digest: str
    rows: int
    counts: dict[str, int] = field(default_factory=dict)
    duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not self.duplicate:
            data.pop("duplicate")
        return data


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def parse_time(value: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


class RunStore:
    def __init__(self, root: str | Path, keep: int = 7):
        self.root = Path(root)
        self.keep = max(1, keep)
        self._lock = threading.Lock()

    def ready(self) -> bool:
        return self.root.is_dir() and os.access(self.root, os.W_OK)

    def _key_file(self, tenant: str, key: str) -> Path:
        return self.root / tenant / "_keys" / hashlib.sha256(key.encode()).hexdigest()

    def known(self, tenant: str, key: str) -> RunReceipt | None:
        key_file = self._key_file(tenant, key)
        if not key_file.exists():
            return None
        receipt = self.receipt(tenant, key_file.read_text(encoding="utf-8").strip())
        if receipt is not None:
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
        with self._lock:
            known = self.known(tenant, key)
            if known is not None:
                return known
            rid = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{sha[:12]}"
            receipt = RunReceipt(
                rid,
                tenant,
                document["generated_at"],
                now.isoformat(timespec="seconds"),
                sha,
                len(document["rows"]),
                counts,
            )
            folder = self.root / tenant / "runs"
            _atomic(folder / f"{rid}.json.gz", gzipped if gzipped is not None else gzip.compress(body, 6))
            _atomic(folder / f"{rid}.meta.json", json.dumps(receipt.to_dict()).encode())
            _atomic(self._key_file(tenant, key), rid.encode())
            self._prune(tenant)
        return receipt

    def receipts(self, tenant: str) -> list[RunReceipt]:
        """Every run kept, oldest first (by generated_at, then received_at)."""
        out = []
        for meta in (self.root / tenant / "runs").glob("*.meta.json"):
            try:
                out.append(RunReceipt(**json.loads(meta.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(out, key=lambda r: (parse_time(r.generated_at), r.received_at))

    def receipt(self, tenant: str, rid: str) -> RunReceipt | None:
        if not RID.match(rid):
            return None
        meta = self.root / tenant / "runs" / f"{rid}.meta.json"
        try:
            return RunReceipt(**json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return None

    def latest(self, tenant: str) -> RunReceipt | None:
        receipts = self.receipts(tenant)
        return receipts[-1] if receipts else None

    def load(self, tenant: str, rid: str) -> dict[str, Any] | None:
        if not RID.match(rid):
            return None
        path = self.root / tenant / "runs" / f"{rid}.json.gz"
        if not path.exists():
            return None
        return json.loads(gzip.decompress(path.read_bytes()))

    def _prune(self, tenant: str) -> None:
        folder = self.root / tenant / "runs"
        dropped = {r.id for r in self.receipts(tenant)[: -self.keep]}
        for rid in dropped:
            for suffix in (".json.gz", ".meta.json"):
                (folder / f"{rid}{suffix}").unlink(missing_ok=True)
        if dropped:
            for key_file in (self.root / tenant / "_keys").glob("*"):
                try:
                    if key_file.read_text(encoding="utf-8").strip() in dropped:
                        key_file.unlink(missing_ok=True)
                except OSError:
                    continue
