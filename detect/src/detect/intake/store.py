# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Where the detection service keeps what it accepted (LLD detection §8.2).

v0.13.0 keeps the detections on a volume, one folder per tenant and source; PostgreSQL replaces
it behind the same interface once the shared platform has it (D15 step 3).

  <root>/<tenant>/<source>/<id>.json.gz    the document as received (uncompressed digest in the id)
  <root>/<tenant>/<source>/<id>.meta.json  its receipt
  <root>/<tenant>/_keys/<sha256>           idempotency: collector and key -> id

Retention and "latest" are per source and collector: two collectors of one tenant (two networks)
may push the same source, and the daily run merges their latest detections.

Writes go to a temporary file renamed into place, so a reader never sees half a document.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

RID = re.compile(r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12}$")


@dataclass
class Receipt:
    id: str
    tenant: str
    collector: str
    source: str
    generated_at: str
    received_at: str
    digest: str
    duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not self.duplicate:
            data.pop("duplicate")
        return data


def parse_time(value: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def age_hours(generated_at: str, now: dt.datetime | None = None) -> float:
    now = now or dt.datetime.now(dt.UTC)
    return round((now - parse_time(generated_at)).total_seconds() / 3600, 2)


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class FileStore:
    def __init__(self, root: str | Path, keep: int = 14):
        self.root = Path(root)
        self.keep = max(1, keep)
        self._lock = threading.Lock()

    def _key_file(self, tenant: str, collector: str, key: str) -> Path:
        return self.root / tenant / "_keys" / hashlib.sha256(f"{collector}\0{key}".encode()).hexdigest()

    def known(self, tenant: str, collector: str, key: str) -> Receipt | None:
        """The receipt stored under this collector's idempotency key, read without the document."""
        key_file = self._key_file(tenant, collector, key)
        if not key_file.exists():
            return None
        receipt = self.receipt(tenant, key_file.read_text(encoding="utf-8").strip())
        if receipt is not None:
            receipt.duplicate = True
        return receipt

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
        """Store one accepted detection; `gzipped`, the body as received when it came compressed, is
        stored as it is (no second compression of a large document)."""
        now = now or dt.datetime.now(dt.UTC)
        source = document["source"]
        sha = hashlib.sha256(body).hexdigest()
        key_file = self._key_file(tenant, collector, key)
        with self._lock:
            known = self.known(tenant, collector, key)
            if known is not None:
                return known
            rid = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{sha[:12]}"
            receipt = Receipt(
                rid, tenant, collector, source, document["generated_at"], now.isoformat(timespec="seconds"), sha
            )
            folder = self.root / tenant / source
            _atomic(folder / f"{rid}.json.gz", gzipped if gzipped is not None else gzip.compress(body, 6))
            _atomic(folder / f"{rid}.meta.json", json.dumps(receipt.to_dict()).encode())
            _atomic(key_file, rid.encode())
            self._prune(folder, collector)
        return receipt

    def receipt(self, tenant: str, rid: str) -> Receipt | None:
        if not RID.match(rid):
            return None
        for s in self.sources(tenant):
            meta = self.root / tenant / s / f"{rid}.meta.json"
            if meta.exists():
                try:
                    return Receipt(**json.loads(meta.read_text(encoding="utf-8")))
                except (OSError, ValueError, TypeError):
                    return None
        return None

    def _receipts(self, folder: Path) -> list[Receipt]:
        out = []
        for meta in folder.glob("*.meta.json"):
            try:
                out.append(Receipt(**json.loads(meta.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(out, key=lambda r: (parse_time(r.generated_at), r.received_at))

    def _prune(self, folder: Path, collector: str) -> None:
        dropped = {r.id for r in [r for r in self._receipts(folder) if r.collector == collector][: -self.keep]}
        for rid in dropped:
            for suffix in (".json.gz", ".meta.json"):
                (folder / f"{rid}{suffix}").unlink(missing_ok=True)
        if dropped:  # the idempotency keys of the detections dropped go with them
            for key_file in (folder.parent / "_keys").glob("*"):
                try:
                    if key_file.read_text(encoding="utf-8").strip() in dropped:
                        key_file.unlink(missing_ok=True)
                except OSError:
                    continue

    def ready(self) -> bool:
        """The volume is mounted and writable."""
        return self.root.is_dir() and os.access(self.root, os.W_OK)

    def sources(self, tenant: str) -> list[str]:
        base = self.root / tenant
        return (
            sorted(p.name for p in base.iterdir() if p.is_dir() and not p.name.startswith("_")) if base.exists() else []
        )

    def latest(self, tenant: str, source: str | None = None) -> list[tuple[Receipt, dict[str, Any]]]:
        """The latest detection of each source and collector (the newest generated_at wins)."""
        out = []
        for s in [source] if source else self.sources(tenant):
            newest: dict[str, Receipt] = {}
            for r in self._receipts(self.root / tenant / s):
                newest[r.collector] = r  # sorted oldest first
            for collector in sorted(newest):
                found = self.get(tenant, newest[collector].id, s)
                if found:
                    out.append(found)
        return out

    def get(self, tenant: str, rid: str, source: str | None = None) -> tuple[Receipt, dict[str, Any]] | None:
        if not RID.match(rid):
            return None
        for s in [source] if source else self.sources(tenant):
            folder = self.root / tenant / s
            meta, doc = folder / f"{rid}.meta.json", folder / f"{rid}.json.gz"
            if meta.exists() and doc.exists():
                receipt = Receipt(**json.loads(meta.read_text(encoding="utf-8")))
                return receipt, json.loads(gzip.decompress(doc.read_bytes()))
        return None
