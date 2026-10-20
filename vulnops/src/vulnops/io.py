# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Exchange files between stages: JSON documents with a declared kind and schema version.

Every file a stage writes is validated against its JSON Schema before it is written, and every
file a stage reads is validated before it is used: a stage never consumes something it did not
expect, and a schema change shows up as a clear error at the boundary.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict, dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema

from .models import Asset, AssetObservation, Finding, NotAffected, VulnRecord

RECORDS = "vulnops.records/1"
DETECTION = "vulnops.detection/1"
ASSETS = "vulnops.assets/1"
FINDINGS = "vulnops.findings/2"

_SCHEMA_FILES = {
    RECORDS: "vulnerability_records",
    DETECTION: "detection",
    ASSETS: "assets",
    FINDINGS: "findings",
}


class ExchangeError(ValueError):
    pass


@cache
def load_schema(name: str) -> dict[str, Any]:
    text = resources.files("vulnops").joinpath("schemas", f"{name}.schema.json").read_text(encoding="utf-8")
    return json.loads(text)


def _validate(kind: str, data: dict[str, Any], where: str) -> None:
    validator = jsonschema.Draft202012Validator(load_schema(_SCHEMA_FILES[kind]))
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise ExchangeError(f"{where}: {path}: {e.message} ({len(errors)} error(s))")


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def _write(path: Path, kind: str, data: dict[str, Any]) -> Path:
    data = {"schema": kind, "generated_at": now(), **data}
    _validate(kind, data, str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def _read(path: Path, kind: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != kind:
        raise ExchangeError(f"{path}: expected a {kind} file, got {data.get('schema')!r}")
    _validate(kind, data, str(path))
    return data


# -- vulnerability records (intel -> detect, verdict) ------------------------------------------
def write_records(path: str | Path, records: list[VulnRecord], requested: list[str], errors: list[dict]) -> Path:
    return _write(
        Path(path),
        RECORDS,
        {"requested": requested, "records": [r.to_dict() for r in records], "errors": errors},
    )


def read_records(path: str | Path) -> tuple[list[str], dict[str, VulnRecord], list[dict]]:
    """(requested CVE ids in order, records by id, errors)."""
    data = _read(Path(path), RECORDS)
    records = {r["cve_id"]: VulnRecord.from_dict(r) for r in data["records"]}
    return data["requested"], records, data["errors"]


# -- detection output (detect connectors -> assets, intel) -------------------------------------
@dataclass
class Detection:
    client_id: str
    source: str
    observations: list[AssetObservation]
    findings: list[Finding]
    not_affected: list[NotAffected] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)


def write_detection(path: str | Path, d: Detection) -> Path:
    return _write(
        Path(path),
        DETECTION,
        {
            "client_id": d.client_id,
            "source": d.source,
            "observations": [asdict(o) for o in d.observations],
            "findings": [f.to_dict() for f in d.findings],
            "not_affected": [asdict(n) for n in d.not_affected],
            "skipped": d.skipped,
        },
    )


def read_detection(path: str | Path) -> Detection:
    data = _read(Path(path), DETECTION)
    return Detection(
        client_id=data["client_id"],
        source=data["source"],
        observations=[AssetObservation(**o) for o in data["observations"]],
        findings=[Finding.from_dict(f) for f in data["findings"]],
        not_affected=[NotAffected(**n) for n in data["not_affected"]],
        skipped=data["skipped"],
    )


def detection_files(directory: str | Path, client_id: str | None = None) -> list[Path]:
    """work/detect/<client>/<source>.json, for one client or all of them."""
    base = Path(directory)
    pattern = f"{client_id}/*.json" if client_id else "*/*.json"
    return sorted(base.glob(pattern))


# -- consolidated assets and findings (assets -> verdict) ----------------------------------------
def write_assets(path: str | Path, client_id: str, assets: list[Asset]) -> Path:
    return _write(Path(path), ASSETS, {"client_id": client_id, "assets": [a.to_dict() for a in assets]})


def read_assets(path: str | Path) -> tuple[str, dict[str, Asset]]:
    data = _read(Path(path), ASSETS)
    return data["client_id"], {a["id"]: Asset.from_dict(a) for a in data["assets"]}


def write_findings(path: str | Path, client_id: str, findings: list[Finding], not_affected: list[NotAffected]) -> Path:
    return _write(
        Path(path),
        FINDINGS,
        {
            "client_id": client_id,
            "findings": [f.to_dict() for f in findings],
            "not_affected": [asdict(n) for n in not_affected],
        },
    )


def read_findings(path: str | Path) -> tuple[str, list[Finding], list[NotAffected]]:
    data = _read(Path(path), FINDINGS)
    findings = [Finding.from_dict(f) for f in data["findings"]]
    not_affected = [NotAffected(**n) for n in data["not_affected"]]
    return data["client_id"], findings, not_affected
