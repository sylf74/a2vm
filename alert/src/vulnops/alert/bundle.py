# SPDX-License-Identifier: AGPL-3.0-only
"""Feed bundle: the public half of the watch, for deployments where public data is fetched on one
runner (e.g. in the cloud) and matched to the client on another (on-prem, with the local LLM).

`vulnops-alert discover` reads the sources, finds what is new and writes a bundle directory:

  items.json        the new items (publications already parsed), the errors met, baseline flag
  cves/<id>.json    CVE records of every CVE the items name
  kev.json          the CISA KEV catalogue
  epss.json         EPSS scores of those CVEs
  gti/<id>.json     GTI answers, when GTI is enabled

The layout is the one `Sources(fixtures_dir=...)` reads, so `vulnops-alert watch --bundle` runs the
same matching and alert code as a single-runner watch, without any network access. Nothing in a
bundle is about the client: the client profile is only read by the matching side.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vulnops.core.config import Settings
from vulnops.intel.sources import SourceAuthError, SourceError, Sources

from .certfr import Publication
from .watch import Item

BUNDLE_VERSION = 1
ITEMS_FILE = "items.json"


def item_to_dict(item: Item) -> dict[str, Any]:
    return asdict(item)


def item_from_dict(data: dict[str, Any]) -> Item:
    pub = data.get("publication")
    return Item(**{**data, "publication": Publication(**pub) if pub else None})


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def write_bundle(
    sources: Sources, settings: Settings, items: list[Item], errors: list[str], out: str | Path, baseline: bool
) -> list[str]:
    """Write the bundle of `items`; returns log lines. Source failures become bundle errors, not exceptions."""
    out = Path(out)
    if (out / ITEMS_FILE).exists():  # a previous bundle left in the build directory: start clean
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    errors = list(errors)
    notes: list[str] = []
    cves = sorted({c for it in items for c in it.cves})

    def fetch(cve: str) -> tuple[str, Any, str]:
        try:
            return cve, sources.cve_record(cve), ""
        except (SourceError, ValueError) as exc:
            return cve, None, str(exc)

    with ThreadPoolExecutor(max_workers=max(1, settings.sources.fetch_workers)) as pool:
        for cve, raw, err in pool.map(fetch, cves):
            if raw:
                _write_json(out / "cves" / f"{cve}.json", raw)
            elif err:
                errors.append(f"{cve}: {err}")

    try:
        _write_json(out / "kev.json", {"vulnerabilities": list(sources.kev().values())})
    except SourceError as exc:
        errors.append(f"KEV: {exc}")
    try:
        rows = [{"cve": c, "epss": s, "percentile": p} for c, (s, p) in sources.epss(cves).items()] if cves else []
        _write_json(out / "epss.json", {"data": rows})
    except SourceError as exc:
        errors.append(f"EPSS: {exc}")

    if settings.sources.gti_enabled and cves:
        found = 0
        for cve in cves:
            try:
                raw = sources.gti_vulnerability(cve)
            except SourceAuthError as exc:
                errors.append(f"GTI: {exc}")
                break
            except (SourceError, ValueError) as exc:
                errors.append(f"GTI {cve}: {exc}")
                continue
            if raw:
                found += 1
                _write_json(out / "gti" / f"{cve}.json", raw)
        notes.append(f"GTI: {found}/{len(cves)} CVE known to GTI")

    _write_json(
        out / ITEMS_FILE,
        {
            "version": BUNDLE_VERSION,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "baseline": baseline,
            "items": [item_to_dict(it) for it in items],
            "errors": errors,
        },
    )
    notes.append(f"bundle: {len(items)} items, {len(cves)} CVE records -> {out}")
    return notes


def read_bundle(path: str | Path) -> tuple[list[Item], bool, list[str]]:
    """(items, baseline, errors of the discovery side)."""
    data = json.loads((Path(path) / ITEMS_FILE).read_text(encoding="utf-8"))
    if data.get("version") != BUNDLE_VERSION:
        raise ValueError(f"{path}: bundle version {data.get('version')!r}, expected {BUNDLE_VERSION}")
    return [item_from_dict(d) for d in data.get("items", [])], bool(data.get("baseline")), list(data.get("errors", []))
