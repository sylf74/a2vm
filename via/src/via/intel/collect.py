# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Collect vulnerability records: CVE JSON 5 record + KEV + EPSS (+ GTI when enabled), merged into one
VulnRecord each.

With a shared intelligence service (D17, v0.22.0, `sources.intel_url`), the records come from it:
collected and enriched once for every tenant. When it cannot answer, the job reads the sources
itself and says so."""

from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from a2vm.models import REJECTED, VulnRecord

from .gti import enrich
from .packages import SOURCES as PACKAGE_SOURCES
from .packages import parse as parse_packages
from .record import parse_record
from .remote import IntelClient, IntelError
from .sources import SourceError, Sources


@dataclass
class Collection:
    requested: list[str]
    records: list[VulnRecord] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # enrichment log lines (GTI)


def select_cve_ids(
    sources: Sources,
    explicit: list[str],
    since: dt.datetime | None = None,
    include_updated: bool = False,
) -> list[str]:
    """Explicit ids first, then CVEs published since `since` and KEV additions since that day."""
    ids: list[str] = []
    for cve in explicit:
        cve = cve.strip().upper()
        if cve and cve not in ids:
            ids.append(cve)
    if since:
        for cve in sources.new_cve_ids(since, include_updated) + sources.kev_added_since(since.date()):
            if cve not in ids:
                ids.append(cve)
    return ids


def _fetch(sources: Sources, cve_id: str) -> tuple[dict[str, Any] | None, Exception | None]:
    try:
        return sources.cve_record(cve_id), None
    except (SourceError, ValueError) as exc:
        return None, exc


def collect(sources: Sources, cve_ids: list[str], packages: bool = False) -> Collection:
    """The records of `cve_ids`; with `packages`, the package advisories of the distributions too
    (the watch, to match the hosts' packages, D20)."""
    kw = {"packages": True} if packages else {}
    if sources.settings.intel_url and not sources.fixtures and cve_ids:
        try:
            return collect_shared(sources, cve_ids, **kw)
        except IntelError as exc:
            out = collect_direct(sources, cve_ids, **kw)
            out.notes.insert(0, f"intel: {exc}; records read from the sources directly")
            return out
    return collect_direct(sources, cve_ids, **kw)


def collect_shared(sources: Sources, cve_ids: list[str], transport=None, packages: bool = False) -> Collection:  # noqa: ANN001
    """The records from the shared intelligence service."""
    client = IntelClient.from_settings(sources.settings, transport)
    assert client is not None
    try:
        records, errors, notes = client.records(cve_ids, packages=packages)
    finally:
        client.close()
    out = Collection(requested=list(cve_ids), records=records, errors=errors, notes=notes)
    out.notes.append(f"intel: {len(records)}/{len(cve_ids)} records from the shared service")
    return out


def add_packages(sources: Sources, records: list[VulnRecord]) -> list[str]:
    """The package advisories of each record (D20), from the distributions configured; a source
    that fails loses only its advisories, said in the notes."""
    wanted = [s for s in sources.settings.packages_sources if s in PACKAGE_SOURCES]
    if not wanted or not records:
        return []
    failures: dict[str, str] = {}

    def one(record: VulnRecord) -> None:
        found: list[dict[str, str]] = []
        for source in wanted:
            try:
                found += parse_packages(source, sources.package_advisory(source, record.cve_id))
            except (SourceError, ValueError, TypeError, KeyError, AttributeError) as exc:
                failures.setdefault(source, f"{record.cve_id}: {exc}")
        record.packages = found

    workers = max(1, getattr(sources.settings, "fetch_workers", 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, records))
    with_any = sum(1 for r in records if r.packages)
    notes = [f"packages: advisories of {', '.join(wanted)} for {with_any}/{len(records)} records"]
    notes += [f"packages: {source} not read ({detail})" for source, detail in sorted(failures.items())]
    return notes


def collect_direct(sources: Sources, cve_ids: list[str], packages: bool = False) -> Collection:
    out = Collection(requested=list(cve_ids))
    kev = sources.kev()
    epss = sources.epss(cve_ids)
    workers = max(1, getattr(sources.settings, "fetch_workers", 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fetched = list(pool.map(lambda c: _fetch(sources, c), cve_ids))
    for cve_id, (raw, exc) in zip(cve_ids, fetched, strict=True):
        if exc is not None:
            out.errors.append({"cve": cve_id, "error": str(exc)})
            continue
        if raw is None:
            out.errors.append({"cve": cve_id, "error": "CVE record not found"})
            continue
        try:
            record = parse_record(raw)
        except ValueError as exc:
            out.errors.append({"cve": cve_id, "error": f"unreadable record: {exc}"})
            continue
        if record.state.upper() == "REJECTED":
            out.errors.append({"cve": cve_id, "error": REJECTED})
            continue
        record.kev = kev.get(cve_id)
        if cve_id in epss:
            record.epss, record.epss_percentile = epss[cve_id]
            record.epss_date = sources.epss_dates.get(cve_id)
        out.records.append(record)
    if getattr(sources.settings, "gti_enabled", False):
        out.notes = enrich(sources, out.records)
    if packages:
        out.notes += add_packages(sources, out.records)
    return out
