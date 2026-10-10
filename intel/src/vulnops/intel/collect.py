"""Collect vulnerability records: CVE JSON 5 record + KEV + EPSS, merged into one VulnRecord each."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from vulnops.core.models import VulnRecord

from .record import parse_record
from .sources import SourceError, Sources


@dataclass
class Collection:
    requested: list[str]
    records: list[VulnRecord] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


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


def collect(sources: Sources, cve_ids: list[str]) -> Collection:
    out = Collection(requested=list(cve_ids))
    kev = sources.kev()
    epss = sources.epss(cve_ids)
    for cve_id in cve_ids:
        try:
            raw = sources.cve_record(cve_id)
        except (SourceError, ValueError) as exc:
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
            out.errors.append({"cve": cve_id, "error": "CVE rejected"})
            continue
        record.kev = kev.get(cve_id)
        if cve_id in epss:
            record.epss, record.epss_percentile = epss[cve_id]
        out.records.append(record)
    return out
