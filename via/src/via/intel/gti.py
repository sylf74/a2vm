# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Google Threat Intelligence (GTI, VirusTotal API v3) enrichment of vulnerability records.

One lookup per CVE: GET {gti_url}/collections/vulnerability--cve-yyyy-nnnn, header x-apikey. Only
the CVE id leaves the network; nothing about the client (assets, versions, exposure) is sent.

What is kept (record.gti) is a small, flat view: GTI's exploitation state and exploit availability
feed the SSVC "Exploitation" decision point (verdict.triage); the risk rating, consequence and
mitigations are shown to analysts. GTI's analyst prose (executive summary, analysis) is kept for
analysts only: it is licensed content, so it is neither sent to the LLM nor copied into client
deliverables.

Access needs a GTI Enterprise or Enterprise Plus licence. Disabled unless sources.gti_enabled
(or A2VM_GTI_ENABLED=true) and the API key variable (GTI_API_KEY by default) is set.
"""

from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from a2vm.gti import gti_unconfirmed, ssvc_exploitation  # noqa: F401  (re-exported)
from a2vm.models import VulnRecord

from .sources import SourceAuthError, SourceError, Sources

UI_URL = "https://www.virustotal.com/gui/collection/{id}"


def _norm(value: Any) -> str:
    """'EXPLOITATION_STATE_CONFIRMED', 'Confirmed', 'publicly_available' -> 'confirmed', 'publicly available'."""
    text = str(value or "").strip().lower().replace("_", " ")
    for prefix in ("exploitation state ", "exploit availability ", "risk rating "):
        text = text.removeprefix(prefix)
    return text


def _date(value: Any) -> str:
    if isinstance(value, (int, float)) and value > 0:
        return dt.datetime.fromtimestamp(value, dt.UTC).date().isoformat()
    return str(value or "")


def parse_gti(raw: dict[str, Any]) -> dict[str, Any]:
    """Flat view of a GTI vulnerability object (the `data` envelope or the object itself)."""
    obj = raw.get("data", raw)
    a = obj.get("attributes") or {}
    exploitation = a.get("exploitation") or {}
    rating = a.get("risk_rating") or ""
    view: dict[str, Any] = {
        "id": obj.get("id", ""),
        "url": UI_URL.format(id=obj.get("id", "")),
        "name": a.get("name", ""),
        "origin": a.get("origin", ""),
        "exploitation_state": _norm(a.get("exploitation_state")),
        "exploit_availability": _norm(a.get("exploit_availability")),
        "risk_rating": _norm(rating or a.get("predicted_risk_rating")),
        "risk_rating_predicted": not rating and bool(a.get("predicted_risk_rating")),
        "exploitation_consequence": a.get("exploitation_consequence") or "",
        "exploitation_vectors": list(a.get("exploitation_vectors") or []),
        "first_exploitation": _date(exploitation.get("first_exploitation")),
        "exploit_release_date": _date(exploitation.get("exploit_release_date")),
        "available_mitigation": list(a.get("available_mitigation") or []),
        "cisa_known_exploited": a.get("cisa_known_exploited") or None,
        "last_modification_date": _date(a.get("last_modification_date")),
        # analysts only (licensed prose): never sent to the LLM or to clients
        "executive_summary": (a.get("executive_summary") or "")[:3000],
    }
    return view


def _priority(record: VulnRecord) -> tuple:
    """Lookups go to the CVEs where GTI can change the decision first: not in KEV, then most severe."""
    metric = record.best_cvss()
    return (record.in_kev, -(metric.score or 0) if metric else 0, -(record.epss or 0))


def enrich(sources: Sources, records: list[VulnRecord]) -> list[str]:
    """Fill record.gti in place. Returns log lines (errors, budget, credentials); never raises."""
    settings = sources.settings
    notes: list[str] = []
    if not records:
        return notes
    if not sources.fixtures and not settings.gti_api_key:
        return [f"GTI: enabled but {settings.gti_api_key_env} is not set, lookups skipped"]

    ordered = sorted(records, key=_priority)
    stop: dict[str, str] = {}
    skipped = 0

    def lookup(record: VulnRecord) -> str | None:
        nonlocal skipped
        if stop:
            return None
        if not sources.gti_cached(record.cve_id) and sources.gti_calls >= settings.gti_max_calls:
            skipped += 1
            return None
        try:
            raw = sources.gti_vulnerability(record.cve_id)
        except SourceAuthError as exc:
            stop.setdefault("reason", str(exc))
            return None
        except (SourceError, ValueError) as exc:
            return f"GTI {record.cve_id}: {exc}"
        if raw:
            try:
                record.gti = parse_gti(raw)
            except (AttributeError, TypeError) as exc:
                return f"GTI {record.cve_id}: unreadable answer ({exc})"
        return None

    with ThreadPoolExecutor(max_workers=max(1, settings.gti_workers)) as pool:
        errors = [e for e in pool.map(lookup, ordered) if e]
    notes += errors[:20]
    if len(errors) > 20:
        notes.append(f"GTI: {len(errors) - 20} more lookup errors")
    if stop:
        notes.append(f"GTI: stopped, {stop['reason']}")
    if skipped:
        notes.append(f"GTI: budget of {settings.gti_max_calls} lookups reached, {skipped} CVE not looked up")
    found = sum(1 for r in records if r.gti)
    notes.append(f"GTI: {found}/{len(records)} CVE known to GTI ({sources.gti_calls} lookups, rest from cache)")
    return notes
