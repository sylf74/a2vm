"""Best-effort comparison of vendor version strings against CVE JSON 5 version ranges.

Vendor versions are not standardized ("11.1.2-h3", "7.0.12 build 1234", "2.4.58p1"). The key
function below orders them well enough for the common cases; anything that cannot be decided
is reported as "unknown" so that a human reviews it instead of silently dropping the CVE.
"""

from __future__ import annotations

import re
from typing import Any

from .models import AffectedEntry

_TOKEN = re.compile(r"\d+|[a-z]+")
_PRERELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot", "m"}
_LOWEST = {"", "0", "*", "-", "n/a", "unspecified", "all"}

# Token ranks: prerelease < end-of-version < other suffixes (hotfix, patch...) < numbers.
_END = (1, "")


def version_key(version: str) -> tuple:
    tokens = _TOKEN.findall(version.strip().lower())
    key: list[tuple] = []
    for t in tokens:
        if t.isdigit():
            key.append((2, int(t)))
        elif t in _PRERELEASE:
            key.append((0, t))
        else:
            key.append((1, t))
    key.append(_END)
    return tuple(key)


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def _status_for_entry(deployed: str, v: dict[str, Any]) -> str | None:
    """Status of `deployed` according to one `versions[]` item, or None if not covered."""
    if v.get("versionType") == "git":
        return None
    status = v.get("status", "affected")
    start = str(v.get("version", "")).strip()
    less_than = v.get("lessThan")
    less_equal = v.get("lessThanOrEqual")

    if less_than is None and less_equal is None:
        if start.lower() in _LOWEST:
            return None
        return status if _cmp(deployed, start) == 0 else None

    if start.lower() not in _LOWEST and _cmp(deployed, start) < 0:
        return None
    if less_than is not None:
        upper = str(less_than).strip()
        if upper not in {"*", ""} and _cmp(deployed, upper) >= 0:
            return None
    else:
        upper = str(less_equal).strip()
        if upper not in {"*", ""} and _cmp(deployed, upper) > 0:
            return None

    for change in sorted(v.get("changes", []) or [], key=lambda c: version_key(str(c.get("at", "")))):
        if _cmp(deployed, str(change.get("at", ""))) >= 0:
            status = change.get("status", status)
    return status


def evaluate_entry(deployed: str, entry: AffectedEntry) -> str:
    """affected | unaffected | unknown for one deployed version and one affected block."""
    statuses = [s for s in (_status_for_entry(deployed, v) for v in entry.versions) if s]
    if "affected" in statuses:
        return "affected"
    if statuses:
        return "unaffected" if all(s == "unaffected" for s in statuses) else "unknown"
    default = (entry.default_status or "unknown").lower()
    return default if default in {"affected", "unaffected"} else "unknown"


def evaluate(deployed: str, entries: list[AffectedEntry]) -> str:
    """Combine CNA and ADP blocks: the CNA (vendor) statement wins when it is conclusive."""
    for source in ("cna", "adp"):
        results = [evaluate_entry(deployed, e) for e in entries if e.source == source]
        if not results:
            continue
        if "affected" in results:
            return "affected"
        if all(r == "unaffected" for r in results):
            return "unaffected"
    return "unknown"
