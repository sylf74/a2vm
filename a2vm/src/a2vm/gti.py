# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Reading the Google Threat Intelligence view of a record (filled by via.intel.gti) as SSVC input.

Kept in core so that verdict and alert interpret GTI the same way without depending on intel.
"""

from __future__ import annotations

from typing import Any

RANK = {"none": 0, "poc": 1, "active": 2}  # SSVC Exploitation values, weakest first


def ssvc_exploitation(gti: dict[str, Any] | None) -> tuple[str | None, str]:
    """GTI view -> (SSVC Exploitation value or None, note for the analyst).

    Confirmed / Wide exploitation -> active. A public or trivial exploit -> poc. Reported / Suspected
    exploitation is not confirmed: it does not raise the value on its own, it is flagged for review.
    """
    if not gti:
        return None, ""
    state, avail = gti.get("exploitation_state", ""), gti.get("exploit_availability", "")
    detail = f"GTI : exploitation « {state or 'n/a'} », exploit « {avail or 'n/a'} »"
    if gti.get("first_exploitation"):
        detail += f", première exploitation {gti['first_exploitation']}"
    if state in ("confirmed", "wide"):
        return "active", detail
    if avail in ("publicly available", "trivial"):
        return "poc", detail
    if state in ("no known", "none") and avail in ("none", "", "unavailable"):
        return "none", detail
    return None, detail


def gti_unconfirmed(gti: dict[str, Any] | None) -> bool:
    """GTI reports or suspects exploitation without confirming it (worth an analyst's look)."""
    return bool(gti) and gti.get("exploitation_state") in ("reported", "suspected")
