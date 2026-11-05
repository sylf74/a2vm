# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The client's priorities and SLA on the decisions of a run (HLD D19, v0.21.0; LLD §17).

After the SSVC decision and the policy have set each level, the rules of the profile's `sla` section
sort the decisions into the client's priorities (`a2vm.sla`): the first rule that matches gives the
priority and its delay. The start of the delay comes from the state of the tenant's database before
this run (`verdict sla-state`, a file given with `verdict run --sla-state`): the day the decision
entered its priority. Without that state (GitLab pipeline mode, decision service not reached), the
delay starts at the first observation of the finding, and the decisions say so (`since_source`).
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from a2vm import sla
from a2vm.models import TriageRow, TriageRun

STATE = "a2vm.sla_state/1"


class StateError(ValueError):
    """The state file is not one of this tenant."""


def read_state(path: str | Path, tenant: str, timezone: str = "UTC") -> dict[str, sla.Previous]:
    """Finding id -> what the tenant's database knew of it before this run (a file of `verdict sla-state`)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        return read_state_data(data, tenant, timezone)
    except StateError as exc:
        raise StateError(f"{path}: {exc}") from None


def _local_day(value: Any, timezone: str) -> dt.date | None:
    """The day of a moment of the database in the client's time zone (a plain day as it is)."""
    if not value:
        return None
    try:
        moment = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return sla.day(value)
    if moment.tzinfo is None:
        return moment.date()
    return moment.astimezone(ZoneInfo(timezone)).date()


def read_state_data(data: dict[str, Any], tenant: str, timezone: str = "UTC") -> dict[str, sla.Previous]:
    """The same from the answer of the decision service (`a2vm.sla_state/1`)."""
    if data.get("schema") != STATE or data.get("tenant") != tenant:
        raise StateError(f"not a state {STATE} of the tenant {tenant!r}")
    out: dict[str, sla.Previous] = {}
    for item in data.get("findings") or []:
        out[str(item["id"])] = sla.Previous(
            level=str(item.get("level") or ""),
            level_since=_local_day(item.get("level_since"), timezone),
            sla=item.get("sla") if isinstance(item.get("sla"), dict) else None,
        )
    return out


def facts(row: TriageRow, item: dict[str, Any] | None) -> dict[str, Any]:
    """What a rule of the SLA can test on a decision."""
    return {
        "level": row.delivery_decision,
        "kev": row.in_kev,
        "exposure": row.exposure,
        "zone": row.zone,
        "epss": row.epss,
        "cvss": row.cvss.score if row.cvss else None,
        "cmdb": item or {},
    }


def apply(run: TriageRun, state: dict[str, sla.Previous] | None = None) -> None:
    """Set `sla` on every decision of `run` from the client's rules; nothing without a `sla` section.

    `state`: the tenant's database before this run (None: unknown, the delays start at the first
    observation)."""
    policy: sla.SlaPolicy | None = run.client.sla
    if policy is None:
        return
    today = policy.today(run.generated_at)
    items = {a["id"]: (a.get("cmdb") or [{}])[0] for a in run.assets}
    history = state is not None
    for row in run.rows:
        rule = policy.classify(facts(row, items.get(row.asset_id_full)))
        previous = (state or {}).get(row.finding_id)
        row.sla = sla.carry(rule, today, row.delivery_decision, sla.day(row.first_seen), previous, history)
        row.sla["bod_due"] = sla.bod_due(row.bod_timeline, row.first_seen)
    run.sla = {**policy.describe(), "today": today.isoformat(), "history": history}


def counts(rows: list[TriageRow], today: str) -> dict[str, Any]:
    """Per priority, the open decisions on track and overdue, and the due within 7 days."""
    day = dt.date.fromisoformat(today)
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        p = (r.sla or {}).get("priority")
        if not p:
            continue
        c = out.setdefault(p, {"open": 0, "overdue": 0, "due_soon": 0, "rank": r.sla.get("rank", 0)})
        c["open"] += 1
        left = (dt.date.fromisoformat(r.sla["due"]) - day).days
        c["overdue"] += left < 0
        c["due_soon"] += 0 <= left <= sla.SOON_DAYS
    return dict(sorted(out.items(), key=lambda kv: (kv[1]["rank"], kv[0])))
