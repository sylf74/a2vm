# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Priorities and SLA of a client (HLD D19, v0.21.0): a library of the common contract owned by
pillar 3, like `a2vm.ssvc`.

The BOD 26-04 timelines are the default SLA. A client may set its own priorities and their delays
in its profile (`client.yaml`, section `sla`), within the levels: ACT, ATTEND and TRACK stay the
SSVC decision and the policy (D4); the client's rules only sort the decisions into priorities with
free names (P0..Pn, Q0...). The first rule that matches a decision gives its priority; a decision
that no rule matches has none, and its BOD 26-04 due date stays its only one.

The delay of a priority starts on the day verdict puts the decision into it (the run that
publishes it to the portal and to the ITSM), a day in the client's time zone, and is counted in
calendar days (24/7, follow the sun) or in business days (no weekend, no public holiday), set for
the client and overridden by a rule. A due date announced is never moved later while the decision
stays in a priority:

- a priority that goes up gives a new delay from the change, never beyond the due date already set;
- a priority that goes down keeps the due date already announced.

Everything here is deterministic (D11): no LLM, the rule applied is recorded on each decision and
the BOD 26-04 due date is kept beside it for comparison.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

CALENDARS = ("calendar", "business")
HOLIDAY_SETS = ("FR",)
LEVELS = ("ACT", "ATTEND", "TRACK")
EXPOSURES = ("open", "controlled", "small")
CRITERIA = ("level", "kev", "exposure", "zone", "epss", "cvss", "cmdb")
# Where the start of a delay comes from: the run that put the decision into its priority (with the
# history of the tenant's database), the history (the priority did not change), the day the level
# was set (a decision known before the client's SLA, v0.21.0 upgrade), the first observation (no
# history: the GitLab pipeline mode, or the decision service not reached).
SINCE_SOURCES = ("run", "history", "level_since", "first_seen")
SOON_DAYS = 7


class SlaError(ValueError):
    """The `sla` section of a profile is not valid."""


# -- public holidays ----------------------------------------------------------------------------
def easter(year: int) -> dt.date:
    """Easter Sunday of the Gregorian calendar (anonymous algorithm, Meeus/Jones/Butcher)."""
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7  # noqa: E741 - the algorithm's name
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = (h + l - 7 * m + 114) % 31 + 1
    return dt.date(year, month, day)


@lru_cache(maxsize=64)
def holidays_fr(year: int) -> frozenset[dt.date]:
    """The eleven public holidays of metropolitan France (Code du travail L3133-1)."""
    e = easter(year)
    fixed = [(1, 1), (5, 1), (5, 8), (7, 14), (8, 15), (11, 1), (11, 11), (12, 25)]
    moving = [e + dt.timedelta(days=1), e + dt.timedelta(days=39), e + dt.timedelta(days=50)]
    return frozenset([dt.date(year, m, d) for m, d in fixed] + moving)


HOLIDAYS = {"FR": holidays_fr}


@dataclass(frozen=True)
class Calendar:
    """How days are counted: `calendar` (every day) or `business` (Monday to Friday, less the public
    holidays of `holidays` and the days of `extra`)."""

    kind: str = "calendar"
    holidays: tuple[str, ...] = ()
    extra: frozenset[dt.date] = frozenset()

    def working(self, day: dt.date) -> bool:
        if self.kind == "calendar":
            return True
        if day.weekday() >= 5 or day in self.extra:
            return False
        return not any(day in HOLIDAYS[code](day.year) for code in self.holidays)

    def add(self, start: dt.date, days: int) -> dt.date:
        """The day `days` days after `start` (the day of the start counts as day 0)."""
        if self.kind == "calendar":
            return start + dt.timedelta(days=days)
        day, left = start, days
        while left > 0:
            day += dt.timedelta(days=1)
            if self.working(day):
                left -= 1
        return day

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {"calendar": self.kind}
        if self.kind == "business":
            out["holidays"] = list(self.holidays)
            if self.extra:
                out["extra_holidays"] = sorted(d.isoformat() for d in self.extra)
        return out


@dataclass(frozen=True)
class Rule:
    index: int  # 1-based position in the client's list
    priority: str
    days: int
    when: dict[str, Any]
    calendar: Calendar
    rank: int  # position of the priority among the priorities, the first named first (0 = most urgent)


@dataclass
class SlaPolicy:
    timezone: str
    calendar: Calendar
    rules: list[Rule] = field(default_factory=list)

    @property
    def priorities(self) -> list[str]:
        return list(dict.fromkeys(r.priority for r in self.rules))

    def today(self, at: str) -> dt.date:
        """The day of a moment (ISO 8601, a run's `generated_at`) in the client's time zone."""
        moment = dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.UTC)
        return moment.astimezone(ZoneInfo(self.timezone)).date()

    def classify(self, facts: dict[str, Any]) -> Rule | None:
        return next((r for r in self.rules if matches(r.when, facts)), None)

    def describe(self) -> dict[str, Any]:
        """The policy as the triage file records it: the rules in force for this run."""
        return {
            "timezone": self.timezone,
            **self.calendar.describe(),
            "priorities": self.priorities,
            "rules": [
                {"rule": r.index, "priority": r.priority, "days": r.days, "when": r.when, **r.calendar.describe()}
                for r in self.rules
            ],
        }


# -- the profile's section --------------------------------------------------------------------------
def _days(values: Any, where: str) -> frozenset[dt.date]:
    out = set()
    for v in values or []:
        try:
            out.add(v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v)))
        except ValueError as exc:
            raise SlaError(f"{where}: {v!r} is not a day YYYY-MM-DD") from exc
    return frozenset(out)


def _holidays(value: Any, where: str) -> tuple[str, ...]:
    codes = [value] if isinstance(value, str) else list(value or [])
    for code in codes:
        if code not in HOLIDAYS:
            raise SlaError(f"{where}: public holidays {code!r} unknown (known: {', '.join(HOLIDAY_SETS)})")
    return tuple(dict.fromkeys(codes))


def _calendar(data: dict[str, Any], base: Calendar | None, where: str) -> Calendar:
    kind = data.get("calendar", base.kind if base else "calendar")
    if kind not in CALENDARS:
        raise SlaError(f"{where}: calendar {kind!r}: calendar or business")
    holidays = _holidays(data["holidays"], where) if "holidays" in data else (base.holidays if base else ())
    extra = _days(data["extra_holidays"], where) if "extra_holidays" in data else (base.extra if base else frozenset())
    return Calendar(kind, holidays, extra)


def _check_when(when: dict[str, Any], where: str) -> None:
    for key in when:
        if key not in CRITERIA:
            raise SlaError(f"{where}: unknown criterion {key!r} (known: {', '.join(CRITERIA)})")
    for value in _values(when.get("level")):
        if str(value).upper() not in LEVELS:
            raise SlaError(f"{where}: level {value!r}: ACT, ATTEND or TRACK")
    for value in _values(when.get("exposure")):
        if value not in EXPOSURES:
            raise SlaError(f"{where}: exposure {value!r}: open, controlled or small")
    for key in ("epss", "cvss"):
        v = when.get(key)
        if v is not None and not isinstance(v, (int, float, dict)):
            raise SlaError(f"{where}: {key}: a number (at least) or {{min, max}}")
    if "cmdb" in when and not isinstance(when["cmdb"], dict):
        raise SlaError(f"{where}: cmdb: fields of the configuration item, e.g. {{criticality: high}}")


PRIORITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$")


def parse(data: dict[str, Any] | None, where: str = "sla") -> SlaPolicy | None:
    """The client's SLA from the `sla` section of its profile; None without one (BOD 26-04 only)."""
    if not data:
        return None
    timezone = str(data.get("timezone") or "UTC")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SlaError(f"{where}: time zone {timezone!r} unknown (e.g. Europe/Paris)") from exc
    calendar = _calendar(data, None, where)
    rules: list[Rule] = []
    ranks: dict[str, int] = {}
    for i, r in enumerate(data.get("rules") or [], start=1):
        at = f"{where}/rules/{i}"
        priority = str(r.get("priority") or "")
        if not PRIORITY.match(priority):
            raise SlaError(f"{at}: priority {priority!r}: a short name (P0, P1, Q0...)")
        days = r.get("days")
        if not isinstance(days, int) or isinstance(days, bool) or days < 0:
            raise SlaError(f"{at}: days: a whole number of days, 0 or more")
        when = dict(r.get("when") or {})
        _check_when(when, at)
        rank = ranks.setdefault(priority, len(ranks))
        rules.append(Rule(i, priority, days, when, _calendar(r, calendar, at), rank))
    if not rules:
        raise SlaError(f"{where}: rules: at least one rule")
    return SlaPolicy(timezone, calendar, rules)


# -- matching ---------------------------------------------------------------------------------------
def _values(want: Any) -> list[Any]:
    if want is None:
        return []
    return list(want) if isinstance(want, (list, tuple)) else [want]


def _text_in(value: Any, want: Any) -> bool:
    have = str(value or "").casefold()
    return any(have == str(w).casefold() for w in _values(want))


def _number_in(value: Any, want: Any) -> bool:
    if value is None:
        return False
    if isinstance(want, dict):
        low, high = want.get("min"), want.get("max")
        return (low is None or value >= low) and (high is None or value <= high)
    return value >= want


def matches(when: dict[str, Any], facts: dict[str, Any]) -> bool:
    """Every criterion of `when` holds for the decision's `facts` (an empty `when` matches all):

    level, exposure, zone   one value or a list (any of them); text compared without case
    kev                     true or false
    epss, cvss              a number (at least that), or {min, max} (both included)
    cmdb                    fields of the asset's configuration item (criticality, class, status,
                            organization, type... any field the CMDB connector reads), each one value
                            or a list; an asset without an item matches no cmdb criterion
    """
    for key, want in when.items():
        if key in ("level", "exposure", "zone"):
            if not _text_in(facts.get(key), want):
                return False
        elif key == "kev":
            if bool(facts.get("kev")) != bool(want):
                return False
        elif key in ("epss", "cvss"):
            if not _number_in(facts.get(key), want):
                return False
        elif key == "cmdb":
            item = facts.get("cmdb") or {}
            if not item or not all(_text_in(item.get(f), w) for f, w in want.items()):
                return False
        else:
            return False
    return True


# -- the delay of a decision -----------------------------------------------------------------------
@dataclass
class Previous:
    """What the tenant's database knows of an open finding before this run (LLD triage §17)."""

    level: str
    level_since: dt.date | None = None
    sla: dict[str, Any] | None = None  # None: no SLA computed yet (before v0.21.0, or no `sla` section)


def day(value: Any) -> dt.date | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def bod_due(bod_timeline: str, first_seen: str) -> str | None:
    """First observation + the BOD 26-04 delay ('3 days', '14 days & …'); none for 'fix on system
    upgrade'. Calendar days, as the BOD counts them."""
    m = re.match(r"(\d+) days", bod_timeline or "")
    start = day(first_seen)
    if not m or start is None:
        return None
    return (start + dt.timedelta(days=int(m.group(1)))).isoformat()


def carry(
    rule: Rule | None,
    today: dt.date,
    level: str,
    first_seen: dt.date | None,
    previous: Previous | None,
    history: bool,
) -> dict[str, Any]:
    """The priority and SLA due date of a decision on `today` (see the module's docstring).

    `history`: the run knows the state of the tenant's database (a finding absent from it is new);
    without it, the delay starts at the first observation. Returns the `sla` of the decision:
    priority, rank, rule, days, calendar, since, since_source, due; {"priority": ""} without a rule.
    """
    if rule is None:
        return {"priority": ""}
    add = rule.calendar.add
    before = previous.sla if previous else None
    if previous is None:
        since, source = (today, "run") if history else (first_seen or today, "first_seen")
        due = add(since, rule.days)
    elif before is None:
        if previous.level == level and previous.level_since and previous.level_since <= today:
            since, source = previous.level_since, "level_since"
        else:
            since, source = today, "run"
        due = add(since, rule.days)
    elif before.get("priority") == rule.priority and day(before.get("since")):
        since, source = day(before["since"]), "history"
        due = add(since, rule.days)
        if day(before.get("due")):
            due = min(due, day(before["due"]))
    else:
        since, source = today, "run"
        due = add(today, rule.days)
        if before.get("priority") and day(before.get("due")):
            due = min(due, day(before["due"]))
    return {
        "priority": rule.priority,
        "rank": rule.rank,
        "rule": rule.index,
        "days": rule.days,
        **rule.calendar.describe(),
        "since": since.isoformat(),
        "since_source": source,
        "due": due.isoformat(),
    }


def deadline(sla: dict[str, Any] | None, bod: str | None) -> str | None:
    """The due date a decision must meet: its SLA due date when it has a priority, else BOD 26-04."""
    if sla and sla.get("priority") and sla.get("due"):
        return str(sla["due"])
    return bod


def status(due: str | None, today: dt.date, fixed_on: dt.date | None = None) -> str | None:
    """Respect of a due date: `met` (fixed on or before it), `missed` (fixed after), `overdue` (open,
    past it), `on-track` (open, not past it); None without a due date."""
    end = day(due)
    if end is None:
        return None
    if fixed_on is not None:
        return "met" if fixed_on <= end else "missed"
    return "overdue" if today > end else "on-track"
