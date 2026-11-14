# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The next time of a cron schedule (v0.23.10): the daily run's CronJob, for the chat's « quand les
décisions seront-elles mises à jour ? ». Five fields (minute, hour, day of month, month, day of
week), each `*`, a number, a range `a-b`, a step `*/n` or `a-b/n`, or a list of them; day of week
0 to 7 (0 and 7: Sunday). When both day fields are restricted, either matches (cron's rule).
"""

from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo

RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


class ScheduleError(ValueError):
    pass


def _field(text: str, low: int, high: int) -> set[int]:
    out: set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) < 1:
                raise ScheduleError(f"bad step in {text!r}")
            step = int(s)
        if part == "*":
            a, b = low, high
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise ScheduleError(f"bad range in {text!r}")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
            if step > 1:
                b = high
        else:
            raise ScheduleError(f"bad field {text!r}")
        if not low <= a <= b <= high:
            raise ScheduleError(f"{text!r} out of {low}-{high}")
        out.update(range(a, b + 1, step))
    return out


def next_run(expr: str, after: dt.datetime, timezone: str = "UTC") -> dt.datetime:
    """The first time strictly after `after` that matches `expr`, in `timezone` (aware datetime)."""
    fields = expr.split()
    if len(fields) != 5:
        raise ScheduleError(f"{expr!r}: five fields expected")
    minutes, hours, days, months, weekdays = (_field(f, *r) for f, r in zip(fields, RANGES, strict=True))
    weekdays = {0 if d == 7 else d for d in weekdays}
    dom_any, dow_any = fields[2] == "*", fields[4] == "*"
    tz = ZoneInfo(timezone)
    t = after.astimezone(tz).replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    limit = t + dt.timedelta(days=366 * 5)
    while t < limit:
        if t.month not in months:
            t = (t.replace(day=1, hour=0, minute=0) + dt.timedelta(days=32)).replace(day=1)
            continue
        dom, dow = t.day in days, (t.isoweekday() % 7) in weekdays
        day_ok = dom and dow if (dom_any or dow_any) else dom or dow
        if not day_ok:
            t = t.replace(hour=0, minute=0) + dt.timedelta(days=1)
            continue
        if t.hour not in hours:
            t = t.replace(minute=0) + dt.timedelta(hours=1)
            continue
        if t.minute not in minutes:
            t += dt.timedelta(minutes=1)
            continue
        return t
    raise ScheduleError(f"{expr!r}: no time in five years")
