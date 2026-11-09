# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.2: the chat asks a period in days or dates and times (the tenant's time zone), the
alerts say when they were drafted, and the radar's validated events are a tool of the chat."""

from __future__ import annotations

import datetime as dt
import json

import httpx
import pytest

from a2vm.service import Problem, TokenSet, digest, moment

from .conftest import ROOT

READ = "read-token-0123456789abcdef012345678"
CHAT = "chat-token-0123456789abcdef0123456789"
TENANT = "example-client"


def test_moments() -> None:
    utc = dt.UTC
    assert moment("2026-11-07", tz="Europe/Paris") == dt.datetime(2026, 11, 6, 23, 0, tzinfo=utc)
    assert moment("2026-11-07", tz="Europe/Paris", end=True) == dt.datetime(2026, 11, 7, 22, 59, 59, 999999, tzinfo=utc)
    assert moment("2026-11-07T09:00", tz="Europe/Paris") == dt.datetime(2026, 11, 7, 8, 0, tzinfo=utc)
    assert moment("2026-11-07T09:00Z", tz="Europe/Paris") == dt.datetime(2026, 11, 7, 9, 0, tzinfo=utc)
    assert moment("2026-07-01T09:00", tz="Europe/Paris").hour == 7  # summer time
    with pytest.raises(Problem, match="until: a day"):
        moment("yesterday", "until")


# -- the watch service: alerts between two moments --------------------------------------------------
def _store_with_alerts(tmp_path):
    from via.service.store import WatchStore

    store = WatchStore(tmp_path / "store")
    for at, aid in ((dt.datetime(2026, 11, 6, 17, 30, tzinfo=dt.UTC), "early"),
                    (dt.datetime(2026, 11, 7, 7, 50, tzinfo=dt.UTC), "late")):  # fmt: skip
        index = [{"id": f"{TENANT}-{aid}", "level": "urgent", "title": aid, "cves": ["CVE-2026-0001"]}]
        store.put_run(
            TENANT, b"{}", [], {"index.json": json.dumps(index).encode(), f"{TENANT}-{aid}.md": b"# x"}, now=at
        )
    return store


def test_alerts_between_two_moments(tmp_path) -> None:
    from via.service.server import WatchService

    digests = tmp_path / "digests"
    digests.write_text(f"read {digest(READ)}\n")
    svc = WatchService(TENANT, TokenSet.load(digests, {"run", "read"}), _store_with_alerts(tmp_path))

    def ids(**q):
        return [a["title"] for a in svc.list_alerts(TENANT, READ, q)["items"]]

    assert ids() == ["late", "early"]
    assert ids(since="2026-11-06T18:00:00+00:00") == ["late"]
    assert ids(until="2026-11-07T07:00:00+00:00") == ["early"]
    assert ids(since="2026-11-06", until="2026-11-06") == ["early"]  # a day alone: all of it (UTC)
    assert ids(since="2026-11-07") == ["late"]
    page = svc.list_alerts(TENANT, READ, {})["items"]
    assert page[0]["drafted_at"] == "2026-11-07T07:50:00+00:00"
    with pytest.raises(Problem):
        svc.list_alerts(TENANT, READ, {"since": "hier"})


# -- the shared service: the feed by period and kind --------------------------------------------------
def _intel(tmp_path):
    from .test_v0220 import _service

    service = _service(tmp_path)
    for at, item in (
        (dt.datetime(2026, 11, 6, 17, 0, tzinfo=dt.UTC), {"id": "radar:a", "kind": "radar", "level": "urgent",
                                                          "title": "A", "cves": ["CVE-2026-0001"]}),
        (dt.datetime(2026, 11, 7, 6, 0, tzinfo=dt.UTC), {"id": "gti:CVE-2026-0002", "kind": "gti", "level": "info",
                                                         "title": "CVE-2026-0002", "cves": ["CVE-2026-0002"]}),
        (dt.datetime(2026, 11, 7, 7, 30, tzinfo=dt.UTC), {"id": "radar:b", "kind": "radar", "level": "info",
                                                          "title": "B", "cves": ["CVE-2026-0003"]}),
    ):  # fmt: skip
        service.store.add_to_feed(item, now=at)
    return service


def test_the_feed_by_period_and_kind(tmp_path) -> None:
    from .test_v0220 import READ as INTEL_READ

    service = _intel(tmp_path)

    def ids(since="", **q):
        return [i["id"] for i in service.feed(INTEL_READ, since, q)["items"]]

    assert ids() == ["radar:a", "gti:CVE-2026-0002", "radar:b"]
    mark = service.feed(INTEL_READ, "")["items"][0]["at"]
    assert ids(mark) == ["gti:CVE-2026-0002", "radar:b"]  # a watch's mark: after it, as before
    assert ids("2026-11-07T07:00:00+01:00", kind="radar") == ["radar:b"]
    assert ids("2026-11-06", until="2026-11-06") == ["radar:a"]
    assert ids(cve="cve-2026-0001") == ["radar:a"] and ids(level="info", kind="radar") == ["radar:b"]
    with pytest.raises(Problem):
        service.feed(INTEL_READ, "", {"kind": "other"})


# -- the chat's tools ---------------------------------------------------------------------------------
def _tools(tmp_path, handler, **kw):
    from verdict.service.tools import Tools

    digests = tmp_path / "chat-digests"
    digests.write_text(f"chat {digest(CHAT)}\n")
    return Tools(TENANT, TokenSet.load(digests, {"chat"}), "http://verdict.example", "unused",
                 transport=httpx.MockTransport(handler), timezone="Europe/Paris", **kw)  # fmt: skip


def test_the_radar_tool_in_the_tenant_time_zone(tmp_path) -> None:
    asked = []
    items = [
        {"id": "radar:a", "kind": "radar", "level": "urgent", "title": "A", "cves": ["CVE-2026-0001"],
         "at": "2026-11-06T17:00:00.000000+00:00", "summary": "s", "links": [], "score": 6, "terms": ["x"]},
        {"id": "gti:CVE-2026-0002", "kind": "gti", "level": "info", "title": "CVE-2026-0002",
         "products": [{"vendor": "v", "product": "secret technology"}], "at": "2026-11-07T06:00:00.000000+00:00"},
        {"id": "radar:b", "kind": "radar", "level": "info", "title": "B", "cves": [],
         "at": "2026-11-07T07:30:00.000000+00:00"},
    ]  # fmt: skip

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "intel.example" and request.url.path == "/v1/feed"
        asked.append(dict(request.url.params))
        return httpx.Response(200, json={"items": items, "next": items[-1]["at"]})

    tools = _tools(tmp_path, handler, intel_url="http://intel.example", intel_token="t")
    out = tools.call(CHAT, "/radar", {"since": "2026-11-06T18:00", "until": "2026-11-07"})
    assert asked[0] == {"since": "2026-11-06T17:00:00+00:00", "until": "2026-11-07T22:59:59.999999+00:00",
                        "kind": "radar"}  # fmt: skip
    assert [i["id"] for i in out["items"]] == ["radar:b", "radar:a"]  # newest first; never a GTI item
    assert out["total"] == 2 and out["counts"] == {"info": 1, "urgent": 1} and "terms" not in out["items"][1]
    assert "secret technology" not in json.dumps(out)
    tools.close()
    without = _tools(tmp_path, handler)
    with pytest.raises(Problem) as p:
        without.call(CHAT, "/radar", {})
    assert p.value.status == 503
    without.close()


def test_alerts_tool_takes_a_period(tmp_path) -> None:
    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    tools = _tools(tmp_path, handler, via_url="http://via.example", via_token="t")
    tools.call(CHAT, "/alerts", {"since": "2026-11-06T18:00", "until": "2026-11-07T09:00"})
    assert asked[0]["since"] == "2026-11-06T17:00:00+00:00" and asked[0]["until"] == "2026-11-07T08:00:00+00:00"
    with pytest.raises(Problem, match="since: a day"):
        tools.call(CHAT, "/alerts", {"since": "hier soir"})
    tools.close()


def test_tools_and_chart_wiring() -> None:
    from verdict.service.tools import OPERATIONS

    assert any(op[1] == "list_radar_events" and op[4] == "intel:feed" for op in OPERATIONS)
    params = next(op[3] for op in OPERATIONS if op[1] == "list_alerts")
    assert {"since", "until"} <= {p["name"] for p in params}
    chat = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "chat.yaml").read_text()
    assert "--intel-url={{ .Values.intel.url }}" in chat and "--timezone=" in chat and "key: intel-token" in chat
    intel = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "intel.yaml").read_text()
    assert intel.count("values: [daily, watch, send, tools]}") == 2


def test_release_recorded() -> None:
    import re

    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"^\| v0\.23\.2( \(current\))? \| The chat", hld, re.M)
    assert re.search(r"^\| v0\.23\.[2-9]( \(to confirm\)| \(current\))? \| D20: SentinelOne", hld, re.M)
    assert "## v0.23.2 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
