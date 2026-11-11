# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.7: a lighter triage. The thinking of a reasoning model turned off, the LLM's answers kept
from one run to the next, a review only where an uncertain input could change the decision, and
what the LLM cost in each run."""

from __future__ import annotations

import json

import httpx
import pytest

from a2vm.config import LlmSettings, Settings, describe_llm, load_settings
from a2vm.llm import LlmClient
from a2vm.llm.cache import LlmCache
from a2vm.models import Assessed, Attribute, VulnRecord
from verdict.policy import Policy
from verdict.triage import CveInputs, Triage

from .conftest import ROOT, fake_llm_transport

SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"], "additionalProperties": False}


def _client(tmp_path, transport, **extra) -> LlmClient:
    s = LlmSettings(enabled=True, max_retries=0, **extra)
    return LlmClient(s, transport=transport)


# -- thinking ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(("value", "sent"), [("", None), ("off", False), ("on", True), ("false", False)])
def test_thinking(tmp_path, value, sent) -> None:
    transport = fake_llm_transport(lambda name, body: {"x": "y"})
    _client(tmp_path, transport, thinking=value).structured("s", "u", "q", SCHEMA)
    (body,) = transport.calls
    assert body.get("chat_template_kwargs", {}).get("enable_thinking") is sent


def test_thinking_and_cache_from_the_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("A2VM_LLM_THINKING", "off")
    monkeypatch.setenv("A2VM_LLM_CACHE_FILE", str(tmp_path / "c.json"))
    s = load_settings(ROOT / "config" / "settings.yaml")
    assert (s.llm.thinking, s.llm.cache_file, s.llm.cache_days) == ("off", str(tmp_path / "c.json"), 30)
    s.llm.enabled = True
    assert describe_llm(s).endswith(f", thinking off, cache {tmp_path / 'c.json'}")
    assert Policy.from_dict(s.policy).review == "decisive"
    with pytest.raises(ValueError, match="policy.review"):
        Policy.from_dict({"review": "some"})


# -- cache and usage --------------------------------------------------------------------------------
def test_the_same_question_is_asked_once(tmp_path) -> None:
    path = tmp_path / "cache" / "llm.json"

    def answer(name, body):
        return {"x": body["messages"][1]["content"].upper()}

    def server():
        calls: list[dict] = []

        def handler(request):
            calls.append(json.loads(request.content))
            content = json.dumps(answer("q", calls[-1]))
            usage = {"prompt_tokens": 100, "completion_tokens": 20}
            return httpx.Response(200, json={"choices": [{"message": {"content": content}}], "usage": usage})

        t = httpx.MockTransport(handler)
        t.calls = calls
        return t

    first = server()
    llm = _client(tmp_path, first, cache_file=str(path), thinking="off")
    assert llm.structured("s", "a", "q", SCHEMA) == {"x": "A"}
    assert llm.structured("s", "a", "q", SCHEMA) == {"x": "A"}  # same run: from the cache
    assert llm.structured("s", "b", "q", SCHEMA) == {"x": "B"}
    usage = llm.usage_summary()
    assert (usage["questions"], usage["from_cache"], usage["prompt_tokens"], usage["completion_tokens"]) == (
        3,
        1,
        200,
        40,
    )
    assert usage["thinking"] == "off" and len(first.calls) == 2
    llm.close()
    assert set(json.loads(path.read_text())["answers"]) and not path.with_suffix(".json.tmp").exists()

    second = server()  # the next run: nothing asked again
    llm = _client(tmp_path, second, cache_file=str(path), thinking="off")
    assert llm.structured("s", "a", "q", SCHEMA) == {"x": "A"} and second.calls == []
    other = _client(tmp_path, second, cache_file=str(path), thinking="on")  # another question
    other.structured("s", "a", "q", SCHEMA)
    assert len(second.calls) == 1


def test_cache_forgets_and_survives(tmp_path) -> None:
    path = tmp_path / "c.json"
    old = LlmCache(path, days=30, today="2026-09-01")
    old.put("k1", {"x": "1"})
    old.save()
    now = LlmCache(path, days=30, today="2026-11-11")
    assert now.get("k1") == {"x": "1"}  # read again: used today
    now.put("k2", {"x": "2"})
    now.save()
    assert set(json.loads(path.read_text())["answers"]) == {"k1", "k2"}
    later = LlmCache(path, days=30, today="2027-01-01")
    later.save()
    assert json.loads(path.read_text())["answers"] == {}
    path.write_text("not json")
    assert LlmCache(path).entries == {}  # a broken file: asked again, no failure
    blocked = LlmCache(tmp_path / "file" / "c.json")
    (tmp_path / "file").write_text("x")
    blocked.put("k", {"x": "1"})
    blocked.save()  # cannot write: a warning, no failure


def test_a_cached_answer_that_no_longer_fits_is_asked_again(tmp_path) -> None:
    path = tmp_path / "c.json"
    transport = fake_llm_transport(lambda name, body: {"x": "new"})
    llm = _client(tmp_path, transport, cache_file=str(path))
    from a2vm.llm.cache import question_key

    payload = {
        "model": llm.model, "temperature": 0,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
        "response_format": {"type": "json_schema", "json_schema": {"name": "q", "schema": SCHEMA, "strict": True}},
    }  # fmt: skip
    llm.cache.put(question_key(payload), {"y": "old"})
    assert llm.structured("s", "u", "q", SCHEMA) == {"x": "new"} and len(transport.calls) == 1


# -- review only where it matters -------------------------------------------------------------------
def _record(**extra) -> VulnRecord:
    base = dict(cve_id="CVE-2099-0701", state="PUBLISHED", published=None, description="", cwes=[], cvss=[],
                affected=[], adp_ssvc=None, adp_kev=None, references=[])  # fmt: skip
    return VulnRecord(**{**base, **extra})


def _inputs(
    exploitation=("none", "default"), automatable=("no", "cvss-heuristic"), impact=("partial", "cvss-heuristic")
):
    return CveInputs(_record(), Assessed(*exploitation), Assessed(*automatable), Assessed(*impact), ["noted"])


def _decisive(inputs, exposure=("controlled", "declared"), mission=("minimal", "declared")) -> bool:
    t = Triage(Settings())
    exp = Attribute(*exposure)
    mis = Attribute(*mission)
    wb = Attribute("minimal", "declared")
    mwi = "low" if mission[0] == "minimal" else "medium"
    return t._decisive(inputs, inputs.record, exp, mis, wb, mwi, exp.value == "open")


def test_review_only_when_a_doubt_changes_the_decision() -> None:
    sure = _inputs(exploitation=("none", "cisa-adp"), automatable=("no", "cisa-adp"), impact=("partial", "cisa-adp"))
    assert not _decisive(sure)
    assert _decisive(_inputs(), exposure=("open", "default"), mission=("essential", "default"))
    assert _decisive(_inputs(exploitation=("poc", "references"), automatable=("yes", "default")),
                     exposure=("open", "default"))  # fmt: skip


def test_review_all_as_before() -> None:
    s = Settings()
    s.policy = {"review": "all"}
    assert Triage(s).policy.review == "all"


def test_a_second_run_asks_nothing_again(settings, sources, profile, tmp_path) -> None:
    from verdict.report import write_json

    from .test_pipeline import _run

    def answer(name, body):
        if name == "ssvc_inputs":
            return {"automatable": "no", "technical_impact": "partial", "justification": "Local user required."}
        if name == "product_match":
            return {"same_product": False, "justification": "Mobile client, not the gateway OS."}
        return {"summary": "Decision.", "action": "Plan it."}

    settings.llm.enabled = True
    settings.llm.cache_file = str(tmp_path / "llm-cache.json")
    settings.llm.thinking = "off"
    first = fake_llm_transport(answer)
    llm = LlmClient(settings.llm, transport=first)
    run = _run(settings, sources, profile, llm)
    llm.close()
    asked = len(first.calls)
    assert asked > 0 and run.llm_usage["from_cache"] == 0 and run.llm_usage["thinking"] == "off"
    assert run.llm_usage["questions"] >= 1 and set(run.llm_usage) >= {"prompt_tokens", "completion_tokens", "seconds"}

    second = fake_llm_transport(answer)
    llm = LlmClient(settings.llm, transport=second)
    again = _run(settings, sources, profile, llm)
    llm.close()
    assert second.calls == []
    assert again.llm_usage["questions"] == again.llm_usage["from_cache"] == run.llm_usage["questions"]
    assert [r.delivery_decision for r in again.rows] == [r.delivery_decision for r in run.rows]
    write_json(again, tmp_path / "triage.json")
    assert json.loads((tmp_path / "triage.json").read_text())["llm_usage"]["from_cache"] > 0
    without = _run(Settings(), sources, profile)
    assert without.llm_usage == {}


def test_epss_rounded_in_the_rationale_facts() -> None:
    import inspect

    from verdict import rationale

    assert "round(row.epss, 2)" in inspect.getsource(rationale.rationale_facts)


def test_wiring() -> None:
    helpers = (ROOT / "deploy" / "charts" / "a2vm-tenant" / "templates" / "_helpers.tpl").read_text()
    assert 'A2VM_LLM_CACHE_FILE="${A2VM_LLM_CACHE_FILE:-/data/llm-cache.json}"' in helpers
    assert "A2VM_LLM_THINKING" in (ROOT / "templates" / "client-pipeline.yml").read_text()
    schema = json.loads((ROOT / "a2vm" / "src" / "a2vm" / "schemas" / "triage.schema.json").read_text())
    assert "llm_usage" in schema["properties"]
