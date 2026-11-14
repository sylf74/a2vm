# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Minimal client for an OpenAI-compatible chat completions API (vLLM, SGLang, llama.cpp server...).

Every call asks for a JSON object constrained by a JSON Schema (`response_format=json_schema`,
supported by vLLM/SGLang guided decoding). The answer is re-validated locally: a model that does
not honour the schema raises LlmError and the pipeline falls back to deterministic behaviour.

Several endpoints may serve the same model (`llm.base_url` as a list, v0.15.0): calls go to the
current one; when it cannot be reached, times out or answers 429 or 5xx, the call moves to the next
and later calls stay there. An answer that is not valid JSON is retried on the same endpoint.

Since v0.23.7: `llm.thinking` turns a reasoning model's thinking off (or on) through vLLM's
`chat_template_kwargs`, and since v0.23.8 `llm.reasoning` sets the level of reasoning the way the
model's family takes it (`families.py`); `llm.cache_file` keeps the answers from one run to the next (`cache.py`);
`usage` counts the questions, the answers from the cache, the tokens and the seconds of a run.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import httpx
import jsonschema

from ..config import LlmSettings
from .cache import LlmCache, question_key
from .families import family_of, reasoning_of, request_fields

log = logging.getLogger("ngvm.llm")


class LlmError(RuntimeError):
    pass


def _endpoint_down(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return isinstance(exc, httpx.TransportError)


class LlmClient:
    def __init__(self, settings: LlmSettings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self.endpoints = settings.base_urls or ["http://localhost:8000/v1"]
        headers = {"Content-Type": "application/json"}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        # A client certificate and the endpoint's CA, behind mutual TLS (v0.23.14)
        self._client = httpx.Client(
            timeout=settings.timeout_seconds, headers=headers, transport=transport, **settings.tls()
        )
        self._current = 0
        self._lock = threading.Lock()
        self.cache = LlmCache(settings.cache_file, settings.cache_days) if settings.cache_file else None
        self.family = family_of(settings.model, settings.family)
        self.reasoning = reasoning_of(settings.reasoning, settings.thinking)
        # `thinking` alone (v0.23.7): Qwen3's switch, sent as then whatever the model
        self._fields = (
            request_fields("qwen3", self.reasoning)
            if settings.thinking and not settings.reasoning
            else request_fields(self.family, self.reasoning)
        )
        self.usage = {"questions": 0, "from_cache": 0, "prompt_tokens": 0, "completion_tokens": 0, "seconds": 0.0}

    def _count(self, **values: float) -> None:
        with self._lock:
            for k, v in values.items():
                self.usage[k] += v

    def usage_summary(self) -> dict[str, Any]:
        """What the LLM cost in this process: questions, answers from the cache, tokens, seconds."""
        with self._lock:
            out = dict(self.usage)
        out["seconds"] = round(out["seconds"], 1)
        out["thinking"] = self.settings.thinking or "default"
        out["family"] = self.family
        out["reasoning"] = self.reasoning or "default"
        return out

    @property
    def model(self) -> str:
        return self.settings.model

    def _post(self, payload: dict[str, Any]) -> httpx.Response:
        """One request, on the current endpoint or, when it is down, on the next ones in turn."""
        with self._lock:
            start = self._current
        last: Exception | None = None
        for step in range(len(self.endpoints)):
            i = (start + step) % len(self.endpoints)
            try:
                resp = self._client.post(f"{self.endpoints[i]}/chat/completions", json=payload)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                if not _endpoint_down(exc) or len(self.endpoints) == 1:
                    raise
                last = exc
                log.warning(
                    "LLM endpoint %s unavailable (%s): trying the next one", self.endpoints[i], type(exc).__name__
                )
                continue
            if i != start:
                with self._lock:
                    self._current = i
                log.warning("LLM calls move to %s", self.endpoints[i])
            return resp
        assert last is not None
        raise last

    def structured(self, system: str, user: str, name: str, schema: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.settings.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": name, "schema": schema, "strict": True},
            },
        }
        payload.update(self._fields)
        self._count(questions=1)
        key = question_key(payload) if self.cache else ""
        if self.cache:
            kept = self.cache.get(key)
            if kept is not None:
                try:
                    jsonschema.validate(kept, schema)
                    self._count(from_cache=1)
                    return kept
                except jsonschema.ValidationError:
                    pass  # the schema changed since: ask again
        last_error: Exception | None = None
        for _ in range(self.settings.max_retries + 1):
            started = time.monotonic()
            try:
                resp = self._post(payload)
                body = resp.json()
                used = body.get("usage") or {}
                self._count(
                    prompt_tokens=int(used.get("prompt_tokens") or 0),
                    completion_tokens=int(used.get("completion_tokens") or 0),
                    seconds=time.monotonic() - started,
                )
                content = body["choices"][0]["message"]["content"]
                data = json.loads(content)
                jsonschema.validate(data, schema)
                if self.cache:
                    self.cache.put(key, data)
                return data
            except (
                httpx.HTTPError,
                KeyError,
                IndexError,
                TypeError,
                ValueError,
                AttributeError,
                jsonschema.ValidationError,
            ) as exc:
                last_error = exc
        raise LlmError(f"{name}: {last_error}")

    def close(self) -> None:
        if self.cache:
            self.cache.save()
        self._client.close()
