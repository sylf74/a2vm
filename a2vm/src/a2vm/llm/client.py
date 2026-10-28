# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Minimal client for an OpenAI-compatible chat completions API (vLLM, SGLang, llama.cpp server...).

Every call asks for a JSON object constrained by a JSON Schema (`response_format=json_schema`,
supported by vLLM/SGLang guided decoding). The answer is re-validated locally: a model that does
not honour the schema raises LlmError and the pipeline falls back to deterministic behaviour.

Several endpoints may serve the same model (`llm.base_url` as a list, v0.15.0): calls go to the
current one; when it cannot be reached, times out or answers 429 or 5xx, the call moves to the next
and later calls stay there. An answer that is not valid JSON is retried on the same endpoint.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

import httpx
import jsonschema

from ..config import LlmSettings

log = logging.getLogger("a2vm.llm")


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
        self._client = httpx.Client(timeout=settings.timeout_seconds, headers=headers, transport=transport)
        self._current = 0
        self._lock = threading.Lock()

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
        last_error: Exception | None = None
        for _ in range(self.settings.max_retries + 1):
            try:
                resp = self._post(payload)
                content = resp.json()["choices"][0]["message"]["content"]
                data = json.loads(content)
                jsonschema.validate(data, schema)
                return data
            except (
                httpx.HTTPError,
                KeyError,
                IndexError,
                TypeError,
                json.JSONDecodeError,
                jsonschema.ValidationError,
            ) as exc:
                last_error = exc
        raise LlmError(f"{name}: {last_error}")

    def close(self) -> None:
        self._client.close()
