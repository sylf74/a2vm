# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Minimal client for an OpenAI-compatible chat completions API (vLLM, SGLang, llama.cpp server...).

Every call asks for a JSON object constrained by a JSON Schema (`response_format=json_schema`,
supported by vLLM/SGLang guided decoding). The answer is re-validated locally: a model that does
not honour the schema raises LlmError and the pipeline falls back to deterministic behaviour.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import jsonschema

from ..config import LlmSettings


class LlmError(RuntimeError):
    pass


class LlmClient:
    def __init__(self, settings: LlmSettings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        headers = {"Content-Type": "application/json"}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        self._client = httpx.Client(
            base_url=settings.base_url.rstrip("/"),
            timeout=settings.timeout_seconds,
            headers=headers,
            transport=transport,
        )

    @property
    def model(self) -> str:
        return self.settings.model

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
                resp = self._client.post("/chat/completions", json=payload)
                resp.raise_for_status()
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
