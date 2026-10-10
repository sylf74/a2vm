"""Runtime settings (config/settings.yaml), with environment-variable overrides for CI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy import Policy

CVELIST_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


@dataclass
class SourceSettings:
    cve_record_url: str = CVELIST_URL
    delta_log_url: str = DELTA_LOG_URL
    kev_url: str = KEV_URL
    epss_url: str = EPSS_URL
    timeout_seconds: float = 30
    cache_dir: str = ".cache"
    cve_cache_hours: float = 12
    feed_cache_hours: float = 6


@dataclass
class LlmSettings:
    enabled: bool = False
    base_url: str = "http://localhost:8000/v1"
    model: str = "openai/gpt-oss-120b"
    api_key_env: str = "LLM_API_KEY"
    timeout_seconds: float = 180
    max_retries: int = 2
    ssvc_inputs: bool = True
    match_adjudication: bool = True
    rationale: bool = True

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None


@dataclass
class Settings:
    sources: SourceSettings = field(default_factory=SourceSettings)
    llm: LlmSettings = field(default_factory=LlmSettings)
    policy: Policy = field(default_factory=Policy)
    fuzzy_threshold: float = 0.75


_ENV_OVERRIDES = {
    "VERDICT_LLM_ENABLED": ("llm", "enabled"),
    "VERDICT_LLM_BASE_URL": ("llm", "base_url"),
    "VERDICT_LLM_MODEL": ("llm", "model"),
    "VERDICT_CACHE_DIR": ("sources", "cache_dir"),
    "VERDICT_CVE_RECORD_URL": ("sources", "cve_record_url"),
}


def _coerce(current: Any, raw: str) -> Any:
    if isinstance(current, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, int):
        return int(raw)
    return raw


def _fill(obj: Any, data: dict[str, Any], section: str) -> None:
    for key, value in (data or {}).items():
        if not hasattr(obj, key):
            raise ValueError(f"settings: unknown key {section}.{key}")
        setattr(obj, key, value)


def load_settings(path: str | Path | None = None) -> Settings:
    settings = Settings()
    data: dict[str, Any] = {}
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    llm = dict(data.get("llm") or {})
    tasks = llm.pop("tasks", {}) or {}
    _fill(settings.sources, data.get("sources") or {}, "sources")
    _fill(settings.llm, llm, "llm")
    _fill(settings.llm, tasks, "llm.tasks")
    settings.policy = Policy.from_dict(data.get("policy"))
    if "fuzzy_threshold" in data:
        settings.fuzzy_threshold = float(data["fuzzy_threshold"])

    for env, (section, key) in _ENV_OVERRIDES.items():
        if env in os.environ:
            target = getattr(settings, section)
            setattr(target, key, _coerce(getattr(target, key), os.environ[env]))
    return settings
