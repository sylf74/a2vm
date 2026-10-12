# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime settings shared by all stages (config/settings.yaml), with environment overrides for CI.

Each stage reads its own section: `sources` (intel), `fuzzy_threshold` (detect), `policy` (verdict),
`llm` (every stage that calls a model). The policy is kept as a plain mapping here and parsed by
verdict, so that core does not depend on any stage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CVELIST_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CERTFR_URL = "https://www.cert.ssi.gouv.fr"


@dataclass
class SourceSettings:
    cve_record_url: str = CVELIST_URL
    delta_log_url: str = DELTA_LOG_URL
    kev_url: str = KEV_URL
    epss_url: str = EPSS_URL
    certfr_url: str = CERTFR_URL
    timeout_seconds: float = 30
    cache_dir: str = ".cache"
    cve_cache_hours: float = 12
    feed_cache_hours: float = 6
    fetch_workers: int = 8  # parallel CVE record downloads (scanner runs request thousands)


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
    rationale_for: list[str] = field(default_factory=lambda: ["ACT", "ATTEND"])  # template for the rest
    max_calls: int = 300  # LLM calls per client run; beyond, templates and defaults (flagged)
    max_consecutive_errors: int = 3  # then the LLM is considered down for the rest of the run
    parallel: int = 4  # concurrent LLM requests (vLLM batches them)

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None


@dataclass
class Settings:
    sources: SourceSettings = field(default_factory=SourceSettings)
    llm: LlmSettings = field(default_factory=LlmSettings)
    policy: dict[str, Any] = field(default_factory=dict)
    fuzzy_threshold: float = 0.75


# VULNOPS_* is the current prefix; VERDICT_* is still accepted so existing CI variables keep working.
_ENV_OVERRIDES = {
    "LLM_ENABLED": ("llm", "enabled"),
    "LLM_BASE_URL": ("llm", "base_url"),
    "LLM_MODEL": ("llm", "model"),
    "LLM_MAX_CALLS": ("llm", "max_calls"),
    "CACHE_DIR": ("sources", "cache_dir"),
    "CVE_RECORD_URL": ("sources", "cve_record_url"),
}
ENV_PREFIXES = ("VULNOPS_", "VERDICT_")


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
    settings.policy = dict(data.get("policy") or {})
    if "fuzzy_threshold" in data:
        settings.fuzzy_threshold = float(data["fuzzy_threshold"])

    for suffix, (section, key) in _ENV_OVERRIDES.items():
        for prefix in ENV_PREFIXES:
            if prefix + suffix in os.environ:
                target = getattr(settings, section)
                setattr(target, key, _coerce(getattr(target, key), os.environ[prefix + suffix]))
                break
    return settings


def describe_llm(settings: Settings) -> str:
    """One log line saying which LLM configuration a job actually received (never the key)."""
    llm = settings.llm
    if not llm.enabled:
        return "LLM: disabled"
    key = "set" if llm.api_key else "not set"
    return f"LLM: enabled, base_url={llm.base_url}, model={llm.model}, api key {key}"
