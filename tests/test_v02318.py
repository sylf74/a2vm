# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.18: what the homelab and the integration found after v0.23.17.

- The tenant pipeline: `publish` needed `triage`, excluded on Kubernetes, so GitLab refused every
  "Run pipeline" and every schedule of a tenant on Kubernetes with a reporting database;
  `deploy-k8s` also starts from the API.
"""

from __future__ import annotations

import itertools
import re

import pytest
import yaml

from .conftest import ROOT

PIPELINE = ROOT / "templates/client-pipeline.yml"


# -- the tenant pipeline: GitLab's rules, evaluated -----------------------------------------------
def _jobs() -> dict[str, dict]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))

    def resolved(name: str) -> dict:
        job = doc[name]
        base = job.get("extends")
        if not base:
            return dict(job)
        merged: dict = {}
        for b in [base] if isinstance(base, str) else base:
            merged.update(resolved(b))
        merged.update(job)
        return merged

    keywords = {"variables", "default", "include", "stages", "workflow"}
    return {k: resolved(k) for k, v in doc.items() if not k.startswith(".") and k not in keywords and isinstance(v, dict)}


def _condition(expr: str, env: dict[str, str]) -> bool:
    """GitLab's `if:` as used in the template: $VAR, ==, !=, &&, ||, parentheses, a bare $VAR."""
    py = re.sub(r'"([^"]*)"', lambda m: repr(m.group(1)), expr)
    py = re.sub(r"\$(\w+)", lambda m: f"env.get({m.group(1)!r}, '')", py)
    py = py.replace("&&", " and ").replace("||", " or ")
    return bool(eval(py, {"env": env}))  # noqa: S307 - the template's own expressions, in a test


def _included(job: dict, env: dict[str, str]) -> bool:
    for rule in job.get("rules", []):
        if "if" not in rule or _condition(rule["if"], env):
            return rule.get("when", "on_success") != "never"
    return False


def _pipeline(env: dict[str, str]) -> set[str]:
    return {name for name, job in _jobs().items() if _included(job, env)}


SOURCES = ["push", "web", "schedule", "api", "merge_request_event"]
MODES = ["gitlab", "kubernetes"]
JOBS = ["", "watch", "send"]


def _env(source: str, mode: str, job: str, **extra: str) -> dict[str, str]:
    env = {
        "CI_PIPELINE_SOURCE": source,
        "A2VM_RUN_MODE": mode,
        "A2VM_JOB": job,
        "CI_COMMIT_BRANCH": "main",
        "CI_DEFAULT_BRANCH": "main",
        "A2VM_K8S_CONTEXT": "vulnops/k8s:lab",
        "A2VM_REPORTING_DSN": "set",
    }
    env.update(extra)
    return env


@pytest.mark.parametrize("source,mode,job", list(itertools.product(SOURCES, MODES, JOBS)))
def test_no_job_needs_a_job_that_is_not_there(source, mode, job) -> None:
    jobs = _jobs()
    present = _pipeline(_env(source, mode, job))
    for name in present:
        for need in jobs[name].get("needs", []):
            need = need if isinstance(need, str) else need["job"]
            assert need in present, f"{source}/{mode}/{job or 'daily'}: {name} needs {need}, not in the pipeline"


def test_run_pipeline_on_kubernetes_deploys_and_publishes_nothing() -> None:
    present = _pipeline(_env("web", "kubernetes", ""))
    assert {"validate", "deploy-k8s"} <= present
    assert "publish" not in present and "triage" not in present


def test_the_daily_run_in_gitlab_mode_still_publishes() -> None:
    present = _pipeline(_env("schedule", "gitlab", ""))
    assert {"collect", "triage", "publish"} <= present
    assert "publish" not in _pipeline(_env("schedule", "gitlab", "", A2VM_REPORTING_DSN=""))


def test_deploy_k8s_starts_from_the_api_on_the_default_branch_only() -> None:
    assert {"validate", "deploy-k8s"} <= _pipeline(_env("api", "kubernetes", ""))
    assert "deploy-k8s" not in _pipeline(_env("api", "kubernetes", "", CI_COMMIT_BRANCH="feature"))
    assert "deploy-k8s" not in _pipeline(_env("api", "kubernetes", "", A2VM_K8S_CONTEXT=""))
    assert "deploy-k8s" not in _pipeline(_env("trigger", "kubernetes", ""))
