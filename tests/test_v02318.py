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

from . import test_verdict_service as _vs
from .conftest import ROOT

PIPELINE = ROOT / "templates/client-pipeline.yml"
triage = _vs.triage


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
    names = [k for k, v in doc.items() if not k.startswith(".") and k not in keywords and isinstance(v, dict)]
    return {k: resolved(k) for k in names}


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


# -- the decision service: a push of a large run ----------------------------------------------------
def test_a_connection_closed_during_the_push_says_so_with_its_size(tmp_path) -> None:
    import httpx

    from verdict.service.client import PushError, push

    big = tmp_path / "triage.json"
    big.write_text('{"rows": []}' + " " * 3_000_000)

    def closed(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)

    with pytest.raises(PushError) as err:
        push("http://verdict:8080", "lab", "t", big, transport=httpx.MockTransport(closed))
    assert err.value.retry
    message = str(err.value)
    assert "closed the connection during the push of 3 MB" in message
    assert "OOMKilled" in message and "A2VM_VERDICT_MEMORY" in message


def test_a_push_drops_the_indexes_and_gives_the_memory_back(triage, tmp_path, monkeypatch, caplog) -> None:
    import gzip
    import json
    import logging

    from verdict.service import server

    from .test_verdict_service import PUBLISH, _service

    _, path = triage
    doc = json.loads(path.read_text())
    service = _service(tmp_path, doc["client"]["id"])
    released = []
    monkeypatch.setattr(server, "release_memory", lambda: released.append(True))
    service.push(service.tenant, PUBLISH, "k1", gzip.compress(json.dumps(doc).encode()), True)
    assert released == [True]
    service.index("latest")
    assert len(service._indexes) == 1
    doc["generated_at"] = doc["generated_at"].replace(doc["generated_at"][:4], str(int(doc["generated_at"][:4]) - 1))
    with caplog.at_level(logging.INFO, logger=server.log.name):
        service.push(service.tenant, PUBLISH, "k2", gzip.compress(json.dumps(doc).encode()), True)
    assert service._indexes == {} and released == [True, True]
    assert any("receiving=" in r.getMessage() for r in caplog.records)
    # a refused push gives the memory back too
    with pytest.raises(server.Problem):
        service.push(service.tenant, PUBLISH, "k3", b"not gzip", True)
    assert released == [True, True, True]


def test_release_memory_runs_where_there_is_no_glibc(monkeypatch) -> None:
    import ctypes

    from verdict.service import server

    def missing(name):
        raise OSError(name)

    monkeypatch.setattr(ctypes, "CDLL", missing)
    server.release_memory()


def test_the_decision_service_has_room_for_a_large_run() -> None:
    values = yaml.safe_load((ROOT / "deploy/charts/a2vm-tenant/values.yaml").read_text())
    assert values["verdict"]["resources"]["limits"]["memory"] == "2Gi"
    template = (ROOT / "deploy/charts/a2vm-tenant/templates/verdict.yaml").read_text()
    assert "MALLOC_ARENA_MAX" in template
    assert "timeoutSeconds: 5" in template and "failureThreshold: 6" in template
    pipeline = PIPELINE.read_text()
    assert "--set-string verdict.resources.limits.memory=$A2VM_VERDICT_MEMORY" in pipeline
    assert "grep -qE '^[1-9][0-9]*(Mi|Gi)$'" in pipeline
    assert "A2VM_VERDICT_MEMORY" in (ROOT / "docs/kubernetes.md").read_text()
