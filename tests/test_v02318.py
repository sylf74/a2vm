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

    from a2vm.service import release_memory

    def missing(name):
        raise OSError(name)

    release_memory()
    monkeypatch.setattr(ctypes, "CDLL", missing)
    release_memory()


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


# -- the inventory of the watch -------------------------------------------------------------------
def _big_inventory(tmp_path, n: int = 400):
    """An inventory of a run with many findings, components and fixed packages."""
    from a2vm.io import write_assets, write_findings
    from a2vm.models import Asset, Attribute, Finding, FindingObservation, Match, NotAffected

    seen = "2026-11-12T08:30:00+00:00"
    asset = Asset(
        "host:hyp03.lan.example", "lab", "host", "hyp03", "hyp03", {"hostname": "hyp03"},
        {"exposure": Attribute("controlled", "rule"), "owner": Attribute("infra", "declared"),
         "mission_prevalence": Attribute("support", "default"),
         "public_wellbeing_impact": Attribute("minimal", "default")},
        ["trivy"], seen, seen,
    )  # fmt: skip
    asset.components = [{"name": f"pkg{i}", "version": "1.0", "type": "rpm"} for i in range(50)]
    asset.scans = {"trivy": seen}
    findings, fixed = [], []
    for i in range(n):
        cve = f"CVE-2026-{10000 + i}"
        obs = FindingObservation(
            "trivy", seen, Match("scanner", "", "openssl", 1.0, "matched by the scanner on its own name"),
            "openssl", "3.0.7", "3.0.8", "fixed", "HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "trivy:nvd",
        )  # fmt: skip
        findings.append(
            Finding(Finding.make_id("lab", asset.id, cve), "lab", asset.id, cve, "affected", ["3.0.7"], [obs],
                    ["the version range of the advisory is not sure"])
        )  # fmt: skip
        fixed += [NotAffected("lab", f"CVE-2025-{20000 + i * 3 + k}", asset.id, ["2.0"], "trivy") for k in range(3)]
    base = tmp_path / "lab"
    write_assets(base / "assets.json", "lab", [asset])
    write_findings(base / "findings.json", "lab", findings, fixed)
    return base


def test_the_watch_gets_what_it_reads_and_nothing_more(tmp_path) -> None:
    import json

    from a2vm.io import validate_assets, validate_findings
    from via.alert.inventory import for_watch, load

    base = _big_inventory(tmp_path)
    assets = json.loads((base / "assets.json").read_text())
    findings = json.loads((base / "findings.json").read_text())
    slim_assets, slim_findings = for_watch(assets, findings)
    validate_assets(slim_assets, "assets")
    validate_findings(slim_findings, "findings")
    assert slim_findings["not_affected"] == [] and "scans" not in slim_assets["assets"][0]
    full = len(json.dumps(assets)) + len(json.dumps(findings))
    assert len(json.dumps(slim_assets)) + len(json.dumps(slim_findings)) < full / 2

    # the watch reads the same inventory from both
    out = tmp_path / "slim" / "lab"
    out.mkdir(parents=True)
    (out / "assets.json").write_text(json.dumps(slim_assets))
    (out / "findings.json").write_text(json.dumps(slim_findings))
    before, after = load(tmp_path, "lab"), load(tmp_path / "slim", "lab")
    assert before.assets.keys() == after.assets.keys()
    assert after.assets["host:hyp03.lan.example"].components == before.assets["host:hyp03.lan.example"].components
    assert before.findings_by_cve.keys() == after.findings_by_cve.keys()
    a, b = before.findings_by_cve["CVE-2026-10000"][0], after.findings_by_cve["CVE-2026-10000"][0]
    keep = ("package", "installed_version", "fixed_version", "source", "source_status")
    assert [getattr(a.observations[0], k) for k in keep] == [getattr(b.observations[0], k) for k in keep]
    assert a.asset_ref == b.asset_ref and a.affected_versions == b.affected_versions
    # the daily run's own files are left as they are
    assert json.loads((base / "findings.json").read_text())["not_affected"]


def test_a_refused_inventory_says_its_size_and_what_to_raise(tmp_path, capsys, backend) -> None:
    from a2vm.service import TokenSet, digest
    from via.service.server import WatchService, serve

    from .test_v0160 import RUN, watch_store

    base = _big_inventory(tmp_path)
    digests = tmp_path / "digests"
    digests.write_text(f"run {digest(RUN)}\n")
    svc = WatchService("lab", TokenSet.load(digests, {"run"}), watch_store(tmp_path, backend), max_bytes=10_000)
    httpd = serve(svc, "127.0.0.1", 0)
    import threading

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    token = tmp_path / "token"
    token.write_text(RUN)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    from via.cli import main

    args = ["service", "push-inventory", "--url", url, "--tenant", "lab", "--token-file", str(token)]
    try:
        assert main([*args, "--assets-dir", str(base)]) == 1
        err = capsys.readouterr().err
        assert "(413)" in err and "MB of assets and" in err and "MB of findings" in err
        assert "A2VM_WATCH_MAX_MB" in err
        svc.max_bytes = 50 * 1024 * 1024
        assert main([*args, "--assets-dir", str(base)]) == 0
        out = capsys.readouterr().out
        assert "inventory pushed to the watch service (1 assets, 400 findings;" in out and "MB of the" in out
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_watch_service_takes_a_larger_inventory_when_asked() -> None:
    values = yaml.safe_load((ROOT / "deploy/charts/a2vm-tenant/values.yaml").read_text())
    assert values["watch"]["maxMb"] == 50 and values["watch"]["resources"]["limits"]["memory"] == "512Mi"
    assert (
        "--max-mb={{ $w.maxMb | default 50 }}" in (ROOT / "deploy/charts/a2vm-tenant/templates/watch.yaml").read_text()
    )
    pipeline = PIPELINE.read_text()
    assert "--set watch.maxMb=$A2VM_WATCH_MAX_MB" in pipeline and "A2VM_WATCH_MAX_MB: a number of MB" in pipeline
