# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.12.0 (HLD D15, step 1): pillar images, the tenant chart and the job that deploys it stay in
step with the packages and with the pipeline they replace."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

import a2vm

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"
PILLARS = ("via", "detect", "verdict")


def _deploy_job() -> dict:
    return yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())["deploy-k8s"]


def _chart_text() -> str:
    return "\n".join(p.read_text() for p in sorted((CHART / "templates").glob("*")))


def test_chart_carries_the_package_version():
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert chart["version"] == chart["appVersion"] == a2vm.__version__


def test_one_image_per_pillar_from_the_same_dockerfile():
    dockerfile = (ROOT / "images" / "Dockerfile").read_text()
    assert 'case "$PILLAR" in via|detect|verdict)' in dockerfile
    assert "USER 10001" in dockerfile  # the chart runs as this user
    job = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())["images"]
    assert "for p in " + " ".join(PILLARS) + "; do" in "\n".join(job["script"])
    assert all(rule["if"].startswith("$CI_REGISTRY && ") for rule in job["rules"])
    for pillar in PILLARS:
        assert (ROOT / pillar / "pyproject.toml").exists()


def test_the_cronjob_runs_the_commands_of_the_daily_pipeline():
    pipeline = yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())
    chart = _chart_text()
    for stage, command in (
        ("collect", "detect collect"),
        ("collect", "detect external"),
        ("via", "via collect"),
        ("detect", "detect inventory"),
        ("assets", "verdict assets build"),
        ("triage", "verdict run"),
        ("publish", "verdict publish"),
    ):
        assert command in "\n".join(pipeline[stage]["script"]), (stage, command)
        assert command in chart, command
    for step, pillar in (("collect", "detect"), ("via", "via"), ("detect", "detect"), ("assets", "verdict")):
        assert f'"name" "{step}" "pillar" "{pillar}"' in chart


def test_every_secret_the_job_writes_is_read_by_the_chart_and_documented():
    script = "\n".join(_deploy_job()["script"])
    written = set(re.findall(r"^put ([a-z-]+) ", script, re.MULTILINE))
    chart = _chart_text()
    read = set(re.findall(r"/secrets/([a-z-]+)", chart)) | set(re.findall(r'"([a-z]+(?:-[a-z]+)+)" ?}}?', chart))
    read |= set(re.findall(r'"[A-Z0-9_]+" "([a-z-]+)"', chart))
    read |= set(re.findall(r"key: ([a-z]+(?:-[a-z]+)+)", chart))  # items of a Secret volume (v0.15.0)
    tools: set[str] = set()
    assert written and written - tools <= read, written - tools - read
    values = (CHART / "values.yaml").read_text()
    documented = set(re.findall(r"^#   ([a-z][a-z-]+)(?:, ([a-z][a-z-]+))?\s", values, re.MULTILINE))
    documented = {k for pair in documented for k in pair if k}
    assert written == documented, written ^ documented


def test_deploy_job_runs_only_with_an_agent_context_and_never_in_watch_mode():
    pipeline = yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())
    stages = pipeline["stages"]
    assert stages.index("validate") < stages.index("deploy") < stages.index("collect")
    job = pipeline["deploy-k8s"]
    assert job["rules"][0]["when"] == "never" and "watch" in job["rules"][0]["if"]
    assert job["rules"][1]["if"].startswith("$A2VM_K8S_CONTEXT && ")
    script = "\n".join(job["script"])
    assert '--set image.tag="$A2VM_REF"' in script  # images and chart of the same release
    for secret in ("A2VM_SSH_KEY", "LLM_API_KEY", "A2VM_REPORTING_DSN", "A2VM_REGISTRY_PASSWORD"):
        assert f'echo "${secret}' not in script and f"echo ${secret}" not in script


def test_pods_run_unprivileged_and_mount_secrets_readable_by_their_group_only():
    chart = (CHART / "templates" / "cronjob-daily.yaml").read_text()
    for needle in (
        "runAsNonRoot: true",
        "runAsUser: 10001",
        "fsGroup: 10001",
        "allowPrivilegeEscalation: false",
        "automountServiceAccountToken: false",
        "defaultMode: 0440",
        "optional: true",
        "concurrencyPolicy: Forbid",
    ):
        assert needle in chart, needle
