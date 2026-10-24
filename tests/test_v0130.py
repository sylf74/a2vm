# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.13.0 (HLD D15 step 2): the chart deploys the detection service next to the daily run, the
deploy job makes its secrets from the tenant project, and the daily run reads what the collectors
pushed (LLD detection §8.3-8.5)."""

from __future__ import annotations

import ast
import importlib.util
import stat
from pathlib import Path

import pytest
import yaml

from detect.intake.registry import digest, load_registry

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"
SCRIPT = ROOT / "deploy" / "intake" / "intake_secrets.py"
TOKEN = "0123456789abcdef0123456789abcdef"


def _script():
    spec = importlib.util.spec_from_file_location("intake_secrets", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pipeline() -> dict:
    return yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())


@pytest.fixture
def collectors(tmp_path):
    path = tmp_path / "collectors.yaml"
    path.write_text(
        "collectors:\n  - {id: lab-lan, sources: [trivy, dnf-updateinfo]}\n  - {id: lab-dmz, sources: [openvas]}\n"
    )
    return path


def test_deploy_script_makes_digests_the_service_accepts(tmp_path, collectors, monkeypatch, capsys):
    secrets = _script()
    token_file = tmp_path / "dmz-token"
    token_file.write_text("f" * 64 + "\n")  # a File variable
    monkeypatch.setenv("A2VM_COLLECTOR_TOKEN_LAB_LAN", TOKEN)
    monkeypatch.setenv("A2VM_COLLECTOR_TOKEN_LAB_LAN_NEXT", "n" * 40)
    monkeypatch.setenv("A2VM_COLLECTOR_TOKEN_LAB_DMZ", str(token_file))
    out = tmp_path / "out"
    assert secrets.main([str(collectors), "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "collector lab-lan: token set (A2VM_COLLECTOR_TOKEN_LAB_LAN, A2VM_COLLECTOR_TOKEN_LAB_LAN_NEXT)" in printed
    assert TOKEN not in printed and "f" * 64 not in printed and "read token: new" in printed
    for name in ("digests", "detect-read-token"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600
    registry = load_registry("lab", collectors, out / "digests")
    assert registry.collector_for(TOKEN).id == registry.collector_for("n" * 40).id == "lab-lan"
    assert registry.collector_for("f" * 64).id == "lab-dmz"
    assert registry.may_read((out / "detect-read-token").read_text())
    assert secrets.digest(TOKEN) == digest(TOKEN)


def test_deploy_script_keeps_the_read_token_and_names_missing_tokens(tmp_path, collectors, capsys):
    secrets = _script()
    deployed = tmp_path / "deployed"
    deployed.write_text("r" * 43)
    assert secrets.main([str(collectors), "--out", str(tmp_path / "o"), "--read-token", str(deployed)]) == 0
    printed = capsys.readouterr().out
    assert "read token: kept" in printed and "no token: set A2VM_COLLECTOR_TOKEN_LAB_LAN (masked)" in printed
    assert (tmp_path / "o" / "detect-read-token").read_text() == "r" * 43
    assert (tmp_path / "o" / "digests").read_text() == f"read {digest('r' * 43)}\n"
    # Nothing deployed yet (an empty file from the cluster): a new one.
    deployed.write_text("")
    secrets.main([str(collectors), "--out", str(tmp_path / "p"), "--read-token", str(deployed)])
    assert len((tmp_path / "p" / "detect-read-token").read_text()) >= 32


@pytest.mark.parametrize("token", ["short", "with a space in it, long enough to pass the length"])
def test_deploy_script_refuses_a_weak_token_without_printing_it(tmp_path, collectors, monkeypatch, capsys, token):
    monkeypatch.setenv("A2VM_COLLECTOR_TOKEN_LAB_DMZ", token)
    assert _script().main([str(collectors), "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert "A2VM_COLLECTOR_TOKEN_LAB_DMZ" in err and token not in err
    assert not (tmp_path / "o" / "digests").exists()


def test_deploy_script_runs_without_the_a2vm_packages():
    tree = ast.parse(SCRIPT.read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "argparse", "hashlib", "os", "re", "secrets", "sys", "pathlib", "yaml"}


def test_deploy_job_hands_the_declaration_and_digests_to_the_chart():
    pipeline = _pipeline()
    script = "\n".join(pipeline["deploy-k8s"]["script"])
    assert 'if [ -f "$A2VM_COLLECTORS" ]' in script
    assert "deploy/intake/intake_secrets.py" in script and "py3-yaml" in script
    assert "create secret generic a2vm-intake --from-file=digests=" in script
    for flag in (
        "--set intake.enabled=true",
        "--set-file intake.collectors=$A2VM_COLLECTORS",
        "--set intake.digestsSecret=a2vm-intake",
        "--set intake.digestsChecksum=",
        "--set collect.mode=${A2VM_COLLECT_MODE:-intake}",
        "$INTAKE",
    ):
        assert flag in script, flag
    assert 'put detect-read-token "$READ_TOKEN"' in script
    assert 'rm -rf "$I"' in script
    assert 'echo "${READ_TOKEN' not in script and "cat $READ_TOKEN" not in script
    validate = "\n".join(pipeline["validate"]["script"])
    assert 'detect collectors "$A2VM_COLLECTORS"' in validate and '--profile "$A2VM_PROFILE"' in validate
    assert pipeline["variables"]["A2VM_COLLECTORS"] == "collectors.yaml"


def test_daily_run_reads_the_service_in_intake_mode_and_collects_in_local_mode():
    chart = (CHART / "templates" / "cronjob-daily.yaml").read_text()
    intake, local = chart.split('{{- if eq .Values.collect.mode "intake" }}', 1)[1].split("{{- else }}", 1)
    assert "detect fetch" in intake and "--collectors /intake/collectors.yaml" in intake
    assert "/secrets/detect-read-token" in intake and "detect collect " not in intake
    assert "detect collect /config/targets.yaml" in local.split("{{- end }}")[0]
    assert "app.kubernetes.io/component: daily" in chart
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["collect"]["mode"] == "local"  # a tenant without collectors keeps v0.12
    assert values["intake"]["enabled"] is False and values["intake"]["networkPolicy"]["enabled"] is True


def test_detection_service_is_unprivileged_closed_and_publishes_the_push_only():
    text = (CHART / "templates" / "intake.yaml").read_text()
    for needle in (
        "{{- if .Values.intake.enabled }}",
        "replicas: 1",
        "type: Recreate",
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "drop: [ALL]",
        'command: ["detect", "serve"]',
        "--digests=/intake-secret/digests",
        "checksum/digests:",
        "helm.sh/resource-policy: keep",
        "pathType: Exact",
        '"/v1/tenants/%s/detections"',
        "nginx.ingress.kubernetes.io/whitelist-source-range",
        "policyTypes: [Ingress, Egress]",
        "egress: []",
        '"component" "daily"',
    ):
        assert needle in text, needle
    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    for message in ("collect.mode must be local or intake", "needs intake.enabled", "allowFrom is required"):
        assert message in helpers, message


def test_contract_status_and_read_by_source_and_collector():
    spec = yaml.safe_load((ROOT / "a2vm" / "src" / "a2vm" / "schemas" / "openapi" / "detect.v1.yaml").read_text())
    assert not spec["info"]["version"].endswith("draft")
    latest = spec["paths"]["/v1/tenants/{tenant}/detections/latest"]["get"]
    assert "collector" in latest["summary"]
