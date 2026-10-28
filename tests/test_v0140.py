# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.14.0 (HLD D15 step 3, read side): the decision service's contract, its place in the chart,
the tokens made by the deploy job, and the release notes."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from a2vm import __version__
from a2vm.service import TokenSet

from .test_detect_api_contract import _refs

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"
SPEC = ROOT / "a2vm" / "src" / "a2vm" / "schemas" / "openapi" / "verdict.v1.yaml"


def _spec() -> dict:
    return yaml.safe_load(SPEC.read_text())


def test_contract_is_openapi_31_and_every_reference_resolves():
    spec = _spec()
    assert spec["openapi"].startswith("3.1")
    for ref in _refs(spec):
        if ref.startswith("#/"):
            node = spec
            for part in ref[2:].split("/"):
                node = node[part]
        else:
            assert (SPEC.parent / ref).resolve().exists(), ref


def test_every_tenant_call_carries_the_tenant_and_its_role():
    spec = _spec()
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if path.startswith("/v1/tenants/{tenant}"):
                assert {"$ref": "#/components/parameters/tenant"} in op["parameters"], (path, method)
                want = [{"publishToken": []}] if method == "post" else [{"readToken": []}]
                assert op["security"] == want, (path, method)


def test_contract_names_the_routes_the_service_answers():
    paths = set(_spec()["paths"])
    assert paths == {
        "/v1/tenants/{tenant}/runs",
        "/v1/tenants/{tenant}/summary",
        "/v1/tenants/{tenant}/decisions",
        "/v1/tenants/{tenant}/decisions/{id}",
        "/v1/tenants/{tenant}/cves/{cve}",
        "/v1/tenants/{tenant}/assets",
        "/v1/tenants/{tenant}/assets/{asset}",
        "/v1/tenants/{tenant}/assets/{asset}/fixes",
        "/v1/tenants/{tenant}/changes",
        "/healthz",
        "/readyz",
    }
    push = _spec()["paths"]["/v1/tenants/{tenant}/runs"]["post"]
    assert any(p.get("name") == "Idempotency-Key" and p["required"] for p in push["parameters"])
    body = push["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert yaml.safe_load((SPEC.parent / body).read_text())["$id"].endswith("a2vm.triage/1")


def test_decision_service_is_unprivileged_closed_and_fed_by_the_publish_step():
    text = (CHART / "templates" / "verdict.yaml").read_text()
    for needle in (
        "{{- if .Values.verdict.enabled }}",
        "replicas: 1",
        "type: Recreate",
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "drop: [ALL]",
        'command: ["verdict", "serve"]',
        "--digests=/verdict-secret/digests",
        "checksum/digests:",
        "helm.sh/resource-policy: keep",
        "type: ClusterIP",
        "policyTypes: [Ingress, Egress]",
        "egress: []",
        '"component" "daily"',
        "a2vm.io/verdict-reader",
    ):
        assert needle in text, needle
    assert "kind: Ingress" not in text  # read inside the cluster only
    daily = (CHART / "templates" / "cronjob-daily.yaml").read_text()
    publish = daily.split("a2vm-tenant.step.publish", 1)[1]
    assert publish.index("verdict push") < publish.index("verdict publish ")
    assert "/secrets/verdict-publish-token" in publish and "WARN decision service not updated" in publish
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["verdict"]["enabled"] is False and values["verdict"]["networkPolicy"]["enabled"] is True
    assert "verdict.digestsSecret is required" in (CHART / "templates" / "_helpers.tpl").read_text()


def _verdict_block() -> str:
    pipeline = yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())
    return next(s for s in pipeline["deploy-k8s"]["script"] if 'VERDICT=""' in s)


FAKE_KUBECTL = """#!/bin/sh
# get secret a2vm-tenant -o jsonpath={.data.<key>}: the key from $STORE, base64
case "$*" in
  *"get secret a2vm-tenant"*)
    key=$(echo "$*" | sed -n 's/.*{.data.\\([a-z-]*\\)}.*/\\1/p')
    if [ -f "$STORE/$key" ]; then base64 < "$STORE/$key"; else exit 1; fi ;;
  *"create secret generic a2vm-verdict"*)
    src=$(echo "$*" | sed -n 's/.*--from-file=digests=\\([^ ]*\\).*/\\1/p'); cp "$src" "$STORE/digests" ;;
  *apply*) cat > /dev/null ;;
esac
"""


def _run_block(tmp_path: Path, **env) -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "kubectl").write_text(FAKE_KUBECTL)
    (bin_dir / "kubectl").chmod(0o755)
    store = tmp_path / "store"
    store.mkdir(exist_ok=True)
    keep = 'for k in verdict-publish-token verdict-read-token; do cp "$V/$k" "$STORE/$k" 2>/dev/null || true; done'
    script = f'{_verdict_block()}\n{keep}\necho "VERDICT=$VERDICT"\n'
    full = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STORE": str(store), "NS": "a2vm-lab", **env}
    out = subprocess.run(["sh", "-ec", script], env=full, capture_output=True, text=True, check=True)
    return out.stdout + out.stderr


@pytest.mark.skipif(not all(Path(f"/usr/bin/{t}").exists() for t in ("od", "sha256sum", "base64")), reason="coreutils")
def test_deploy_job_makes_the_tokens_once_and_their_digests(tmp_path):
    out = _run_block(tmp_path)
    store = tmp_path / "store"
    publish, read = (store / "verdict-publish-token").read_text(), (store / "verdict-read-token").read_text()
    assert re.fullmatch(r"[0-9a-f]{64}", publish) and re.fullmatch(r"[0-9a-f]{64}", read) and publish != read
    assert publish not in out and read not in out  # never printed
    tokens = TokenSet.load(store / "digests", {"publish", "read"})
    assert tokens.role_of(publish) == "publish" and tokens.role_of(read) == "read"
    assert "--set verdict.enabled=true" in out and "verdict.digestsChecksum=" in out
    digests = (store / "digests").read_text()
    _run_block(tmp_path)  # a second deployment keeps the tokens
    assert (store / "verdict-publish-token").read_text() == publish and (store / "digests").read_text() == digests


def test_deploy_job_can_leave_the_service_out(tmp_path):
    out = _run_block(tmp_path, A2VM_VERDICT_SERVICE="false")
    assert "VERDICT=\n" in out and not (tmp_path / "store" / "digests").exists()
    script = "\n".join(yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())["deploy-k8s"]["script"])
    assert "put verdict-publish-token" in script and "$INTAKE $VERDICT" in script


def test_release_notes_cover_every_version():
    notes = (ROOT / "CHANGELOG.md").read_text()
    versions = re.findall(r"^## v(\d+\.\d+\.\d+)", notes, re.M)
    assert versions[0] == __version__  # newest first, the current version written
    assert "0.4.0" in versions
    keyed = [tuple(int(x) for x in v.split(".")) for v in versions]
    assert keyed == sorted(keyed, reverse=True) and len(set(keyed)) == len(keyed)
