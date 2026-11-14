# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.16: the Secrets of deploy-k8s are created or replaced, never applied.

A client-side `kubectl apply` copies the whole object into the annotation
last-applied-configuration, limited to 256 KiB: the Secret ngvm-tenant, with the CA bundle of the
proxy (about 180 KB) and the certificates of v0.23.14 and v0.23.15, went over it and the job failed.
Found by the integration of v0.23.15 on a tenant with a proxy CA, a mutual TLS LLM and the
development identity provider."""

from __future__ import annotations

import re
import subprocess

import yaml

from .conftest import ROOT

PIPELINE = ROOT / "templates/client-pipeline.yml"


def _script() -> list[str]:
    return yaml.safe_load(PIPELINE.read_text())["deploy-k8s"]["script"]


def test_no_secret_is_applied() -> None:
    text = "\n".join(_script())
    assert not re.search(r"create secret[^\n]*(\n[^\n]*)?--dry-run=client -o yaml \| kubectl apply", text)
    assert not re.search(r"ngvm-tenant[^\n]*kubectl apply", text)
    secrets = re.findall(r"create secret (?:generic|docker-registry) (\S+)", text)
    assert {"ngvm-tenant", "ngvm-intake", "ngvm-verdict", "ngvm-chat", "ngvm-via", "ngvm-dispatch", "ngvm-intel",
            "ngvm-registry"} <= set(secrets)  # fmt: skip
    for name in secrets:
        line = text[text.index(f"create secret generic {name}") if f"generic {name}" in text else text.index(name) :]
        assert re.match(r"[^|]*\| upsert", line.replace("\\\n", " ")), name


def test_upsert_creates_then_replaces(tmp_path) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "kubectl"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {calls}\n'
        f'case "$*" in *" get -f "*) [ -f {tmp_path}/exists ] && exit 0 || exit 1;; esac\n'
        'f=$(echo "$*" | sed "s/.* -f //"); test -f "$f" && stat -c %a "$f" >> ' + str(calls) + "\n"
    )
    stub.chmod(0o755)
    block = next(x for x in _script() if "upsert() {" in x)
    run = (
        "NS=ngvm-lab\n" + block
        + "\nprintf 'kind: Secret\\n' | upsert\ntouch " + str(tmp_path / "exists")
        + "\nprintf 'kind: Secret\\n' | upsert\n"
    )  # fmt: skip
    subprocess.run(["sh", "-c", run], env={"PATH": f"{tmp_path}:/usr/bin:/bin"}, check=True)
    lines = calls.read_text().split("\n")
    verbs = [ln.split()[2] for ln in lines if ln.startswith("-n ngvm-lab")]
    assert verbs == ["get", "create", "get", "replace"]
    assert lines.count("600") == 2  # the manifest of a Secret is readable by the job only


def test_release_recorded() -> None:
    assert "## v0.23.16 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[6-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
