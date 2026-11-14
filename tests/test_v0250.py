# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.0: A2VM renamed NGVM, and the platform deployed with OpenTofu.

The rename: no a2vm left but where it is history or compatibility; an A2VM_ variable, an a2vm.
exchange file and a database of A2VM still read until v0.26.0. The deployment: the scripts that
OpenTofu runs on the machines, run here in a test root (NGVM_TEST_ROOT: files written under it, no
command run), and the checks of deploy/tofu when OpenTofu is installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from ngvm.io import legacy_schema
from verdict.assets.gaps import read_gaps

from .conftest import ROOT

SCRIPTS = ROOT / "deploy" / "tofu" / "scripts"
# Where a2vm may still be written: history, the iTop extension kept by its name, compatibility.
A2VM_ALLOWED = {
    "CHANGELOG.md",
    "tests/fixtures/reporting-schema-v1.sql",
    "tests/test_v0250.py",
    "tests/test_config.py",
    "tests/test_restitution.py",
    "tests/test_itop_extension.py",
    "tests/test_v0120.py",
    "tests/test_v0160.py",
    "tests/conftest.py",
    "docs/hld/00-product-strategy.md",
    "docs/deployment.md",
    "docs/platform.md",
    "deploy/itop/README.md",
    "docs/cmdb.md",
    "docs/lld/vulnerability-detection.md",
    "detect/src/detect/cmdb.py",
    "ngvm/src/ngvm/__init__.py",
    "ngvm/src/ngvm/cli.py",
    "ngvm/src/ngvm/config.py",
    "ngvm/src/ngvm/db.py",
    "ngvm/src/ngvm/io.py",
    "templates/client-pipeline.yml",
    "verdict/src/verdict/restitution/sql/legacy.sql",
    "verdict/src/verdict/restitution/db.py",
    "deploy/tofu/scripts/collector.sh",
    "deploy/tofu/modules/platform/variables.tf",
    "deploy/tofu/existing/variables.tf",
}


def _tracked() -> list[str]:
    """The files of the repository: git ls-files, or, without git (the CI's python image), the work
    tree without what tools leave there (caches, egg-info)."""
    if shutil.which("git") and (ROOT / ".git").exists():
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return out.split()
    files = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d != "__pycache__" and not d.endswith(".egg-info")
        ]
        rel = os.path.relpath(dirpath, ROOT)
        files += [os.path.normpath(os.path.join(rel, f)) for f in filenames if f != "junit.xml"]
    return files


# -- the rename -------------------------------------------------------------------------------------
def test_no_a2vm_left_but_history_and_compatibility() -> None:
    files = _tracked()
    assert "ngvm/src/ngvm/__init__.py" in files and not any(f.startswith("a2vm/") for f in files)
    found = []
    for f in files:
        path = ROOT / f
        if f in A2VM_ALLOWED or "a2vm-iot-device" in f or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"a2vm", text, re.I):
            found.append(f)
    assert found == []
    assert not any("a2vm" in f for f in files if "a2vm-iot-device" not in f)


def test_the_hld_keeps_its_history_and_names_ngvm() -> None:
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert hld.startswith("# Next-Generation Vulnerability Management")
    assert "| v0.11.0 | Project renamed A2VM" in hld  # the version history as written
    lines = [line for line in hld.splitlines() if re.search("a2vm", line, re.I)]
    assert all(line.startswith("| v0.") or line.startswith("| NGVM |") or "A2VM_" in line for line in lines)


def test_an_a2vm_variable_is_read_with_a_warning_by_every_process() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NGVM_", "A2VM_"))}
    env |= {"A2VM_INTEL_URL": "https://intel.example.org", "A2VM_OSV_MODE": "online", "NGVM_OSV_MODE": "offline"}
    code = "import os, ngvm; print(os.environ['NGVM_INTEL_URL'], os.environ['NGVM_OSV_MODE'])"
    run = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert run.stdout.split() == ["https://intel.example.org", "offline"]  # the NGVM_ name wins
    assert "WARN  CI/CD variable A2VM_INTEL_URL is deprecated: rename it NGVM_INTEL_URL" in run.stderr
    assert "A2VM_OSV_MODE" not in run.stderr


def test_the_pipeline_copies_a2vm_variables_and_no_longer_reads_vulnops() -> None:
    text = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    assert "s/^A2VM_\\([A-Z0-9_]*\\)=.*/\\1/p" in text and "VULNOPS" not in text
    assert ".ngvm/ngvm" in text and "${NGVM_JOB:-${A2VM_JOB:-daily}}" in text
    pipeline = yaml.safe_load(text)
    for job in ("deploy-k8s", "send-alerts-k8s"):  # not under .ngvm: the copy is theirs too
        assert pipeline[job]["script"][0] == pipeline[".ngvm"]["before_script"][0]
        assert "$A2VM_K8S_CONTEXT" in " ".join(r.get("if", "") for r in pipeline[job]["rules"])
    publish = " ".join(r.get("if", "") for r in pipeline["publish"]["rules"])
    assert "$A2VM_REPORTING_DSN" in publish
    assert "A2VM_RUN_MODE" not in text  # defined by the template: renamed in .gitlab-ci.yml


def test_an_exchange_file_of_a2vm_is_read_under_its_new_name(tmp_path) -> None:
    old = {"schema": "a2vm.triage/1", "a2vm_version": "0.24.0", "rows": []}
    assert legacy_schema(old) == {"schema": "ngvm.triage/1", "ngvm_version": "0.24.0", "rows": []}
    run = {"schema": "a2vm.reporting/1", "run": {"a2vm_version": "0.24.0"}}
    assert legacy_schema(run)["run"] == {"ngvm_version": "0.24.0"}
    other = {"schema": "vulnops.findings/2"}
    assert legacy_schema(dict(other)) == other  # the names kept since before A2VM
    path = tmp_path / "exposure_gaps.json"
    gap = {"asset": "web01", "kind": "no-external-scan", "detail": "x"}
    path.write_text(json.dumps({"schema": "a2vm.exposure_gaps/1", "client_id": "lab", "gaps": [gap]}))
    assert read_gaps(path, "lab") == [gap]


def test_the_meta_schema_of_a_tenant_database_of_a2vm_is_renamed(tenant_db) -> None:
    import psycopg

    from ngvm.db import Database, Migration

    with psycopg.connect(tenant_db, autocommit=True) as conn:  # as v0.24.0 left it
        conn.execute("CREATE SCHEMA a2vm_meta")
        conn.execute(
            "CREATE TABLE a2vm_meta.versions (component text PRIMARY KEY, version integer NOT NULL,"
            " at timestamptz NOT NULL DEFAULT now())"
        )
        conn.execute("INSERT INTO a2vm_meta.versions VALUES ('test', 1)")
        conn.execute("CREATE TABLE kept (v integer)")
    steps = [Migration(1, "CREATE TABLE kept (v integer)"), Migration(2, "ALTER TABLE kept ADD COLUMN w integer")]
    db = Database(tenant_db, "test", steps)
    assert db.init() == 2  # version 1 was applied by A2VM: only 2 runs
    with db.tx("") as conn:
        assert conn.execute("SELECT to_regnamespace('a2vm_meta')").fetchone()[0] is None
        assert conn.execute("SELECT version FROM ngvm_meta.versions WHERE component = 'test'").fetchone()[0] == 2
    db.close()


def test_the_itop_extension_keeps_its_name() -> None:
    ext = ROOT / "deploy/itop/a2vm-iot-device"
    assert "<db_table>a2vm_iotdevice</db_table>" in (ext / "datamodel.a2vm-iot-device.xml").read_text()
    assert "'label' => 'NGVM: connected objects (IoTDevice)'" in (ext / "module.a2vm-iot-device.php").read_text()


# -- the scripts OpenTofu runs on the machines ------------------------------------------------------
def _work(tmp_path, step: str, env: dict[str, str], stage: dict[str, str], os_release: str):
    work, root = tmp_path / "work", tmp_path / "root"
    (work / "stage").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    shutil.copytree(SCRIPTS, work / "scripts")
    (root / "etc/os-release").write_text(os_release)
    (work / f"{step}.env").write_text("".join(f"{k}='{v}'\n" for k, v in env.items()))
    for name, content in stage.items():
        (work / "stage" / name).write_text(content)
    return work, root


def _run(script: str, work, root) -> subprocess.CompletedProcess:
    env = dict(os.environ, NGVM_TEST_ROOT=str(root))
    return subprocess.run(["bash", str(work / "scripts" / script), str(work)], env=env, capture_output=True, text=True)


ROCKY = 'ID=rocky\nID_LIKE="rhel centos fedora"\n'
UBUNTU = "ID=ubuntu\nID_LIKE=debian\n"
PROXY = {"HTTP_PROXY_URL": "http://proxy.example.org:3128", "HTTPS_PROXY_URL": "", "NO_PROXY_LIST": "192.0.2.0/24"}
RKE2 = {
    "ROLE": "server", "SERVER_URL": "", "NODE_NAME": "k8s01", "NODE_IP": "10.60.0.4",
    "TLS_SAN": "192.0.2.11,k8s.example.org",
    "RKE2_VERSION": "", "RKE2_CHANNEL": "stable", "INSTALL_URL": "https://get.rke2.io", "INGRESS": "ingress-nginx",
    "CIS": "false", "CLUSTER_CIDR": "10.42.0.0/16", "SERVICE_CIDR": "10.43.0.0/16", "DISABLE_FIREWALL": "true",
    "MIRRORS": "docker.io=https://mirror.example.org,https://mirror2.example.org", **PROXY,
}  # fmt: skip


def test_an_rke2_server_behind_a_proxy_and_mirrors(tmp_path) -> None:
    stage = {"token": "t0k3n\n", "ca-1.pem": "CA\n", "registry-registry.example.org.pem": "RCA\n"}
    work, root = _work(tmp_path, "rke2", RKE2, stage, ROCKY)
    run = _run("rke2.sh", work, root)
    assert run.returncode == 0, run.stderr
    conf = root / "etc/rancher/rke2"
    config = (conf / "config.yaml").read_text()
    assert "token-file: /etc/rancher/rke2/ngvm-token\n" in config and "server:" not in config
    assert "selinux: true\n" in config and "node-ip: 10.60.0.4\n" in config
    assert "tls-san:\n  - 10.60.0.4\n  - 192.0.2.11\n  - k8s.example.org\n" in config
    assert (conf / "ngvm-token").read_text() == "t0k3n\n" and oct((conf / "ngvm-token").stat().st_mode)[-3:] == "600"
    registries = (conf / "registries.yaml").read_text()
    assert (
        '"docker.io":\n    endpoint:\n      - "https://mirror.example.org"\n      - "https://mirror2.example.org"'
        in registries
    )
    assert "ca_file: /etc/rancher/rke2/registry-registry.example.org.crt" in registries
    proxy = (root / "etc/default/rke2-server").read_text()
    assert "NO_PROXY=127.0.0.1,localhost,10.42.0.0/16,10.43.0.0/16,.svc,.cluster.local,192.0.2.0/24" in proxy
    assert (root / "etc/pki/ca-trust/source/anchors/ngvm-ca-1.pem").exists()
    assert (root / "etc/NetworkManager/conf.d/rke2-canal.conf").exists()
    log = (root / "commands.log").read_text()
    assert "RUN install rke2 server stable" in log and "RUN systemctl enable rke2-server" in log
    # run again: nothing changes, nothing to restart
    again = _run("rke2.sh", work, root)
    assert again.returncode == 0 and (conf / "config.yaml").read_text() == config


def test_an_rke2_agent_needs_the_server_and_is_no_server(tmp_path) -> None:
    env = RKE2 | {"ROLE": "agent", "NODE_NAME": "k8s04"}
    work, root = _work(tmp_path, "rke2", env, {"token": "t"}, UBUNTU)
    assert _run("rke2.sh", work, root).returncode != 0  # no SERVER_URL
    env["SERVER_URL"] = "https://10.60.0.4:9345"
    work, root = _work(tmp_path / "2", "rke2", env, {"token": "t"}, UBUNTU)
    run = _run("rke2.sh", work, root)
    assert run.returncode == 0, run.stderr
    config = (root / "etc/rancher/rke2/config.yaml").read_text()
    assert "server: https://10.60.0.4:9345\n" in config and "tls-san" not in config and "selinux" not in config
    assert (root / "etc/default/rke2-agent").exists()


COLLECTOR = {
    "TENANT": "lab", "COLLECTOR": "lab-lan", "IMAGE": "registry.example.org/vulnops/ngvm/detect:v0.25.0",
    "CONNECTORS": "lan-ssh=*-*-* 07:30:00;lan-s1=*-*-* 01:30:00", "CONTAINER_PROXY": "false",
    "OPENVAS_SOCKET_DIR": "/var/lib/docker/volumes/gvmd_socket_vol/_data", "LEGACY_CLEANUP": "true", **PROXY,
}  # fmt: skip
COLLECTOR_YAML = (
    "collector: lab-lan\ntenant: lab\nservice: https://detect-lab.example.org\nconnectors:\n"
    "  - {name: lan-ssh, type: targets, targets: /etc/ngvm/collector/targets.yaml}\n"
    "  - name: lan-s1\n    type: sentinelone\n"
)


def test_a_collector_with_podman_one_timer_per_connector(tmp_path) -> None:
    stage = {"collector.yaml": COLLECTOR_YAML, "token": "tok", "ca.pem": "CA", "gvm.env": "NGVM_GVM_USER=scan\n",
             "registry-user": "u", "registry-password": "p"}  # fmt: skip
    work, root = _work(tmp_path, "collector", COLLECTOR, stage, UBUNTU)
    run = _run("collector.sh", work, root)
    assert run.returncode == 0, run.stderr
    c = root / "etc/ngvm/collector"
    assert sorted(p.name for p in c.iterdir()) == ["ca.pem", "collector.yaml", "gvm.env", "token"]
    assert all(oct(p.stat().st_mode)[-3:] == "600" for p in c.iterdir())
    units = root / "etc/systemd/system"
    service = (units / "ngvm-collector@.service").read_text()
    assert "/usr/bin/podman run --rm --replace --pull=never --name ngvm-collector-%i --http-proxy=false" in service
    assert "-v /var/lib/docker/volumes/gvmd_socket_vol/_data:/run/gvmd" in service
    assert "--env-file /etc/ngvm/collector/gvm.env" in service and "Environment=HTTP_PROXY" not in service
    assert "detect agent run --config /etc/ngvm/collector/collector.yaml --connector %i" in service
    assert (units / "ngvm-collector@lan-s1.timer.d/schedule.conf").read_text() == "[Timer]\nOnCalendar=*-*-* 01:30:00\n"
    assert "OnCalendar" not in (units / "ngvm-collector@.timer").read_text()
    log = (root / "commands.log").read_text()
    assert "RUN podman login registry.example.org" in log and "p\n" not in log
    assert "RUN systemctl enable --now ngvm-collector@lan-ssh.timer" in log
    # a connector no longer listed: its timer removed
    (work / "collector.env").write_text((work / "collector.env").read_text().replace(";lan-s1=*-*-* 01:30:00", ""))
    run = _run("collector.sh", work, root)
    assert run.returncode == 0, run.stderr
    assert not (units / "ngvm-collector@lan-s1.timer.d").exists()
    assert "RUN systemctl disable --now ngvm-collector@lan-s1.timer" in (root / "commands.log").read_text()


def test_a_collector_refuses_a_connector_its_file_does_not_have(tmp_path) -> None:
    env = COLLECTOR | {"CONNECTORS": "lan-cbw=*-*-* 01:30:00", "CONTAINER_PROXY": "true"}
    work, root = _work(tmp_path, "collector", env, {"collector.yaml": COLLECTOR_YAML}, ROCKY)
    run = _run("collector.sh", work, root)
    assert run.returncode != 0 and "collector.yaml has no connector lan-cbw" in run.stderr
    env = COLLECTOR | {"COLLECTOR": "lab-other"}
    work, root = _work(tmp_path / "2", "collector", env, {"collector.yaml": COLLECTOR_YAML}, ROCKY)
    assert "'collector: lab-other' expected" in _run("collector.sh", work, root).stderr


def test_the_container_gets_the_proxy_only_when_asked(tmp_path) -> None:
    env = COLLECTOR | {"CONTAINER_PROXY": "true", "OPENVAS_SOCKET_DIR": ""}
    work, root = _work(tmp_path, "collector", env, {"collector.yaml": COLLECTOR_YAML}, ROCKY)
    assert _run("collector.sh", work, root).returncode == 0
    service = (root / "etc/systemd/system/ngvm-collector@.service").read_text()
    assert "--http-proxy=true" in service and "Environment=HTTP_PROXY=http://proxy.example.org:3128" in service
    assert "/run/gvmd" not in service


KEYCLOAK = {
    "PUBLIC_HOST": "auth.example.org", "REALM": "ngvm", "KC_GROUPS": "NGVM-Analysts;NGVM-Admins",
    "CLIENTS": "ngvm-portal|https://portal.example.org/login/generic_oauth",
    "TLS": "files", "ACME_EMAIL": "", "KEYCLOAK_IMAGE": "quay.io/keycloak/keycloak:26.4",
    "POSTGRES_IMAGE": "docker.io/library/postgres:17", "CADDY_IMAGE": "docker.io/library/caddy:2",
    "OPERATOR_URL": "https://raw.example.org/kubernetes", "NAMESPACE": "keycloak", "INGRESS_CLASS": "nginx",
    "CLUSTER_ISSUER": "ngvm", "TLS_SECRET": "", "STORAGE_SIZE": "2Gi", **PROXY,
}  # fmt: skip


def test_keycloak_on_a_vm_its_secrets_made_there(tmp_path) -> None:
    work, root = _work(tmp_path, "keycloak", KEYCLOAK, {"tls.crt": "C", "tls.key": "K"}, ROCKY)
    run = _run("keycloak-vm.sh", work, root)
    assert run.returncode == 0, run.stderr
    k = root / "etc/ngvm/keycloak"
    password = (k / "admin-password").read_text()
    assert len(password) >= 32 and password not in run.stdout + run.stderr
    assert f"KC_BOOTSTRAP_ADMIN_PASSWORD={password}\n" in (k / "admin.env").read_text()
    assert "tls /etc/caddy/tls.crt /etc/caddy/tls.key" in (k / "caddy/Caddyfile").read_text()
    kc = (root / "etc/systemd/system/ngvm-keycloak.service").read_text()
    assert "-e KC_HOSTNAME=https://auth.example.org -e KC_HTTP_ENABLED=true -e KC_HTTP_HOST=127.0.0.1" in kc
    assert password not in kc
    log = (root / "commands.log").read_text()
    assert (
        "RUN realm ngvm clients ngvm-portal|https://portal.example.org/login/generic_oauth"
        " groups NGVM-Analysts;NGVM-Admins" in log
    )
    again = _run("keycloak-vm.sh", work, root)  # the passwords are made once
    assert again.returncode == 0 and (k / "admin-password").read_text() == password


def test_keycloak_in_the_cluster_with_its_database_and_ingress(tmp_path) -> None:
    work, root = _work(tmp_path, "keycloak", KEYCLOAK, {}, UBUNTU)
    run = _run("keycloak-k8s.sh", work, root)
    assert run.returncode == 0, run.stderr
    manifests = (root / "manifests.yaml").read_text()
    assert "kind: Cluster\nmetadata:\n  name: ngvm-keycloak-db" in manifests
    assert "passwordSecret: {name: ngvm-keycloak-db-app, key: password}" in manifests
    assert "hostname: https://auth.example.org" in manifests and "cert-manager.io/cluster-issuer: ngvm" in manifests
    assert "secretName: ngvm-keycloak-tls" in manifests and "name: ngvm-keycloak-service" in manifests


ADDONS = {
    "HELM_VERSION": "v3.19.0", "HELM_URL": "https://get.helm.sh", "STORAGE": "local-path",
    "LOCAL_PATH_URL": "https://raw.example.org/local-path.yaml", "CERT_MANAGER": "true",
    "CERT_MANAGER_CHART": "oci://quay.io/jetstack/charts/cert-manager", "CERT_MANAGER_VERSION": "v1.19.1",
    "ISSUER": "acme", "ISSUER_NAME": "ngvm", "ACME_EMAIL": "ops@example.org",
    "ACME_SERVER": "https://acme.example.org/directory", "INGRESS_CLASS": "nginx", "CNPG": "true",
    "CNPG_URL": "https://raw.example.org/cnpg.yaml", "AGENT": "true", "AGENT_NAME": "ngvm",
    "KAS_ADDRESS": "wss://gitlab.example.org/-/kubernetes-agent/", "AGENT_CHART_REPO": "https://charts.gitlab.io",
    "AGENT_VERSION": "", **PROXY,
}  # fmt: skip


def test_the_addons_of_the_cluster(tmp_path) -> None:
    stage = {
        "agent-token": "glagent-x",
        "gitlab-ca.pem": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
    }
    work, root = _work(tmp_path, "addons", ADDONS, stage, UBUNTU)
    run = _run("addons.sh", work, root)
    assert run.returncode == 0, run.stderr
    log = (root / "commands.log").read_text()
    assert (
        "--set crds.enabled=true" in log
        and "kubectl apply --server-side --force-conflicts -f https://raw.example.org/cnpg.yaml" in log
    )
    assert "RUN secret gitlab-agent-ngvm/gitlab-agent-token" in log and "glagent-x" not in log
    assert "acme:\n    email: ops@example.org" in (root / "manifests.yaml").read_text()
    values = (work / "agent-values.yaml").read_text()
    assert "secretName: gitlab-agent-token" in values and "    -----BEGIN CERTIFICATE-----" in values
    assert '{name: NO_PROXY, value: "192.0.2.0/24,127.0.0.1,localhost,.svc,.cluster.local"}' in values


def test_the_portal_with_its_pull_secret_and_its_client_secret(tmp_path) -> None:
    env = {"NAMESPACE": "ngvm-portal", "RELEASE": "portal", "REGISTRY": "registry.example.org", **PROXY}
    stage = {"portal-values.yaml": "grafana:\n  host: portal.example.org\n", "registry-user": "u",
             "registry-password": "p", "oidc-client-secret": "s"}  # fmt: skip
    work, root = _work(tmp_path, "portal", env, stage, UBUNTU)
    run = _run("portal.sh", work, root)
    assert run.returncode != 0 and "missing charts/ngvm-portal" in run.stderr
    shutil.copytree(ROOT / "deploy/charts/ngvm-portal", work / "charts/ngvm-portal")
    run = _run("portal.sh", work, root)
    assert run.returncode == 0, run.stderr
    log = (root / "commands.log").read_text()
    assert f"helm upgrade --install portal {work}/charts/ngvm-portal -n ngvm-portal" in log
    assert "--set image.pullSecret=ngvm-registry" in log and not (work / "dockerconfig.json").exists()


def test_the_scripts_are_clean() -> None:
    for f in sorted(SCRIPTS.glob("*.sh")):
        subprocess.run(["bash", "-n", str(f)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-x", "-P", str(SCRIPTS), *map(str, sorted(SCRIPTS.glob("*.sh")))], check=True)


# -- deploy/tofu --------------------------------------------------------------------------------
def test_the_variables_of_the_root_are_those_of_the_module() -> None:
    module = (ROOT / "deploy/tofu/modules/platform/variables.tf").read_text().split('variable "hosts"', 1)[1]
    root = (ROOT / "deploy/tofu/existing/variables.tf").read_text().split('variable "hosts"', 1)[1]
    assert module == root


def test_no_secret_is_a_variable() -> None:
    for f in (ROOT / "deploy/tofu").rglob("*.tf"):
        text = f.read_text()
        assert "sensitive" not in text, f
        names = re.findall(r"^\s*(\w+)\s*=\s*optional\(", text, re.M) + re.findall(r'^variable "(\w+)"', text, re.M)
        # a file, a folder, or the name of a Kubernetes Secret: never the secret itself
        names = [n for n in names if not n.endswith(("_file", "_dir")) and n != "tls_secret"]
        assert not [n for n in names if re.search("password|secret|token", n)], f


@pytest.mark.skipif(not shutil.which("tofu"), reason="OpenTofu not installed (the CI job tofu runs it)")
def test_deploy_tofu_checks_and_the_plan_of_the_example(tmp_path) -> None:
    plan = tmp_path / "plan.json"
    env = dict(os.environ, PLAN_JSON=str(plan))
    run = subprocess.run([str(ROOT / "deploy/tofu/check.sh"), "--offline"], env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    changes = {r["address"]: r["change"]["after"] for r in json.loads(plan.read_text())["resource_changes"]}
    assert sorted(a.removeprefix("module.platform.terraform_data.") for a in changes) == [
        "addons[0]", 'collector["lab-lan"]', "keycloak[0]", "kubeconfig[0]", "portal[0]",
        "rke2_first[0]", "rke2_second[0]", "rke2_third[0]",
    ]  # fmt: skip
    second = changes["module.platform.terraform_data.rke2_second[0]"]["triggers_replace"]["env"]
    assert second["SERVER_URL"] == "https://192.0.2.11:9345" and second["ROLE"] == "server"
    collector = changes['module.platform.terraform_data.collector["lab-lan"]']["triggers_replace"]
    assert collector["env"]["CONNECTORS"] == "lan-ssh=*-*-* 07:30:00"
    assert "token" in collector["files"] and "placeholder" not in json.dumps(changes)  # file names, never their content


def test_release_recorded() -> None:
    assert "## v0.25.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.\d+|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
