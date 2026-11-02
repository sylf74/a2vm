# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.18.2: the cloud scanner deployed by Terraform and cloud-init (deploy/scanner)."""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest
import yaml

from .conftest import ROOT

SCANNER = ROOT / "deploy" / "scanner"
VALUES = {
    "gitlab_url": "https://gitlab.example.org",
    "runner_tag": "scan-cloud",
    "greenbone_compose_url": "https://greenbone.github.io/docs/latest/_static/compose.yaml",
    "feed_update_time": "*-*-* 03:30:00",
}


def _render() -> dict:
    """templatefile() for this file: ${name} from VALUES, then $${ and %%{ unescaped."""
    text = (SCANNER / "cloud-init.yaml.tftpl").read_text()
    names = set(re.findall(r"(?<!\$)\$\{(\w+)\}", text))
    assert names == set(VALUES)
    for name, value in VALUES.items():
        text = re.sub(r"(?<!\$)\$\{" + name + r"\}", value, text)
    text = text.replace("$${", "${").replace("%%{", "%{")
    assert text.startswith("#cloud-config\n")
    return yaml.safe_load(text)


def _files() -> dict[str, str]:
    return {f["path"]: f["content"] for f in _render()["write_files"]}


def test_template_variables_are_passed_by_terraform():
    main = (SCANNER / "main.tf").read_text()
    for name in VALUES:
        assert f"{name} = var.{name}" in re.sub(r" +", " ", main)
        assert f'variable "{name}"' in (SCANNER / "variables.tf").read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_scripts_are_valid_bash():
    scripts = {p: c for p, c in _files().items() if p.endswith(".sh")}
    assert {"/opt/a2vm-scanner/bootstrap.sh", "/opt/a2vm-scanner/register-runner.sh"} <= set(scripts)
    for path, content in scripts.items():
        assert subprocess.run(["bash", "-n"], input=content, text=True).returncode == 0, path


def test_only_ssh_is_open_inbound():
    main = (SCANNER / "main.tf").read_text()
    assert 'inbound_default_policy  = "drop"' in main
    assert re.findall(r"port\s+=\s+(\d+)", main) == ["22"]


def test_no_secret_goes_through_terraform():
    files = _files()
    register = files["/opt/a2vm-scanner/register-runner.sh"]
    assert "read -r token" in register and "CI_SERVER_TOKEN=" in register  # stdin, not argv
    assert "--token" not in register
    # `gitlab-runner list` prints the tokens (with colour codes around "Token="): never called.
    for path, content in files.items():
        assert "gitlab-runner list" not in content, path
    status = files["/opt/a2vm-scanner/status.sh"]
    assert "(name|url)" in status and status.count("timeout 20") == 2
    assert "openssl rand" in files["/opt/a2vm-scanner/bootstrap.sh"]
    variables = (SCANNER / "variables.tf").read_text()
    assert not re.search(r'variable "\w*(token|password|secret)\w*"', variables)


def test_jobs_get_the_gvmd_socket_and_the_gmp_account():
    register = _files()["/opt/a2vm-scanner/register-runner.sh"]
    env = _files()["/opt/a2vm-scanner/scanner.env"]
    assert "SOCKET_VOLUME=greenbone-community-edition_gvmd_socket_vol" in env
    assert ':/run/gvmd"]' in register and "A2VM_GVM_PASSWORD=" in register and "A2VM_SERVER_URL=" in register


def test_feed_update_timer():
    timer = _files()["/etc/systemd/system/a2vm-greenbone-feed.timer"]
    assert f"OnCalendar={VALUES['feed_update_time']}" in timer


def test_documented():
    readme = (SCANNER / "README.md").read_text()
    assert "register-runner.sh" in readme and "A2VM_GVM_PASSWORD" in readme
    assert "deploy/scanner" in (ROOT / "docs" / "openvas.md").read_text()
    assert "`deploy/scanner/`" in (ROOT / "CLAUDE.md").read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_a_registration_deleted_in_gitlab_is_removed_locally(tmp_path):
    lib = _files()["/opt/a2vm-scanner/lib.sh"]
    helper = lib[lib.index("RUNNER_CONFIG=") :]
    config = tmp_path / "config.toml"
    config.write_text('concurrent = 1\n\n[[runners]]\n  name = "s"\n  token = "glrt-x"\n')
    script = (
        helper.replace("/etc/gitlab-runner/config.toml", str(config))
        + "runner_registered && sed -i '/^\\[\\[runners\\]\\]/,$d' \"$RUNNER_CONFIG\"; runner_registered || echo gone"
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout
    assert out.strip() == "gone" and config.read_text() == "concurrent = 1\n\n"
