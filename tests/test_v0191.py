# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.19.1: the cloud scanner cleans up its disk; its scripts are updated in place; D17 and D18."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess

import pytest

from .conftest import ROOT
from .test_v0182 import SCANNER, _files

spec = importlib.util.spec_from_file_location("update_scripts", SCANNER / "update-scripts.py")
update_scripts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_scripts)


def test_volume_is_90_gb_by_default():
    text = (SCANNER / "variables.tf").read_text()
    block = text[text.index('variable "root_volume_gb"') :].split("}", 1)[0]
    assert re.search(r"default\s+=\s+90\b", block)


def test_cleanup_runs_after_the_feeds_and_spares_greenbone():
    files = _files()
    assert '"$D/cleanup.sh"' in files["/opt/a2vm-scanner/feed-update.sh"]
    cleanup = files["/opt/a2vm-scanner/cleanup.sh"]
    assert '--filter "label!=com.docker.compose.project=$COMPOSE_PROJECT"' in cleanup
    assert "grep '^runner-'" in cleanup
    assert "system prune" not in cleanup and "volume prune" not in cleanup


def test_status_shows_the_free_space():
    status = _files()["/opt/a2vm-scanner/status.sh"]
    assert "== disk" in status and "less than 15 % free" in status


def test_a_changed_template_does_not_replace_the_scanner():
    main = (SCANNER / "main.tf").read_text()
    assert re.search(r"lifecycle\s*\{\s*ignore_changes\s*=\s*\[user_data\]", main)


def test_update_scripts_writes_what_cloud_init_writes(tmp_path):
    text = (SCANNER / "cloud-init.yaml.tftpl").read_text()
    out = update_scripts.script(text)
    written = re.findall(r"install -D -m (\d+) /dev/stdin (\S+) <<'A2VM_END_OF_FILE'\n(.*?)A2VM_END_OF_FILE", out, re.S)
    files = _files()
    paths = {path for _, path, _ in written}
    assert "/opt/a2vm-scanner/cleanup.sh" in paths and "/opt/a2vm-scanner/status.sh" in paths
    assert not paths & {"/opt/a2vm-scanner/scanner.env", "/opt/a2vm-scanner/bootstrap.sh"}
    assert "/etc/systemd/system/a2vm-greenbone-feed.timer" not in paths  # holds a Terraform value
    for _mode, path, content in written:
        assert content == files[path], path
    assert out.rstrip().endswith("systemctl daemon-reload")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_update_scripts_output_is_valid_bash():
    out = update_scripts.script((SCANNER / "cloud-init.yaml.tftpl").read_text())
    assert subprocess.run(["bash", "-n"], input=out, text=True).returncode == 0


def test_decisions_d17_and_d18_are_recorded():
    hld = (ROOT / "docs" / "hld" / "00-product-strategy.md").read_text()
    assert re.search(r"^\| D17 \| Vulnerability knowledge is shared", hld, re.M)
    assert re.search(r"^\| D18 \| Dashboards show, A2VM acts", hld, re.M)
    assert "| v0.22.0 (to confirm) | D17" in hld  # moved to v0.22.0 by v0.21.0 (D19 first)
