# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.13.2: the install script of a collector (deploy/collector/install-collector.sh)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "collector" / "install-collector.sh"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")


@needs_bash
def test_script_is_valid_bash():
    assert subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode == 0


@needs_bash
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--collector", "lab-lan"], "--tenant is required"),
        (["--tenant", "Lab", "--collector", "lab-lan"], "--tenant is required"),
        (["--tenant", "lab"], "--collector is required"),
        (["--tenant", "lab", "--collector", "lab-lan", "--service", "http://x", "--image", "i"], "--service"),
        (["--tenant", "lab", "--collector", "lab-lan", "--service", "https://x"], "--image is required"),
        (
            ["--tenant", "lab", "--collector", "lab-lan", "--service", "https://x", "--image", "i"]
            + ["--openvas-hosts", "192.0.2.0/24"],
            "--gvm-socket-volume",
        ),
        (["--nope"], "unknown argument"),
    ],
)
def test_arguments_are_checked_before_anything_is_touched(args, message):
    result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True)
    assert result.returncode == 2 and message in result.stderr


def test_no_secret_is_printed_or_passed_as_an_argument():
    text = SCRIPT.read_text()
    assert "--password-stdin <" in text  # registry password read from its file
    assert 'rm -f "$HERE/registry-password.txt"' in text and 'rm -f "$HERE/scan_key"' in text
    assert "( umask 077; printf 'A2VM_GVM_USER=%s\\nA2VM_GVM_PASSWORD=%s\\n'" in text
    assert 'chmod 0600 "$C/gvm.env"' in text and "unset pw out" in text
    for line in text.splitlines():
        if re.search(r"\becho\b", line):
            assert "$pw" not in line and "token)" not in line, line
    assert "--env-file $C/gvm.env" in text  # GMP account handed as an environment file


def test_units_and_checks_match_the_guide():
    text = SCRIPT.read_text()
    for needle in (
        "--user 10001:10001",
        "SuccessExitStatus=3",
        "Persistent=true",
        "detect agent run --config %s/collector.yaml --connector %%i",
        "from detect.agent import load_config",
        "gmp: unix:///run/gvmd/gvmd.sock",
        "--group-add",
    ):
        assert needle in text, needle
    guide = (ROOT / "docs" / "collectors.md").read_text()
    assert "deploy/collector/install-collector.sh" in guide and "### By hand" in guide
