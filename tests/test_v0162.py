# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.16.2: the watch runs with via and a2vm only (no detect, no verdict installed), as in its image."""

from __future__ import annotations

import subprocess
import sys
import textwrap

from a2vm.models import CvssMetric, VulnRecord
from a2vm.ssvc import BOD_EN, BOD_FR, remediation_delay

from .conftest import FIXTURES, ROOT

PROFILE = ROOT / "examples" / "example-client" / "client.yaml"

# Run in a fresh interpreter where importing detect or verdict fails, as in the via image.
WATCH_ALONE = textwrap.dedent(
    """
    import importlib.abc, json, sys
    from pathlib import Path

    class Absent(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in {"detect", "verdict"}:
                raise ModuleNotFoundError(f"No module named {name!r} (not in the via image)")
            return None

    sys.meta_path.insert(0, Absent())
    from via.alert.cli import main
    from via.alert.watch import State

    profile, settings, fixtures, out = sys.argv[1:5]
    args = ["watch", profile, "--settings", settings, "--no-llm", "--fixtures", fixtures,
            "--state", out + "/state.json", "--out", out + "/alerts"]
    assert main(args) == 0
    state = State.load(out + "/state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.kev.discard("CVE-2024-3400")
    state.save()
    assert main(args) == 0
    assert not {m.split(".")[0] for m in sys.modules} & {"detect", "verdict"}
    index = json.loads(Path(out, "alerts", "index.json").read_text())
    print(json.dumps(index))
    """
)


def test_the_watch_runs_without_detect_nor_verdict(tmp_path):
    out = subprocess.run(
        [sys.executable, "-c", WATCH_ALONE, str(PROFILE), str(ROOT / "config" / "settings.yaml"), str(FIXTURES),
         str(tmp_path)],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}, timeout=120,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr[-2000:]
    index = __import__("json").loads(out.stdout.strip().splitlines()[-1])
    [pan] = [a for a in index if "CERTFR-2024-ALE-006" in a["id"]]
    assert pan["level"] == "urgent"
    md = (tmp_path / "alerts" / f"{pan['id']}.md").read_text()
    assert "## Recommended remediation delay" in md and "(CISA BOD 26-04)" in md


def _record(in_kev=False, adp_ssvc=None, cvss=None) -> VulnRecord:
    return VulnRecord(
        "CVE-2099-0001",
        "PUBLISHED",
        None,
        "",
        [],
        cvss or [],
        [],
        adp_ssvc,
        {"date": "2099-01-01"} if in_kev else None,
        [],
    )


def test_remediation_delay_from_the_common_tables():
    adp = {"automatable": "yes", "technical_impact": "total"}
    assert remediation_delay(_record(in_kev=True, adp_ssvc=adp), True) == BOD_EN["3 days & forensic investigation"]
    assert (
        remediation_delay(_record(in_kev=True, adp_ssvc=adp), True, lang="fr")
        == BOD_FR["3 days & forensic investigation"]
    )
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss = [CvssMetric("3.1", vector, 9.8, "CRITICAL", "cna")]
    assert remediation_delay(_record(cvss=cvss), True) == BOD_EN["3 days"]
    # Nothing known: the policy's default for unknown inputs.
    assert remediation_delay(_record(), False, "optimistic") == BOD_EN["fix on system upgrade"]
    assert remediation_delay(_record(), True) == BOD_EN["3 days"]


def test_the_images_hold_one_pillar_and_no_pillar_offers_extensions():
    dockerfile = (ROOT / "images" / "Dockerfile").read_text()
    assert "COPY ${PILLAR} /src/${PILLAR}" in dockerfile and "COPY detect" not in dockerfile
    assert not (ROOT / "a2vm" / "src" / "a2vm" / "extensions.py").exists()
    for pillar in ("via", "detect", "verdict"):
        assert "entry-points" not in (ROOT / pillar / "pyproject.toml").read_text()
