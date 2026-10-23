# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.11.7: the fictitious tenant is valid; the documentation sync runs only when configured."""

from __future__ import annotations

from pathlib import Path

import yaml

from a2vm.profile import load_profile
from via.alert.contacts import load_contacts

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-industrie"


def test_demo_tenant_profile_and_contacts_are_valid():
    profile = load_profile(DEMO / "client.yaml")
    assert profile.id == "demo-industrie" and len(profile.assets) == 9
    assert all(a.versions for a in profile.assets)
    assert any(a.public_wellbeing_impact == "material" for a in profile.assets)
    assert len(profile.alerts["watchlist"]) == 10
    assert len(load_contacts(DEMO / "contacts.yaml")) == 4
    ci = yaml.safe_load((DEMO / ".gitlab-ci.yml").read_text())
    assert ci["include"][0]["ref"] == ci["variables"]["A2VM_REF"]


def test_docs_sync_job_needs_its_three_variables_and_deletes_only_in_its_folder():
    job = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())["sync-product-docs"]
    for rule in job["rules"]:
        assert all(v in rule["if"] for v in ("$PRODUCT_DOCS_REPO", "$PRODUCT_DOCS_PATH", "$PRODUCT_SYNC_TOKEN"))
    script = "\n".join(job["script"])
    assert "rsync -a --delete --exclude '.synced-from' docs/ \"product/${PRODUCT_DOCS_PATH}/\"" in script
    assert "PRODUCT_SYNC_TOKEN" not in script.replace("oauth2:${PRODUCT_SYNC_TOKEN}@", "")  # never echoed


def _lines(value):
    for item in value:
        if isinstance(item, list):  # a YAML alias of a list (&install), flattened by GitLab
            yield from _lines(item)
        else:
            yield item


def test_every_ci_script_line_is_a_command_not_a_yaml_mapping():
    """A plain YAML line containing ': ' becomes a mapping and GitLab rejects the whole file."""
    for path in (ROOT / ".gitlab-ci.yml", ROOT / "templates" / "client-pipeline.yml"):
        for name, job in yaml.safe_load(path.read_text()).items():
            if not isinstance(job, dict):
                continue
            for key in ("before_script", "script", "after_script"):
                bad = [line for line in _lines(job.get(key, [])) if not isinstance(line, str)]
                assert not bad, f"{path.name}: {name}.{key}: {bad}"
