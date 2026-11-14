# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.13: an image lives in the exposure of its host.

An image scanned on a host takes from it what nothing says of the image itself: owner, exposure,
mission, zone, from the host's CMDB entry or rule. A rule can name images (`image: vllm/*`). Every
asset says where each attribute comes from (`origins`)."""

from __future__ import annotations

import json
import re

import yaml

from ngvm.io import Detection
from ngvm.models import AssetObservation
from ngvm.profile import load_profile, validate_profile_data

from .conftest import ROOT

AT = "2026-11-12T07:00:00+00:00"


def _profile(tmp_path, rules=()):
    data = {"schema_version": 2, "client": {"id": "lab", "name": "Lab", "updated": "2026-11-12"},
            "rules": list(rules)}  # fmt: skip
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_profile(path)


def _host(attrs=None, source="trivy"):
    return AssetObservation(ref="gpu01.lab.example", kind="host", source=source, observed_at=AT, name="gpu01",
                            identifiers={"fqdn": "gpu01.lab.example", "hostname": "gpu01"},
                            attributes=attrs or {})  # fmt: skip


def _image(runs_on="gpu01.lab.example", attrs=None):
    a = {"runs_on": runs_on} if runs_on else {}
    return AssetObservation(ref="vllm/vllm-openai:latest", kind="image", source="trivy", observed_at=AT,
                            name="vllm/vllm-openai:latest", identifiers={"image": "vllm/vllm-openai:latest"},
                            attributes={**a, **(attrs or {})})  # fmt: skip


def _inventory(profile, observations):
    from verdict.assets.build import build_inventory

    by_source: dict[str, list] = {}
    for o in observations:
        by_source.setdefault(o.source, []).append(o)
    inv = build_inventory(profile, [Detection("lab", s, obs, []) for s, obs in by_source.items()])
    return {a.id: a for a in inv.assets}


CMDB = {"owner": "ia-team", "exposure": "controlled", "mission_prevalence": "support"}


def test_the_image_inherits_from_the_cmdb_of_its_host(tmp_path) -> None:
    from verdict.triage import run_asset

    assets = _inventory(_profile(tmp_path), [_host(), _host(CMDB, source="cmdb"), _image()])
    image = assets["image:vllm/vllm-openai:latest"]
    assert {n: (a.value, a.source, a.note) for n, a in image.attributes.items()} == {
        "owner": ("ia-team", "host", "gpu01, cmdb"),
        "exposure": ("controlled", "host", "gpu01, cmdb"),
        "mission_prevalence": ("support", "host", "gpu01, cmdb"),
        "public_wellbeing_impact": ("minimal", "default", "worst case"),  # the host assumes it too
    }
    assert image.identifiers["runs_on"] == "host:gpu01.lab.example"
    row = run_asset(image)
    assert row["exposure_source"] == "host" and row["runs_on"] == "host:gpu01.lab.example"
    assert row["origins"]["owner"] == "host (gpu01, cmdb)"
    assert row["origins"]["public_wellbeing_impact"] == "default (worst case)"


def test_the_image_rule_and_its_own_cmdb_come_first(tmp_path) -> None:
    rules = [{"image": "vllm/*", "set": {"owner": "ml-platform", "zone": "lab"}, "description": "vLLM images"},
             {"hostname": "gpu*", "set": {"exposure": "small", "zone": "gpu"}}]  # fmt: skip
    assets = _inventory(_profile(tmp_path, rules), [_host(), _host(CMDB, source="cmdb"), _image()])
    image = assets["image:vllm/vllm-openai:latest"]
    assert (image.attributes["owner"].value, image.attributes["owner"].source) == ("ml-platform", "rule")
    assert (image.attributes["zone"].value, image.attributes["zone"].source) == ("lab", "rule")
    # the host: its CMDB first, then its rule; the image inherits the host's exposure
    host = assets["host:gpu01.lab.example"]
    assert host.attributes["exposure"].value == "controlled" and host.attributes["zone"].value == "gpu"
    assert (image.attributes["exposure"].value, image.attributes["exposure"].note) == ("controlled", "gpu01, cmdb")


def test_the_zone_of_the_host(tmp_path) -> None:
    rules = [{"fqdn": "*.lab.example", "set": {"zone": "lan"}}]
    image = _inventory(_profile(tmp_path, rules), [_host(), _image()])["image:vllm/vllm-openai:latest"]
    assert (image.attributes["zone"].value, image.attributes["zone"].source) == ("lan", "host")
    assert image.attributes["exposure"].source == "default"  # the host assumes it: nothing to inherit


def test_an_image_without_its_host_keeps_the_worst_case(tmp_path) -> None:
    for runs_on in ("", "elsewhere.lab.example"):
        image = _inventory(_profile(tmp_path), [_host(), _host(CMDB, source="cmdb"), _image(runs_on)])[
            "image:vllm/vllm-openai:latest"
        ]
        assert image.attributes["owner"].source == "default" and "runs_on" not in image.identifiers


def test_the_short_name_finds_the_host(tmp_path) -> None:
    image = _inventory(_profile(tmp_path), [_host(), _host(CMDB, source="cmdb"), _image("gpu01")])[
        "image:vllm/vllm-openai:latest"
    ]
    assert image.attributes["owner"].value == "ia-team"


def test_the_collector_says_where_the_image_runs(tmp_path) -> None:
    from detect.collect import load_targets, plan
    from detect.scanners import Target, parse_trivy

    (tmp_path / "targets.yaml").write_text(json.dumps({"client": "lab", "targets": [
        {"host": "GPU01.lab.example", "method": "trivy", "images": ["vllm/vllm-openai:latest"]}]}))  # fmt: skip
    tf = load_targets(tmp_path / "targets.yaml")
    image = [j[3] for j in plan(tf) if j[3].kind == "image"][0]
    assert image.host == "gpu01.lab.example"
    d = parse_trivy({"SchemaVersion": 2, "Results": []}, "lab", image)
    assert d.observations[0].attributes["runs_on"] == "gpu01.lab.example"
    host = parse_trivy({"SchemaVersion": 2, "Results": []}, "lab", Target("gpu01", fqdn="gpu01.lab.example"))
    assert host.observations[0].attributes == {}


def test_an_sbom_image_names_its_host(tmp_path) -> None:
    from detect.sbom import SbomConfig, read

    (tmp_path / "web.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
        {"name": "jinja2", "version": "3.1.2", "purl": "pkg:pypi/jinja2@3.1.2"}]}))  # fmt: skip
    cfg = SbomConfig.from_dict({"directory": str(tmp_path), "assets": [
        {"file": "web.cdx.json", "kind": "image", "name": "registry.example.org/web:1", "host": "web01"}]})  # fmt: skip
    d = read(cfg, "lab", log=lambda _: None)
    assert d.observations[0].attributes["runs_on"] == "web01"


def test_the_profile_takes_an_image_rule() -> None:
    data = {"schema_version": 2, "client": {"id": "lab", "name": "Lab", "updated": "2026-11-12"},
            "rules": [{"image": "vllm/*", "set": {"owner": "ml"}}]}  # fmt: skip
    assert validate_profile_data(data, "client.yaml") == []


def test_the_chat_shows_the_origins() -> None:
    from verdict.service.index import RunIndex

    doc = {"rows": [], "assets": [{"id": "image:vllm/vllm-openai:latest", "name": "vllm/vllm-openai:latest",
                                   "owner": "ia-team", "exposure": "controlled", "exposure_source": "host",
                                   "origins": {"owner": "host (gpu01, cmdb)"}, "runs_on": "host:gpu01.lab.example",
                                   "scans": {"trivy": AT}, "last_seen": AT}]}  # fmt: skip
    index = RunIndex({"run_id": "r1"}, doc)
    card = index._card("image:vllm/vllm-openai:latest")
    assert card["origins"] == {"owner": "host (gpu01, cmdb)"} and card["runs_on"] == "host:gpu01.lab.example"


def test_docs() -> None:
    lld = (ROOT / "docs/lld/triage-prioritization.md").read_text(encoding="utf-8")
    assert "inherit_from_host" in lld and "image: vllm/*" in lld
    assert "exps.host" in (ROOT / "verdict/src/verdict/i18n.py").read_text(encoding="utf-8")


def test_release_recorded() -> None:
    assert "## v0.23.13 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[3-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
