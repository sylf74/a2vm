# SPDX-License-Identifier: AGPL-3.0-only
"""Split deployment: public data fetched on one runner, matched to the client on another."""

import json
from pathlib import Path

import yaml

from vulnops.alert.bundle import item_from_dict, item_to_dict, read_bundle
from vulnops.alert.cli import main
from vulnops.alert.watch import State
from vulnops.core.io import write_detection
from vulnops.detect.scanners import load_trivy_file
from vulnops.intel.cli import main as intel_main

from .conftest import FIXTURES, ROOT

PROFILE = str(ROOT / "examples" / "example-client" / "client.yaml")
SETTINGS = ["--settings", str(ROOT / "config" / "settings.yaml")]
NEWS = {"certfr": {"CERTFR-2024-ALE-006", "CERTFR-2099-AVI-0101"}, "kev": {"CVE-2024-3400"}}


def _discover(tmp, out):
    state = ["--state", str(tmp / "d.json")]
    return main(["discover", *SETTINGS, "--fixtures", str(FIXTURES), *state, "--out", str(tmp / out)])


def _make_news(state_path):
    state = State.load(state_path)
    state.certfr -= NEWS["certfr"]
    state.kev -= NEWS["kev"]
    state.save()


def _single(tmp, monkeypatch):
    """Reference: one runner reads the sources and matches."""
    monkeypatch.delenv("VULNOPS_ANALYST_TO", raising=False)
    args = ["watch", PROFILE, *SETTINGS, "--no-llm", "--fixtures", str(FIXTURES), "--state", str(tmp / "s.json")]
    main([*args, "--out", str(tmp / "a0")])
    _make_news(tmp / "s.json")
    main([*args, "--out", str(tmp / "a1")])
    return json.loads((tmp / "a1" / "index.json").read_text())


def test_split_watch_gives_the_same_alerts(tmp_path, monkeypatch):
    (tmp_path / "single").mkdir()
    expected = _single(tmp_path / "single", monkeypatch)
    assert expected, "the reference run must produce alerts"

    disc = ["discover", *SETTINGS, "--fixtures", str(FIXTURES), "--state", str(tmp_path / "discover.json")]
    match = ["watch", PROFILE, *SETTINGS, "--no-llm", "--state", str(tmp_path / "alerted.json")]

    # first run: baseline on the public side, nothing to match on the client side
    assert main([*disc, "--out", str(tmp_path / "b0")]) in (0, 3)  # 3: a fixture lacks one catalogue source
    _, baseline, _ = read_bundle(tmp_path / "b0")
    assert baseline
    assert main([*match, "--bundle", str(tmp_path / "b0"), "--out", str(tmp_path / "x0")]) == 0
    assert json.loads((tmp_path / "x0" / "index.json").read_text()) == []

    # news on the public side, matched without any network access on the client side
    _make_news(tmp_path / "discover.json")
    main([*disc, "--out", str(tmp_path / "b1")])
    assert (tmp_path / "b1" / "cves" / "CVE-2024-3400.json").exists()
    assert main([*match, "--bundle", str(tmp_path / "b1"), "--out", str(tmp_path / "x1")]) == 0
    got = json.loads((tmp_path / "x1" / "index.json").read_text())
    assert [(a["id"], a["level"]) for a in got] == [(a["id"], a["level"]) for a in expected]
    assert State.load(tmp_path / "alerted.json").alerted  # the 14-day memory stays on the client side


def test_bundle_holds_no_client_data(tmp_path):
    profile = yaml.safe_load(Path(PROFILE).read_text())
    _discover(tmp_path, "b0")
    _make_news(tmp_path / "d.json")
    _discover(tmp_path, "b1")
    text = " ".join(p.read_text() for p in (tmp_path / "b1").rglob("*.json"))
    client = profile["client"]
    assert client["id"] not in text and client["name"] not in text
    for asset in profile.get("assets", []):
        assert asset["id"] not in text


def test_item_round_trip(tmp_path):
    _discover(tmp_path, "b0")
    _make_news(tmp_path / "d.json")
    _discover(tmp_path, "b1")
    items, _, _ = read_bundle(tmp_path / "b1")
    assert items and all(item_from_dict(item_to_dict(it)) == it for it in items)
    assert any(it.publication and it.publication.ref == "CERTFR-2024-ALE-006" for it in items)


def test_cve_ids_export_has_only_ids(tmp_path):
    d = load_trivy_file(FIXTURES / "trivy" / "node00.lab.example.json", "lab")
    write_detection(tmp_path / "detect" / "lab" / "trivy.json", d)
    assert intel_main(["cve-ids", "--detect", str(tmp_path / "detect"), "--out", str(tmp_path / "ids.txt")]) == 0
    assert (tmp_path / "ids.txt").read_text() == "CVE-2021-3712\n"
