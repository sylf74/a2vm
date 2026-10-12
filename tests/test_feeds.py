# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path

import yaml

from vulnops.alert.cli import main
from vulnops.alert.feeds import Source, csaf_entries, parse_generic_feed
from vulnops.alert.watch import State

from .conftest import FIXTURES, ROOT

FEEDS = FIXTURES / "feeds"
CATALOGUE = {
    "version": 1,
    "sources": [
        {"id": "inst", "category": "institutional", "kind": "rss", "url": "https://feeds.example/atom.xml",
         "name": "Institution test"},
        {"id": "psirt", "category": "vendor", "kind": "rss", "url": "https://feeds.example/fortinet.xml",
         "name": "Vendor PSIRT"},
        {"id": "pcert", "category": "vendor", "kind": "csaf",
         "url": "https://csaf.example/.well-known/csaf/provider-metadata.json", "name": "Example ProductCERT"},
        {"id": "acme", "category": "vendor", "kind": "cna", "vendors": ["Acme Networks"], "name": "Acme (CNA)"},
        {"id": "cvelist", "category": "institutional", "kind": "cvelist", "name": "CVE (cvelistV5)"},
    ],
}  # fmt: skip


def test_generic_feeds():
    rss = parse_generic_feed((FEEDS / "feeds.example_fortinet.xml").read_text(), Source("p", "PSIRT", "vendor", "rss"))
    assert [p.ref for p in rss] == ["FG-IR-99-001", "FG-IR-99-002"]
    assert rss[0].cves == ["CVE-2099-20001"] and "Fortinet FortiOS SSL-VPN" in rss[0].summary  # HTML stripped
    atom = parse_generic_feed(
        (FEEDS / "feeds.example_atom.xml").read_text(), Source("i", "Inst", "institutional", "rss")
    )
    assert atom[0].link == "https://cert.example/adv/1" and atom[0].cves == ["CVE-2099-10001"]


def test_csaf_index_newest_first():
    text = (FEEDS / "csaf.example_csaf_changes.csv").read_text()
    entries = csaf_entries("changes", "https://csaf.example/csaf/changes.csv", text)
    assert entries[0] == ("https://csaf.example/csaf/2099/ssa-0001.json", "2099-10-12T06:00:00Z")


def test_watch_with_catalogue(tmp_path, monkeypatch):
    monkeypatch.delenv("VULNOPS_ANALYST_TO", raising=False)
    data = yaml.safe_load((ROOT / "examples" / "example-client" / "client.yaml").read_text())
    data["alerts"] = {"level": "all", "watchlist": ["Fortinet FortiOS", "Siemens SCALANCE X"]}
    profile = tmp_path / "client.yaml"
    profile.write_text(yaml.safe_dump(data))
    catalogue = tmp_path / "sources.yaml"
    catalogue.write_text(yaml.safe_dump(CATALOGUE))
    args = ["watch", str(profile), "--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm",
            "--fixtures", str(FIXTURES), "--sources", str(catalogue),
            "--state", str(tmp_path / "state.json"), "--out", str(tmp_path / "alerts")]  # fmt: skip

    main(args)  # baseline
    state = State.load(tmp_path / "state.json")
    assert state.marks["pcert"] == "2099-10-12T06:00:00Z" and "FG-IR-99-001" in state.seen["psirt"]
    state.seen = {k: [] for k in state.seen}  # everything is new again
    state.marks["pcert"] = "2099-10-05T00:00:00Z"
    state.save()
    main(args)
    index = {a["id"]: a for a in json.loads((tmp_path / "alerts" / "index.json").read_text())}

    vendor = index["example-client-psirt-FG-IR-99-001"]  # watchlist match in a vendor RSS feed
    md = (tmp_path / "alerts" / f"{vendor['id']}.md").read_text()
    assert "Source : Vendor PSIRT (éditeur / constructeur)" in md and "Fortinet FortiOS" in md
    assert "example-client-psirt-FG-IR-99-002" not in index  # FortiClient: not on the watchlist

    csaf = index["example-client-pcert-SSA-0001"]
    md = (tmp_path / "alerts" / f"{csaf['id']}.md").read_text()
    assert "Correctif : disponible — Update to V5.5 or later" in md and "sévérité éditeur : critical" in md

    assert any(k.startswith("example-client-inst-") for k in index)  # declared asset named in the Atom entry
    cna = next(a for k, a in index.items() if k.endswith("CVE-CVE-2099-10002"))
    assert "Source : Acme (CNA) (éditeur / constructeur)" in (tmp_path / "alerts" / f"{cna['id']}.md").read_text()

    # The same CVEs are not alerted again from another source within 14 days.
    state = State.load(tmp_path / "state.json")
    assert "CVE-2099-20002" in state.alerted
    state.marks["pcert"] = "2099-10-05T00:00:00Z"
    state.save()
    main(args)
    again = json.loads((tmp_path / "alerts" / "index.json").read_text())
    assert not any("SSA-0001" in a["id"] for a in again)


def test_check_sources(capsys):
    assert main(["check-sources", "--sources", str(ROOT / "config" / "watch-sources.yaml"),
                 "--fixtures", str(FIXTURES)]) in (0, 3)  # fmt: skip
    out = capsys.readouterr().out
    assert "OK  on  institutional certfr-alerte" in out and "dell" in out


def test_catalogue_is_valid():
    from vulnops.alert.feeds import load_catalogue

    cat = load_catalogue(ROOT / "config" / "watch-sources.yaml")
    assert {s.category for s in cat} == {"institutional", "vendor", "research"}
    assert any(s.id == "supermicro" and "Supermicro" in s.vendors for s in cat)
    assert Path(ROOT / "config" / "watch-sources.yaml").read_text().count("kind: cna") >= 10
