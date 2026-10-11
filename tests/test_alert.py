import json
from pathlib import Path

from vulnops.alert.certfr import parse_feed
from vulnops.alert.cli import main
from vulnops.alert.watch import State

from .conftest import FIXTURES, ROOT

PROFILE = str(ROOT / "examples" / "example-client" / "client.yaml")


def _watch(tmp_path, *extra):
    settings = ["--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm", "--fixtures", str(FIXTURES)]
    paths = ["--state", str(tmp_path / "state.json"), "--out", str(tmp_path / "alerts")]
    return main(["watch", PROFILE, *settings, *paths, *extra])


def test_feed_parsing():
    items = parse_feed((FIXTURES / "certfr" / "avis.xml").read_text(), "avis")
    assert [i.ref for i in items] == ["CERTFR-2099-AVI-0101", "CERTFR-2099-AVI-0102"]
    assert items[0].published.startswith("2099-10-01T08:00")


def test_first_run_records_a_baseline_then_alerts_on_news(tmp_path, monkeypatch):
    monkeypatch.delenv("VULNOPS_ANALYST_TO", raising=False)
    assert _watch(tmp_path) == 0
    assert json.loads((tmp_path / "alerts" / "index.json").read_text()) == []
    state = State.load(tmp_path / "state.json")
    assert "CERTFR-2024-ALE-006" in state.certfr and "CVE-2024-3400" in state.kev

    # The CERT-FR alert and the KEV entry are "new" again: one alert (KEV merged into CERT-FR).
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.kev.discard("CVE-2024-3400")
    state.save()
    _watch(tmp_path)
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    pan = [a for a in index if "CERTFR-2024-ALE-006" in a["id"]]
    assert len(pan) == 1 and pan[0]["level"] == "urgent"
    assert not any(a["id"].endswith("KEV-CVE-2024-3400") for a in index)
    md = (tmp_path / "alerts" / f"{pan[0]['id']}.md").read_text()
    for heading in ("## CVE", "## Produit concerné", "## Type de vulnérabilité", "## CVSS", "## Impact principal",
                    "## État d'exploitation", "## Description", "## Liens"):  # fmt: skip
        assert heading in md
    assert "Internet-facing firewalls" in md and "(exposé à Internet)" in md
    assert "oui — catalogue KEV de la CISA" in md and "10 (critique)" in md
    assert "Exécution de code arbitraire à distance" in md
    assert "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-006/" in md


def test_advisories_only_with_level_all(tmp_path, monkeypatch):
    import yaml

    monkeypatch.delenv("VULNOPS_ANALYST_TO", raising=False)
    data = yaml.safe_load(Path(PROFILE).read_text())
    data["alerts"] = {"level": "all", "recipients": ["rssi@client.example"], "watchlist": ["Unrelated Product"]}
    profile = tmp_path / "client.yaml"
    profile.write_text(yaml.safe_dump(data))
    args = ["--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm", "--fixtures", str(FIXTURES)]
    common = ["--state", str(tmp_path / "state.json"), "--out", str(tmp_path / "alerts")]
    main(["watch", str(profile), *args, *common])  # baseline
    state = State.load(tmp_path / "state.json")
    state.certfr -= {"CERTFR-2099-AVI-0101", "CERTFR-2099-AVI-0102"}
    state.save()
    main(["watch", str(profile), *args, *common])
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    ids = {a["id"] for a in index}
    assert {"example-client-CERTFR-2099-AVI-0101", "example-client-CERTFR-2099-AVI-0102"} <= ids
    assert all(a["level"] == "info" for a in index if "AVI" in a["id"])

    # send: no SMTP host -> dry run, one .eml per alert, addressed to the client
    monkeypatch.delenv("VULNOPS_SMTP_HOST", raising=False)
    assert main(["send", str(profile), "--alerts", str(tmp_path / "alerts")]) == 0
    eml = list((tmp_path / "alerts" / "outbox").glob("*.eml"))
    assert len(eml) == len(index) and "rssi@client.example" in eml[0].read_text()


def test_prose_written_by_llm_and_guarded(settings):
    from vulnops.alert.certfr import FeedItem, parse_publication
    from vulnops.alert.fiche import build
    from vulnops.alert.watch import Item, relevant
    from vulnops.core.llm import LlmClient
    from vulnops.core.profile import load_profile
    from vulnops.detect.inventory import InventoryScanner
    from vulnops.intel.sources import Sources

    from .conftest import fake_llm_transport

    profile = load_profile(PROFILE)
    sources = Sources(settings.sources, fixtures_dir=FIXTURES)
    fi = FeedItem("CERTFR-2024-ALE-006", "alerte", "t", "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-006/", "")
    pub = parse_publication(fi, sources.certfr_item(fi.link))
    item = Item(pub.ref, "certfr-alerte", pub.title, pub.cves, "", publication=pub)
    [alert] = relevant([item], profile, sources, settings, InventoryScanner(settings))

    impact = "Exécution de code à distance en root."
    answers = iter(
        [
            {"impact": impact, "description": "Faille corrigée en 11.1.9.\n\nExploitée."},  # invented version
            {"impact": impact, "description": "Faille GlobalProtect.\n\nExploitée."},
        ]
    )
    settings.llm.enabled = True
    llm = LlmClient(settings.llm, transport=fake_llm_transport(lambda name, body: next(answers)))
    rejected = build(alert, settings, llm)
    assert rejected.prose_source.startswith("template (LLM output rejected: 11.1.9")
    accepted = build(alert, settings, llm)
    assert accepted.prose_source.startswith("llm") and "Faille GlobalProtect." in accepted.markdown()
