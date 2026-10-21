# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
import json
from pathlib import Path

from via.alert.certfr import parse_feed
from via.alert.cli import main
from via.alert.watch import State

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
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
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
    assert "| **Internet-facing firewalls with GlobalProtect VPN portal** |" in md and "| exposé à Internet |" in md
    assert "oui — catalogue KEV de la CISA" in md and "10 (critique)" in md
    assert "Exécution de code arbitraire à distance" in md
    assert "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-006/" in md


def test_advisories_only_with_level_all(tmp_path, monkeypatch):
    import yaml

    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
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
    monkeypatch.delenv("A2VM_SMTP_HOST", raising=False)
    assert main(["send", str(profile), "--alerts", str(tmp_path / "alerts")]) == 0
    eml = list((tmp_path / "alerts" / "outbox").glob("*.eml"))
    assert len(eml) == len(index) and "rssi@client.example" in eml[0].read_text()


def test_prose_written_by_llm_and_guarded(settings):
    from a2vm.llm import LlmClient
    from a2vm.profile import load_profile
    from detect.inventory import InventoryScanner
    from via.alert.certfr import FeedItem, parse_publication
    from via.alert.fiche import build
    from via.alert.watch import Item, relevant
    from via.intel.sources import Sources

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


def test_graph_transport(monkeypatch):
    import httpx

    from via.alert.mail import message, send

    calls = []

    def handler(request):
        calls.append(request)
        if "login.microsoftonline.com" in str(request.url):
            assert b"client_credentials" in request.content
            return httpx.Response(200, json={"access_token": "t0k"})
        assert request.headers["Authorization"] == "Bearer t0k"
        body = json.loads(request.content)
        assert body["message"]["toRecipients"] == [{"emailAddress": {"address": "rssi@client.example"}}]
        assert body["message"]["body"]["contentType"] == "HTML"
        return httpx.Response(202)

    for k, v in {"TENANT_ID": "tid", "CLIENT_ID": "cid", "CLIENT_SECRET": "sec", "SENDER": "veille@x.example"}.items():
        monkeypatch.setenv(f"A2VM_GRAPH_{k}", v)
    monkeypatch.setenv("A2VM_MAIL_TRANSPORT", "graph")
    msg = message("Sujet", "<p>fiche</p>", "fiche", ["rssi@client.example"], "veille@x.example")
    out = send(msg, transport=httpx.MockTransport(handler))
    assert "Microsoft Graph" in out and len(calls) == 2
    assert "/users/veille@x.example/sendMail" in str(calls[1].url)


def test_contacts_by_level_and_role(tmp_path, capsys):
    from a2vm.profile import load_profile
    from via.alert.contacts import load_contacts, recipients

    lab = ROOT / "examples" / "lab"
    contacts = load_contacts(lab / "contacts.yaml")
    profile = load_profile(lab / "client.yaml")
    urgent = [c.email for c in recipients("urgent", contacts, profile)]
    info = [c.email for c in recipients("info", contacts, profile)]
    assert urgent == ["rssi@lab.example", "cert@lab.example", "dsi@lab.example", "admin@lab.example"]
    assert "dsi@lab.example" not in info and "soc@lab.example" not in urgent  # level filter, inactive
    assert main(["contacts", str(lab / "client.yaml"), "--contacts", str(lab / "contacts.yaml")]) == 0
    assert "Jeanne Martin (RSSI)" in capsys.readouterr().out

    bad = tmp_path / "contacts.yaml"
    bad.write_text("schema_version: 1\ncontacts:\n  - {name: X, email: not-an-address}\n")
    assert main(["contacts", str(lab / "client.yaml"), "--contacts", str(bad)]) == 2


def _inventory(directory, client_id, cve, seen):
    from a2vm.io import write_assets, write_findings
    from a2vm.models import Asset, Attribute, Finding, FindingObservation, Match

    asset = Asset(
        "host:web01.lan.example", client_id, "host", "web01", "web01", {"hostname": "web01"},
        {
            "exposure": Attribute("open", "external-scan", "seen from the internet at www.example.org:443"),
            "zone": Attribute("dmz", "rule"),
            "owner": Attribute("web-team", "declared"),
            "mission_prevalence": Attribute("support", "default"),
            "public_wellbeing_impact": Attribute("minimal", "default"),
        },
        ["trivy", "external-scan"], seen, seen,
    )  # fmt: skip
    obs = FindingObservation("trivy", seen, Match("scanner", "", "httpd", 1.0), "httpd", "2.4.57", "2.4.62")
    finding = Finding(
        Finding.make_id(client_id, asset.id, cve), client_id, asset.id, cve, "affected", ["2.4.57"], [obs]
    )
    base = directory / client_id
    write_assets(base / "assets.json", client_id, [asset])
    write_findings(base / "findings.json", client_id, [finding], [])


def _second_run(work, *extra):
    assert _watch(work, *extra) == 0  # baseline
    state = State.load(work / "state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.save()
    _watch(work, *extra)
    return {a["id"]: a for a in json.loads((work / "alerts" / "index.json").read_text())}


def test_watch_names_the_assets_of_the_last_daily_inventory(tmp_path, monkeypatch):
    import datetime as dt

    from a2vm.profile import load_profile

    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    client_id = load_profile(PROFILE).id
    seen = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    _inventory(tmp_path / "inv", client_id, "CVE-2099-10001", seen)

    without = _second_run(tmp_path / "a", "--inventory", "none")
    assert not any("CVE-2099-10001" in i for i in without)  # the profile alone does not match it

    found = _second_run(tmp_path / "b", "--inventory", str(tmp_path / "inv"))
    alert = next(i for i in found if "CVE-2099-10001" in i)
    md = (tmp_path / "b" / "alerts" / f"{alert}.md").read_text()
    row = "| **web01** | dmz | ouverte (Internet), scan externe | httpd 2.4.57 | 2.4.62 | web-team "
    row += "| détecté (scan des paquets) |"
    assert row in md
    assert f"Inventaire du {seen[:10]}" in md
    html = (tmp_path / "b" / "alerts" / f"{alert}.html").read_text()
    assert "<table" in html and "<td" in html and "web-team" in html
    assert "- Vulnérabilité critique sur un actif exposé à Internet" in md


def test_inventory_fetch_reads_the_triage_artifacts_and_flags_an_old_one(tmp_path):
    import io
    import zipfile

    import httpx

    from via.alert.inventory import fetch

    _inventory(tmp_path / "work" / "assets", "acme", "CVE-2099-10001", "2026-01-02T05:00:00+00:00")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for f in (tmp_path / "work").rglob("*.json"):
            z.write(f, f.relative_to(tmp_path).as_posix())
    asked = {}

    def handler(request):
        asked["url"] = str(request.url)
        return httpx.Response(200, content=buf.getvalue())

    env = {"CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_JOB_TOKEN": "t"}
    inv, note = fetch(42, "acme", tmp_path / "dl", environ=env, transport=httpx.MockTransport(handler))
    assert asked["url"].endswith("/projects/42/jobs/artifacts/main/download?job=triage")
    assert inv is not None and list(inv.findings_by_cve) == ["CVE-2099-10001"]
    assert "inventory of 2026-01-02: 1 assets, 1 findings" in note and "WARN" in note

    missing, note = fetch(42, "other", tmp_path / "dl2", environ=env, transport=httpx.MockTransport(handler))
    assert missing is None and "declared assets only" in note
    gone, note = fetch(
        42, "acme", tmp_path / "dl3", environ=env, transport=httpx.MockTransport(lambda r: httpx.Response(404))
    )
    assert gone is None and "declared assets only" in note


def test_watch_reads_the_inventory_left_in_the_runner_cache(tmp_path, monkeypatch):
    import datetime as dt

    from a2vm.profile import load_profile

    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    monkeypatch.chdir(tmp_path)  # the pipeline restores the cache into work/assets of the job
    seen = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    _inventory(tmp_path / "work" / "assets", load_profile(PROFILE).id, "CVE-2099-10001", seen)
    found = _second_run(tmp_path / "c")  # --inventory auto (default)
    assert any("CVE-2099-10001" in i for i in found)


def test_analysts_mail_numbers_the_alerts_and_the_journal_keeps_every_event(tmp_path, monkeypatch, capsys):
    from via.alert import journal

    monkeypatch.setenv("A2VM_ANALYST_TO", "soc@example.org")
    monkeypatch.delenv("A2VM_SMTP_HOST", raising=False)
    monkeypatch.delenv("A2VM_MAIL_TRANSPORT", raising=False)
    monkeypatch.delenv("A2VM_SEND_ONLY", raising=False)
    monkeypatch.setenv("CI_PIPELINE_URL", "https://gitlab.example/acme/-/pipelines/1")
    found = _second_run(tmp_path)
    assert len(found) == 2
    outbox = sorted((tmp_path / "alerts" / "outbox").glob("*.eml"))
    import email
    from email import policy

    first = email.message_from_bytes(outbox[0].read_bytes(), policy=policy.default)
    html = first.get_body(("html",)).get_content()
    assert "A2VM_SEND_ONLY" in html and "sur 2 de ce pipeline" in html

    log = journal.read(tmp_path / "alerts-log.jsonl")  # next to --state
    assert [e["event"] for e in log].count("drafted") == 2
    assert [e["event"] for e in log].count("analysts") == 2
    assert (tmp_path / "alerts" / "alerts-log.jsonl").exists()  # published with the artifacts
    drafted = next(e for e in log if e["event"] == "drafted" and "CVE-2099-10002" in e["alert"])
    assert drafted["cves"] == ["CVE-2099-10002"]

    # Send only the second alert, by its number; the choice and the result are traced.
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    import yaml

    data = yaml.safe_load(Path(PROFILE).read_text())
    data.setdefault("alerts", {})["recipients"] = ["it@example.org"]
    profile = tmp_path / "client.yaml"
    profile.write_text(yaml.safe_dump(data, allow_unicode=True))
    monkeypatch.setenv("A2VM_SEND_ONLY", "2")
    args = ["send", str(profile), "--alerts", str(tmp_path / "alerts"), "--journal", str(tmp_path / "alerts-log.jsonl")]
    assert main(args) == 0
    sent = json.loads((tmp_path / "alerts" / "sent.json").read_text())
    assert [s["alert"] for s in sent] == [index[1]["id"]] and sent[0]["event"] == "sent"
    assert journal.read(tmp_path / "alerts-log.jsonl")[-1]["event"] == "sent"

    # An unknown choice sends nothing.
    monkeypatch.setenv("A2VM_SEND_ONLY", "7")
    assert main(args) == 1
    assert len(json.loads((tmp_path / "alerts" / "sent.json").read_text())) == 1


def test_select_by_number_id_or_suffix():
    from via.alert.cli import select

    index = [{"id": "acme-CERTFR-2024-ALE-006"}, {"id": "acme-CVE-CVE-2099-10002"}]
    assert select(index, ["2"]) == ([index[1]], [])
    assert select(index, ["CERTFR-2024-ALE-006", "acme-CVE-CVE-2099-10002"]) == (index, [])
    assert select(index, ["3", "nothing"]) == ([], ["3", "nothing"])


def test_test_mail_without_smtp_writes_the_message(tmp_path, monkeypatch):
    monkeypatch.delenv("A2VM_SMTP_HOST", raising=False)
    monkeypatch.delenv("A2VM_MAIL_TRANSPORT", raising=False)
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    assert main(["test-mail"]) == 2  # nobody to write to
    assert main(["test-mail", "--to", "soc@example.org", "--out", str(tmp_path)]) == 0
    import email
    from email import policy

    msg = email.message_from_bytes(next(tmp_path.glob("*.eml")).read_bytes(), policy=policy.default)
    assert "Test d'envoi" in msg["Subject"]
