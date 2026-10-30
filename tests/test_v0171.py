# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.17.1: the English reference, the contacts' languages, the translation checked by an analyst,
one mail and one Word file per language."""

from __future__ import annotations

import email
import json
from email import policy
from pathlib import Path

import httpx
import pytest
import yaml
from docx import Document

from a2vm.config import LlmSettings
from a2vm.llm import LlmClient
from via.alert import i18n, translate
from via.alert.watch import State
from via.service import sender
from via.service.client import WatchClient
from via.service.review import Review

from .conftest import FIXTURES, ROOT, fake_llm_transport
from .test_alert import PROFILE
from .test_v0160 import RUN, TENANT, _service, service  # noqa: F401 - fixture

URL = "https://alerts-lab.apps.example.org"
CONTACTS = """schema_version: 1
contacts:
  - {name: IT, email: it@example.org}
  - {name: RSSI, role: RSSI, email: rssi@example.org, language: fr}
"""


def test_the_catalogue_is_complete_and_the_sheet_is_english():
    assert i18n.check() == []
    assert i18n.t("fr", "h.impact") == "Impact principal" and i18n.t("de", "h.impact") == "Main impact"
    assert i18n.heading_key("Impact principal") == i18n.heading_key("Main impact") == "h.impact"


def _french(answer_name: str, body: dict) -> dict:
    """A model that translates the impact and keeps everything else."""
    ref = body["messages"][1]["content"].split("<untrusted>\n", 1)[1].rsplit("\n</untrusted>", 1)[0]
    lines, out, in_impact = ref.splitlines(), [], False
    for line in lines:
        if line.startswith("## "):
            in_impact = line == "## Main impact"
            out.append(line)
        elif in_impact and line.strip():
            out.append("Impact traduit en français.")
        else:
            out.append(line)
    return {"markdown": "\n".join(out)}


def _llm(answer) -> LlmClient:
    s = LlmSettings(enabled=True, base_url="http://llm.example/v1", model="m")
    return LlmClient(s, transport=fake_llm_transport(answer))


def test_a_translation_keeps_the_facts_and_takes_the_catalogue_headings():
    ref = "# [URGENT] Title\n\n## Main impact\n\nRemote code.\n\n## CVE\n\nCVE-2099-0001 9.8\n"
    text, source = translate.translate(_llm(_french), ref, "fr")
    assert source == "llm (m)" and "## Impact principal" in text and "Impact traduit" in text
    assert "CVE-2099-0001 9.8" in text
    added = _llm(lambda n, b: {"markdown": ref.replace("Remote code.", "Remote code in 1.2.3.")})
    with pytest.raises(translate.TranslationError, match="not in the reference"):
        translate.translate(added, ref, "fr")
    lost = _llm(lambda n, b: {"markdown": ref.replace("CVE-2099-0001", "la CVE")})
    with pytest.raises(translate.TranslationError, match="missing"):
        translate.translate(lost, ref, "fr")
    shape = _llm(lambda n, b: {"markdown": ref.replace("## CVE\n\n", "")})
    with pytest.raises(translate.TranslationError, match="structure"):
        translate.translate(shape, ref, "fr")
    with pytest.raises(translate.TranslationError, match="no LLM"):
        translate.translate(None, ref, "fr")


@pytest.fixture
def flow(service, tmp_path, monkeypatch):  # noqa: F811 - the fixture of test_v0160
    svc, url, token = service
    for v in ("A2VM_ANALYST_TO", "A2VM_SMTP_HOST", "A2VM_MAIL_TRANSPORT"):
        monkeypatch.delenv(v, raising=False)
    data = yaml.safe_load(Path(PROFILE).read_text())
    data.setdefault("alerts", {}).update({"attach": ["docx"], "recipients": []})
    profile = tmp_path / "client.yaml"
    profile.write_text(yaml.safe_dump(data, allow_unicode=True))
    contacts = tmp_path / "contacts.yaml"
    contacts.write_text(CONTACTS)
    settings = ["--settings", str(ROOT / "config" / "settings.yaml"), "--no-llm", "--fixtures", str(FIXTURES)]
    watch = ["watch", str(profile), *settings, "--contacts", str(contacts)]
    assert _service(url, token, *watch) == 0
    state = State.load(svc.store.root / TENANT / "state.json")
    state.certfr.discard("CERTFR-2024-ALE-006")
    state.save()
    assert _service(url, token, *watch) == 0
    review = Review(TENANT, svc.store, b"k" * 32, set(), {"V"}, URL, contacts=contacts, profile=profile)
    alert = next(a for a in svc.store.alerts(TENANT) if "CERTFR-2024-ALE-006" in a["id"])
    client = WatchClient(url, TENANT, RUN)
    yield svc, review, alert, client, profile, contacts
    client.close()


def test_the_watch_lays_the_word_facts_out_in_each_language(flow):
    svc, _, alert, *_ = flow
    assert set(alert["ctx"]) == {"en", "fr"}
    fr = json.loads(svc.store.file(TENANT, alert["run"], alert["ctx"]["fr"]))
    en = json.loads(svc.store.file(TENANT, alert["run"], alert["ctx"]["en"]))
    assert fr["cves"][0]["vecteur"] == "Réseau" and en["cves"][0]["vecteur"] == "Network"
    assert fr["exploitee"] == "Oui" and en["exploitee"] == "Yes"


def test_translate_validate_and_send_one_mail_per_language(flow, monkeypatch):
    svc, review, alert, client, profile, contacts = flow
    user = "val@example.org"
    review.prepare(review.alert(alert["id"]), user, ["it@example.org", "rssi@example.org"])
    a = review.alert(alert["id"])
    assert a["status"] == "translating" and a["translations"]["fr"]["state"] == "waiting" and not a["ready"]
    with pytest.raises(Exception, match="Not ready"):
        review.act(a, user, "validate")

    assert sender.translate_requested(client, _llm(_french), TENANT) == 1
    a = review.alert(alert["id"])
    assert a["translations"]["fr"]["state"] == "fresh" and a["ready"]
    text, _ = svc.store.translation(TENANT, alert["id"], "fr")
    assert "## Impact principal" in text and "## Pourquoi cette alerte" in text and "Impact traduit" in text

    # Enriching the reference outdates the translation: the recipients are chosen again.
    review.save_edit(a, user, review.current(a) + "\nAnalyst's note.\n")
    a = review.alert(alert["id"])
    assert a["status"] == "pending" and a["translations"]["fr"]["state"] == "outdated"
    review.prepare(a, user, ["it@example.org", "rssi@example.org"])
    assert review.alert(alert["id"])["translations"]["fr"]["state"] == "waiting"
    sender.translate_requested(client, _llm(_french), TENANT)
    a = review.alert(alert["id"])
    review.save_translation(a, user, "fr", svc.store.translation(TENANT, alert["id"], "fr")[0] + "\nRelu.\n")
    review.act(review.alert(alert["id"]), user, "validate")

    mails = []
    monkeypatch.setattr(sender, "send", lambda msg, outbox: mails.append(msg) or "written")
    from a2vm.profile import load_profile
    from via.alert.contacts import load_contacts

    sent, failed = sender.send_validated(client, load_profile(profile), str(profile), load_contacts(contacts), TENANT)
    assert (sent, failed) == (2, 0)
    by_to = {m["To"]: m for m in mails}
    en = by_to["it@example.org"].get_body(("plain",)).get_content()
    fr_msg = by_to["rssi@example.org"]
    fr = fr_msg.get_body(("plain",)).get_content()
    assert "Analyst's note." in en and "## Main impact" in en
    assert "## Impact principal" in fr and "Relu." in fr
    [docx] = [p for p in fr_msg.iter_attachments() if p.get_filename().endswith(".docx")]
    path = Path(review.store.root) / "fr.docx"
    path.write_bytes(docx.get_content())
    word = "\n".join(p.text for p in Document(str(path)).paragraphs)
    assert "Impact traduit en français." in word and "Vecteur d’attaque : Réseau" in word
    events = [e for e in svc.store.events(TENANT) if e["event"] == "sent"]
    assert sorted(e["language"] for e in events) == ["en", "fr"]
    assert svc.store.alert(TENANT, alert["id"])["status"] == "sent"


def test_a_refused_translation_is_said_and_can_be_written_by_hand(flow):
    svc, review, alert, client, *_ = flow
    user = "val@example.org"
    review.prepare(review.alert(alert["id"]), user, ["rssi@example.org"])
    bad = _llm(lambda n, b: {"markdown": "Résumé."})
    sender.translate_requested(client, bad, TENANT)
    a = review.alert(alert["id"])
    assert a["translations"]["fr"]["state"] == "failed" and "structure" in a["translations"]["fr"]["error"]
    review.save_translation(a, user, "fr", review.current(a).replace("## Main impact", "## Impact principal"))
    assert review.alert(alert["id"])["ready"]


def test_the_contact_language_is_checked(tmp_path):
    from via.alert.contacts import ContactsError, load_contacts

    path = tmp_path / "contacts.yaml"
    path.write_text("schema_version: 1\ncontacts:\n  - {email: a@example.org, language: french}\n")
    with pytest.raises(ContactsError, match="language"):
        load_contacts(path)
    path.write_text(CONTACTS)
    assert [c.language for c in load_contacts(path)] == ["en", "fr"]


def test_the_sender_needs_no_mail_for_an_empty_pass(service, tmp_path):  # noqa: F811
    svc, url, token = service
    contacts = tmp_path / "contacts.yaml"
    contacts.write_text(CONTACTS)
    assert _service(url, token, "send", PROFILE, "--contacts", str(contacts), "--validated") == 0
    assert httpx  # imported for the fake transport's types
    assert email and policy
