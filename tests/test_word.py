# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.11.4: the alert sheet in Word, and the analysts' edits before sending."""

from __future__ import annotations

import email
import json
from email import policy
from pathlib import Path

import yaml
from docx import Document

from a2vm.models import CvssMetric
from via.alert import journal, word
from via.alert.cli import main

from .test_alert import PROFILE, _second_run


def _profile(tmp_path: Path, **alerts) -> Path:
    data = yaml.safe_load(Path(PROFILE).read_text())
    data.setdefault("alerts", {}).update({"recipients": ["it@example.org"], **alerts})
    path = tmp_path / "client.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    return path


def _text(docx: Path) -> str:
    doc = Document(str(docx))
    cells = [c.text for t in doc.tables for row in t.rows for c in row.cells]
    return "\n".join([p.text for p in doc.paragraphs] + cells)


def test_calculator_and_vector_words():
    m4 = CvssMetric("4.0", "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "CRITICAL", "cna")
    assert word.calculator_url(m4).startswith("https://www.first.org/cvss/calculator/4-0#CVSS:4.0/")
    m3 = CvssMetric("3.1", "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N", 7.5, "HIGH", "cna")
    assert word.calculator_url(m3) == "https://www.first.org/cvss/calculator/3.1#" + m3.vector
    assert word._vector(m3)["AV"] == "L"


def test_template_check_lists_unknown_tags(tmp_path):
    assert word.check_template(word.default_template()) == []
    doc = Document()
    doc.add_paragraph("{{ titre }} {{ titre_inconnu }}")
    bad = tmp_path / "alert.docx"
    doc.save(str(bad))
    assert "titre_inconnu" in word.check_template(bad)[0]
    assert main(["check-template", str(bad)]) == 1


def test_watch_attaches_the_word_sheet_and_send_uses_the_edits(tmp_path, monkeypatch):
    monkeypatch.setenv("A2VM_ANALYST_TO", "soc@example.org")
    monkeypatch.setenv("CI_PIPELINE_URL", "https://gitlab.example/acme/-/pipelines/1")
    monkeypatch.setenv("CI_PROJECT_URL", "https://gitlab.example/acme")
    monkeypatch.setenv("CI_JOB_URL", "https://gitlab.example/acme/-/jobs/9")
    for v in ("A2VM_SMTP_HOST", "A2VM_MAIL_TRANSPORT", "A2VM_SEND_ONLY"):
        monkeypatch.delenv(v, raising=False)
    profile = _profile(tmp_path, attach=["docx"])

    import tests.test_alert as ta

    monkeypatch.setattr(ta, "PROFILE", str(profile))
    found = _second_run(tmp_path)
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    pan = next(a for a in index if "CERTFR-2024-ALE-006" in a["id"])
    sheet = tmp_path / "alerts" / pan["docx"]
    text = _text(sheet)
    assert "CVE-2024-3400" in text and "Vulnérabilité dans Palo Alto Networks PAN-OS" in text
    assert "{{" not in text and "{%" not in text
    assert "Internet-facing firewalls with GlobalProtect VPN portal" in text  # assets table
    assert len(found) == 2

    # The analysts' mail carries the Word file and says how to edit the sheet.
    mails = [email.message_from_bytes(p.read_bytes(), policy=policy.default)
             for p in (tmp_path / "alerts" / "outbox").glob("*.eml")]  # fmt: skip
    mail = next(m for m in mails if "PAN-OS" in m["Subject"])
    assert [p.get_filename() for p in mail.iter_attachments()] == [pan["docx"]]
    html = mail.get_body(("html",)).get_content()
    assert f"edits/{pan['id']}.md" in html and "/-/jobs/9/artifacts/raw/alerts/" in html

    # An edited sheet citing another CVE is refused; a proper edit is sent, with the edited Word file.
    edits = tmp_path / "edits"
    edits.mkdir()
    (edits / f"{pan['id']}.md").write_text("# Alerte\n\n## CVE\n\nCVE-2024-3400 et CVE-2023-0001\n")
    number = str(index.index(pan) + 1)
    monkeypatch.setenv("A2VM_SEND_ONLY", number)
    args = ["send", str(profile), "--alerts", str(tmp_path / "alerts"), "--edits", str(edits),
            "--journal", str(tmp_path / "alerts-log.jsonl")]  # fmt: skip
    assert main(args) == 1
    (edits / f"{pan['id']}.md").write_text("# Alerte corrigée\n\n## CVE\n\nCVE-2024-3400\n\n- point modifié\n")
    Document().save(str(edits / pan["docx"]))
    before = set((tmp_path / "alerts" / "outbox").glob("*.eml"))
    assert main(args) == 0
    sent = email.message_from_bytes(
        next(iter(set((tmp_path / "alerts" / "outbox").glob("*.eml")) - before)).read_bytes(), policy=policy.default
    )
    assert "point modifié" in sent.get_body(("html",)).get_content()
    attached = next(sent.iter_attachments()).get_content()
    assert attached == (edits / pan["docx"]).read_bytes()
    assert journal.read(tmp_path / "alerts-log.jsonl")[-1]["edited"] == ["text", "docx"]


def test_client_template_next_to_the_profile_wins(tmp_path):
    from a2vm.profile import load_profile
    from via.alert.cli import _word_template

    profile = _profile(tmp_path, attach=["docx"])
    assert _word_template(load_profile(profile), str(profile)) == word.default_template()
    (tmp_path / "templates").mkdir()
    Document().save(str(tmp_path / "templates" / "alert.docx"))
    assert _word_template(load_profile(profile), str(profile)) == tmp_path / "templates" / "alert.docx"
    plain = _profile(tmp_path)
    data = yaml.safe_load(plain.read_text())
    data["alerts"].pop("attach", None)
    plain.write_text(yaml.safe_dump(data, allow_unicode=True))
    assert _word_template(load_profile(plain), str(plain)) is None


def test_client_gets_a_pdf_made_from_the_word_sheet(tmp_path, monkeypatch):
    import shutil

    import pytest

    if not (shutil.which("soffice") or shutil.which("libreoffice")):
        pytest.skip("LibreOffice not installed")
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    for v in ("A2VM_SMTP_HOST", "A2VM_MAIL_TRANSPORT"):
        monkeypatch.delenv(v, raising=False)
    profile = _profile(tmp_path, attach=["pdf"])

    import tests.test_alert as ta

    monkeypatch.setattr(ta, "PROFILE", str(profile))
    _second_run(tmp_path)
    index = json.loads((tmp_path / "alerts" / "index.json").read_text())
    assert all(a.get("docx") for a in index)  # the Word sheet is always made: analysts edit it
    pan = next(a for a in index if "CERTFR-2024-ALE-006" in a["id"])
    monkeypatch.setenv("A2VM_SEND_ONLY", str(index.index(pan) + 1))
    assert main(["send", str(profile), "--alerts", str(tmp_path / "alerts")]) == 0
    sent = email.message_from_bytes(next((tmp_path / "alerts" / "outbox").glob("*.eml")).read_bytes(),
                                    policy=policy.default)  # fmt: skip
    files = list(sent.iter_attachments())
    assert [f.get_filename() for f in files] == [Path(pan["docx"]).with_suffix(".pdf").name]
    assert files[0].get_content_type() == "application/pdf" and files[0].get_content()[:5] == b"%PDF-"


def test_without_libreoffice_the_alert_is_not_sent(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    import pytest

    with pytest.raises(word.ConversionError, match="LibreOffice is not installed"):
        word.to_pdf(word.default_template(), tmp_path)
