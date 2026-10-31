# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.17.3: A2VM writes in English; a tenant whose profile says `client.language: fr` gets the
labels of its deliverables in French, from a catalogue, never from a model (HLD D16)."""

from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import replace
from pathlib import Path

from verdict import i18n
from verdict.dashboard import render_dashboard
from verdict.report import render_markdown
from verdict.restitution.cli import DASHBOARDS, dashboard
from verdict.service import exports

from .conftest import ROOT

SOURCES = ("a2vm", "via", "detect", "verdict")


def test_the_catalogue_is_complete():
    assert i18n.check() == []
    assert i18n.t("fr", "report.act") == "ACT — remédier maintenant"
    assert i18n.t("de", "report.act") == "ACT — remediate now"  # unknown language: English


def test_decision_texts_are_english():
    """The texts A2VM writes into a decision (rationale, reasons, assumptions) are English."""
    french = re.compile(r"relevé à|supposée?\b|pire cas|correspondance produit|Hypothèses|Correctif disponible|"
                        r"Politique :|Décision SSVC CISA|délai BOD|non confirmée|déduite?s?\b|estimés par")  # fmt: skip
    for path in [
        ROOT / "verdict/src/verdict/rationale.py",
        ROOT / "verdict/src/verdict/policy.py",
        ROOT / "verdict/src/verdict/triage.py",
        ROOT / "verdict/src/verdict/llm_tasks.py",
        ROOT / "a2vm/src/a2vm/declared.py",
        ROOT / "a2vm/src/a2vm/gti.py",
        ROOT / "detect/src/detect/openvas.py",
    ]:
        assert not french.search(path.read_text(encoding="utf-8")), path


def test_the_watch_sources_are_named_in_english():
    text = (ROOT / "config" / "watch-sources.yaml").read_text(encoding="utf-8")
    names = " ".join(re.findall(r'name: "([^"]+)"', text))
    assert names and not re.search(r"\b(alertes|avis|bulletins de|publiés)\b", names)


def _runs(settings, sources, profile):
    from .test_pipeline import _run

    run = _run(settings, sources, profile)
    return run, replace(run, client=replace(run.client, language="fr"))


def test_the_report_and_dashboard_follow_the_client_language(settings, sources, profile):
    en, fr = _runs(settings, sources, profile)
    md_en, md_fr = render_markdown(en), render_markdown(fr)
    assert "## ACT — remediate now" in md_en and "remédier" not in md_en
    assert "## ACT — remédier maintenant" in md_fr and "## Par actif" in md_fr
    # The rationales stay as written (English), in both.
    for r in en.rows[:3]:
        assert r.rationale in md_en or r.delivery_decision == "TRACK"
    assert render_markdown(en, language="fr") == md_fr
    html_en, html_fr = render_dashboard(en), render_dashboard(fr)
    assert '<html lang="en">' in html_en and "Findings by asset" in html_en
    assert '<html lang="fr">' in html_fr and "Constats par actif" in html_fr


def test_the_triage_document_says_the_language(settings, sources, profile, tmp_path):
    from verdict.report import write_json

    path = tmp_path / "triage.json"
    write_json(_runs(settings, sources, profile)[1], path)
    assert json.loads(path.read_text())["client"]["language"] == "fr"


def test_exports_take_the_language_of_the_run():
    meta = {"tenant": "lab", "run": {"id": "r1", "generated_at": "2026-10-31T06:00:00Z", "language": "fr"},
            "filters": {"level": "ACT"}, "total": 1, "shown": 1, "truncated": False, "counts": {"ACT": 1}}  # fmt: skip
    items = [{"id": "x", "level": "ACT", "cve": "CVE-2099-0001", "asset": "edge01", "kev": True}]
    fr = exports.build("csv", meta, items, []).decode("utf-8-sig")
    assert fr.splitlines()[0].startswith("id;Niveau;CVE;Actif") and ";oui;" in fr
    meta["run"]["language"] = "en"
    en = exports.build("csv", meta, items, []).decode("utf-8-sig")
    assert en.splitlines()[0].startswith("id;Level;CVE;Asset") and ";yes;" in en


def _strings(o, key=None):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _strings(v, k)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v, key)
    elif isinstance(o, str):
        yield key, o


def test_the_french_dashboards_are_current_and_only_relabel():
    spec = importlib.util.spec_from_file_location("mgd", ROOT / "scripts" / "make_grafana_dashboards.py")
    mgd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mgd)
    builders = {"overview": mgd.overview_dashboard, "assets": mgd.assets_dashboard, "cves": mgd.cves_dashboard}
    for name in DASHBOARDS:
        en, fr = json.loads(dashboard(name)), json.loads(dashboard(name, "fr"))
        assert en == builders[name]() and fr == mgd.french(builders[name]()), f"run make_grafana_dashboards ({name})"
        assert fr["uid"] == en["uid"] + "-fr"
        # Same queries once the column names are put back: only labels differ.
        back = {v: k for k, v in mgd.FR_COLUMN.items()}
        sql_en = [s for k, s in _strings(en) if k == "rawSql"]
        sql_fr = [re.sub(r'(\b[Aa][Ss]\s+)"([^"]+)"', lambda m, back=back: f'{m.group(1)}"{back[m.group(2)]}"', s)
                  for k, s in _strings(fr) if k == "rawSql"]  # fmt: skip
        assert sql_en == sql_fr


def test_the_profile_schema_takes_a_language(tmp_path):
    from a2vm.profile import load_profile

    from .test_alert import PROFILE

    text = Path(PROFILE).read_text(encoding="utf-8")
    assert load_profile(PROFILE).language == "en"
    path = tmp_path / "client.yaml"
    path.write_text(text.replace("client:\n", "client:\n  language: fr\n", 1), encoding="utf-8")
    assert load_profile(path).language == "fr"
