# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.11.3: pipeline file check, source failures in a row, CSAF index named directly."""

from __future__ import annotations

from ngvm.cli import check_ci
from ngvm.cli import main as ngvm_main
from via.alert.feeds import csaf_index
from via.alert.watch import State

CI = """include:
  - project: vulnops/ngvm
    ref: {include}
    file: templates/client-pipeline.yml
variables:
  NGVM_REF: {ref}
job:
  script: !reference [.x, script]
"""


def test_include_ref_must_equal_ngvm_ref(tmp_path):
    ci = tmp_path / ".gitlab-ci.yml"
    ci.write_text(CI.format(include="v0.11.3", ref="v0.11.3"))
    assert check_ci(ci, environ={}) == []
    ci.write_text(CI.format(include="v0.11.3", ref="v0.11.2"))
    assert "include ref v0.11.3 but NGVM_REF v0.11.2" in check_ci(ci, environ={})[0]
    # In the job, the variable the pipeline actually runs with wins over the file.
    ci.write_text(CI.format(include="v0.11.3", ref="v0.11.3"))
    assert check_ci(ci, environ={"NGVM_REF": "main"})
    ci.write_text("include:\n  - project: vulnops/ngvm\n    file: t.yml\n")
    assert "without `ref:`" in check_ci(ci, environ={})[0]
    ci.write_text("include:\n  - project: other/thing\n    ref: x\n")
    assert check_ci(ci, environ={}) == []


def test_validate_fails_on_a_ref_mismatch(tmp_path, monkeypatch, capsys):
    from .conftest import ROOT

    monkeypatch.delenv("NGVM_REF", raising=False)
    ci = tmp_path / ".gitlab-ci.yml"
    ci.write_text(CI.format(include="v0.11.3", ref="v0.11.1"))
    profile = str(ROOT / "examples" / "lab" / "client.yaml")
    assert ngvm_main(["validate", profile, "--ci", str(ci)]) == 1
    assert "two versions" in capsys.readouterr().err
    ci.write_text(CI.format(include="v0.11.3", ref="v0.11.3"))
    assert ngvm_main(["validate", profile, "--ci", str(ci)]) == 0


def test_a_source_is_in_error_only_after_failures_in_a_row(tmp_path):
    state = State.load(tmp_path / "s.json")
    hard, soft = state.count_failures(["CISA — IT advisories: HTTP 503"], 3)
    assert not hard and "failure 1/3" in soft[0]
    state.count_failures(["CISA — IT advisories: HTTP 503"], 3)
    hard, soft = state.count_failures(["CISA — IT advisories: HTTP 503"], 3)
    assert hard == ["CISA — IT advisories: HTTP 503 (3 runs in a row)"] and not soft
    state.save()
    state = State.load(tmp_path / "s.json")  # kept between runs
    assert state.failures == {"CISA — IT advisories": 3}
    assert state.count_failures([], 3) == ([], []) and state.failures == {}  # one success resets


def test_csaf_index_named_directly():
    url = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv"
    assert csaf_index(None, url) == ("changes", url)
