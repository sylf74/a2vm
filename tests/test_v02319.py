# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.23.19: what the homelab and the integration found after v0.23.18.

- The watch's inventory: 26,000 findings were still 75 MB once slimmed, refused by the watch
  service, which had no inventory at all while the step said it kept the previous one. The findings
  now go compact (`a2vm.watch_findings/1`), the inventory replaces the previous one whole, and the
  step says what the watch keeps.
"""

from __future__ import annotations

import json
import re
import threading

import pytest

from a2vm.service import TokenSet, digest

from .conftest import ROOT
from .test_v0160 import RUN, watch_store
from .test_v02318 import _big_inventory

TENANT = "lab"


@pytest.fixture
def watch(tmp_path, backend):
    from via.service.server import WatchService, serve

    digests = tmp_path / "digests"
    digests.write_text(f"run {digest(RUN)}\n")
    svc = WatchService(TENANT, TokenSet.load(digests, {"run"}), watch_store(tmp_path, backend))
    httpd = serve(svc, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    token = tmp_path / "token"
    token.write_text(RUN)
    yield svc, f"http://127.0.0.1:{httpd.server_address[1]}", token
    httpd.shutdown()
    httpd.server_close()


def _push(url, token, base) -> int:
    from via.cli import main

    return main(
        ["service", "push-inventory", "--url", url, "--tenant", TENANT, "--token-file", str(token),
         "--assets-dir", str(base)]
    )  # fmt: skip


# -- the compact findings ------------------------------------------------------------------------
def test_the_findings_go_compact_and_much_smaller(tmp_path) -> None:
    from a2vm.io import validate_watch_findings
    from via.alert.inventory import for_watch

    base = _big_inventory(tmp_path, n=2000)
    assets = json.loads((base / "assets.json").read_text())
    findings = json.loads((base / "findings.json").read_text())
    _, compact = for_watch(assets, findings)
    validate_watch_findings(compact)
    assert compact["schema"] == "a2vm.watch_findings/1" and compact["client_id"] == TENANT
    rows = compact["assets"]["host:hyp03.lan.example"]
    assert len(rows) == 2000
    assert rows[0] == ["CVE-2026-10000", "affected", ["3.0.7"], [["trivy", "openssl", "3.0.7", "3.0.8"]]]
    slim_findings = [f for f in findings["findings"]]
    assert len(json.dumps(compact)) < len(json.dumps(slim_findings)) / 5


def test_the_same_observation_twice_is_kept_once(tmp_path) -> None:
    from via.alert.inventory import for_watch

    base = _big_inventory(tmp_path, n=1)
    findings = json.loads((base / "findings.json").read_text())
    obs = findings["findings"][0]["observations"][0]
    findings["findings"][0]["observations"] = [obs, {**obs, "observed_at": "2026-11-11T00:00:00+00:00"}]
    _, compact = for_watch(json.loads((base / "assets.json").read_text()), findings)
    assert compact["assets"]["host:hyp03.lan.example"][0][3] == [["trivy", "openssl", "3.0.7", "3.0.8"]]


def test_a_compact_file_of_another_client_is_refused(tmp_path) -> None:
    from a2vm.io import ExchangeError
    from via.alert.inventory import for_watch, load

    base = _big_inventory(tmp_path, n=3)
    assets = json.loads((base / "assets.json").read_text())
    _, compact = for_watch(assets, json.loads((base / "findings.json").read_text()))
    (base / "findings.json").unlink()
    (base / "watch-findings.json").write_text(json.dumps({**compact, "client_id": "other"}))
    with pytest.raises(ExchangeError, match="belongs to 'other'"):
        load(tmp_path, TENANT)


# -- the watch service ---------------------------------------------------------------------------
def test_the_service_keeps_the_compact_inventory_and_the_watch_reads_it(watch, tmp_path) -> None:
    from via.alert.inventory import load
    from via.service.client import WatchClient

    svc, url, token = watch
    base = _big_inventory(tmp_path / "run", n=50)
    assert _push(url, token, base) == 0
    assert svc.store.inventory(TENANT, TENANT, "watch-findings.json") is not None
    assert svc.store.inventory(TENANT, TENANT, "findings.json") is None
    status = svc.get_status(TENANT, RUN)
    assert status["inventory"]["assets"] == 1 and status["inventory"]["findings"] == 50

    client = WatchClient(url, TENANT, RUN)
    dest = tmp_path / "watch"
    assert client.inventory(dest)
    client.close()
    inv = load(dest, TENANT)
    assert len(inv.findings_by_cve) == 50
    f = inv.findings_by_cve["CVE-2026-10003"][0]
    assert f.asset_ref == "host:hyp03.lan.example" and f.observations[0].fixed_version == "3.0.8"


def test_an_inventory_replaces_the_previous_one_whole(watch, tmp_path) -> None:
    """A findings.json of an older version left beside the compact file would be read by nobody, or
    by an older watch: it goes."""
    svc, url, token = watch
    base = _big_inventory(tmp_path / "run", n=5)
    body = {
        "assets": json.loads((base / "assets.json").read_text()),
        "findings": json.loads((base / "findings.json").read_text()),
    }
    svc.put_inventory(TENANT, RUN, json.dumps(body).encode(), False)
    assert svc.store.inventory(TENANT, TENANT, "findings.json") is not None
    assert _push(url, token, base) == 0
    assert svc.store.inventory(TENANT, TENANT, "findings.json") is None
    assert svc.store.inventory(TENANT, TENANT, "watch-findings.json") is not None


def test_findings_in_both_forms_are_refused(watch, tmp_path) -> None:
    from a2vm.service import Problem
    from via.alert.inventory import for_watch

    svc, _, _ = watch
    base = _big_inventory(tmp_path / "run", n=2)
    assets = json.loads((base / "assets.json").read_text())
    findings = json.loads((base / "findings.json").read_text())
    _, compact = for_watch(assets, findings)
    body = {"assets": assets, "findings": findings, "watch_findings": compact}
    with pytest.raises(Problem, match="one of them|expected"):
        svc.put_inventory(TENANT, RUN, json.dumps(body).encode(), False)


@pytest.mark.parametrize("before", [False, True])
def test_a_refused_inventory_says_what_the_watch_keeps(watch, tmp_path, capsys, before) -> None:
    svc, url, token = watch
    base = _big_inventory(tmp_path / "run", n=20)
    if before:
        assert _push(url, token, base) == 0
        capsys.readouterr()
    svc.max_bytes = 1000
    assert _push(url, token, base) == 1
    err = capsys.readouterr().err
    assert "(413)" in err
    if before:
        assert re.search(r"the watch keeps the inventory of \d{4}-\d\d-\d\dT\d\d:\d\d \(1 assets, 20 findings\)", err)
    else:
        assert "the watch has no inventory: its alerts name the declared assets only" in err


def test_the_step_no_longer_claims_a_previous_inventory() -> None:
    daily = (ROOT / "deploy/charts/a2vm-tenant/templates/cronjob-daily.yaml").read_text()
    assert "WARN watch service not updated (exit $rc): see above what the watch keeps" in daily


def test_the_contract_lists_the_compact_findings() -> None:
    import yaml

    api = yaml.safe_load((ROOT / "a2vm/src/a2vm/schemas/openapi/via.v1.yaml").read_text())
    post = api["paths"]["/v1/tenants/{tenant}/inventory"]["post"]
    forms = post["requestBody"]["content"]["application/json"]["schema"]["oneOf"]
    assert [f["required"] for f in forms] == [["assets", "watch_findings"], ["assets", "findings"]]
    get = api["paths"]["/v1/tenants/{tenant}/inventory/{file}"]["get"]
    assert "watch-findings.json" in get["parameters"][1]["schema"]["enum"]


# -- the timing: the whole step ------------------------------------------------------------------
def test_the_timing_covers_the_whole_step(settings, sources, profile, tmp_path, capsys) -> None:
    """v0.23.18 timed the decisions only (3.5 s for a step of minutes): the step now counts from
    reading its inputs, the decisions alone kept as decide_seconds."""
    import shutil

    from verdict.cli import main

    from .test_pipeline import _run

    _run(settings, sources, profile, tmp=tmp_path)
    client = tmp_path / "assets" / profile.id
    client.mkdir(parents=True)
    for name in ("assets.json", "findings.json"):
        shutil.copy(tmp_path / name, client / name)
    out = tmp_path / "out"
    code = main(
        ["run", str(ROOT / "examples" / "example-client" / "client.yaml"),
         "--settings", str(ROOT / "config" / "settings.yaml"), "--records", str(tmp_path / "records.json"),
         "--assets", str(tmp_path / "assets"), "--out", str(out), "--no-llm", "--run-started", "1700000000"]
    )  # fmt: skip
    assert code == 0
    t = json.loads(next(out.rglob("triage.json")).read_text())["timing"]
    assert t["seconds"] >= t["decide_seconds"] >= 0
    assert t["started_at"] <= t["ended_at"] and t["run_started_at"] == "2023-11-14T22:13:20+00:00"
    assert "(deciding " in capsys.readouterr().out


def test_the_timing_note_names_the_decisions_alone() -> None:
    from verdict.service.tools import _timing_note

    note = _timing_note({"seconds": 312, "decide_seconds": 3.5, "findings": 26329, "decided": 26263,
                         "without_record": 66, "run_seconds": 480})  # fmt: skip
    assert note == (
        "the decision step (verdict) ran 5 min 12 s on 26329 findings: 26263 decided, 66 without a vulnerability "
        "record (reading its inputs included; the decisions alone 4 s); the whole run took 8 min 00 s from its "
        "start up to the decisions"
    )


# -- deploy-k8s: the CloudNativePG check ---------------------------------------------------------
def _cnpg_block() -> str:
    import yaml

    doc = yaml.safe_load((ROOT / "templates/client-pipeline.yml").read_text())
    return next(line for line in doc["deploy-k8s"]["script"] if "postgresql.cnpg.io" in line)


@pytest.mark.parametrize(
    "answers,code,says",
    [
        (["ok"], 0, "A2VM_DATABASE=true: the services keep"),
        (["fail", "ok"], 0, "discovery of the API failed (try 1 of 3)"),
        (["absent"], 1, "the CloudNativePG operator is not installed"),
        (["fail", "fail", "fail"], 1, "did not answer the discovery through the agent"),
        (["partial"], 0, "A2VM_DATABASE=true: the services keep"),
    ],
)
def test_the_operator_check_tells_a_failed_discovery_from_an_absent_operator(tmp_path, answers, code, says):
    """Found in integration: one failed discovery through the agent's tunnel stopped deploy-k8s with
    "the operator is not installed" on a cluster where it runs."""
    import os
    import stat
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "answers").write_text("\n".join(answers) + "\n")
    kubectl = bin_dir / "kubectl"
    kubectl.write_text(
        "#!/bin/sh\n"
        f'a=$(head -1 "{tmp_path}/answers"); sed -i 1d "{tmp_path}/answers"\n'
        'case "$a" in\n'
        "  ok) echo clusters.postgresql.cnpg.io; echo poolers.postgresql.cnpg.io;;\n"
        "  absent) ;;\n"
        "  partial) echo clusters.postgresql.cnpg.io; echo 'unable to retrieve metrics.k8s.io' >&2; exit 1;;\n"
        "  *) echo 'error: the server is currently unable to handle the request' >&2; exit 1;;\n"
        "esac\n"
    )
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "A2VM_DATABASE": "true",
           "A2VM_K8S_CONTEXT": "voc/a2vm/k8s:ngvm", "CI_PROJECT_NAME": "lab"}  # fmt: skip
    r = subprocess.run(["sh", "-c", _cnpg_block()], env=env, capture_output=True, text=True)
    assert r.returncode == code, r.stdout + r.stderr
    assert says in r.stdout


# -- dispatch: what failed, said ------------------------------------------------------------------
def test_dispatch_says_its_errors_grouped(tmp_path, capsys) -> None:
    """Found in the homelab: 'errors 61' and nothing else, the messages only in the database."""
    from dispatch.connectors import ConnectorError

    from .test_v0200 import FakeTool, dec, dispatcher

    msg = "iTop refused: code 100: Error: caller_id: Several items found (2) with criteria: name: A2VM"

    class Refusing(FakeTool):
        def create(self, ticket, text, title):
            raise ConnectorError(msg)

    items = [dec(i, f"host:web0{i}.lab.example", "ACT", ["openssl 3.0.15"]) for i in range(1, 4)]
    d, _ = dispatcher(tmp_path, items, tool=Refusing())
    s = d.process_run()
    assert s["errors"] == 3 and s["error_messages"] == [{"count": 3, "error": msg}]
    d2, _ = dispatcher(tmp_path, items)
    s2 = d2.process_run()
    assert s2["sent"] == 3 and "error_messages" not in s2


def test_the_step_prints_the_grouped_errors(tmp_path, capsys, monkeypatch) -> None:
    import httpx

    from dispatch.cli import main

    answer = {"run": {"id": "r1"}, "mode": "live", "sent": 0, "errors": 61,
              "error_messages": [{"count": 61, "error": "iTop refused: code 100: Several items found (2)"}],
              "detail": "iTop: 2 Persons with name 'A2VM' in 'Homelab'"}  # fmt: skip

    def post(url, **kwargs):
        return httpx.Response(200, json=answer)

    monkeypatch.setattr(httpx, "post", post)
    token = tmp_path / "token"
    token.write_text("t" * 40)
    code = main(["run", "--url", "http://dispatch:8080", "--tenant", "homelab", "--token-file", str(token)])
    out = capsys.readouterr()
    assert code == 3
    assert "errors 61; iTop: 2 Persons with name 'A2VM' in 'Homelab'" in out.out
    assert "  61 x iTop refused: code 100: Several items found (2)" in out.err


@pytest.mark.parametrize(
    "caller,found,says",
    [
        ("A2VM", 1, ""),
        ("A2VM", 2, "iTop: 2 Persons with name 'A2VM' in 'Lab': iTop refuses every ticket"),
        ("a2vm@example.org", 0, "iTop: no Person with email 'a2vm@example.org' in 'Lab'"),
        ("O'Brien", 1, ""),
    ],
)
def test_the_itop_caller_is_checked_before_any_ticket(caller, found, says) -> None:
    import httpx

    from dispatch.connectors.itop import ItopConnector
    from dispatch.rules import Rules

    from .test_v0200 import RULES

    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(dict(httpx.QueryParams(request.content.decode()))["json_data"])
        asked.append(payload)
        objects = {f"Person::{i}": {"code": 0, "fields": {"id": str(i)}} for i in range(1, found + 1)}
        return httpx.Response(200, json={"code": 0, "objects": objects or None})

    rules = Rules.from_dict({**RULES, "targets": {"itsm": {**RULES["targets"]["itsm"], "caller": caller}}})
    c = ItopConnector(rules.targets["itsm"], "secret", transport=httpx.MockTransport(handler))
    assert c.check().startswith(says) and bool(c.check()) == bool(says)
    assert asked[0]["operation"] == "core/get" and asked[0]["class"] == "Person"
    key = "email" if "@" in caller else "name"
    escaped = caller.replace("'", "\\'")
    assert asked[0]["key"] == f"SELECT Person WHERE {key} = '{escaped}' AND org_name = 'Lab'"


def test_the_run_says_what_the_check_found(tmp_path) -> None:
    from .test_v0200 import FakeTool, dec, dispatcher

    class Checked(FakeTool):
        def check(self):
            return "iTop: 2 Persons with name 'A2VM' in 'Lab': ..."

    d, _ = dispatcher(tmp_path, [dec(1, "host:web01.lab.example", "ACT", ["openssl 3.0.15"])], tool=Checked())
    assert d.process_run()["detail"].startswith("iTop: 2 Persons")
