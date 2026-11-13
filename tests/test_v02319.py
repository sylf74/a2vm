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
