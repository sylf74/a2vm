# SPDX-License-Identifier: AGPL-3.0-only
import pytest
import yaml
from lxml import etree as ET

from vulnops.assets.build import build_inventory
from vulnops.core.io import read_detection
from vulnops.core.profile import load_profile
from vulnops.detect.cli import main
from vulnops.detect.collect import collect, load_targets
from vulnops.detect.openvas import FULL_AND_FAST, OpenvasConfig, parse_gmp_report, run_scan

from .conftest import FIXTURES, ROOT

REPORT = FIXTURES / "openvas" / "report.xml"


def test_report_parsing():
    d = parse_gmp_report(REPORT.read_bytes(), "lab")
    assert d.source == "openvas"
    hosts = {o.ref: o for o in d.observations}
    assert set(hosts) == {"node00.lab.example", "192.0.2.11"}
    assert hosts["node00.lab.example"].identifiers == {
        "hostname": "node00",
        "fqdn": "node00.lab.example",
        "ips": ["192.0.2.10"],
    }
    assert hosts["node00.lab.example"].os == "Rocky Linux 9"
    by_cve = {(f.asset_ref, f.cve_id): f for f in d.findings}
    assert set(by_cve) == {
        ("node00.lab.example", "CVE-2024-6387"),
        ("node00.lab.example", "CVE-2024-38476"),
        ("node00.lab.example", "CVE-2024-38477"),
        ("192.0.2.11", "CVE-2099-10002"),
        ("192.0.2.11", "CVE-2099-10003"),
    }
    ssh = by_cve[("node00.lab.example", "CVE-2024-6387")].observations[0]
    assert (ssh.installed_version, ssh.fixed_version, ssh.source_status) == ("8.7p1", "9.8p1", "vendorfix")
    assert ssh.cvss_vector.startswith("CVSS:3.1/AV:N/AC:H") and ssh.cvss_source == "openvas"
    assert ssh.package.startswith("22/tcp") and "1.3.6.1.4.1.25623.1.0.999001" in ssh.match.note
    assert d.skipped == {"QoD below 70": 1, "log-level result": 1, "result without CVE": 1}


def test_qod_threshold_is_configurable():
    d = parse_gmp_report(REPORT.read_bytes(), "lab", min_qod=20)
    assert any(f.cve_id == "CVE-2099-10001" for f in d.findings)


def test_hostile_xml_is_refused():
    bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    with pytest.raises(ValueError, match="unreadable OpenVAS report"):
        parse_gmp_report(bomb, "lab")


def test_import_command(tmp_path):
    assert main(["import", "--client", "lab", "--source", "openvas", str(REPORT), "--out", str(tmp_path)]) == 0
    d = read_detection(tmp_path / "lab" / "openvas.json")  # schema-checked
    assert len(d.findings) == 5


def test_hosts_reconcile_with_ssh_collection(tmp_path):
    """The OpenVAS host node00 (by FQDN) and the Trivy host node00 become one asset."""
    from vulnops.detect.scanners import load_trivy_file

    profile = load_profile(ROOT / "examples" / "lab" / "client.yaml")
    trivy = load_trivy_file(FIXTURES / "trivy" / "node00.lab.example.json", "lab")
    ov = parse_gmp_report(REPORT.read_bytes(), "lab")
    inv = build_inventory(profile, [trivy, ov])
    node00 = [a for a in inv.assets if "node00" in (a.name or a.id)]
    assert len(node00) == 1
    assert {f.cve_id for f in inv.findings if f.asset_ref == node00[0].id} >= {"CVE-2021-3712", "CVE-2024-6387"}


# -- scanning over GMP, against a simulated gvmd ---------------------------------------------------
class FakeGmp:
    def __init__(self, existing=False, running=False):
        self.calls = []
        self.existing, self.running, self.polls = existing, running, 0

    def _el(self, xml):
        return ET.fromstring(xml)

    def get_targets(self, filter_string):
        self.calls.append(("get_targets", filter_string))
        name = filter_string.split('"')[1]
        return self._el(f'<r><target id="t1"><name>{name}</name></target></r>' if self.existing else "<r/>")

    def create_target(self, name, **kw):
        self.calls.append(("create_target", name, kw))
        return self._el('<r id="t1"/>')

    def get_tasks(self, filter_string):
        name = filter_string.split('"')[1]
        return self._el(f'<r><task id="k1"><name>{name}</name></task></r>' if self.existing else "<r/>")

    def create_task(self, name, config_id, target_id, scanner_id, **kw):
        self.calls.append(("create_task", name, config_id, target_id, scanner_id))
        return self._el('<r id="k1"/>')

    def get_task(self, task_id):
        if self.running and self.polls == 0:
            self.polls += 1
            return self._el('<r><task id="k1"><status>Running</status><progress>40</progress>'
                            '<current_report><report id="rep-running"/></current_report></task></r>')  # fmt: skip
        if not any(c[0] == "start_task" for c in self.calls) and not self.running:
            return self._el("<r><task id='k1'><status>New</status><progress>-1</progress></task></r>")
        self.polls += 1
        status = "Running" if self.polls < 3 else "Done"
        return self._el(f"<r><task id='k1'><status>{status}</status><progress>{self.polls * 30}</progress></task></r>")

    def start_task(self, task_id):
        self.calls.append(("start_task", task_id))
        return self._el("<r><report_id>rep-new</report_id></r>")

    def stop_task(self, task_id):
        self.calls.append(("stop_task", task_id))

    def get_report(self, report_id, **kw):
        self.calls.append(("get_report", report_id, kw))
        return self._el(REPORT.read_bytes())


def _cfg(**kw):
    return OpenvasConfig.from_dict({"gmp": "tls://scanner.lab.example:9390", "hosts": ["192.0.2.0/28"], **kw})


def test_scan_creates_target_and_task_then_fetches_the_report():
    gmp = FakeGmp()
    xml = run_scan(gmp, _cfg(exclude=["192.0.2.1"]), "lab", log=lambda m: None, sleep=lambda s: None)
    names = [c[0] for c in gmp.calls]
    assert names[:4] == ["get_targets", "create_target", "create_task", "start_task"]
    create_target = gmp.calls[1]
    assert create_target[2]["hosts"] == ["192.0.2.0/28"] and create_target[2]["exclude_hosts"] == ["192.0.2.1"]
    assert gmp.calls[2][2] == FULL_AND_FAST
    report_call = gmp.calls[-1]
    assert report_call[1] == "rep-new" and "min_qod=70" in report_call[2]["filter_string"]
    assert len(parse_gmp_report(xml, "lab").findings) == 5


def test_scan_reuses_and_waits_for_a_running_scan():
    gmp = FakeGmp(existing=True, running=True)
    run_scan(gmp, _cfg(), "lab", log=lambda m: None, sleep=lambda s: None)
    names = [c[0] for c in gmp.calls]
    assert "create_target" not in names and "create_task" not in names and "start_task" not in names
    assert gmp.calls[-1][1] == "rep-running"


def test_scan_name_changes_with_the_hosts():
    assert _cfg().key("lab") != _cfg(hosts=["192.0.2.0/24"]).key("lab") and _cfg().key("lab").startswith("vulnops-lab-")


def test_targets_file_with_openvas_only(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump({"client": "lab", "openvas": {"gmp": "unix:///run/gvmd/gvmd.sock", "hosts": ["192.0.2.10"]}})
    )
    tf = load_targets(path)
    assert tf.targets == [] and tf.openvas.min_qod == 70

    class Session:
        def __enter__(self):
            return FakeGmp()

        def __exit__(self, *exc):
            return False

    from unittest.mock import patch

    def quick(gmp, cfg, client):
        return run_scan(gmp, cfg, client, sleep=lambda s: None)

    with patch("vulnops.detect.collect.run_scan", quick):
        detections, errors = collect(tf, tmp_path / "raw", gmp_session=Session())
    assert errors == [] and detections[0].source == "openvas"
    assert (tmp_path / "raw" / "lab" / "openvas" / "report.xml").exists()


def test_bad_openvas_section(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump({"client": "lab", "openvas": {"gmp": "http://x", "hosts": ["h"]}}))
    with pytest.raises(ValueError, match="gmp must be"):
        load_targets(path)


def test_missing_credentials_is_a_collection_error(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump({"client": "lab", "openvas": {"gmp": "tls://scanner:9390", "hosts": ["h"]}}))
    detections, errors = collect(load_targets(path), tmp_path / "raw", env={})
    assert detections == [] and errors and "openvas" in errors[0]
