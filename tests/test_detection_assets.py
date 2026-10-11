import subprocess

import pytest
import yaml

from vulnops.assets.build import WORST_CASE, build_inventory
from vulnops.core.config import Settings
from vulnops.core.io import Detection, now
from vulnops.core.models import AssetObservation
from vulnops.core.profile import load_profile, validate_profile_data
from vulnops.detect.collect import DNF, TRIVY_HOST, collect, load_targets, plan, ssh_command
from vulnops.detect.scanners import Target, load_dnf_file, load_trivy_file, parse_trivy
from vulnops.intel.collect import collect as collect_records
from vulnops.verdict.triage import Triage

from .conftest import FIXTURES, ROOT

TRIVY = FIXTURES / "trivy"
DNF_EDGE01 = FIXTURES / "dnf" / "edge01.lab.example.txt"


@pytest.fixture
def lab():
    return load_profile(ROOT / "examples" / "lab" / "client.yaml")


# -- scanners -------------------------------------------------------------------------------------
def test_trivy_real_output():
    d = load_trivy_file(TRIVY / "node00.lab.example.json", "lab")
    [obs] = d.observations
    assert (obs.kind, obs.ref, obs.name, obs.os) == ("host", "node00.lab.example", "node00", "rocky 8.5")
    assert obs.identifiers == {"hostname": "node00", "fqdn": "node00.lab.example"}
    [f] = d.findings
    assert (f.cve_id, f.status, f.affected_versions) == ("CVE-2021-3712", "affected", ["1:1.1.1k-4.el8"])
    o = f.observations[0]
    assert (o.package, o.fixed_version, o.source_status, o.match.method) == (
        "openssl-libs",
        "1:1.1.1k-5.el8_5",
        "fixed",
        "scanner",
    )


def test_trivy_groups_packages_and_skips_non_cve():
    data = {
        "SchemaVersion": 2,
        "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-1", "PkgName": "a", "InstalledVersion": "1", "FixedVersion": "2"},
                    {"VulnerabilityID": "CVE-2024-1", "PkgName": "b", "InstalledVersion": "1"},
                    {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": "c", "InstalledVersion": "1"},
                ]
            }
        ],
    }
    with pytest.raises(ValueError):
        parse_trivy({"SchemaVersion": 1}, "c", Target("h"))
    data["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "CVE-2024-12345"
    data["Results"][0]["Vulnerabilities"][1]["VulnerabilityID"] = "CVE-2024-12345"
    d = parse_trivy(data, "c", Target("h", fqdn="h.example", ips=["192.0.2.1"]))
    [f] = d.findings
    assert [o.package for o in f.observations] == ["a", "b"] and f.affected_versions == ["1"]
    assert d.skipped == {"non-CVE id (GHSA)": 1}
    assert d.observations[0].identifiers == {"hostname": "h", "fqdn": "h.example", "ips": ["192.0.2.1"]}


def test_dnf_updateinfo_real_output():
    d = load_dnf_file(DNF_EDGE01, "lab")
    by_cve = {f.cve_id: f for f in d.findings}
    assert sorted(by_cve) == ["CVE-2026-4802", "CVE-2026-56391", "CVE-2026-56392"]
    cockpit = by_cve["CVE-2026-4802"]
    assert [o.package for o in cockpit.observations] == [
        "cockpit-bridge",
        "cockpit-system",
        "cockpit-ws",
        "cockpit-ws-selinux",
    ]
    assert cockpit.observations[0].fixed_version == "356.2-1.el10_2.rocky.0.1"
    assert cockpit.observations[0].source_severity == "Important"
    assert by_cve["CVE-2026-56391"].observations[0].fixed_version == "9.5-8.el10_2.1"
    assert d.skipped == {"non-CVE id (RLSA)": 5, "non-CVE id (RHSA)": 5, "non-CVE id (CC)": 4}


# -- SSH collection (no real SSH: the runner is replaced) -----------------------------------------
def test_collect_plan_and_commands(tmp_path):
    tf = load_targets(ROOT / "examples" / "lab" / "targets.yaml")
    jobs = plan(tf)
    methods = {(t.host, m) for t, m, _, _ in jobs}
    assert ("edge01.lab.example", "dnf-updateinfo") in methods and ("node00.lab.example", "trivy") in methods
    image_jobs = [j for j in jobs if j[3].kind == "image"]
    assert image_jobs and image_jobs[0][2].endswith("vllm/vllm-openai:latest")
    for _, method, remote, _ in jobs:  # read-only, low priority, no file-system traversal
        assert remote.startswith("nice -n 19 ionice -c3")
        if method == "trivy" and "rootfs" in remote:
            assert "--pkg-types os" in remote and "--scanners vuln" in remote
    cmd = ssh_command(tf, tf.targets[0], TRIVY_HOST)
    assert cmd[0] == "ssh" and "BatchMode=yes" in cmd and cmd[-2] == "vulnops@gitlab.lab.example"


def test_collect_with_fake_ssh(tmp_path):
    targets = tmp_path / "t.yaml"
    targets.write_text(
        yaml.safe_dump(
            {
                "client": "lab",
                "targets": [
                    {"host": "node00.lab.example", "method": "trivy"},
                    {"host": "edge01.lab.example", "ip": "198.51.100.4", "method": "dnf-updateinfo"},
                    {"host": "down.lab.example", "method": "trivy"},
                ],
            }
        )
    )
    outputs = {
        "node00.lab.example": (0, (TRIVY / "node00.lab.example.json").read_text()),
        "edge01.lab.example": (100, DNF_EDGE01.read_text()),  # dnf exits 100 when updates exist
        "down.lab.example": (255, ""),
    }

    def fake_run(cmd, **kwargs):
        host = cmd[-2]
        code, out = outputs[host]
        assert cmd[-1] in (TRIVY_HOST, DNF)
        return subprocess.CompletedProcess(cmd, code, out, "ssh: connect to host down: refused" if code else "")

    detections, errors = collect(load_targets(targets), tmp_path / "raw", runner=fake_run)
    assert {d.source for d in detections} == {"trivy", "dnf-updateinfo"}
    assert len(errors) == 1 and "down.lab.example" in errors[0] and "255" in errors[0]
    dnf = next(d for d in detections if d.source == "dnf-updateinfo")
    assert dnf.observations[0].identifiers["ips"] == ["198.51.100.4"]
    assert (tmp_path / "raw" / "lab" / "dnf-updateinfo" / "edge01.lab.example.txt").exists()


# -- assets stage ---------------------------------------------------------------------------------
def _obs(ref, source, **ids):
    return AssetObservation(ref, "host", source, now(), ref.split(".")[0], identifiers=ids)


def test_reconciliation_merges_on_fqdn_hostname_and_ip(lab):
    trivy = Detection(
        "lab", "trivy", [_obs("gitlab.lab.example", "trivy", fqdn="gitlab.lab.example", hostname="gitlab")], []
    )
    other = Detection(
        "lab",
        "openvas",
        [
            _obs("192.0.2.102", "openvas", hostname="gitlab", ips=["192.0.2.102"]),  # same short name
            _obs("192.0.2.200", "openvas", ips=["192.0.2.200"]),  # unknown machine
        ],
        [],
    )
    inv = build_inventory(lab, [trivy, other])
    hosts = {a.id: a for a in inv.assets}
    gitlab = hosts["host:gitlab.lab.example"]
    assert gitlab.sources == ["openvas", "trivy"] and gitlab.identifiers["ips"] == ["192.0.2.102"]
    assert gitlab.attributes["exposure"].value == "internal" and gitlab.attributes["exposure"].source == "rule"
    unknown = hosts["host:192.0.2.200"]
    assert {k: (v.value, v.source) for k, v in unknown.attributes.items() if k != "owner"} == {
        "exposure": ("internet", "default"),
        "mission_prevalence": ("essential", "default"),
        "public_wellbeing_impact": ("minimal", "default"),
    }
    assert WORST_CASE["exposure"] == "internet"


def test_client_defaults_replace_worst_case(lab):
    lab.defaults = {"exposure": "internal"}
    inv = build_inventory(lab, [Detection("lab", "x", [_obs("a.lan", "x", hostname="a")], [])])
    attr = inv.assets[0].attributes["exposure"]
    assert (attr.value, attr.source, attr.note) == ("internal", "default", "client default")


def test_lab_end_to_end(lab, settings, sources):
    detections = [
        load_trivy_file(TRIVY / "node00.lab.example.json", "lab"),
        load_trivy_file(TRIVY / "poc-llm01.json", "lab"),
        load_dnf_file(DNF_EDGE01, "lab", Target("edge01", fqdn="edge01.lab.example", ips=["198.51.100.4"])),
    ]
    cves = sorted({f.cve_id for d in detections for f in d.findings})
    collected = collect_records(sources, cves)
    records = {r.cve_id: r for r in collected.records}
    detections.append(Detection("lab", "inventory", [], []))
    inv = build_inventory(lab, detections)
    run = Triage(settings).run(lab, records, {a.id: a for a in inv.assets}, inv.findings)
    rows = {(r.cve_id, r.asset_id): r for r in run.rows}
    edge01 = rows[("CVE-2026-4802", "edge01")]
    assert edge01.publicly_exposed and edge01.delivery_decision == "ATTEND" and edge01.bod_timeline == "14 days"
    assert edge01.fixes[0] == "cockpit-bridge 356.2-1.el10_2.rocky.0.1" and "Correctif disponible" in edge01.rationale
    assert edge01.finding_source == "dnf-updateinfo" and edge01.asset_id_full == "host:edge01.lab.example"
    assert not run.errors


def test_assumed_attributes_flag_review(lab, settings, sources):
    record = collect_records(sources, ["CVE-2024-3400"]).records[0]
    d = load_trivy_file(TRIVY / "node00.lab.example.json", "lab", Target("mystery", fqdn="mystery.lan"))
    d.findings[0].cve_id = "CVE-2024-3400"
    inv = build_inventory(lab, [d])
    [row] = Triage(settings).run(lab, {record.cve_id: record}, {a.id: a for a in inv.assets}, inv.findings).rows
    assert row.publicly_exposed and row.needs_review
    assert any(a.startswith("exposition supposée : internet (pire cas)") for a in row.assumptions)
    assert "Hypothèses :" in row.rationale


# -- client profile v2 ----------------------------------------------------------------------------
def test_profile_v2_and_v1_compatibility(lab):
    assert len(lab.rules) == 4 and lab.rules[0].hostname == "edge01"
    v2_minimal = {"schema_version": 2, "client": {"id": "c", "name": "C", "updated": "2026-10-11"}}
    assert validate_profile_data(v2_minimal) == []
    v1_incomplete = {
        "schema_version": 1,
        "client": {"id": "c", "name": "C", "updated": "2026-10-11"},
        "assets": [{"id": "a", "description": "d", "vendor": "v", "product": "p"}],
    }
    assert validate_profile_data(v1_incomplete)  # v1 still requires fully described assets
    bad_rule = {**v2_minimal, "rules": [{"set": {"exposure": "internet"}}]}
    assert validate_profile_data(bad_rule)  # a rule needs a hostname, fqdn or ip


def test_settings_rationale_scope():
    assert Settings().llm.rationale_for == ["ACT", "ATTEND"]


def test_targets_extra_ips_and_eosl(tmp_path):
    from vulnops.detect.collect import load_targets
    from vulnops.detect.scanners import Target, parse_trivy

    tf = load_targets(ROOT / "examples" / "lab" / "targets.yaml")
    node02 = next(t for t in tf.targets if t.host.startswith("node02"))
    assert node02.ip == "192.0.2.75" and "192.0.2.195" in node02.ips

    data = {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "centos", "Name": "8.5.2111", "EOSL": True}}}
    d = parse_trivy(data, "lab", Target(name="node03"))
    assert d.observations[0].os == "centos 8.5.2111 (end of support)"


def test_plan_checks_client_id(capsys):
    from vulnops.detect.cli import main

    lab = str(ROOT / "examples" / "lab")
    assert main(["plan", f"{lab}/targets.yaml", "--profile", f"{lab}/client.yaml"]) == 0
    assert "lab: 10 targets" in capsys.readouterr().out
    other = str(ROOT / "examples" / "example-client" / "client.yaml")
    assert main(["plan", f"{lab}/targets.yaml", "--profile", other]) == 2
