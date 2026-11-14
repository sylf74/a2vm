# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.6 (D20): appliances and network devices. Their exact firmware read by SNMP or from the CMDB,
matched against the CVE records and the vendors' CSAF advisories with the level of proof embedded."""

from __future__ import annotations

import asyncio
import json
import re

import pytest

from detect.firmware import SYS_DESCR, SYS_NAME, SYS_OBJECT_ID, from_cmdb, from_snmp
from detect.snmp import SnmpConfig, fetch
from ngvm import applications as apps
from ngvm.models import AffectedEntry, VulnRecord

from .conftest import ROOT

FORTI_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"


# -- fingerprints -----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({SYS_DESCR: "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E2, RELEASE"},
         ("Cisco", "IOS", "15.2(7)E2", "cpe:2.3:o:cisco:ios")),
        ({SYS_DESCR: "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, "
                     "RELEASE SOFTWARE (fc5)"},
         ("Cisco", "IOS XE", "17.9.4a", "cpe:2.3:o:cisco:ios_xe")),
        ({SYS_DESCR: "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(8), RELEASE SOFTWARE"},
         ("Cisco", "NX-OS", "9.3(8)", "cpe:2.3:o:cisco:nx-os")),
        ({SYS_DESCR: "Cisco Adaptive Security Appliance Version 9.16(3)19"},
         ("Cisco", "Adaptive Security Appliance Software", "9.16(3)19",
          "cpe:2.3:o:cisco:adaptive_security_appliance_software")),
        ({SYS_DESCR: "Juniper Networks, Inc. srx300 internet router, kernel JUNOS 21.4R3-S5.4, Build date: x"},
         ("Juniper", "Junos OS", "21.4R3-S5.4", "cpe:2.3:o:juniper:junos")),
        ({SYS_DESCR: "FGT60F", SYS_OBJECT_ID: "1.3.6.1.4.1.12356.101.1.4",
          FORTI_VERSION: "v7.2.8,build1639,240313 (GA.M)"},
         ("Fortinet", "FortiOS", "7.2.8", "cpe:2.3:o:fortinet:fortios")),
        ({SYS_DESCR: "Palo Alto Networks PA-3200 series firewall", SYS_OBJECT_ID: ".1.3.6.1.4.1.25461.2.3.38",
          "1.3.6.1.4.1.25461.2.1.2.1.1.0": "10.2.9-h1"},
         ("Palo Alto Networks", "PAN-OS", "10.2.9-h1", "cpe:2.3:o:paloaltonetworks:pan-os")),
        ({SYS_DESCR: "RouterOS CCR2004-16G-2S+", SYS_OBJECT_ID: "1.3.6.1.4.1.14988.1",
          "1.3.6.1.4.1.14988.1.1.4.4.0": "7.14.3"},
         ("MikroTik", "RouterOS", "7.14.3", "cpe:2.3:o:mikrotik:routeros")),
        ({SYS_DESCR: "VyOS 1.4.0"}, ("VyOS", "VyOS", "1.4.0", "cpe:2.3:o:vyos:vyos")),
    ],
)  # fmt: skip
def test_snmp_fingerprints(values, expected) -> None:
    fw = from_snmp(values)
    assert fw is not None and (fw.vendor, fw.product, fw.version, fw.cpe) == expected


def test_hosts_and_unknown_families() -> None:
    assert from_snmp({SYS_DESCR: "Linux nas 4.4.302+ #72806 SMP x86_64"}) is None  # SSH or an agent says more
    assert from_snmp({SYS_DESCR: "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153"}) is None
    fw = from_snmp({SYS_DESCR: "Acme Switch 3000, firmware 4.2.1"})
    assert fw is not None and fw.cpe == "" and fw.version == "4.2.1"  # goes through the applications table
    c = fw.component("snmp")
    assert c["type"] == "firmware" and "cpe" not in c and apps.is_application(c)


def test_cmdb_firmware() -> None:
    assert from_cmdb("Cisco", "C9300", "IOS-XE 17.9.4a").cpe == "cpe:2.3:o:cisco:ios_xe"
    fw = from_cmdb("Fortinet", "FG-60F", "FortiOS 7.2.8")
    assert (fw.product, fw.version, fw.cpe) == ("FortiOS", "7.2.8", "cpe:2.3:o:fortinet:fortios")
    assert from_cmdb("Cisco", "2960X", "15.2(7)E2").cpe == ""  # IOS or IOS XE: not certain
    assert from_cmdb("HP", "2530", "YA.16.10.0012").version == "YA.16.10.0012"
    assert from_cmdb("Cisco", "x", "") is None


def test_cmdb_observation_carries_the_firmware() -> None:
    from detect.cmdb import observation

    fields = {"name": "fw01", "managementip": "192.0.2.1", "brand_name": "Fortinet", "model_name": "FG-60F",
              "iosversion_name": "7.2.8", "finalclass": "NetworkDevice"}  # fmt: skip
    obs = observation("NetworkDevice", "12", fields, "2026-11-10T06:00:00+00:00")
    assert obs.os == "Fortinet FortiOS 7.2.8"
    (c,) = obs.components
    assert c["cpe"] == "cpe:2.3:o:fortinet:fortios" and c["source"] == "cmdb"
    assert observation("Server", "13", {"name": "web01"}, "x").components == []


# -- the connector ----------------------------------------------------------------------------------
def _config(**extra) -> SnmpConfig:
    data = {"targets": ["192.0.2.1", "192.0.2.64/30", "fw.lab.example"], "user": "ngvm-ro",
            "auth_password_file": "/x", "priv_password_file": "/y", **extra}  # fmt: skip
    return SnmpConfig.from_dict(data)


def test_snmp_config() -> None:
    cfg = _config(exclude=["192.0.2.65"])
    assert cfg.addresses() == ["192.0.2.1", "192.0.2.66", "fw.lab.example"]
    assert cfg.version == "3" and cfg.auth_protocol == "sha256" and cfg.priv_protocol == "aes"
    for bad, text in [
        ({"targets": []}, "targets"),
        ({"targets": ["192.0.2.1"], "user": "u"}, "auth_password_file"),
        ({"targets": ["192.0.2.1"], "user": "u", "auth_password_file": "/x"}, "priv_password_file"),
        ({"targets": ["192.0.2.1"], "version": "2c"}, "community_file"),
        ({"targets": ["192.0.2.1"], "version": "1", "community_file": "/c"}, "version"),
        ({"targets": ["10.0.0.0/8"], "version": "2c", "community_file": "/c"}, "more than"),
        ({"targets": ["not a target!"], "version": "2c", "community_file": "/c"}, "not an address"),
        ({"targets": ["192.0.2.1"], "version": "2c", "community_file": "/c", "write": True}, "unknown keys"),
    ]:
        with pytest.raises(ValueError, match=text):
            SnmpConfig.from_dict(bad)
    assert SnmpConfig.from_dict({"targets": ["192.0.2.1"], "user": "u", "auth_password_file": "/x",
                                 "priv_protocol": "none"}).priv_protocol == "none"  # fmt: skip


DEVICES = {
    "192.0.2.1": {SYS_DESCR: "FGT60F", SYS_OBJECT_ID: "1.3.6.1.4.1.12356.101.1.4", SYS_NAME: "fw01.lab.example"},
    "192.0.2.66": {SYS_DESCR: "Cisco IOS XE Software, Version 17.03.04a", SYS_NAME: "sw01"},
    "fw.lab.example": {SYS_DESCR: "", SYS_NAME: "x"},
}


def test_snmp_fetch_reads_a_few_objects_only() -> None:
    asked: list[tuple[str, list[str]]] = []

    async def query(target, oids):
        asked.append((target, oids))
        if oids == [FORTI_VERSION]:
            return {FORTI_VERSION: "v7.2.8,build1639,240313 (GA.M)"}
        return dict(DEVICES.get(target, {}))

    logs: list[str] = []
    d = fetch(_config(), "lab", query=query, log=logs.append)
    assert d.source == "snmp" and d.findings == []
    assert [o.ref for o in d.observations] == ["snmp:192.0.2.1", "snmp:192.0.2.66"]
    fw, sw = d.observations
    assert fw.identifiers == {"ips": ["192.0.2.1"], "hostname": "fw01", "fqdn": "fw01.lab.example"}
    assert fw.os == "Fortinet FortiOS 7.2.8" and fw.attributes == {"snmp_object_id": "1.3.6.1.4.1.12356.101.1.4"}
    assert fw.components[0]["cpe"] == "cpe:2.3:o:fortinet:fortios"
    assert sw.components[0]["version"] == "17.03.04a" and sw.name == "sw01"
    assert d.skipped == {"no answer": 1, "no sysDescr": 1}
    assert all(len(oids) <= 3 for _, oids in asked) and len(asked) == 5
    assert logs == ["snmp: 4 targets, 2 devices, firmware known on 2"]


def test_snmp_is_not_a_scan() -> None:
    from verdict.assets.build import NOT_SCANS

    assert "snmp" in NOT_SCANS


def test_the_agent_and_the_cli_know_snmp(tmp_path) -> None:
    from detect.agent import SnmpConnector, load_config
    from detect.cli import main

    (tmp_path / "token").write_text("t")
    (tmp_path / "c.yaml").write_text(json.dumps({
        "collector": "c1", "tenant": "lab", "service": "https://ngvm.example.org",
        "token_file": str(tmp_path / "token"),
        "connectors": [{"name": "network", "type": "snmp", "targets": ["192.0.2.1"], "version": "2c",
                        "community_file": str(tmp_path / "community")}],
    }))  # fmt: skip
    cfg = load_config(tmp_path / "c.yaml")
    assert isinstance(cfg.connectors[0], SnmpConnector)
    (tmp_path / "snmp.yaml").write_text(json.dumps({"targets": ["192.0.2.1"], "version": "2c",
                                                    "community_file": str(tmp_path / "missing")}))  # fmt: skip
    assert main(["snmp", "fetch", "--config", str(tmp_path / "snmp.yaml"), "--tenant", "lab",
                 "--out", str(tmp_path / "out")]) == 2  # fmt: skip


def test_pysnmp_query_against_nothing(tmp_path) -> None:
    pytest.importorskip("pysnmp")
    from detect.snmp import pysnmp_query

    (tmp_path / "community").write_text("public\n")
    cfg = SnmpConfig.from_dict({"targets": ["127.0.0.1"], "version": "2c",
                                "community_file": str(tmp_path / "community"),
                                "port": 1, "timeout_seconds": 0.2, "retries": 0})  # fmt: skip
    query = pysnmp_query(cfg)
    assert asyncio.run(query("127.0.0.1", [SYS_DESCR])) == {}


# -- matching ---------------------------------------------------------------------------------------
def _record(entries, cve="CVE-2099-0101"):
    return VulnRecord(cve, "PUBLISHED", None, "", [], [], entries, None, None, [])


FORTIOS = {"name": "FortiOS", "version": "7.2.8", "type": "firmware", "vendor": "Fortinet",
           "cpe": "cpe:2.3:o:fortinet:fortios", "source": "snmp", "seen": "2026-11-10T06:00:00+00:00"}  # fmt: skip
IOS_XE = {"name": "IOS XE", "version": "17.03.04a", "type": "firmware", "vendor": "Cisco",
          "cpe": "cpe:2.3:o:cisco:ios_xe", "source": "snmp", "seen": "2026-11-10T06:00:00+00:00"}  # fmt: skip


def test_firmware_in_range_is_embedded() -> None:
    entry = AffectedEntry("Fortinet", "FortiOS", [{"version": "7.2.0", "lessThanOrEqual": "7.2.10",
                                                    "status": "affected", "versionType": "semver"}],
                          "unaffected", [], "cna")  # fmt: skip
    (hit,) = apps.firmware_matches(_record([entry]), [FORTIOS])
    assert hit.proof == "embedded" and hit.exposure.origin == "firmware"
    assert hit.exposure.component == "Fortinet FortiOS" and hit.exposure.version == "7.2.8"
    newer = {**FORTIOS, "version": "7.2.11"}
    assert apps.firmware_matches(_record([entry]), [newer]) == []
    undecided = AffectedEntry("Fortinet", "FortiOS", [], "unknown", [], "cna")
    (hit,) = apps.firmware_matches(_record([undecided]), [FORTIOS])
    assert hit.proof == "possible" and hit.reason == "version not decided"
    other = AffectedEntry("Fortinet", "FortiProxy", entry.versions, "unaffected", [], "cna")
    assert apps.firmware_matches(_record([other]), [FORTIOS]) == []


def test_cisco_lists_its_versions() -> None:
    listed = [{"version": v, "status": "affected", "versionType": "custom"} for v in ("17.3.4a", "17.9.4")]
    entry = AffectedEntry("Cisco", "Cisco IOS XE Software", listed, "", [], "cna")
    (hit,) = apps.firmware_matches(_record([entry]), [IOS_XE])
    assert hit.proof == "embedded"
    assert apps.firmware_matches(_record([entry]), [{**IOS_XE, "version": "17.9.5"}]) == []
    ios = AffectedEntry("Cisco", "Cisco IOS Software", listed, "", [], "cna")
    assert apps.firmware_matches(_record([ios]), [IOS_XE]) == []
    by_cpe = AffectedEntry("n/a", "n/a", listed, "", ["cpe:2.3:o:cisco:ios_xe:17.3.4a:*:*:*:*:*:*:*"], "adp")
    assert apps.firmware_matches(_record([by_cpe]), [IOS_XE])[0].proof == "embedded"


def test_firmware_without_cpe_goes_through_the_table() -> None:
    comp = {"name": "Acme Switch 3000", "version": "4.2.1", "type": "firmware", "vendor": "Acme", "source": "snmp"}
    entry = AffectedEntry("Acme", "Switch OS", [{"version": "4.0", "lessThan": "4.3", "status": "affected"}],
                          "unaffected", [], "cna")  # fmt: skip
    key = apps.app_key("Acme", "Acme Switch 3000")
    table = {key: apps.Row(key, "Acme", "Acme Switch 3000", apps.VALIDATED, "cpe:2.3:o:acme:switch_os")}
    (hit,) = apps.matches(_record([entry]), [comp], table)
    assert hit.proof == "embedded" and hit.exposure.origin == "cve-record"
    forti = AffectedEntry("Fortinet", "FortiOS", [{"version": "7.0", "lessThan": "7.4", "status": "affected"}], "", [],
                          "cna")  # fmt: skip
    (hit,) = apps.matches(_record([forti]), [FORTIOS], {})
    assert hit.proof == "embedded"  # the table is not needed for a firmware with its CPE


def test_the_watch_names_the_device_embedded() -> None:
    from via.alert.fiche import concerned_rows
    from via.alert.inventory import Inventory
    from via.alert.watch import Alert, Item, inventory_matches

    from .test_v0230 import _asset

    entry = AffectedEntry("Fortinet", "FortiOS", [{"version": "7.2.0", "lessThan": "7.2.9", "status": "affected"}],
                          "unaffected", [], "cna")  # fmt: skip
    record = _record([entry])
    inv = Inventory("acme", {"host:fw01": _asset("host:fw01", "fw01", [FORTIOS])}, {}, "x")
    exposed, possible = inventory_matches([record], inv, set(), None)
    assert possible == [] and [(a.id, e.fixed) for a, e in exposed] == [("host:fw01", "7.2.9")]
    item = Item("CVE:CVE-2099-0101", "cve", "x", [record.cve_id], "")
    alert = Alert("a", "acme", "info", item, [record], [], [], {}, exposed=exposed)
    for lang, proof, source in (("en", "embedded", "firmware reported (snmp, 2026-11-10)"),
                                ("fr", "embarqué", "firmware déclaré (snmp, 2026-11-10)")):  # fmt: skip
        (row,) = concerned_rows(alert, "CVE", lang)[0]
        assert (row["preuve"], row["source"], row["version_installee"]) == (proof, source, "Fortinet FortiOS 7.2.8")
    assert inventory_matches([record], inv, {("host:fw01", record.cve_id)}, None) == ([], [])


# -- CSAF -------------------------------------------------------------------------------------------
CSAF = {
    "document": {"title": "FortiOS: heap overflow", "tracking": {"id": "FG-IR-99-001",
                 "current_release_date": "2099-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{"category": "vendor", "name": "Fortinet", "branches": [
        {"category": "product_name", "name": "FortiOS", "branches": [
            {"category": "product_version_range", "name": "vers:fortios/>=7.0.0|<=7.0.15|>=7.2.0|<=7.2.8",
             "product": {"product_id": "P1", "name": "FortiOS 7.0.0-7.2.8",
                         "product_identification_helper": {"cpe": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}}},
            {"category": "product_version", "name": "7.2.9", "product": {"product_id": "P2", "name": "FortiOS 7.2.9"}},
            {"category": "product_version_range", "name": "vers:fortios/>=7.4.0|<=7.4.4",
             "product": {"product_id": "P3", "name": "FortiOS 7.4 fixed"}},
        ]}]}]},
    "vulnerabilities": [{"cve": "CVE-2099-0101", "product_status": {"known_affected": ["P1"], "fixed": ["P2", "P3"]}},
                        {"cve": "bad"}],
}  # fmt: skip


def test_csaf_product_status() -> None:
    from via.alert.feeds import Source, csaf_affected, parse_csaf

    (block,) = csaf_affected(CSAF)["CVE-2099-0101"]
    assert block["vendor"] == "Fortinet" and block["product"] == "FortiOS" and block["source"] == "cna"
    assert block["cpes"] == ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"]
    assert block["versions"] == [
        {"version": "7.0.0", "status": "affected", "versionType": "custom", "lessThanOrEqual": "7.0.15"},
        {"version": "7.2.0", "status": "affected", "versionType": "custom", "lessThanOrEqual": "7.2.8"},
        {"version": "7.2.9", "status": "unaffected", "versionType": "custom"},
    ]  # a fixed range says nothing exact: left out
    pub = parse_csaf(CSAF, "https://csaf.example.org/x.json", Source("fortinet", "Fortinet", "vendor", "csaf"))
    assert set(pub.affected) == {"CVE-2099-0101"}


def test_the_vendor_status_comes_before_the_record() -> None:
    from via.alert.feeds import Source, parse_csaf
    from via.alert.watch import Item, with_vendor_status

    pub = parse_csaf(CSAF, "https://csaf.example.org/x.json", Source("fortinet", "Fortinet", "vendor", "csaf"))
    item = Item("fortinet:FG-IR-99-001", "fortinet", pub.title, pub.cves, pub.published, publication=pub)
    undecided = _record([AffectedEntry("Fortinet", "FortiOS", [], "unknown", [], "cna")])
    assert apps.firmware_matches(undecided, [FORTIOS])[0].proof == "possible"
    record = with_vendor_status(undecided, item)
    assert len(record.affected) == 1 and record.affected[0].versions and len(undecided.affected) == 1
    assert apps.firmware_matches(record, [FORTIOS])[0].proof == "embedded"
    assert apps.firmware_matches(record, [{**FORTIOS, "version": "7.2.9"}]) == []
    plain = Item("CVE:CVE-2099-0101", "cve", "x", ["CVE-2099-0101"], "")
    assert with_vendor_status(undecided, plain) is undecided


# -- wiring -----------------------------------------------------------------------------------------
def test_schemas_carry_the_cpe() -> None:
    for name in ("detection", "assets", "triage"):
        text = (ROOT / "ngvm" / "src" / "ngvm" / "schemas" / f"{name}.schema.json").read_text()
        assert '"cpe": {' in text and "since v0.23.6" in text


def test_the_snmp_extra_is_installed_everywhere() -> None:
    assert re.search(r'snmp = \["pysnmp>=7,<8"\]', (ROOT / "detect" / "pyproject.toml").read_text())
    assert "[openvas,snmp]" in (ROOT / "images" / "Dockerfile").read_text()
    assert "detect[openvas,snmp]" in (ROOT / "templates" / "client-pipeline.yml").read_text()
    assert "detect[openvas,snmp]" in (ROOT / "requirements-dev.txt").read_text()
