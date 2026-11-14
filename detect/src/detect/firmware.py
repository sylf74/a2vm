# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The exact version of an appliance or a network device, as a component (HLD D20, v0.23.6).

An appliance has no package manager an SSH collection could read, no agent and no SBOM. What it
says of itself is its system: SNMP's sysDescr and its vendor's own objects, or the CMDB's brand,
model and OS version. This module turns that into one component of type `firmware`: the vendor, the
product, the version, and the CPE of its operating system when the family is known
(`cpe:2.3:o:fortinet:fortios`). The watch matches it against the affected ranges of the CVE records
and of the vendors' CSAF advisories, with the level of proof `embedded` (`ngvm.applications`). A
family not known here keeps its vendor and product, and goes through the tenant's applications table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .collect import component

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
# Version objects of some vendors, read when sysDescr does not carry the version.
VENDOR_VERSION = {
    "12356": "1.3.6.1.4.1.12356.101.4.1.1.0",  # Fortinet: fgSysVersion "v7.2.8,build1639,240313 (GA.M)"
    "25461": "1.3.6.1.4.1.25461.2.1.2.1.1.0",  # Palo Alto Networks: panSysSwVersion "10.2.9-h1"
    "14988": "1.3.6.1.4.1.14988.1.1.4.4.0",  # MikroTik: mtxrFirmwareVersion "7.14.3"
}
ENTERPRISE = re.compile(r"^1\.3\.6\.1\.4\.1\.(\d+)")


@dataclass(frozen=True)
class Firmware:
    vendor: str
    product: str
    version: str
    cpe: str = ""  # cpe:2.3:o:<vendor>:<product>, when the family is known

    def component(self, source: str) -> dict[str, str]:
        out = component(self.product, self.version, "", "firmware", "", "", source, self.vendor)
        if self.cpe:
            out["cpe"] = self.cpe
        return out


# (pattern on sysDescr, vendor, product, cpe); the version is the group `v`, when present.
FAMILIES: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"Cisco IOS[ -]XE Software.*?Version (?P<v>[\w.()]+)", re.S),
        "Cisco",
        "IOS XE",
        "cpe:2.3:o:cisco:ios_xe",
    ),
    (re.compile(r"Cisco NX-OS.*?[Vv]ersion (?P<v>[\w.()]+)", re.S), "Cisco", "NX-OS", "cpe:2.3:o:cisco:nx-os"),
    (
        re.compile(r"Cisco Adaptive Security Appliance Version (?P<v>[\w.()]+)"),
        "Cisco",
        "Adaptive Security Appliance Software",
        "cpe:2.3:o:cisco:adaptive_security_appliance_software",
    ),
    (re.compile(r"Cisco IOS Software.*?Version (?P<v>[\w.()]+)", re.S), "Cisco", "IOS", "cpe:2.3:o:cisco:ios"),
    (re.compile(r"Juniper Networks.*?JUNOS (?P<v>[\w.\-]+)", re.S), "Juniper", "Junos OS", "cpe:2.3:o:juniper:junos"),
    (re.compile(r"\bVyOS (?P<v>[\w.\-]+)"), "VyOS", "VyOS", "cpe:2.3:o:vyos:vyos"),
    (
        re.compile(r"\bRouterOS\b(?:.*?(?P<v>\d+\.\d+(?:\.\d+)?))?"),
        "MikroTik",
        "RouterOS",
        "cpe:2.3:o:mikrotik:routeros",
    ),
    (re.compile(r"\bFortiGate\b|\bFortinet\b", re.I), "Fortinet", "FortiOS", "cpe:2.3:o:fortinet:fortios"),
    (re.compile(r"\bPalo Alto Networks\b", re.I), "Palo Alto Networks", "PAN-OS", "cpe:2.3:o:paloaltonetworks:pan-os"),
    (
        re.compile(r"ArubaOS-CX.*?(?P<v>[A-Z]{2}\.\d+\.\d+\.\d+)", re.S),
        "Aruba",
        "ArubaOS-CX",
        "cpe:2.3:o:arubanetworks:arubaos-cx",
    ),
]
IOS_XE = re.compile(r"IOS[- _]?XE", re.I)
ENTERPRISES = {"9": "Cisco", "12356": "Fortinet", "25461": "Palo Alto Networks", "2636": "Juniper", "14988": "MikroTik"}


def _vendor_version(value: str) -> str:
    """A vendor object's version in its plain form: `v7.2.8,build1639,...` -> `7.2.8`."""
    text = value.strip().split(",")[0].strip()
    return text[1:] if re.match(r"^[vV]\d", text) else text


def from_snmp(values: dict[str, str]) -> Firmware | None:
    """sysDescr, sysObjectID and the vendor's version object -> the firmware, or None when sysDescr
    says nothing usable."""
    descr = (values.get(SYS_DESCR) or "").strip()
    oid = (values.get(SYS_OBJECT_ID) or "").strip().lstrip(".")
    enterprise = (ENTERPRISE.match(oid) or [None, ""])[1]
    extra = _vendor_version(values.get(VENDOR_VERSION.get(enterprise, ""), "") or "")
    if re.match(r"^(Linux|Windows|Darwin|FreeBSD)\b", descr):
        return None  # a host: its packages come from SSH or an agent, not from SNMP
    for pattern, vendor, product, cpe in FAMILIES:
        m = pattern.search(descr)
        if m:
            version = (m.groupdict().get("v") or "").rstrip(",.") or extra
            if product == "IOS" and IOS_XE.search(descr):  # IOS XE's sysDescr starts like IOS's
                product, cpe = "IOS XE", "cpe:2.3:o:cisco:ios_xe"
            return Firmware(vendor, product, version, cpe) if version else None
    if enterprise in ENTERPRISES and extra:  # a vendor known by its OID, sysDescr a model name only
        for _pattern, vendor, product, cpe in FAMILIES:
            if vendor == ENTERPRISES[enterprise] and cpe:
                return Firmware(vendor, product, extra, cpe)
    if descr:
        version = re.search(r"\b[Vv]?(\d+\.\d+(?:[.\-]\w+)*)\b", descr)
        if version:
            words = descr.split(",")[0].split()
            vendor = ENTERPRISES.get(enterprise, words[0] if words else "")
            return Firmware(vendor, " ".join(words[:3])[:80], version[1])
    return None


# The CMDB's OS version names the family, when the brand alone does not (Cisco).
CMDB_FAMILIES: list[tuple[re.Pattern[str], str, str, str, str]] = [
    (IOS_XE, "cisco", "Cisco", "IOS XE", "cpe:2.3:o:cisco:ios_xe"),
    (re.compile(r"NX-?OS", re.I), "cisco", "Cisco", "NX-OS", "cpe:2.3:o:cisco:nx-os"),
    (
        re.compile(r"\bASA\b", re.I),
        "cisco",
        "Cisco",
        "Adaptive Security Appliance Software",
        "cpe:2.3:o:cisco:adaptive_security_appliance_software",
    ),
    (re.compile(r"\bIOS\b", re.I), "cisco", "Cisco", "IOS", "cpe:2.3:o:cisco:ios"),
    (re.compile(r""), "fortinet", "Fortinet", "FortiOS", "cpe:2.3:o:fortinet:fortios"),
    (re.compile(r""), "palo alto", "Palo Alto Networks", "PAN-OS", "cpe:2.3:o:paloaltonetworks:pan-os"),
    (re.compile(r""), "juniper", "Juniper", "Junos OS", "cpe:2.3:o:juniper:junos"),
    (re.compile(r""), "mikrotik", "MikroTik", "RouterOS", "cpe:2.3:o:mikrotik:routeros"),
]


def from_cmdb(brand: str, model: str, os_version: str) -> Firmware | None:
    """The CMDB's brand and OS version of a network device -> the firmware. The CPE only when the
    family is certain: Cisco's IOS and IOS XE share their version numbers, so a bare `17.9.4a` of a
    Cisco device stays without CPE and goes through the applications table."""
    text = os_version.strip()
    if not text:
        return None
    version = _vendor_version(re.sub(r"^[A-Za-z][\w\-]*\s+(?=v?\d)", "", text)) or text
    for pattern, key, vendor, product, cpe in CMDB_FAMILIES:
        if key in brand.lower() and pattern.search(text):
            return Firmware(vendor, product, version, cpe)
    name = " ".join(x for x in (brand.strip(), model.strip()) if x) or "device"
    return Firmware(brand.strip(), name[:80], version)
