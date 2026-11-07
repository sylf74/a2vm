# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Package advisories of a CVE (D20, v0.23.0): which source packages of which distribution are
affected, and from which version they are fixed, read by CVE id only (no client data leaves):

  redhat   Red Hat's security data (`/hydra/rest/securitydata/cve/<CVE>.json`): the fixed packages
           of each RHEL major release (`affected_release`) and the packages without a fix
           (`package_state`); they apply to the rebuilds (Rocky Linux, AlmaLinux)
  debian   OSV, the Debian security tracker (`DEBIAN-CVE-<CVE>`)
  ubuntu   OSV, Ubuntu's CVE reports (`UBUNTU-CVE-<CVE>`)

Each advisory becomes one entry of `VulnRecord.packages`: {distro (rhel:9, debian:12,
ubuntu:22.04), name (the source package), introduced, fixed, last_affected, state (fixed, affected,
investigating, not_affected), advisory, url, source}. Matched against the hosts' packages by `a2vm.packages`.
"""

from __future__ import annotations

import re
from typing import Any

from a2vm.packages import AFFECTED, FIXED, INVESTIGATING, NOT_AFFECTED, rpm_compare

SOURCES = ("redhat", "debian", "ubuntu")
_RHEL_CPE = re.compile(r"^cpe:/[ao]:redhat:enterprise_linux:(\d+)(?::|$)")
_NO_FIX = {"affected", "fix deferred", "will not fix"}
_OSV_PREFIX = {"debian": "DEBIAN", "ubuntu": "UBUNTU"}


def osv_id(source: str, cve_id: str) -> str:
    return f"{_OSV_PREFIX[source]}-{cve_id}"


def _nevr(package: str) -> tuple[str, str] | None:
    """`openssl-1:3.0.7-27.el9` -> (openssl, 1:3.0.7-27.el9); None for a module or a container."""
    parts = package.rsplit("-", 2)
    if len(parts) != 3 or not all(parts) or "/" in parts[0] or ":" in parts[0]:
        return None
    return parts[0], f"{parts[1]}-{parts[2]}"


def parse_redhat(data: dict[str, Any] | None) -> list[dict[str, str]]:
    """Red Hat's view of one CVE as package advisories: RHEL main streams only (no EUS, no layered
    products), the lowest fix of each source package per release."""
    if not data:
        return []
    fixed: dict[tuple[str, str], dict[str, str]] = {}
    for rel in _as_list(data.get("affected_release")):
        m = _RHEL_CPE.match(str(rel.get("cpe") or ""))
        nevr = _nevr(str(rel.get("package") or ""))
        if not m or not nevr:
            continue
        key = (f"rhel:{m.group(1)}", nevr[0])
        if key in fixed and rpm_compare(fixed[key]["fixed"], nevr[1]) <= 0:
            continue
        advisory = str(rel.get("advisory") or "")
        fixed[key] = {
            "distro": key[0], "name": nevr[0], "introduced": "0", "fixed": nevr[1], "last_affected": "",
            "state": FIXED, "advisory": advisory,
            "url": f"https://access.redhat.com/errata/{advisory}" if advisory else "", "source": "redhat",
        }  # fmt: skip
    out = list(fixed.values())
    cve = str(data.get("name") or "")
    for st in _as_list(data.get("package_state")):
        m = _RHEL_CPE.match(str(st.get("cpe") or ""))
        name = str(st.get("package_name") or "")
        state = str(st.get("fix_state") or "").strip().lower()
        if not m or not name or "/" in name or ":" in name:
            continue
        if state in _NO_FIX:
            value = AFFECTED
        elif state == "under investigation":
            value = INVESTIGATING
        elif state == "not affected":
            value = NOT_AFFECTED
        else:
            continue  # out of support scope
        key = (f"rhel:{m.group(1)}", name)
        if key in fixed:
            continue
        out.append({
            "distro": key[0], "name": name, "introduced": "0", "fixed": "", "last_affected": "", "state": value,
            "advisory": st.get("fix_state", ""),
            "url": f"https://access.redhat.com/security/cve/{cve}" if cve else "", "source": "redhat",
        })  # fmt: skip
    return sorted(out, key=lambda a: (a["distro"], a["name"]))


def _as_list(value: Any) -> list[dict[str, Any]]:
    """Red Hat gives one object instead of a list when there is one."""
    if isinstance(value, dict):
        return [value]
    return [v for v in value or [] if isinstance(v, dict)]


def osv_distro(ecosystem: str) -> str:
    """`Debian:12` -> debian:12; `Ubuntu:22.04:LTS` -> ubuntu:22.04; empty for Ubuntu Pro (ESM) and
    for an ecosystem without a release."""
    parts = ecosystem.split(":")
    if parts[0] == "Debian" and len(parts) >= 2 and parts[1].isdigit():
        return f"debian:{parts[1]}"
    if parts[0] == "Ubuntu" and len(parts) >= 2 and "Pro" not in parts and re.match(r"^\d+\.\d+$", parts[1]):
        return f"ubuntu:{parts[1]}"
    return ""


def parse_osv(data: dict[str, Any] | None) -> list[dict[str, str]]:
    """An OSV entry of a distribution as package advisories: one per affected range."""
    if not data or data.get("withdrawn"):
        return []
    entry_id = str(data.get("id") or "")
    out = []
    for aff in data.get("affected") or []:
        pkg = aff.get("package") or {}
        distro = osv_distro(str(pkg.get("ecosystem") or ""))
        name = str(pkg.get("name") or "")
        if not distro or not name:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            introduced = ""
            for event in rng.get("events") or []:
                if "introduced" in event:
                    if introduced:  # an open range before this one: no fix
                        out.append(_osv(distro, name, introduced, "", "", entry_id))
                    introduced = str(event["introduced"])
                elif "fixed" in event or "last_affected" in event:
                    out.append(_osv(distro, name, introduced or "0", str(event.get("fixed") or ""),
                                    str(event.get("last_affected") or ""), entry_id))  # fmt: skip
                    introduced = ""
            if introduced:
                out.append(_osv(distro, name, introduced, "", "", entry_id))
    return out


def _osv(distro: str, name: str, introduced: str, fixed: str, last: str, entry_id: str) -> dict[str, str]:
    return {
        "distro": distro, "name": name, "introduced": introduced, "fixed": fixed, "last_affected": last,
        "state": FIXED if fixed else AFFECTED, "advisory": entry_id,
        "url": f"https://osv.dev/vulnerability/{entry_id}" if entry_id else "", "source": "osv",
    }  # fmt: skip


def parse(source: str, data: dict[str, Any] | None) -> list[dict[str, str]]:
    return parse_redhat(data) if source == "redhat" else parse_osv(data)
