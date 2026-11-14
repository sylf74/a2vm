# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The components of an asset matched against the package advisories of a record (D20, v0.23.0).

A host's packages (`Asset.components`, listed by pillar 2, consolidated by pillar 3) are compared
with the fixed versions the distributions publish for a CVE (`VulnRecord.packages`, collected by
pillar 1 from Red Hat's security data and OSV): the asset is exposed when it holds a package of an
affected source package at a version below the fix, or with no fix yet. No scan is needed: the watch
names the hosts within minutes of a publication.

Versions are compared the way the package managers do: rpm (epoch, then rpmvercmp on version and
release) and dpkg (epoch, upstream version, Debian revision, `~` before anything). A distribution is
reduced to the family whose advisories apply to it: Red Hat's advisories apply to RHEL and to its
rebuilds (Rocky Linux, AlmaLinux) of the same major release, a rebuild may lag behind the fix.

Owned by pillar 3, which defines the components of an asset (LLD triage-prioritization §1.1); used by
pillar 1 (the watch). No LLM: a comparison of versions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Distributions whose advisories come from one family: <family>:<release>.
RHEL_LIKE = {"rhel", "rocky", "almalinux", "alma", "redhat"}
FAMILIES = {"debian": "debian", "ubuntu": "ubuntu", **dict.fromkeys(RHEL_LIKE, "rhel")}
# States of a package advisory: fixed in a version, affected with no fix (yet), not decided, or said
# not affected (kept so that the distribution counts as covered).
FIXED, AFFECTED, INVESTIGATING, NOT_AFFECTED = "fixed", "affected", "investigating", "not_affected"
PACKAGE_TYPES = ("rpm", "deb")  # the components matched here; the others go through the applications table


# -- versions ---------------------------------------------------------------------------------------
def _rpm_segments(text: str) -> list[str]:
    return re.findall(r"~|\^|\d+|[A-Za-z]+", text)


def rpmvercmp(a: str, b: str) -> int:
    """rpm's comparison of two version (or release) strings: -1, 0 or 1."""
    if a == b:
        return 0
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    while sa or sb:
        x = sa.pop(0) if sa else None
        y = sb.pop(0) if sb else None
        if x == "~" or y == "~":  # tilde sorts before anything, even the end
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":  # caret sorts after the end, before anything else
            if x is None:
                return -1
            if y is None:
                return 1
            if x != y:
                return 1 if x == "^" else -1
            continue
        if x is None or y is None:
            return -1 if x is None else 1
        if x.isdigit() and y.isdigit():
            nx, ny = int(x), int(y)
            if nx != ny:
                return -1 if nx < ny else 1
        elif x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1  # a number is newer than letters
        elif x != y:
            return -1 if x < y else 1
    return 0


def split_evr(evr: str) -> tuple[int, str, str]:
    """`[epoch:]version[-release]` as (epoch, version, release)."""
    epoch, _, rest = evr.rpartition(":")
    version, _, release = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return (int(epoch) if epoch.isdigit() else 0), version, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256 if c else 0


def _deb_part(a: str, b: str) -> int:
    """dpkg's comparison of an upstream version or a revision."""
    while a or b:
        na = re.match(r"[^\d]*", a).group()
        nb = re.match(r"[^\d]*", b).group()
        for i in range(max(len(na), len(nb))):
            oa = _deb_order(na[i] if i < len(na) else "")
            ob = _deb_order(nb[i] if i < len(nb) else "")
            if oa != ob:
                return -1 if oa < ob else 1
        a, b = a[len(na) :], b[len(nb) :]
        da = re.match(r"\d*", a).group()
        db = re.match(r"\d*", b).group()
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
        a, b = a[len(da) :], b[len(db) :]
    return 0


def deb_compare(a: str, b: str) -> int:
    def split(v: str) -> tuple[int, str, str]:
        epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return (int(epoch) if epoch.isdigit() else 0), upstream, revision

    ea, ua, ra = split(a.strip())
    eb, ub, rb = split(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part(ua, ub) or _deb_part(ra, rb)


def compare(kind: str, a: str, b: str) -> int:
    """Compare two versions of a package of type `kind` (rpm or deb): -1, 0 or 1."""
    return deb_compare(a, b) if kind == "deb" else rpm_compare(a, b)


# -- distributions --------------------------------------------------------------------------------
def family(distro: str) -> str:
    """`rocky-9.4`, `rocky 9.4` (Trivy) -> `rhel:9`; `debian-12` -> `debian:12`; `ubuntu-22.04` ->
    `ubuntu:22.04`; empty when no family is known."""
    m = re.match(r"^\s*([A-Za-z]+)[\s-]+(\d+(?:\.\d+)?)", distro or "")
    if not m:
        return ""
    name, release = m.group(1).lower(), m.group(2)
    fam = FAMILIES.get(name)
    if not fam:
        return ""
    if fam in ("rhel", "debian"):
        release = release.split(".", 1)[0]
    return f"{fam}:{release}"


def asset_family(component: dict[str, Any], os_name: str | None) -> str:
    """The family of a component's distribution, else of the asset's OS (a v0.22.2 listing); none
    for an application that is not a package of a distribution (v0.23.3: `ngvm.applications`)."""
    if component.get("type", "rpm") not in PACKAGE_TYPES:
        return ""
    return family(component.get("distro") or "") or family(os_name or "")


# -- matching ---------------------------------------------------------------------------------------
@dataclass
class Exposure:
    """One component of an asset in the affected range of a package advisory."""

    cve: str
    component: str  # the package installed
    version: str  # its version
    source_package: str
    fixed: str  # the fixed version, empty when none yet
    state: str  # fixed (a fix exists) | affected (no fix yet) | investigating
    advisory: str  # RHSA-..., DEBIAN-CVE-..., UBUNTU-CVE-...
    url: str
    source: str  # where the component was seen (ssh...)
    seen: str  # when that source last listed it
    origin: str  # where the advisory comes from (redhat, osv)

    def to_dict(self) -> dict[str, str]:
        return dict(self.__dict__)


def _in_range(kind: str, version: str, adv: dict[str, Any]) -> bool:
    introduced = str(adv.get("introduced") or "0")
    if introduced not in ("0", "") and compare(kind, version, introduced) < 0:
        return False
    if adv.get("fixed"):
        return compare(kind, version, str(adv["fixed"])) < 0
    if adv.get("last_affected"):
        return compare(kind, version, str(adv["last_affected"])) <= 0
    return True  # no fix: every version from `introduced`


def exposures(
    cve: str, components: list[dict[str, Any]], packages: list[dict[str, Any]], os_name: str | None = None
) -> list[Exposure]:
    """The components in the affected range of the record's package advisories, one per component
    (the first advisory that matches): state fixed or affected, an exposure; investigating, the
    distribution has not decided yet. Components of a distribution the advisories do not cover are
    left out: `covered` tells them apart."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for adv in packages:
        if adv.get("state") in (FIXED, AFFECTED, INVESTIGATING):
            by_key.setdefault((adv.get("distro", ""), adv.get("name", "")), []).append(adv)
    out: list[Exposure] = []
    seen: set[tuple[str, str]] = set()
    for c in components:
        fam = asset_family(c, os_name)
        if not fam:
            continue
        kind = c.get("type", "rpm")
        for name in dict.fromkeys([c.get("source_package") or c["name"], c["name"]]):
            hit = next((a for a in by_key.get((fam, name), []) if _in_range(kind, c["version"], a)), None)
            if hit is None:
                continue
            key = (c["name"], c["version"])
            if key not in seen:
                seen.add(key)
                out.append(
                    Exposure(
                        cve=cve, component=c["name"], version=c["version"], source_package=name,
                        fixed=str(hit.get("fixed") or ""), state=hit.get("state", AFFECTED),
                        advisory=hit.get("advisory", ""), url=hit.get("url", ""),
                        source=c.get("source", "ssh"), seen=c.get("seen", ""), origin=hit.get("source", ""),
                    )
                )  # fmt: skip
            break
    return out


def covered(components: list[dict[str, Any]], packages: list[dict[str, Any]], os_name: str | None = None) -> bool:
    """Whether the record's package advisories speak of the distribution of these components (an
    advisory of any state, not affected included): if not, a component named like a product of the
    record is only a possible exposure."""
    families = {a.get("distro", "") for a in packages}
    return any(asset_family(c, os_name) in families for c in components)


def present(product: str, components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The components named exactly like a product of a record (`OpenSSL` -> openssl), by their own
    name or their source package: the product is there, its version against the record unknown."""
    wanted = product.strip().lower()
    if len(wanted) < 4:
        return []
    return [c for c in components if wanted in (c["name"].lower(), (c.get("source_package") or "").lower())]
