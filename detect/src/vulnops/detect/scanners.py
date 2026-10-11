"""Scanner connectors: turn scanner outputs into asset observations and findings.

  trivy           `trivy rootfs|image --format json` (Linux hosts, container images)
  dnf-updateinfo  `dnf -q updateinfo list --security --with-cve` (Rocky / RHEL hosts Trivy does not
                  cover, e.g. Rocky 10): only advisories with an update available are listed

One output file = one asset. The host name comes from the file name (`<host>.json`, `<host>.txt`)
unless given explicitly; addresses and FQDNs come from the collection targets when known.
Entries that are not CVEs (GHSA, vendor ids) are counted in `skipped`, not dropped silently.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnops.core.io import Detection, now
from vulnops.core.models import AssetObservation, Finding, FindingObservation, Match

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class Target:
    """What we know about the scanned asset, besides the scanner output."""

    name: str  # short host name or image reference
    kind: str = "host"  # host | image
    fqdn: str | None = None
    ips: list[str] = field(default_factory=list)
    image: str | None = None

    @property
    def ref(self) -> str:
        return self.image if self.kind == "image" and self.image else (self.fqdn or self.name)

    def identifiers(self) -> dict[str, Any]:
        ids: dict[str, Any] = {}
        if self.kind == "image":
            ids["image"] = self.image or self.name
        else:
            ids["hostname"] = self.name.split(".")[0].lower()
            if self.fqdn:
                ids["fqdn"] = self.fqdn.lower()
            elif "." in self.name:
                ids["fqdn"] = self.name.lower()
        if self.ips:
            ids["ips"] = list(self.ips)
        return ids


class _Builder:
    """Accumulates findings for one asset, one finding per CVE, one observation per package."""

    def __init__(self, client_id: str, source: str, target: Target, observed_at: str):
        self.client_id, self.source, self.target, self.observed_at = client_id, source, target, observed_at
        self.findings: dict[str, Finding] = {}
        self.skipped: Counter[str] = Counter()

    def add(self, vuln_id: str, package: str, installed: str, fixed: str, status: str, severity: str) -> None:
        if not CVE_RE.match(vuln_id or ""):
            self.skipped[f"non-CVE id ({(vuln_id or '?').split('-')[0]})"] += 1
            return
        obs = FindingObservation(
            source=self.source,
            observed_at=self.observed_at,
            match=Match("scanner", "", package, 1.0, f"{self.source} package match"),
            package=package,
            installed_version=installed,
            fixed_version=fixed,
            source_status=status,
            source_severity=severity,
        )
        ref = self.target.ref
        f = self.findings.get(vuln_id)
        if f is None:
            self.findings[vuln_id] = Finding(
                id=Finding.make_id(self.client_id, ref, vuln_id),
                client_id=self.client_id,
                asset_ref=ref,
                cve_id=vuln_id,
                status="affected",
                affected_versions=[installed] if installed else [],
                observations=[obs],
            )
        else:
            f.observations.append(obs)
            if installed and installed not in f.affected_versions:
                f.affected_versions.append(installed)

    def detection(self, os_name: str | None) -> Detection:
        t = self.target
        observation = AssetObservation(
            ref=t.ref,
            kind=t.kind,
            source=self.source,
            observed_at=self.observed_at,
            name=t.name.split(".")[0] if t.kind == "host" else t.name,
            description="",
            identifiers=t.identifiers(),
            attributes={},
            os=os_name,
        )
        return Detection(
            self.client_id, self.source, [observation], list(self.findings.values()), [], dict(self.skipped)
        )


# -- Trivy ---------------------------------------------------------------------------------------
def parse_trivy(data: dict[str, Any], client_id: str, target: Target, observed_at: str | None = None) -> Detection:
    if data.get("SchemaVersion") != 2:
        raise ValueError(f"unsupported Trivy JSON schema version {data.get('SchemaVersion')!r} (expected 2)")
    b = _Builder(client_id, "trivy", target, observed_at or data.get("CreatedAt") or now())
    os_info = (data.get("Metadata") or {}).get("OS") or {}
    os_name = " ".join(x for x in (os_info.get("Family"), os_info.get("Name")) if x) or None
    if os_name and os_info.get("EOSL"):
        os_name += " (end of support)"
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            b.add(
                v.get("VulnerabilityID", ""),
                v.get("PkgName", ""),
                v.get("InstalledVersion", ""),
                v.get("FixedVersion", "") or "",
                v.get("Status", "") or "",
                v.get("Severity", "") or "",
            )
    return b.detection(os_name)


# -- dnf updateinfo ------------------------------------------------------------------------------
# One advisory line: "<CVE-id> <Severity>/Sec. <package-epoch:version-release.arch>", e.g.
#   CVE-2024-6387 Important/Sec. openssh-8.7p1-38.el9_4.4.x86_64
_DNF_LINE = re.compile(r"^(?P<id>\S+)\s+(?P<type>\S+)\s+(?P<nevra>\S+)\s*$")
_NEVRA = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+-[^-]+)\.(?P<arch>[^.]+)$")


def parse_dnf_updateinfo(text: str, client_id: str, target: Target, observed_at: str | None = None) -> Detection:
    b = _Builder(client_id, "dnf-updateinfo", target, observed_at or now())
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(("last metadata", "updating", "security:")):
            continue
        m = _DNF_LINE.match(line)
        if not m:
            b.skipped["unparsed line"] += 1
            continue
        severity = m.group("type").split("/")[0]
        n = _NEVRA.match(m.group("nevra"))
        package, fixed = (n.group("name"), n.group("version")) if n else (m.group("nevra"), "")
        # dnf lists the update that fixes the CVE: the installed version is older, not reported here.
        b.add(m.group("id"), package, "", fixed, "fixed", severity)
    return b.detection(None)


def target_from_path(path: str | Path, kind: str = "host") -> Target:
    return Target(name=Path(path).stem, kind=kind)


def load_trivy_file(path: str | Path, client_id: str, target: Target | None = None) -> Detection:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_trivy(data, client_id, target or target_from_path(path))


def load_dnf_file(path: str | Path, client_id: str, target: Target | None = None) -> Detection:
    return parse_dnf_updateinfo(Path(path).read_text(encoding="utf-8"), client_id, target or target_from_path(path))


def merge(detections: list[Detection]) -> Detection:
    """Several outputs of the same source and client -> one detection file."""
    if not detections:
        raise ValueError("nothing to merge")
    first = detections[0]
    skipped: Counter[str] = Counter()
    out = Detection(first.client_id, first.source, [], [])
    for d in detections:
        if (d.client_id, d.source) != (first.client_id, first.source):
            raise ValueError("cannot merge detections of different clients or sources")
        out.observations.extend(d.observations)
        out.findings.extend(d.findings)
        out.not_affected.extend(d.not_affected)
        skipped.update(d.skipped)
    out.skipped = dict(skipped)
    return out
