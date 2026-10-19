# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Parse a CVE JSON 5 record (cvelistV5 / CVE Services) into CveFacts."""

from __future__ import annotations

from typing import Any

from vulnops.core.models import AffectedEntry, CveFacts, CvssMetric

_CVSS_KEYS = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0"}

# Vulnrichment key -> internal key
_SSVC_KEYS = {
    "exploitation": "exploitation",
    "automatable": "automatable",
    "technical impact": "technical_impact",
}


def normalize_exploitation(value: str) -> str:
    v = value.strip().lower()
    if v in {"poc", "public poc", "public_poc"}:
        return "poc"
    if v in {"active", "none"}:
        return v
    raise ValueError(f"unknown exploitation value: {value!r}")


def _metrics(container: dict[str, Any], source: str) -> tuple[list[CvssMetric], dict | None, dict | None]:
    cvss: list[CvssMetric] = []
    ssvc: dict[str, str] | None = None
    kev: dict | None = None
    for metric in container.get("metrics", []) or []:
        for key, version in _CVSS_KEYS.items():
            if key in metric and metric[key].get("vectorString"):
                m = metric[key]
                cvss.append(
                    CvssMetric(
                        version=version,
                        vector=m["vectorString"],
                        score=m.get("baseScore"),
                        severity=m.get("baseSeverity"),
                        source=source,
                    )
                )
        other = metric.get("other") or {}
        content = other.get("content") or {}
        if other.get("type") == "ssvc":
            ssvc = {"timestamp": content.get("timestamp", "")}
            for option in content.get("options", []):
                for k, v in option.items():
                    internal = _SSVC_KEYS.get(k.strip().lower())
                    if internal:
                        ssvc[internal] = v.strip().lower()
            if "exploitation" in ssvc:
                ssvc["exploitation"] = normalize_exploitation(ssvc["exploitation"])
        elif other.get("type") == "kev":
            kev = content
    return cvss, ssvc, kev


def _affected(container: dict[str, Any], source: str) -> list[AffectedEntry]:
    out = []
    for a in container.get("affected", []) or []:
        out.append(
            AffectedEntry(
                vendor=(a.get("vendor") or "").strip(),
                product=(a.get("product") or "").strip(),
                versions=a.get("versions", []) or [],
                default_status=a.get("defaultStatus", "unknown"),
                cpes=a.get("cpes", []) or [],
                source=source,
            )
        )
    return out


def parse_record(record: dict[str, Any]) -> CveFacts:
    meta = record.get("cveMetadata", {})
    containers = record.get("containers", {})
    cna = containers.get("cna", {}) or {}
    adps = containers.get("adp", []) or []

    description = ""
    for d in cna.get("descriptions", []) or []:
        if str(d.get("lang", "")).lower().startswith("en"):
            description = d.get("value", "")
            break
    if not description and cna.get("descriptions"):
        description = cna["descriptions"][0].get("value", "")
    if not description:  # rejected records
        for d in cna.get("rejectedReasons", []) or []:
            description = d.get("value", "")

    cwes: list[str] = []
    for container in [cna, *adps]:
        for pt in container.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                cwe = d.get("cweId")
                if cwe and cwe not in cwes:
                    cwes.append(cwe)

    cvss, ssvc, kev = _metrics(cna, "cna")
    affected = _affected(cna, "cna")
    references = list(cna.get("references", []) or [])
    for adp in adps:
        short = (adp.get("providerMetadata") or {}).get("shortName", "adp")
        c, s, k = _metrics(adp, short)
        cvss.extend(c)
        ssvc = ssvc or s
        kev = kev or k
        affected.extend(_affected(adp, "adp"))
        references.extend(adp.get("references", []) or [])

    return CveFacts(
        cve_id=meta.get("cveId", ""),
        state=meta.get("state", "PUBLISHED"),
        published=meta.get("datePublished"),
        description=description.strip(),
        cwes=cwes,
        cvss=cvss,
        affected=affected,
        adp_ssvc=ssvc,
        adp_kev=kev,
        references=references,
    )
