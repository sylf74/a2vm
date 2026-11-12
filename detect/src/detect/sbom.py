# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Software bills of materials: the libraries of an image or an application (v0.23.11, HLD D20).

Two ways in, one model out: a component of type `library` with its `purl`
(`pkg:pypi/jinja2@3.1.2`), matched every day against OSV (`detect.osv`) without touching the
host again.

- Trivy, scanning an image, lists every package it found (`--list-all-pkgs`): the image's
  observation keeps them, with the image's digest.
- An SBOM a client or a build pipeline gives (CycloneDX or SPDX, JSON): the connector `sbom` of a
  collector reads the files of a directory, one asset per file.

The packages of a distribution (`pkg:rpm`, `pkg:deb`, `pkg:apk`) are left to the advisories of the
distributions (`a2vm.packages`): only the language ecosystems are kept here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from a2vm.io import Detection, now
from a2vm.models import AssetObservation

SOURCE = "sbom"
DISTRO_PURLS = ("rpm", "deb", "apk", "alpm")
MAX_LIBRARIES = 20000
PURL = re.compile(r"^pkg:(?P<type>[a-z0-9.+-]+)/(?P<rest>[^@?#]+)@(?P<version>[^?#]+)")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,252}$")


def library(name: str, version: str, purl: str, source: str) -> dict[str, str] | None:
    """One library as a component, or None for a package of a distribution or without a usable purl."""
    m = PURL.match(purl or "")
    if not m or m["type"] in DISTRO_PURLS:
        return None
    return {"name": name or m["rest"].rsplit("/", 1)[-1], "version": version or m["version"], "type": "library",
            "purl": purl.split("#", 1)[0], "source": source}  # fmt: skip


def trivy_libraries(data: dict[str, Any]) -> list[dict[str, str]]:
    """The libraries Trivy listed in an image (`--list-all-pkgs`)."""
    out: dict[str, dict[str, str]] = {}
    for result in data.get("Results") or []:
        for p in result.get("Packages") or []:
            purl = ((p.get("Identifier") or {}).get("PURL")) or ""
            c = library(p.get("Name", ""), p.get("Version", ""), purl, "trivy")
            if c:
                out[c["purl"]] = c
    return [out[k] for k in sorted(out)][:MAX_LIBRARIES]


def image_digest(data: dict[str, Any]) -> str:
    meta = data.get("Metadata") or {}
    digests = meta.get("RepoDigests") or []
    return str(digests[0] if digests else meta.get("ImageID") or "")[:200]


# -- SBOM files ------------------------------------------------------------------------------------
def _cyclonedx(doc: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    found: list[dict[str, str]] = []

    def walk(items: list[dict[str, Any]]) -> None:
        for c in items or []:
            lib = library(c.get("name", ""), c.get("version", ""), c.get("purl", ""), SOURCE)
            if lib:
                found.append(lib)
            walk(c.get("components") or [])

    walk(doc.get("components") or [])
    subject = ((doc.get("metadata") or {}).get("component") or {}).get("name", "")
    return str(subject), found


def _spdx(doc: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    found = []
    for p in doc.get("packages") or []:
        purl = next((r.get("referenceLocator", "") for r in p.get("externalRefs") or []
                     if r.get("referenceType") == "purl"), "")  # fmt: skip
        lib = library(p.get("name", ""), p.get("versionInfo", ""), purl, SOURCE)
        if lib:
            found.append(lib)
    return str(doc.get("name", "")), found


def parse_sbom(doc: dict[str, Any]) -> tuple[str, str, list[dict[str, str]]]:
    """(format, subject's name, libraries) of a CycloneDX or SPDX JSON document."""
    if doc.get("bomFormat") == "CycloneDX":
        name, libs = _cyclonedx(doc)
        fmt = "cyclonedx"
    elif str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        name, libs = _spdx(doc)
        fmt = "spdx"
    else:
        raise ValueError("neither CycloneDX nor SPDX (JSON)")
    unique = {c["purl"]: c for c in libs}
    return fmt, name, [unique[k] for k in sorted(unique)][:MAX_LIBRARIES]


@dataclass
class SbomConfig:
    """Settings of an `sbom` connector: the SBOM files of a directory, one asset per file.

    `assets` names the asset of a file (`{file: app.cdx.json, kind: image, name: registry/app:1.4}`
    or `{file: web.spdx.json, kind: host, name: web01}`); a file not named there takes the subject
    the SBOM gives (CycloneDX `metadata.component.name`, SPDX `name`), as an image (an artifact)."""

    directory: str
    assets: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "sbom") -> SbomConfig:
        unknown = set(data) - {"directory", "assets", "name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        if not data.get("directory"):
            raise ValueError(f"{where}: `directory` is required")
        assets = []
        for a in data.get("assets") or []:
            if not isinstance(a, dict) or not a.get("file") or a.get("kind", "image") not in ("host", "image"):
                raise ValueError(f"{where}: each asset is {{file, kind: host|image, name}}")
            assets.append({k: str(v) for k, v in a.items()})
        return cls(str(data["directory"]), assets)


def read(cfg: SbomConfig, tenant: str, log=print) -> Detection:  # noqa: ANN001
    """Every SBOM of the directory as an observation with its libraries (no finding: OSV matches)."""
    named = {a["file"]: a for a in cfg.assets}
    observations, skipped = [], {}
    directory = Path(cfg.directory)
    files = sorted(p for p in directory.glob("*.json") if p.is_file()) if directory.is_dir() else []
    if not directory.is_dir():
        raise ValueError(f"sbom: {directory} is not a directory")
    observed_at = now()
    for path in files:
        try:
            fmt, subject, libs = parse_sbom(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            skipped[f"{path.name}: {exc}"[:120]] = 1
            continue
        entry = named.get(path.name, {})
        kind = entry.get("kind", "image")
        name = entry.get("name") or subject or path.stem
        if not NAME.match(name):
            skipped[f"{path.name}: no usable name"] = 1
            continue
        identifiers: dict[str, Any] = {}
        if kind == "host":
            identifiers["hostname"] = name.split(".")[0].lower()
        elif kind == "image":
            identifiers["image"] = name
        observations.append(AssetObservation(
            ref=f"{kind}:{name}", kind=kind,
            source=SOURCE, observed_at=observed_at, name=name, description=f"SBOM {fmt} ({path.name})",
            identifiers=identifiers, attributes={"sbom_file": path.name, "sbom_format": fmt}, os=None,
            components=libs,
        ))  # fmt: skip
    libraries = sum(len(o.components) for o in observations)
    log(f"sbom: {len(files)} files, {len(observations)} assets, {libraries} libraries")
    return Detection(tenant, SOURCE, observations, [], skipped=skipped)
