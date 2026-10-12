# SPDX-License-Identifier: AGPL-3.0-only
"""The common data model shared by every vulnops stage.

  VulnRecord        everything known about one vulnerability (intel)
  AssetObservation  one sighting of an asset by one source (detect connectors)
  Asset             one consolidated asset of a client's inventory (assets)
  Finding           one asset affected by one vulnerability (detect, then re-keyed by assets)
  TriageRow         the decision on one finding (verdict)

Records, observations, assets and findings travel between stages as JSON files (vulnops.core.io); the
`to_dict` / `from_dict` helpers are the only (de)serialisation code, so a field added here
is added everywhere.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AffectedEntry:
    """One `affected` block of a CVE JSON 5 record (CNA or ADP container)."""

    vendor: str
    product: str
    versions: list[dict[str, Any]]
    default_status: str
    cpes: list[str]
    source: str  # "cna" or "adp"


@dataclass
class CvssMetric:
    version: str
    vector: str
    score: float | None
    severity: str | None
    source: str  # "cna" or the ADP short name


@dataclass
class VulnRecord:
    """Normalised view of one vulnerability, merged from all intelligence sources."""

    cve_id: str
    state: str
    published: str | None
    description: str
    cwes: list[str]
    cvss: list[CvssMetric]
    affected: list[AffectedEntry]
    adp_ssvc: dict[str, str] | None  # exploitation / automatable / technical_impact / timestamp
    adp_kev: dict[str, Any] | None
    references: list[dict[str, Any]]
    kev: dict[str, Any] | None = None  # entry of the CISA KEV catalogue, when listed
    epss: float | None = None
    epss_percentile: float | None = None
    gti: dict[str, Any] | None = None  # Google Threat Intelligence vulnerability view (intel.gti)

    @property
    def in_kev(self) -> bool:
        return self.kev is not None or self.adp_kev is not None

    def best_cvss(self) -> CvssMetric | None:
        """CNA metric first, newest CVSS version first."""
        if not self.cvss:
            return None
        order = {"4.0": 0, "3.1": 1, "3.0": 2}
        return sorted(self.cvss, key=lambda m: (m.source != "cna", order.get(m.version, 9)))[0]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VulnRecord:
        d = dict(d)
        d["cvss"] = [CvssMetric(**m) for m in d.get("cvss", [])]
        d["affected"] = [AffectedEntry(**a) for a in d.get("affected", [])]
        return cls(**d)


# Kept for readability in the record parser: a record built from a single CVE JSON 5 document.
CveFacts = VulnRecord


@dataclass
class DeclaredAsset:
    """An asset (or a product family) declared in a client profile.

    Exposure, criticality and owner are optional: what is not declared comes from the client's
    rules and default assumptions when the assets stage consolidates the inventory.
    """

    id: str
    description: str
    vendor: str
    product: str
    exposure: str | None = None  # internet | internal | isolated
    mission_prevalence: str | None = None  # minimal | support | essential
    public_wellbeing_impact: str | None = None  # minimal | material | irreversible
    owner: str | None = None
    vendor_aliases: list[str] = field(default_factory=list)
    product_aliases: list[str] = field(default_factory=list)
    cpe: str | None = None
    versions: list[str] = field(default_factory=list)


@dataclass
class AttributeRule:
    """Set asset attributes for hosts matching a hostname/FQDN glob or an address range."""

    set: dict[str, str]
    hostname: str | None = None
    fqdn: str | None = None
    ip: str | None = None  # CIDR
    description: str = ""


@dataclass
class ClientProfile:
    id: str
    name: str
    updated: str
    assets: list[DeclaredAsset]
    rules: list[AttributeRule] = field(default_factory=list)
    defaults: dict[str, str] = field(default_factory=dict)  # default assumptions per attribute
    source_path: str = ""
    alerts: dict[str, Any] = field(default_factory=dict)  # recipients, level, watchlist (watch mode)

    def declared(self, asset_id: str) -> DeclaredAsset:
        for a in self.assets:
            if a.id == asset_id:
                return a
        raise KeyError(f"{self.id}: unknown declared asset {asset_id!r}")


# -- asset inventory ---------------------------------------------------------------------------
ATTRIBUTES = ("exposure", "mission_prevalence", "public_wellbeing_impact", "owner")


@dataclass
class AssetObservation:
    """One sighting of an asset by one source (detection connectors -> assets stage)."""

    ref: str  # source-local reference: declared asset id, hostname, image name
    kind: str  # declared | host | image
    source: str  # inventory | trivy | dnf-updateinfo | ...
    observed_at: str
    name: str
    description: str = ""
    identifiers: dict[str, Any] = field(default_factory=dict)  # fqdn, hostname, ips[], image
    attributes: dict[str, str] = field(default_factory=dict)  # attributes seen by this source
    os: str | None = None


@dataclass
class Attribute:
    value: str
    source: str  # declared | rule | <scanner> | default
    note: str = ""

    @property
    def assumed(self) -> bool:
        return self.source == "default"


@dataclass
class Asset:
    """A consolidated asset of the client's inventory (produced by the assets stage)."""

    id: str  # stable: declared:<id> | host:<fqdn or hostname> | image:<ref>
    client_id: str
    kind: str
    name: str
    description: str
    identifiers: dict[str, Any]
    attributes: dict[str, Attribute]
    sources: list[str]
    first_seen: str
    last_seen: str
    os: str | None = None

    def attr(self, name: str) -> Attribute:
        return self.attributes[name]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Asset:
        d = dict(d)
        d["attributes"] = {k: Attribute(**v) for k, v in d["attributes"].items()}
        return cls(**d)


@dataclass
class Assessed:
    """A decision-point value together with where it came from."""

    value: str
    source: str  # kev | gti | cisa-adp | references | cvss-heuristic | llm | default | asset-profile
    note: str = ""


@dataclass
class Match:
    method: str  # exact | cpe | alias | fuzzy | llm
    vendor: str
    product: str
    score: float
    note: str = ""


@dataclass
class FindingObservation:
    """What one source said about one asset x vulnerability."""

    source: str
    observed_at: str
    match: Match
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    source_status: str = ""  # e.g. Trivy: fixed | affected | will_not_fix | end_of_life
    source_severity: str = ""
    cvss_vector: str = ""  # from the source (Trivy: NVD, then vendor), for CVE records without CVSS
    cvss_source: str = ""  # e.g. trivy:nvd


@dataclass
class Finding:
    """One asset affected (or possibly affected) by one vulnerability.

    In a detection file `asset_ref` is the source-local reference of an observation; after the
    assets stage it is the id of a consolidated asset. `status` uses VEX wording.
    """

    id: str
    client_id: str
    asset_ref: str
    cve_id: str
    status: str  # affected | under_investigation
    affected_versions: list[str]
    observations: list[FindingObservation]
    review_reasons: list[str] = field(default_factory=list)

    @staticmethod
    def make_id(client_id: str, asset_ref: str, cve_id: str) -> str:
        return f"{client_id}:{asset_ref}:{cve_id}"

    @property
    def sources(self) -> list[str]:
        return sorted({o.source for o in self.observations})

    @property
    def match(self) -> Match:
        return self.observations[0].match

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        d["observations"] = [FindingObservation(**{**o, "match": Match(**o["match"])}) for o in d["observations"]]
        return cls(**d)


@dataclass
class NotAffected:
    client_id: str
    cve_id: str
    asset_id: str
    deployed_versions: list[str]
    source: str = "inventory"


@dataclass
class TriageRow:
    client_id: str
    cve_id: str
    asset_id: str
    asset_description: str
    owner: str
    match: Match
    version_status: str  # affected | unknown
    affected_versions: list[str]
    exploitation: Assessed
    automatable: Assessed
    technical_impact: Assessed
    mission_wellbeing: Assessed
    publicly_exposed: bool
    in_kev: bool
    epss: float | None
    epss_percentile: float | None
    cvss: CvssMetric | None
    cwes: list[str]
    ssvc_decision: str  # track | track* | attend | act
    bod_timeline: str
    delivery_decision: str  # ACT | ATTEND | TRACK
    reasons: list[str]
    needs_review: bool
    review_reasons: list[str]
    description: str
    finding_id: str = ""
    finding_source: str = "inventory"
    asset_id_full: str = ""
    assumptions: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)  # "<package> <fixed version>" reported by scanners
    rationale: str = ""
    rationale_source: str = "template"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageRun:
    client: ClientProfile
    generated_at: str
    cve_count: int
    rows: list[TriageRow] = field(default_factory=list)
    not_affected: list[NotAffected] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    llm_model: str | None = None
