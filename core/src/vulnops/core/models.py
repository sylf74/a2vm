"""The common data model shared by every vulnops stage.

  VulnRecord   everything known about one vulnerability (produced by intel)
  Asset        one element of a client's estate (declared in the client profile, later also scanners)
  Finding      one asset affected by one vulnerability (produced by detect)
  TriageRow    the decision on one finding (produced by verdict)

Records and findings travel between stages as JSON files (see vulnops.core.io); the
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
class Asset:
    id: str
    description: str
    vendor: str
    product: str
    exposure: str  # internet | internal | isolated
    mission_prevalence: str  # minimal | support | essential
    public_wellbeing_impact: str  # minimal | material | irreversible
    owner: str
    vendor_aliases: list[str] = field(default_factory=list)
    product_aliases: list[str] = field(default_factory=list)
    cpe: str | None = None
    versions: list[str] = field(default_factory=list)


@dataclass
class ClientProfile:
    id: str
    name: str
    updated: str
    assets: list[Asset]
    source_path: str = ""

    def asset(self, asset_id: str) -> Asset:
        for a in self.assets:
            if a.id == asset_id:
                return a
        raise KeyError(f"{self.id}: unknown asset {asset_id!r}")


@dataclass
class Assessed:
    """A decision-point value together with where it came from."""

    value: str
    source: str  # kev | cisa-adp | references | cvss-heuristic | llm | default | asset-profile
    note: str = ""


@dataclass
class Match:
    method: str  # exact | cpe | alias | fuzzy | llm
    vendor: str
    product: str
    score: float
    note: str = ""


@dataclass
class Finding:
    """One asset affected (or possibly affected) by one vulnerability."""

    id: str  # stable: <client>:<asset>:<cve>
    client_id: str
    asset_id: str
    cve_id: str
    source: str  # inventory | trivy | tenable | ...
    match: Match
    version_status: str  # affected | unknown
    affected_versions: list[str]
    review_reasons: list[str] = field(default_factory=list)

    @staticmethod
    def make_id(client_id: str, asset_id: str, cve_id: str) -> str:
        return f"{client_id}:{asset_id}:{cve_id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        d["match"] = Match(**d["match"])
        return cls(**d)


@dataclass
class NotAffected:
    client_id: str
    cve_id: str
    asset_id: str
    deployed_versions: list[str]


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
