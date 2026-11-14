# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Applications matched against CVE records through the tenant's applications table (D20, v0.23.3).

The applications an EDR lists (SentinelOne, the Windows and macOS agents of Wazuh) are not packages
of a distribution: no advisory names them, only the CVE records do, by vendor and product (and
sometimes a CPE). Their names are free text ("Mozilla Firefox (x64 fr)", publisher "Mozilla"). So
each tenant keeps a table: one row per application, its name reduced to a key (versions,
architectures and languages left out), and the CPE vendor and product it is
(`cpe:2.3:a:mozilla:firefox`). The tenant's LLM proposes the CPE, an analyst validates, corrects or
rejects it (D11); without an LLM the rows wait for an analyst.

At each passage the watch reads the table and matches the applications of the hosts against the
affected blocks of each new record whose vendor and product (or CPE) are those of the row:

  validated row, version in an affected range       exposed
  validated row, version not decided by the record  possible
  proposed row (not validated yet), affected or not decided   possible, "mapping to validate"
  version out of every range, rejected row, new row  nothing

The rows of a table never decide a level: they say which product an application is. The versions of
the record and the SSVC tables decide (D4).

The firmware of an appliance or a network device (v0.23.6, `detect.firmware`) carries its CPE when
its family is known: no table then, the CPE is the product. Its level of proof is `embedded`: the
version is the one the device reports (SNMP) or the CMDB records, not a package an SSH collection
listed. The records name these products their own way (`Cisco IOS XE Software`, `Junos OS`), so a
block matches by its CPE, else by its vendor and by its product less the vendor and `Software`. A
vendor that lists its affected versions one by one (Cisco) says by that list which versions are
affected: a firmware version not in it is not affected.

  firmware with a CPE, version in an affected range or listed   embedded
  firmware with a CPE, version not decided by the record          possible, "version not decided"
  firmware without a CPE                                          through the table, embedded when validated

Owned by pillar 3, which defines the components of an asset (as `ngvm.packages`); used by pillar 1
(the watch, whose service keeps the table of the tenant). No LLM here except `propose`, whose answer
is a proposal only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any

from .llm import UNTRUSTED, LlmClient, LlmError
from .matching import cpe_vendor_product, norm
from .models import AffectedEntry, VulnRecord
from .packages import PACKAGE_TYPES, Exposure
from .versions import _cmp, evaluate, version_key

NEW, PROPOSED, VALIDATED, REJECTED = "new", "proposed", "validated", "rejected"
STATES = (NEW, PROPOSED, VALIDATED, REJECTED)
# The CPE of a row: part a (application) or o (operating system), vendor and product only.
CPE_ATOM = re.compile(r"^[a-z0-9][a-z0-9_.\-~!%+]{0,99}$")
CPE = re.compile(r"^cpe:2\.3:([ao]):([^:\s]+):([^:\s]+)(:.*)?$")
MAX_VERSIONS = 5  # versions kept per row, as examples for the analyst
MAX_ROWS = 20000

# What a name carries besides the product: versions, architectures, languages, editions of a build.
_PARENS = re.compile(r"\s*[\(\[][^\)\]]*[\)\]]")
_VERSION = re.compile(r"(?<![\w.])v?\d+(?:\.\d+){1,}(?:[-.+]?[a-z0-9]+)*(?![\w.])", re.I)
_TRAIL = re.compile(r"[\s\-–:,]+$")
_ARCH = re.compile(r"\b(?:x64|x86|x86_64|amd64|arm64|64-bit|32-bit|64 bit|32 bit|win64|win32)\b", re.I)
_LANG = re.compile(r"\b[a-z]{2}-[a-z]{2}\b", re.I)
_UPDATE = re.compile(r"\b(?:update|build|patch|sp)\s*\d+\b", re.I)  # Java 8 Update 381
_COMPANY = re.compile(
    r"[,\s]+(?:inc|incorporated|corp|corporation|co|company|llc|ltd|limited|gmbh|ag|sa|s\.a|sas|bv|b\.v|plc|"
    r"srl|ab|oy|kg|pty)\.?$",
    re.I,
)


def name_key(name: str) -> str:
    """The product part of an application name: `Mozilla Firefox (x64 fr)` -> `mozilla firefox`,
    `7-Zip 23.01 (x64)` -> `7-zip`; a year (`2015-2022`) stays."""
    text = _PARENS.sub(" ", name)
    text = _VERSION.sub(" ", text)
    text = _ARCH.sub(" ", text)
    text = _LANG.sub(" ", text)
    text = _UPDATE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return _TRAIL.sub("", text).lower()


def vendor_key(vendor: str) -> str:
    """A publisher without its company form: `Google LLC` -> `google`, `Microsoft Corporation` -> `microsoft`."""
    text = re.sub(r"\s+", " ", vendor.strip())
    for _ in range(2):
        text = _COMPANY.sub("", text)
    return text.strip(" ,.").lower()


def app_key(vendor: str, name: str) -> str:
    """The identity of an application in the table: `<publisher>|<product>`."""
    return f"{vendor_key(vendor)}|{name_key(name)}"


# Components matched elsewhere (v0.23.11): the libraries of a language ecosystem (a purl, OSV) and
# the libraries a process still runs from a deleted file (a restart, not a product).
NOT_APPLICATIONS = {"library", "in-memory"}


def is_application(component: dict[str, Any]) -> bool:
    """A component that is not a package of a distribution (matched by `ngvm.packages`) nor a library
    of a language ecosystem (matched by OSV, v0.23.11)."""
    kind = component.get("type", "rpm")
    return kind not in PACKAGE_TYPES and kind not in NOT_APPLICATIONS and bool(name_key(component.get("name", "")))


def cpe_base(value: str) -> str:
    """`cpe:2.3:a:<vendor>:<product>` from a CPE (any further field dropped), or "" when it is not one."""
    m = CPE.match(value.strip().lower())
    if not m or not (CPE_ATOM.match(m[2]) and CPE_ATOM.match(m[3])):
        return ""
    return f"cpe:2.3:{m[1]}:{m[2]}:{m[3]}"


# -- the table --------------------------------------------------------------------------------------
@dataclass
class Row:
    """One application of the tenant and the product it is."""

    key: str
    vendor: str  # the publisher as an EDR gives it (first seen)
    name: str  # a name as an EDR gives it (first seen)
    state: str = NEW
    cpe: str = ""  # validated: cpe:2.3:a:<vendor>:<product>
    proposal: dict[str, str] | None = None  # {cpe, justification, by, at}: "" cpe = not a product of CVE records
    decided_by: str = ""
    decided_at: str = ""
    note: str = ""  # the validator's reason (a rejection, a correction)
    hosts: int = 0  # hosts that carry it in the last inventory
    versions: list[str] | None = None
    sources: list[str] | None = None
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "", [])} | {"state": self.state}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Row:
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        row = cls(**known)
        if row.state not in STATES:
            raise ValueError(f"application {row.key!r}: unknown state {row.state!r}")
        return row

    def product(self) -> str:
        """The CPE that names the product: the validated one, else the proposal still to validate."""
        if self.state == VALIDATED:
            return self.cpe
        if self.state == PROPOSED and self.proposal:
            return self.proposal.get("cpe", "")
        return ""


def load_table(data: Any) -> dict[str, Row]:
    """The table from its JSON form ({"applications": [...]}), or from a list of rows."""
    rows = data.get("applications", []) if isinstance(data, dict) else (data or [])
    out = {}
    for item in rows:
        row = Row.from_dict(item)
        out[row.key] = row
    return out


def dump_table(table: dict[str, Row]) -> dict[str, Any]:
    return {"schema": "ngvm.applications/1", "applications": [table[k].to_dict() for k in sorted(table)]}


def from_declarations(entries: list[dict[str, Any]]) -> dict[str, Row]:
    """A table written by hand (`applications.yaml` of a tenant project in the GitLab mode): each
    entry `{vendor, name, cpe}` is validated by the merge request that added it."""
    out = {}
    for i, e in enumerate(entries or []):
        if not isinstance(e, dict) or not e.get("name"):
            raise ValueError(f"applications[{i}]: `name` is required")
        cpe = cpe_base(str(e.get("cpe") or ""))
        if e.get("cpe") and not cpe:
            raise ValueError(f"applications[{i}]: `cpe` is not cpe:2.3:a:<vendor>:<product>")
        key = app_key(str(e.get("vendor") or ""), str(e["name"]))
        out[key] = Row(
            key, str(e.get("vendor") or ""), str(e["name"]), VALIDATED if cpe else REJECTED, cpe,
            decided_by="tenant project", note=str(e.get("note") or ""),
        )  # fmt: skip
    return out


def candidates(assets: list[Any]) -> dict[str, dict[str, Any]]:
    """The applications of an inventory (assets with `components`), by key: {vendor, name, hosts,
    versions, sources}."""
    out: dict[str, dict[str, Any]] = {}
    for n, asset in enumerate(assets):
        components = asset.get("components") if isinstance(asset, dict) else getattr(asset, "components", None)
        for c in components or []:
            if not is_application(c):
                continue
            key = app_key(c.get("vendor", ""), c["name"])
            item = out.setdefault(key, {"vendor": c.get("vendor", ""), "name": c["name"]})
            for name in ("hosts", "versions", "sources"):
                item.setdefault(name, set())
            item["hosts"].add(n)
            item["versions"].add(c.get("version", ""))
            item["sources"].add(c.get("source", ""))
    return out


def merge(table: dict[str, Row], found: dict[str, dict[str, Any]], at: str) -> tuple[dict[str, Row], int]:
    """The table with the applications of a new inventory: a new key is a new row; a known one gets
    its counts; a row no longer seen keeps its decision (0 hosts). Returns (table, rows added)."""
    added = 0
    for row in table.values():
        row.hosts = 0
    for key, item in sorted(found.items()):
        if key not in table:
            if len(table) >= MAX_ROWS:
                continue
            table[key] = Row(key, item["vendor"], item["name"], first_seen=at)
            added += 1
        row = table[key]
        row.hosts = len(item["hosts"])
        row.versions = sorted({*(row.versions or []), *(v for v in item["versions"] if v)})[-MAX_VERSIONS:]
        row.sources = sorted({*(row.sources or []), *(s for s in item["sources"] if s)})
        row.last_seen = at
    return table, added


def apply_proposals(table: dict[str, Row], proposals: list[dict[str, Any]], at: str) -> int:
    """The LLM's proposals into the rows still `new` (a decision of an analyst is never touched).
    Returns how many rows were proposed."""
    count = 0
    for p in proposals:
        row = table.get(str(p.get("key") or ""))
        if row is None or row.state != NEW:
            continue
        cpe = cpe_base(str(p.get("cpe") or ""))
        if p.get("cpe") and not cpe:
            continue  # a malformed CPE is no proposal
        row.state = PROPOSED
        row.proposal = {
            "cpe": cpe,
            "justification": str(p.get("justification") or "")[:400],
            "by": str(p.get("by") or "llm")[:100],
            "at": at,
        }
        count += 1
    return count


def decide(table: dict[str, Row], key: str, action: str, by: str, at: str, cpe: str = "", note: str = "") -> Row:
    """A validator's decision on a row: validate (with the CPE given, else the proposal's), reject,
    or reset to new."""
    row = table.get(key)
    if row is None:
        raise KeyError(key)
    if action == "validate":
        chosen = cpe_base(cpe) if cpe else cpe_base((row.proposal or {}).get("cpe", ""))
        if not chosen:
            raise ValueError("a CPE cpe:2.3:a:<vendor>:<product> is needed to validate")
        row.state, row.cpe = VALIDATED, chosen
    elif action == "reject":
        row.state, row.cpe = REJECTED, ""
    elif action == "reset":
        row.state, row.cpe, row.proposal = NEW, "", None
    else:
        raise ValueError(f"unknown action {action!r} (validate, reject, reset)")
    row.decided_by, row.decided_at, row.note = by, at, note[:400]
    return row


# -- the LLM's proposals ----------------------------------------------------------------------------
PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["applications"],
    "properties": {
        "applications": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "cpe_vendor", "cpe_product", "justification"],
                "properties": {
                    "id": {"type": "integer"},
                    "cpe_vendor": {"type": "string", "maxLength": 100},
                    "cpe_product": {"type": "string", "maxLength": 100},
                    "justification": {"type": "string", "maxLength": 300},
                },
            },
        }
    },
}

_PROPOSE_SYSTEM = f"""You map software installed on computers to the CPE 2.3 vendor and product names
of the NVD dictionary, as CVE records use them (e.g. Mozilla Firefox -> mozilla firefox, Google Chrome
-> google chrome, 7-Zip -> 7-zip 7-zip, Notepad++ -> notepad-plus-plus notepad\\+\\+). Lower case, words
joined by underscores as in the dictionary. Different editions with their own CPE product keep it
(firefox_esr). For a driver, a runtime component, an update package or anything you do not know as a
product of CVE records, answer an empty vendor and product. Never guess a vendor you do not know.
{UNTRUSTED}
Justification in English, one sentence."""


def propose(llm: LlmClient, rows: list[Row], by: str = "llm") -> tuple[list[dict[str, Any]], str]:
    """Ask the LLM for the CPE of rows (at most 20 at a time). Returns (proposals, error): a proposal
    {key, cpe, justification, by}, cpe "" when the LLM sees no product; the rows of a failed call
    stay new for the next passage."""
    out: list[dict[str, Any]] = []
    for start in range(0, len(rows), 20):
        batch = rows[start : start + 20]
        listing = [{"id": i, "publisher": r.vendor[:120], "name": r.name[:200]} for i, r in enumerate(batch)]
        user = f"Applications:\n<untrusted>\n{json.dumps(listing, ensure_ascii=False)}\n</untrusted>"
        try:
            data = llm.structured(_PROPOSE_SYSTEM, user, "application_cpes", PROPOSAL_SCHEMA)
        except LlmError as exc:
            return out, str(exc)
        for item in data.get("applications", []):
            i = item.get("id")
            if not isinstance(i, int) or not 0 <= i < len(batch):
                continue
            vendor = re.sub(r"\s+", "_", str(item.get("cpe_vendor") or "").strip().lower())
            product = re.sub(r"\s+", "_", str(item.get("cpe_product") or "").strip().lower())
            cpe = f"cpe:2.3:a:{vendor}:{product}" if vendor and product else ""
            if cpe and not cpe_base(cpe):
                continue
            out.append({"key": batch[i].key, "cpe": cpe, "justification": item.get("justification", ""), "by": by})
    return out, ""


# -- matching ---------------------------------------------------------------------------------------
def _entries_of(cpe: str, record: VulnRecord) -> list[AffectedEntry]:
    """The affected blocks of a record that name the product of a CPE: by a CPE of the block, else by
    its vendor and product."""
    parts = cpe_vendor_product(cpe)
    if parts is None:
        return []
    vendor, product = parts
    out = []
    for e in record.affected:
        by_cpe = any(cpe_vendor_product(c) == parts for c in e.cpes)
        if by_cpe or (norm(e.vendor), norm(e.product)) == (vendor, product):
            out.append(e)
    return out


def _firmware_entries(cpe: str, product: str, record: VulnRecord) -> list[AffectedEntry]:
    """The affected blocks of a record that name a firmware: by a CPE, else by vendor and product,
    the product less its vendor and `Software` (`Cisco IOS XE Software` -> `iosxe`)."""
    parts = cpe_vendor_product(cpe)
    if parts is None:
        return []
    vendor, cpe_product = parts
    wanted = {cpe_product, norm(product)}
    out = []
    for e in record.affected:
        if any(cpe_vendor_product(c) == parts for c in e.cpes):
            out.append(e)
            continue
        ev = norm(e.vendor)
        if not ev or not (ev.startswith(vendor) or vendor.startswith(ev)):
            continue
        name = norm(e.product)
        for prefix in (ev, vendor):
            name = name.removeprefix(prefix) if name != prefix else name
        name = name.removesuffix("software") or name
        if name in wanted:
            out.append(e)
    return out


def _listed(entry: AffectedEntry) -> AffectedEntry:
    """A CNA block that lists its affected versions one by one, without a default status: the vendor's
    list, a version not in it is not affected (Cisco)."""
    exact = all(v.get("lessThan") is None and v.get("lessThanOrEqual") is None for v in entry.versions)
    if entry.source == "cna" and entry.versions and exact and not entry.default_status:
        return replace(entry, default_status="unaffected")
    return entry


def firmware_matches(record: VulnRecord, components: list[dict[str, Any]]) -> list[Hit]:
    """The firmware of a device concerned by a record, by its CPE (see the module)."""
    out: list[Hit] = []
    for c in components:
        cpe = cpe_base(c.get("cpe", ""))
        if c.get("type") != "firmware" or not cpe:
            continue
        entries = [_listed(e) for e in _firmware_entries(cpe, c.get("name", ""), record)]
        if not entries:
            continue
        status = evaluate(c.get("version", ""), entries)
        if status == "unaffected":
            continue
        fixed = _fixed(c.get("version", ""), entries) if status == "affected" else ""
        exposure = Exposure(
            cve=record.cve_id, component=f"{c.get('vendor', '')} {c['name']}".strip(), version=c.get("version", ""),
            source_package=cpe, fixed=fixed,
            state=("fixed" if fixed else "affected") if status == "affected" else "investigating",
            advisory=cpe, url="", source=c.get("source", ""), seen=c.get("seen", ""), origin="firmware",
        )  # fmt: skip
        if status == "affected":
            out.append(Hit(exposure, "embedded", ""))
        else:
            out.append(Hit(exposure, "possible", "version not decided"))
    return out


def _fixed(version: str, entries: list[AffectedEntry]) -> str:
    """The lowest upper bound of an affected range above the version, as the fixed version."""
    bounds = [
        str(v["lessThan"])
        for e in entries
        for v in e.versions
        if v.get("lessThan") and v.get("status", "affected") == "affected" and _cmp(version, str(v["lessThan"])) < 0
    ]
    return min(bounds, key=version_key) if bounds else ""


@dataclass
class Hit:
    """One application of a host in a record's affected range, or possibly there."""

    exposure: Exposure
    proof: str  # exposed | embedded (firmware, v0.23.6) | possible
    reason: str  # why possible: "version not decided", "mapping to validate"


def matches(record: VulnRecord, components: list[dict[str, Any]], table: dict[str, Row]) -> list[Hit]:
    """The applications of a host concerned by a record, through the table, and its firmware by its CPE
    (see the module)."""
    out: list[Hit] = firmware_matches(record, components)
    for c in components:
        if not is_application(c) or (c.get("type") == "firmware" and cpe_base(c.get("cpe", ""))):
            continue
        row = table.get(app_key(c.get("vendor", ""), c["name"]))
        cpe = row.product() if row else ""
        if not cpe:
            continue
        entries = _entries_of(cpe, record)
        if not entries:
            continue
        status = evaluate(c.get("version", ""), entries)
        if status == "unaffected":
            continue
        fixed = _fixed(c.get("version", ""), entries) if status == "affected" else ""
        exposure = Exposure(
            cve=record.cve_id, component=c["name"], version=c.get("version", ""), source_package=cpe,
            fixed=fixed, state=("fixed" if fixed else "affected") if status == "affected" else "investigating",
            advisory=cpe, url="",
            source=c.get("source", ""), seen=c.get("seen", ""), origin="cve-record",
        )  # fmt: skip
        if row.state == PROPOSED:
            out.append(Hit(exposure, "possible", "mapping to validate"))
        elif status == "affected":
            out.append(Hit(exposure, "embedded" if c.get("type") == "firmware" else "exposed", ""))
        else:
            out.append(Hit(exposure, "possible", "version not decided"))
    return out
