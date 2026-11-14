# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The client's last asset inventory, as built by the daily pipeline, for the watch.

The watch runs every 10 minutes and only knows what the profile declares; the daily pipeline
knows what is actually installed and where (assets.json, findings.json of verdict assets). The
daily `triage` job leaves a copy in the runner cache (key `inventory`), which the watch restores;
without it, the watch reads the artifacts of the project's last `triage` job. So an alert on a
CVE already found on the client's machines names those machines, with the installed and fixed
versions, the exposure and the owner. Only the exchange files of the common
contract are read: VIA imports no other pillar.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ngvm import applications as apps
from ngvm.gitlab import GitLabError, download_artifacts
from ngvm.io import WATCH_FINDINGS, ExchangeError, read_assets, read_findings, validate_watch_findings
from ngvm.models import Asset, Finding, FindingObservation, Match

MAX_AGE_DAYS = 8


@dataclass
class Inventory:
    client_id: str
    assets: dict[str, Asset]
    findings_by_cve: dict[str, list[Finding]] = field(default_factory=dict)
    as_of: str = ""  # date of the most recent observation
    # The tenant's applications table (v0.23.3): the CPE of each application of an EDR.
    applications: dict[str, apps.Row] = field(default_factory=dict)

    def age_days(self, now: dt.datetime | None = None) -> float | None:
        if not self.as_of:
            return None
        seen = dt.datetime.fromisoformat(self.as_of)
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=dt.UTC)
        return ((now or dt.datetime.now(dt.UTC)) - seen).total_seconds() / 86400


def load(directory: str | Path, client_id: str) -> Inventory | None:
    """<directory>/<client>/assets.json and findings.json, or None when absent."""
    base = Path(directory) / client_id
    if not (base / "assets.json").exists():
        return None
    owner, assets = read_assets(base / "assets.json")
    if owner != client_id:
        raise ExchangeError(f"{base}/assets.json belongs to {owner!r}, not {client_id!r}")
    findings: dict[str, list[Finding]] = {}
    compact = base / WATCH_FINDINGS_FILE
    if compact.exists():  # what the watch service keeps since v0.23.19
        doc = json.loads(compact.read_text(encoding="utf-8"))
        validate_watch_findings(doc, str(compact))
        if doc["client_id"] != client_id:
            raise ExchangeError(f"{compact} belongs to {doc['client_id']!r}, not {client_id!r}")
        as_of = max((a.last_seen for a in assets.values()), default="")
        return Inventory(client_id, assets, _expand(doc, as_of), as_of)
    if (base / "findings.json").exists():
        _, found, _ = read_findings(base / "findings.json")
        for f in found:
            findings.setdefault(f.cve_id, []).append(f)
    as_of = max((a.last_seen for a in assets.values()), default="")
    return Inventory(client_id, assets, findings, as_of)


def fetch(
    project: str | int,
    client_id: str,
    dest: str | Path,
    ref: str = "main",
    job: str = "triage",
    environ: Mapping[str, str] | None = None,
    transport=None,
) -> tuple[Inventory | None, str]:
    """Download and load the last inventory of `client_id`; (inventory, note for the log)."""
    try:
        download_artifacts(project, job, "work/assets", dest, ref=ref, environ=environ, transport=transport)
        inv = load(dest, client_id)
    except (GitLabError, ExchangeError, OSError, ValueError) as exc:
        return None, f"inventory not available ({exc}): declared assets only"
    if inv is None:
        return None, f"no inventory of {client_id} in the last {job!r} artifacts: declared assets only"
    return inv, describe(inv)


WATCH_FINDINGS_FILE = "watch-findings.json"


def for_watch(assets: dict[str, Any], findings: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The inventory as the watch reads it: the assets without their scan dates (v0.23.18), and the
    findings in the compact `ngvm.watch_findings/1` (v0.23.19). Per asset, each finding as
    [cve, status, affected versions, [[source, package, installed, fixed], ...]]: what the alert sheet
    shows, nothing else. 26,000 findings went from 75 MB in `vulnops.findings/2` to a few MB. The
    daily run's own files are left as they are."""
    slim_assets = {**assets, "assets": [{k: v for k, v in a.items() if k != "scans"} for a in assets.get("assets", [])]}
    by_asset: dict[str, list[list[Any]]] = {}
    for f in findings.get("findings", []):
        seen = []
        for o in f.get("observations", []):
            row = [
                o.get("source", ""),
                o.get("package", ""),
                o.get("installed_version", ""),
                o.get("fixed_version", ""),
            ]
            if row not in seen:
                seen.append(row)
        by_asset.setdefault(f["asset_ref"], []).append(
            [f["cve_id"], f.get("status", "affected"), list(f.get("affected_versions") or []), seen]
        )
    compact = {
        "schema": WATCH_FINDINGS,
        "generated_at": findings.get("generated_at", ""),
        "client_id": findings.get("client_id", ""),
        "assets": by_asset,
    }
    return slim_assets, compact


def _expand(doc: dict[str, Any], observed_at: str) -> dict[str, list[Finding]]:
    """`ngvm.watch_findings/1` back into the findings the watch matches, by CVE."""
    out: dict[str, list[Finding]] = {}
    client = doc["client_id"]
    for asset, rows in doc["assets"].items():
        for cve, status, versions, seen in rows:
            observations = [
                FindingObservation(source, observed_at, Match("scanner", "", package, 1.0), package, installed, fixed)
                for source, package, installed, fixed in seen
            ]
            finding = Finding(Finding.make_id(client, asset, cve), client, asset, cve, status, versions, observations)
            out.setdefault(cve, []).append(finding)
    return out


def describe(inv: Inventory) -> str:
    """One line for the job log: date, size, and a warning when the inventory is old."""
    age = inv.age_days()
    count = sum(map(len, inv.findings_by_cve.values()))
    note = f"inventory of {inv.as_of[:10]}: {len(inv.assets)} assets, {count} findings"
    listed = sum(1 for a in inv.assets.values() if a.components)
    if listed:  # matched against the package advisories of each new record (D20, v0.23.0)
        note += f", packages listed on {listed} hosts"
    if inv.applications:  # the applications of an EDR, through the table (v0.23.3)
        valid = sum(r.state == apps.VALIDATED for r in inv.applications.values())
        proposed = sum(r.state == apps.PROPOSED for r in inv.applications.values())
        note += f", applications table {valid} validated, {proposed} to validate"
    if age is not None and age > MAX_AGE_DAYS:
        note += f" (WARN {age:.0f} days old)"
    return note
