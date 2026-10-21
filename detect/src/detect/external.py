# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Bring the client's external detection into its internal run.

The external scan runs in a collection-only project (`<client>-external`); its `collect` job keeps
work/detect/<external client>/*.json as artifacts. This module downloads the latest of them,
checks they belong to the external client the profile names and are recent enough, and rewrites
them as one detection of the internal client, source `external-scan`. The assets stage then maps
each external host to an internal asset through the profile's `published` section.
"""

from __future__ import annotations

import datetime as dt
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from a2vm.gitlab import GitLabError, download_artifacts
from a2vm.io import Detection, ExchangeError, read_detection
from a2vm.models import ClientProfile, Finding

SOURCE = "external-scan"


@dataclass
class ExternalResult:
    detection: Detection | None
    notes: list[str] = field(default_factory=list)  # what was read
    problems: list[str] = field(default_factory=list)  # why something was left out (warning)


def _age_days(observed_at: str, now: dt.datetime) -> float:
    seen = dt.datetime.fromisoformat(observed_at)
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=dt.UTC)
    return (now - seen).total_seconds() / 86400


def as_internal(profile: ClientProfile, detections: list[Detection], now: dt.datetime | None = None) -> ExternalResult:
    """Check the external detections and rewrite the accepted ones as one detection of `profile`."""
    ext = profile.external
    if ext is None:
        return ExternalResult(None, problems=[f"{profile.id}: no `external` section in the profile"])
    now = now or dt.datetime.now(dt.UTC)
    result = ExternalResult(Detection(profile.id, SOURCE, [], []))
    for d in detections:
        if d.client_id != ext.client:
            result.problems.append(f"{d.source}: detection of {d.client_id!r}, expected {ext.client!r}: ignored")
            continue
        dates = [o.observed_at for o in d.observations]
        if not dates:
            result.notes.append(f"{d.source}: no host observed")
            continue
        age = _age_days(max(dates), now)
        if age > ext.max_age_days:
            result.problems.append(
                f"{d.source}: external scan of {max(dates)[:10]}, {age:.0f} days old (max {ext.max_age_days}): ignored"
            )
            continue
        result.detection.observations += [replace(o, source=SOURCE) for o in d.observations]
        for f in d.findings:
            result.detection.findings.append(
                Finding(
                    id=Finding.make_id(profile.id, f.asset_ref, f.cve_id),
                    client_id=profile.id,
                    asset_ref=f.asset_ref,
                    cve_id=f.cve_id,
                    status=f.status,
                    affected_versions=list(f.affected_versions),
                    observations=[replace(o, source=SOURCE) for o in f.observations],
                    review_reasons=list(f.review_reasons),
                )
            )
        result.notes.append(
            f"{d.source}: {len(d.observations)} hosts, {len(d.findings)} findings, scanned {max(dates)[:16]}Z"
        )
    if not result.detection.observations:
        result.detection = None
    return result


def pull(
    profile: ClientProfile,
    project: str,
    ref: str = "main",
    job: str = "collect",
    environ: Mapping[str, str] | None = None,
    transport=None,
) -> ExternalResult:
    """Download the external project's latest detection and check it (see `as_internal`)."""
    if profile.external is None:
        return ExternalResult(None, problems=[f"{profile.id}: no `external` section in the profile"])
    with tempfile.TemporaryDirectory() as tmp:
        try:
            files = download_artifacts(
                project,
                job,
                f"work/detect/{profile.external.client}",
                tmp,
                ref=ref,
                environ=environ,
                transport=transport,
            )
        except GitLabError as exc:
            return ExternalResult(None, problems=[str(exc)])
        detections, problems = [], []
        for path in files:
            if path.suffix != ".json":
                continue
            try:
                detections.append(read_detection(path))
            except (ExchangeError, OSError, ValueError) as exc:
                problems.append(f"{path.name}: unreadable: {exc}")
    if not files:
        problems.append(f"{project}: no detection of {profile.external.client!r} in the latest {job!r} artifacts")
    result = as_internal(profile, detections)
    result.problems = problems + result.problems
    return result
