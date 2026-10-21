# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Read the job artifacts of a GitLab project (the external detection, the last daily inventory).

Two ways to authenticate, the first available wins:

- A2VM_GITLAB_TOKEN (a project access token of the source project, role Reporter, scope read_api):
  the latest successful job of that name is looked up among the project's jobs, whatever the
  pipeline it ran in. Works on every GitLab edition. Use it when the source project also runs
  other pipelines on the same branch (a watch every 10 minutes, a push), or on GitLab CE, where
  the job token may not read another project's artifacts.
- The job token (CI_JOB_TOKEN): GitLab answers with the job of that name in the latest successful
  pipeline of the branch, and nothing when that pipeline has no such job. The source project must
  allow the reading project in Settings > CI/CD > Job token permissions.
 The API is reached at A2VM_SERVER_URL/api/v4 when the runner uses another URL than the
one GitLab advertises, else at CI_API_V4_URL. The private CA and the client certificate that the
runner hands to the job are honoured.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from .config import env

MAX_ARTIFACT_BYTES = 200 * 1024 * 1024


class GitLabError(RuntimeError):
    """The artifacts could not be read (configuration, access, transport)."""


class ArtifactNotFound(GitLabError):
    """No successful job of that name on that ref, or its artifacts have expired."""


def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    import os

    return os.environ if environ is None else environ


def api_base(environ: Mapping[str, str] | None = None) -> str:
    source = _environ(environ)
    server = env("SERVER_URL", environ=source)
    if server:
        return server.rstrip("/") + "/api/v4"
    if source.get("CI_API_V4_URL"):
        return source["CI_API_V4_URL"].rstrip("/")
    raise GitLabError("GitLab API unknown: run in a pipeline (CI_API_V4_URL) or set A2VM_SERVER_URL")


def _client_options(environ: Mapping[str, str]) -> dict:
    headers = {}
    if env("GITLAB_TOKEN", environ=environ):
        headers["PRIVATE-TOKEN"] = env("GITLAB_TOKEN", environ=environ)
    elif environ.get("CI_JOB_TOKEN"):
        headers["JOB-TOKEN"] = environ["CI_JOB_TOKEN"]
    else:
        raise GitLabError("no GitLab credentials: CI_JOB_TOKEN (pipeline) or A2VM_GITLAB_TOKEN")
    options: dict = {"headers": headers, "timeout": 60, "follow_redirects": True}
    ca = environ.get("CI_SERVER_TLS_CA_FILE")
    if ca:
        options["verify"] = ca
    cert, key = environ.get("CI_SERVER_TLS_CERT_FILE"), environ.get("CI_SERVER_TLS_KEY_FILE")
    if cert and key:
        options["cert"] = (cert, key)
    return options


def download_artifacts(
    project: str | int,
    job: str,
    prefix: str,
    dest: str | Path,
    ref: str = "main",
    environ: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> list[Path]:
    """Extract the files under `prefix` of the latest successful `job` on `ref` into `dest`.

    Returns the extracted files (paths relative to `prefix` are kept)."""
    source = _environ(environ)
    options = _client_options(source)
    base = f"{api_base(source)}/projects/{quote(str(project), safe='')}"
    try:
        with httpx.Client(transport=transport, **options) as client:
            if "PRIVATE-TOKEN" in options["headers"]:
                job_id = _latest_job(client, base, project, job, ref)
                resp = client.get(f"{base}/jobs/{job_id}/artifacts")
            else:
                resp = client.get(f"{base}/jobs/artifacts/{quote(ref, safe='')}/download", params={"job": job})
    except httpx.HTTPError as exc:
        raise GitLabError(f"{project}: {exc}") from exc
    if resp.status_code == 404:
        raise ArtifactNotFound(
            f"{project}: no artifacts of job {job!r} on {ref!r} (none yet, expired, not in the latest "
            "successful pipeline of the branch, or no access; A2VM_GITLAB_TOKEN finds the latest job)"
        )
    if resp.status_code in (401, 403):
        raise GitLabError(
            f"{project}: HTTP {resp.status_code}: this project is not allowed to read it "
            "(job token: Settings > CI/CD > Job token permissions of the source project; "
            "A2VM_GITLAB_TOKEN: a token of that project, role Reporter, scope read_api)"
        )
    if resp.status_code != 200:
        raise GitLabError(f"{project}: HTTP {resp.status_code} {resp.text[:200]}")
    if len(resp.content) > MAX_ARTIFACT_BYTES:
        raise GitLabError(f"{project}: artifacts larger than {MAX_ARTIFACT_BYTES // 2**20} MB")
    return _extract(resp.content, prefix, Path(dest))


MAX_JOB_PAGES = 5


def _latest_job(client: httpx.Client, base: str, project, job: str, ref: str) -> int:
    """Id of the latest successful `job` on `ref` that kept artifacts (newest jobs first)."""
    for page in range(1, MAX_JOB_PAGES + 1):
        resp = client.get(f"{base}/jobs", params={"scope[]": "success", "per_page": 100, "page": page})
        if resp.status_code in (401, 403):
            raise GitLabError(
                f"{project}: HTTP {resp.status_code}: A2VM_GITLAB_TOKEN cannot list the jobs (read_api, Reporter)"
            )
        if resp.status_code != 200:
            raise GitLabError(f"{project}: HTTP {resp.status_code} {resp.text[:200]}")
        jobs = resp.json()
        for j in jobs:
            if j.get("name") == job and j.get("ref") == ref and j.get("artifacts_file"):
                return j["id"]
        if len(jobs) < 100:
            break
    raise ArtifactNotFound(f"{project}: no successful job {job!r} with artifacts on {ref!r} among the latest jobs")


def _extract(content: bytes, prefix: str, dest: Path) -> list[Path]:
    prefix = prefix.strip("/") + "/"
    out: list[Path] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise GitLabError(f"artifacts are not a zip archive: {exc}") from exc
    with archive:
        total = 0
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(prefix):
                continue
            rel = PurePosixPath(info.filename[len(prefix) :])
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                continue  # never write outside dest
            total += info.file_size
            if total > MAX_ARTIFACT_BYTES:
                raise GitLabError(f"artifacts larger than {MAX_ARTIFACT_BYTES // 2**20} MB once extracted")
            target = dest.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
            out.append(target)
    return sorted(out)
