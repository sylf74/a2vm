# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Read the job artifacts of a GitLab project (the external detection, the last daily inventory).

Inside a pipeline the job token authenticates the request (the source project must allow the
reading project in Settings > CI/CD > Job token permissions); outside, A2VM_GITLAB_TOKEN (scope
read_api). The API is reached at A2VM_SERVER_URL/api/v4 when the runner uses another URL than the
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
    if environ.get("CI_JOB_TOKEN"):
        headers["JOB-TOKEN"] = environ["CI_JOB_TOKEN"]
    elif env("GITLAB_TOKEN", environ=environ):
        headers["PRIVATE-TOKEN"] = env("GITLAB_TOKEN", environ=environ)
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
    url = f"{api_base(source)}/projects/{quote(str(project), safe='')}/jobs/artifacts/{quote(ref, safe='')}/download"
    try:
        with httpx.Client(transport=transport, **_client_options(source)) as client:
            resp = client.get(url, params={"job": job})
    except httpx.HTTPError as exc:
        raise GitLabError(f"{project}: {exc}") from exc
    if resp.status_code == 404:
        raise ArtifactNotFound(f"{project}: no artifacts of job {job!r} on {ref!r} (none yet, expired, or no access)")
    if resp.status_code in (401, 403):
        raise GitLabError(
            f"{project}: HTTP {resp.status_code}: this project is not allowed to read it "
            "(Settings > CI/CD > Job token permissions of the source project)"
        )
    if resp.status_code != 200:
        raise GitLabError(f"{project}: HTTP {resp.status_code} {resp.text[:200]}")
    if len(resp.content) > MAX_ARTIFACT_BYTES:
        raise GitLabError(f"{project}: artifacts larger than {MAX_ARTIFACT_BYTES // 2**20} MB")
    return _extract(resp.content, prefix, Path(dest))


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
