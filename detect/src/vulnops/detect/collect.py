# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only collection over SSH: run a scanner on each target and keep its raw output.

Targets file (YAML), one per client — see examples/lab/targets.yaml:

  client: lab
  ssh: {user: vulnops, identity_file: ~/.ssh/vulnops_scan}
  targets:
    - {host: gitlab.lab.example, ip: 192.0.2.102, method: trivy}
    - {host: edge01.lab.example, method: dnf-updateinfo}
    - {host: poc-llm01.lab.example, method: trivy, images: [vllm/vllm-openai:latest]}
  openvas:                           # optional: network scan by a Greenbone scanner (openvas.py)
    gmp: tls://scanner.lab.example:9390
    hosts: [192.0.2.0/24]

Every SSH command only reads: Trivy scans the OS package database (`--pkg-types os`, no file-system
traversal) at the lowest CPU and I/O priority; dnf lists the security advisories that apply.
Nothing is installed, changed or exploited on the targets.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vulnops.core.io import Detection

from .openvas import GmpError, OpenvasConfig, parse_gmp_report, run_scan
from .openvas import connect as gmp_connect
from .scanners import Target, load_dnf_file, load_trivy_file, merge

METHODS = ("trivy", "dnf-updateinfo")
LOW_PRIORITY = "nice -n 19 ionice -c3"
TRIVY_HOST = f"{LOW_PRIORITY} trivy rootfs --quiet --timeout 15m --format json --scanners vuln --pkg-types os /"
# Images: language packages too. CUDA binaries (hundreds of MB, no package metadata) are skipped:
# their analysis exceeds Trivy's time limit, and the pip packages' metadata stays outside them.
TRIVY_IMAGE = (
    f"{LOW_PRIORITY} trivy image --quiet --timeout 30m --format json --scanners vuln --pkg-types os,library"
    " --skip-dirs '**/dist-packages/nvidia' --skip-dirs '**/site-packages/nvidia'"
)
DNF = f"{LOW_PRIORITY} dnf -q updateinfo list --security --with-cve"
DEFAULT_SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new"]


@dataclass
class HostTarget:
    host: str
    method: str
    ip: str | None = None
    ips: list[str] = field(default_factory=list)  # extra addresses of the same host (several NICs)
    images: list[str] = field(default_factory=list)
    user: str | None = None


@dataclass
class TargetsFile:
    client: str
    user: str | None
    identity_file: str | None
    ssh_options: list[str]
    timeout_seconds: int
    targets: list[HostTarget]
    openvas: OpenvasConfig | None = None


def load_targets(path: str | Path) -> TargetsFile:
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    ssh = data.get("ssh") or {}
    targets = []
    for t in data.get("targets") or []:
        ht = HostTarget(**t)
        if ht.method not in METHODS:
            raise ValueError(f"{path}: {ht.host}: unknown method {ht.method!r} (expected one of {METHODS})")
        targets.append(ht)
    openvas = OpenvasConfig.from_dict(data["openvas"], f"{path}: openvas") if data.get("openvas") else None
    if not data.get("client") or not (targets or openvas):
        raise ValueError(f"{path}: 'client' and at least one target (or an openvas section) are required")
    return TargetsFile(
        client=data["client"],
        user=ssh.get("user"),
        identity_file=ssh.get("identity_file"),
        ssh_options=list(ssh.get("options") or DEFAULT_SSH_OPTIONS),
        timeout_seconds=int(ssh.get("timeout_seconds", 600)),
        targets=targets,
        openvas=openvas,
    )


def ssh_command(tf: TargetsFile, t: HostTarget, remote: str) -> list[str]:
    cmd = ["ssh", *tf.ssh_options]
    if tf.identity_file:
        cmd += ["-i", str(Path(tf.identity_file).expanduser())]
    user = t.user or tf.user
    cmd.append(f"{user}@{t.host}" if user else t.host)
    cmd.append(remote)
    return cmd


def _short(host: str) -> str:
    return host.split(".")[0]


def plan(tf: TargetsFile) -> list[tuple[HostTarget, str, str, Target]]:
    """(target, method, remote command, asset target) for every scan to run."""
    jobs = []
    for t in tf.targets:
        fqdn = t.host.lower() if "." in t.host else None
        ips = list(dict.fromkeys(([t.ip] if t.ip else []) + list(t.ips)))
        host_target = Target(name=_short(t.host), kind="host", fqdn=fqdn, ips=ips)
        if t.method == "trivy":
            jobs.append((t, "trivy", TRIVY_HOST, host_target))
            for image in t.images:
                img = Target(name=image, kind="image", image=image)
                jobs.append((t, "trivy", f"{TRIVY_IMAGE} {shlex.quote(image)}", img))
        else:
            jobs.append((t, "dnf-updateinfo", DNF, host_target))
    return jobs


def _tail(text: str, limit: int = 600) -> str:
    """End of a command's stderr: the cause of an error is usually on the last lines."""
    lines = [line for line in text.strip().splitlines() if not line.startswith("Warning: Permanently added")]
    out = " | ".join(lines)
    return out if len(out) <= limit else "..." + out[-limit:]


def raw_name(target: Target) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target.ref)


def collect(
    tf: TargetsFile,
    raw_dir: str | Path,
    runner=subprocess.run,
    ssh: bool = True,
    gmp_session=None,
    env: dict[str, str] | None = None,
) -> tuple[list[Detection], list[str]]:
    """Run every scan; return the detections (one per source) and the per-target errors.

    `ssh=False` skips the SSH targets (no key available); `gmp_session` replaces the GMP connection
    (tests)."""
    raw_dir = Path(raw_dir)
    by_source: dict[str, list[Detection]] = {}
    errors: list[str] = []
    if tf.openvas:
        try:
            session = gmp_session or gmp_connect(tf.openvas, env if env is not None else dict(os.environ))
            with session as gmp:
                xml = run_scan(gmp, tf.openvas, tf.client)
            path = raw_dir / tf.client / "openvas" / "report.xml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(xml)
            by_source["openvas"] = [parse_gmp_report(xml, tf.client, tf.openvas.min_qod)]
        except (GmpError, OSError, ValueError) as exc:
            errors.append(f"openvas [{tf.openvas.gmp}]: {exc}")
        except Exception as exc:  # noqa: BLE001 - python-gvm raises its own error classes
            errors.append(f"openvas [{tf.openvas.gmp}]: {type(exc).__name__}: {exc}")
    for t, method, remote, target in plan(tf) if ssh else []:
        cmd = ssh_command(tf, t, remote)
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=tf.timeout_seconds)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{t.host} [{method} {target.ref}]: {exc}")
            continue
        # dnf exits 100 when updates are available; anything else non-zero is a failure.
        if proc.returncode not in (0, 100) or (method == "trivy" and not proc.stdout.strip()):
            errors.append(f"{t.host} [{method} {target.ref}]: exit {proc.returncode}: {_tail(proc.stderr)}")
            continue
        ext = "json" if method == "trivy" else "txt"
        path = raw_dir / tf.client / method / f"{raw_name(target)}.{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(proc.stdout, encoding="utf-8")
        try:
            loader = load_trivy_file if method == "trivy" else load_dnf_file
            by_source.setdefault(method, []).append(loader(path, tf.client, target))
        except (ValueError, KeyError) as exc:
            errors.append(f"{t.host} [{method} {target.ref}]: unreadable output: {exc}")
    return [merge(ds) for ds in by_source.values()], errors
