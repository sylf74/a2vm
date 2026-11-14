# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
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
traversal) at the lowest CPU and I/O priority; dnf lists the security advisories that apply; the
package database lists every package installed (`rpm -qa` or `dpkg-query`, v0.22.2), with the
distribution and the source package of each (v0.23.0), kept with the host's observation so that one
can ask which hosts carry a component, vulnerable or not, and match them against new advisories.
Since v0.24.0 the sockets the host listens on (`ss -ltnu`, numeric, without the processes) are kept
too, as its services: a host that listens on nothing but its loopback is not reachable by the network.
Nothing is installed, changed or exploited on the targets.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from a2vm.io import Detection

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
    " --list-all-pkgs --skip-dirs '**/dist-packages/nvidia' --skip-dirs '**/site-packages/nvidia'"
)
DNF = f"{LOW_PRIORITY} dnf -q updateinfo list --security --with-cve"
# Every package installed, one per line: name, version, architecture, type, source package. rpm first
# (Rocky, RHEL), else dpkg (Debian, Ubuntu; installed ones only). The first line names the
# distribution (/etc/os-release, v0.23.0): the advisories of a package depend on it.
PACKAGES = f"{LOW_PRIORITY} sh -c " + shlex.quote(
    '( . /etc/os-release 2>/dev/null; printf \'os\\t%s\\t%s\\n\' "${ID:-}" "${VERSION_ID:-}" ); '
    "if command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\trpm\\t%{SOURCERPM}\\n'; "
    "elif command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Architecture}\\tdeb\\t${Source}\\n'; fi"
)
# v0.23.11: the files still mapped by a running process after their deletion (an update replaced
# them): "<pid>\t<process>\t<file>". Only the shared libraries; without root, only the processes of
# the SSH user are readable (the others are skipped, nothing fails).
LOADED = f"{LOW_PRIORITY} sh -c " + shlex.quote(
    "for m in /proc/[0-9]*/maps; do p=${m#/proc/}; p=${p%/maps}; "
    "grep -s ' (deleted)$' \"$m\" | awk '{print $6}' | grep '\\.so' | sort -u | "
    'while read -r f; do printf \'%s\\t%s\\t%s\\n\' "$p" "$(cat /proc/$p/comm 2>/dev/null)" "$f"; done; '
    "done; true"
)
# v0.24.0: the sockets listening on the host, TCP and UDP, numeric; read-only and without root (the
# processes are not asked for). A host that listens on nothing but its loopback is not reachable.
LISTENING = f"{LOW_PRIORITY} ss -ltnu"
MAX_COMPONENTS = 20000
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
                img = Target(name=image, kind="image", image=image, host=t.host.lower())
                jobs.append((t, "trivy", f"{TRIVY_IMAGE} {shlex.quote(image)}", img))
        else:
            jobs.append((t, "dnf-updateinfo", DNF, host_target))
    return jobs


def _source_package(kind: str, raw: str, name: str) -> str:
    """The source package a binary one is built from: rpm `openssl-3.0.7-27.el9.src.rpm`, dpkg
    `openssl` or `openssl (3.0.11-1)`; the binary name when none is given."""
    raw = raw.strip()
    if kind == "rpm" and raw.endswith(".src.rpm"):
        parts = raw[: -len(".src.rpm")].rsplit("-", 2)
        return parts[0] if len(parts) == 3 and parts[0] else name
    if kind == "deb" and raw:
        return raw.split(" ", 1)[0]
    return name


def component(
    name: str,
    version: str,
    arch: str,
    kind: str,
    src: str = "",
    distro: str = "",
    source: str = "ssh",
    vendor: str = "",
) -> dict[str, str]:
    """One package as a component of the common model: {name, version, arch, type, purl,
    source_package, distro, vendor, source}. An rpm epoch 0 is left out of the version; the purl
    carries the distribution's vendor as namespace (`pkg:rpm/rocky/...?distro=rocky-9.4`). Shared by
    the SSH collection and the EDR connectors (Wazuh, v0.23.1; SentinelOne, v0.23.3). An application
    that is not a package of a distribution keeps its publisher (`vendor`, v0.23.3): the watch maps
    it to a CPE through the applications table (`a2vm.applications`)."""
    if kind == "rpm" and version.startswith(("0:", "(none):")):
        version = version.split(":", 1)[1]
    epoch, _, bare = version.rpartition(":") if kind == "rpm" else ("", "", version)
    space = distro.rsplit("-", 1)[0] if distro else ""
    qualifiers = [f"arch={arch}"] if arch and arch != "(none)" else []
    qualifiers += [f"distro={distro}"] if distro else []
    qualifiers += [f"epoch={epoch}"] if epoch else []
    namespace = f"{space}/" if space else ""
    out = {"name": name, "version": version, "arch": arch, "type": kind}
    if kind in ("rpm", "deb"):
        out["purl"] = f"pkg:{kind}/{namespace}{name}@{bare}" + ("?" + "&".join(qualifiers) if qualifiers else "")
    out["source_package"] = _source_package(kind, src, name)
    if distro:
        out["distro"] = distro
    if vendor and kind not in ("rpm", "deb"):
        out["vendor"] = vendor
    out["source"] = source
    return out


def parse_packages(text: str) -> list[dict[str, str]]:
    """The output of PACKAGES as components: {name, version, arch, type, purl, source_package,
    distro, source}, sorted, at most MAX_COMPONENTS. An rpm epoch 0 is left out of the version; dpkg
    lines not installed are skipped. The output of a v0.22.2 collector (no distribution, no source
    package) is still read."""
    out: dict[tuple[str, str, str], dict[str, str]] = {}
    distro = ""
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        if parts[0] == "os" and len(parts) == 3:
            vendor = parts[1].strip().lower()
            distro = f"{vendor}-{parts[2].strip()}".strip("-") if vendor else ""
            continue
        if len(parts) in (5, 6) and parts[4] == "deb":  # dpkg: status first
            if not parts[0].startswith(("ii", "hi")):
                continue
            parts = parts[1:]
        if len(parts) == 4:
            parts.append("")
        if len(parts) != 5 or not parts[0] or not parts[1]:
            continue
        name, version, arch, kind, src = (p.strip() for p in parts)
        if name == "gpg-pubkey":  # the keys of the repositories, not software
            continue
        c = component(name, version, arch, kind, src, distro, "ssh")
        out[(name, c["version"], arch)] = c
    return [out[k] for k in sorted(out)][:MAX_COMPONENTS]


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
    log: Callable[[str], None] = print,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[Detection], list[str]]:
    """Run every scan; return the detections (one per source) and the per-target errors.

    `ssh=False` skips the SSH targets (no key available); `gmp_session` replaces the GMP connection
    (tests). `log` gets one line per target as it ends (found, or why it failed, and how long it
    took): the journal of a collector shows where a long run is and which target failed."""
    raw_dir = Path(raw_dir)
    by_source: dict[str, list[Detection]] = {}
    errors: list[str] = []

    def failed(where: str, message: str, started: float, label: str = "") -> None:
        errors.append(f"{where}: {message}")
        log(f"FAIL {label or where}: {message} ({clock() - started:.0f} s)")

    def done(where: str, d: Detection, started: float) -> None:
        hosts = len({o.ref for o in d.observations})
        on = f" on {hosts} assets" if hosts > 1 else ""
        log(f"ok   {where}: {len(d.findings)} findings{on} ({clock() - started:.0f} s)")

    if tf.openvas:
        where = f"openvas [{', '.join(tf.openvas.hosts)}]"
        started = clock()
        try:
            session = gmp_session or gmp_connect(tf.openvas, env if env is not None else dict(os.environ))
            with session as gmp:
                xml = run_scan(gmp, tf.openvas, tf.client, log=log, reopen=getattr(session, "reopen", None))
            path = raw_dir / tf.client / "openvas" / "report.xml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(xml)
            detection = parse_gmp_report(xml, tf.client, tf.openvas.min_qod, zone=tf.openvas.zone)
            by_source["openvas"] = [detection]
            done(where, detection, started)
        except (GmpError, OSError, ValueError) as exc:
            failed(f"openvas [{tf.openvas.gmp}]", str(exc), started, where)
        except Exception as exc:  # noqa: BLE001 - python-gvm raises its own error classes
            failed(f"openvas [{tf.openvas.gmp}]", f"{type(exc).__name__}: {exc}", started, where)
    for t, method, remote, target in plan(tf) if ssh else []:
        where = f"{t.host} [{method} {target.ref}]"  # the error, as before
        label = f"{t.host} [{method}]" if target.kind == "host" else f"{t.host} [{method} {target.ref}]"
        started = clock()
        cmd = ssh_command(tf, t, remote)
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=tf.timeout_seconds)
        except (OSError, subprocess.TimeoutExpired) as exc:
            failed(where, str(exc), started, label)
            continue
        # dnf exits 100 when updates are available; anything else non-zero is a failure.
        if proc.returncode not in (0, 100) or (method == "trivy" and not proc.stdout.strip()):
            failed(where, f"exit {proc.returncode}: {_tail(proc.stderr)}", started, label)
            continue
        ext = "json" if method == "trivy" else "txt"
        path = raw_dir / tf.client / method / f"{raw_name(target)}.{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(proc.stdout, encoding="utf-8")
        try:
            loader = load_trivy_file if method == "trivy" else load_dnf_file
            detection = loader(path, tf.client, target)
        except (ValueError, KeyError) as exc:
            failed(where, f"unreadable output: {exc}", started, label)
            continue
        if target.kind == "host":
            _add_components(tf, t, target, detection, runner, log)
            _add_listening(tf, t, target, detection, runner, log)
        by_source.setdefault(method, []).append(detection)
        done(label, detection, started)
    return [merge(ds) for ds in by_source.values()], errors


def _add_components(tf: TargetsFile, t: HostTarget, target: Target, detection: Detection, runner, log) -> None:  # noqa: ANN001
    """Every package installed on the host, kept with its observation; a failure only loses them."""
    try:
        proc = runner(ssh_command(tf, t, PACKAGES), capture_output=True, text=True, timeout=tf.timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"WARN {t.host} [packages]: {exc}")
        return
    components = parse_packages(proc.stdout) if proc.returncode == 0 else []
    if not components:
        log(f"WARN {t.host} [packages]: none listed (exit {proc.returncode}: {_tail(proc.stderr, 200)})")
        return
    for o in detection.observations:
        if o.ref == target.ref:
            o.components = components
    _add_loaded(tf, t, target, detection, runner, log)


def parse_loaded(text: str) -> list[dict[str, str]]:
    """The output of LOADED as components of type in-memory: one per deleted file, its processes."""
    files: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0].strip().isdigit() or not parts[2].startswith("/"):
            continue
        pid, name, path = (p.strip() for p in parts)
        path = path.removesuffix(" (deleted)")
        files.setdefault(path, []).append(f"{pid} {name}".strip())
    return [
        {"name": path, "version": "", "type": "in-memory", "processes": ", ".join(sorted(set(procs))), "source": "ssh"}
        for path, procs in sorted(files.items())
    ][:MAX_COMPONENTS]


def _add_loaded(tf: TargetsFile, t: HostTarget, target: Target, detection: Detection, runner, log) -> None:  # noqa: ANN001
    """The libraries deleted on disk but still loaded: the processes to restart (best effort)."""
    try:
        proc = runner(ssh_command(tf, t, LOADED), capture_output=True, text=True, timeout=tf.timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"WARN {t.host} [loaded]: {exc}")
        return
    loaded = parse_loaded(proc.stdout) if proc.returncode == 0 else []
    if not loaded:
        return
    log(f"WARN {t.host} [loaded]: {len(loaded)} deleted libraries still in memory, restart needed")
    for o in detection.observations:
        if o.ref == target.ref:
            o.components = list(o.components or []) + loaded


def _bind(address: str) -> str:
    """Where a socket listens: any (every address), loopback, or the address itself."""
    host = address.split("%", 1)[0].strip("[]")
    if host in ("*", "0.0.0.0", "::", ""):
        return "any"
    try:
        return "loopback" if ipaddress.ip_address(host).is_loopback else host
    except ValueError:
        return host


def parse_listening(text: str) -> list[dict[str, str]]:
    """The output of LISTENING as services, view local: {port, view, bind}, one per port and bind."""
    out: dict[tuple[str, str], dict[str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        address, _, port = parts[4].rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            continue
        label = f"{int(port)}/{parts[0]}"
        bind = _bind(address)
        out[(label, bind)] = {"port": label, "view": "local", "bind": bind}
    return [out[k] for k in sorted(out, key=lambda k: (int(k[0].split("/")[0]), k[0], k[1]))]


def _add_listening(tf: TargetsFile, t: HostTarget, target: Target, detection: Detection, runner, log) -> None:  # noqa: ANN001
    """The services the host listens on (v0.24.0); a failure leaves them unknown, nothing else."""
    try:
        proc = runner(ssh_command(tf, t, LISTENING), capture_output=True, text=True, timeout=tf.timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"WARN {t.host} [listening]: {exc}")
        return
    if proc.returncode != 0:
        log(f"WARN {t.host} [listening]: exit {proc.returncode}: {_tail(proc.stderr, 200)}")
        return
    services = parse_listening(proc.stdout)
    for o in detection.observations:
        if o.ref == target.ref:
            o.services = services
