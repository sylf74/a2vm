# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""OpenVAS (Greenbone Community Edition) connector: network scans, without agent or SSH account.

Two ways in:
  - scan: detect drives gvmd over GMP (python-gvm): it creates or reuses a target and a task named
    after the client, starts the scan, waits for it and downloads the report in XML;
  - import: a report exported from the Greenbone web interface (XML), read the same way.

The report is untrusted input (it carries strings from the scanned hosts): it is parsed with
defusedxml, which refuses entity expansion and external entities.

One observation per scanned host (IP, host name, OS when the scanner found it); one finding per
host and CVE, one observation per port and NVT. Results below the quality of detection (QoD)
threshold, and log-level results (severity 0), are counted in `skipped`, not kept.

Scans are network scans: OpenVAS connects to the services of the targets. The default scan
configuration ("Full and fast") runs with safe checks on, which leaves out the tests known to
disrupt services; it is still traffic the client must expect and agree to.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from a2vm.config import env as cfg_env
from a2vm.io import Detection, now

from .scanners import Target, _Builder, merge

SOURCE = "openvas"
# Well-known ids of a stock Greenbone installation (identical on every gvmd).
FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
XML_REPORT_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
FINISHED = {"Done", "Stopped", "Interrupted"}
ACTIVE = {"Requested", "Queued", "Running", "Stop Requested"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# A test that lists this many CVEs without reporting an installed version is a generic check (e.g.
# "HTTP TRACE enabled" lists the CVEs of every product that ever had that flaw): its CVEs are kept
# but flagged, the product being unconfirmed.
GENERIC_NVT_CVES = 5
GENERIC_REASON = "test OpenVAS générique ({n} CVE, produit non identifié) : CVE à confirmer"


@dataclass
class OpenvasConfig:
    """`openvas:` section of a targets file."""

    gmp: str  # tls://host:9390 or unix:///run/gvmd/gvmd.sock
    hosts: list[str]  # addresses, ranges or names the scanner must reach
    exclude: list[str] = field(default_factory=list)
    scan_config: str = FULL_AND_FAST
    port_list: str = ALL_IANA_TCP
    scanner: str = OPENVAS_SCANNER
    min_qod: int = 70
    timeout_minutes: int = 240
    reuse_hours: float = 6  # a finished scan younger than this is collected instead of a new scan (0: never)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "openvas") -> OpenvasConfig:
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        if not data.get("gmp") or not data.get("hosts"):
            raise ValueError(f"{where}: 'gmp' and 'hosts' are required")
        if not str(data["gmp"]).startswith(("tls://", "unix://")):
            raise ValueError(f"{where}: gmp must be tls://host:port or unix:///path/to/gvmd.sock")
        return cls(
            **{**data, "hosts": [str(h) for h in data["hosts"]], "exclude": [str(h) for h in data.get("exclude", [])]}
        )

    def key(self, client: str) -> str:
        """Name of the target and task in gvmd: one per client and scan definition."""
        spec = "|".join([*sorted(self.hosts), "!", *sorted(self.exclude), self.port_list, self.scan_config])
        return f"vulnops-{client}-{hashlib.sha256(spec.encode()).hexdigest()[:8]}"


# -- report parsing --------------------------------------------------------------------------------
def _text(el: Any, path: str) -> str:
    found = el.find(path) if el is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


def _cves(nvt: Any) -> list[str]:
    ids = [r.get("id", "") for r in nvt.findall("refs/ref") if (r.get("type") or "").lower() == "cve"]
    legacy = _text(nvt, "cve")  # GMP before 8: comma-separated list, "NOCVE" when none
    ids += CVE_RE.findall(legacy)
    return sorted({i for i in ids if CVE_RE.fullmatch(i)})


def _cvss(nvt: Any) -> tuple[str, str]:
    """(vector, source): CVSS v4 or v3 when the NVT has one, else its CVSS v2 vector (old NVTs)."""
    values = [_text(sev, "value") for sev in nvt.findall("severities/severity")]
    for vector in values:
        if vector.startswith(("CVSS:4", "CVSS:3")):
            return vector, "openvas"
    tags = dict(t.split("=", 1) for t in _text(nvt, "tags").split("|") if "=" in t)
    for vector in [*values, tags.get("cvss_base_vector", "")]:
        if vector.startswith("AV:") and "/Au:" in vector:
            return vector, "openvas (CVSS v2)"
    return "", ""


def _versions(description: str) -> tuple[str, str]:
    installed = re.search(r"Installed version:\s*(\S.*)", description)
    fixed = re.search(r"Fixed version:\s*(\S.*)", description)
    return (installed.group(1).strip() if installed else "", fixed.group(1).strip() if fixed else "")


def _host_details(root: Any) -> dict[str, dict[str, str]]:
    """ip -> {hostname, os} from the report's <host> blocks."""
    out: dict[str, dict[str, str]] = {}
    for host in root.iter("host"):
        ip = _text(host, "ip")
        if not ip:
            continue
        details = {_text(d, "name"): _text(d, "value") for d in host.findall("detail")}
        out[ip] = {"hostname": details.get("hostname", ""), "os": details.get("best_os_txt", "")}
    return out


def parse_gmp_report(xml: str | bytes, client_id: str, min_qod: int = 70, observed_at: str | None = None) -> Detection:
    """A GMP report (get_reports response, or a report exported as XML) -> one detection."""
    try:
        root = SafeET.fromstring(xml)
    except (DefusedXmlException, SafeET.ParseError) as exc:
        raise ValueError(f"unreadable OpenVAS report: {exc}") from exc
    observed = observed_at or _text(root, ".//scan_start") or now()
    details = _host_details(root)
    builders: dict[str, _Builder] = {}
    skipped: dict[str, int] = {}
    generic: dict[tuple[str, str], int] = {}  # (ip, cve) -> CVE count of the generic test that reported it
    specific: set[tuple[str, str]] = set()  # (ip, cve) also reported by a specific test

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for result in root.iter("result"):
        host_el = result.find("host")
        nvt = result.find("nvt")
        if host_el is None or nvt is None:
            continue  # <result> elements of the delta or override blocks
        ip = (host_el.text or "").strip()
        if not ip:
            continue
        severity = _text(result, "severity")
        try:
            score = float(severity) if severity else 0.0
        except ValueError:
            score = 0.0
        if score <= 0:
            skip("log-level result")
            continue
        qod = _text(result, "qod/value")
        if qod.isdigit() and int(qod) < min_qod:
            skip(f"QoD below {min_qod}")
            continue
        cves = _cves(nvt)
        if not cves:
            skip("result without CVE")
            continue
        hostname = _text(host_el, "hostname") or details.get(ip, {}).get("hostname", "")
        b = builders.get(ip)
        if b is None:
            name = hostname or ip
            target = Target(name=name.split(".")[0] if hostname else ip, kind="host",
                            fqdn=hostname.lower() if "." in hostname else None, ips=[ip])  # fmt: skip
            b = builders[ip] = _Builder(client_id, SOURCE, target, observed)
        installed, fixed = _versions(_text(result, "description"))
        port = _text(result, "port") or "general"
        solution = (nvt.find("solution").get("type", "") if nvt.find("solution") is not None else "").lower()
        label = f"{port} · {_text(nvt, 'name')[:120]}"
        is_generic = len(cves) >= GENERIC_NVT_CVES and not installed
        for cve in cves:
            b.add(cve, label, installed, fixed, solution or "affected", _text(result, "threat"), _cvss(nvt),
                  note=f"openvas NVT {nvt.get('oid', '')} on {port}")  # fmt: skip
            if is_generic:
                generic[(ip, cve)] = max(generic.get((ip, cve), 0), len(cves))
            else:
                specific.add((ip, cve))
    for (ip, cve), n in generic.items():
        if (ip, cve) in specific:
            continue
        finding = builders[ip].findings[cve]
        finding.status = "under_investigation"
        finding.review_reasons.append(GENERIC_REASON.format(n=n))
    detections = [b.detection(details.get(ip, {}).get("os") or None) for ip, b in builders.items()]
    out = merge(detections) if detections else Detection(client_id, SOURCE, [], [])
    for reason, n in skipped.items():
        out.skipped[reason] = out.skipped.get(reason, 0) + n
    return out


def load_openvas_file(path: str | Path, client_id: str, min_qod: int = 70) -> Detection:
    return parse_gmp_report(Path(path).read_bytes(), client_id, min_qod)


# -- scanning over GMP -----------------------------------------------------------------------------
class GmpError(RuntimeError):
    pass


def _first_id(response: Any, tag: str, name: str) -> str | None:
    for el in response.findall(tag):
        if (el.findtext("name") or "") == name:
            return el.get("id")
    return None


def _recent_report(task: Any, max_hours: float, now: datetime) -> tuple[str, str] | None:
    """(report id, end time) of the task's last report when it finished less than max_hours ago."""
    last = task.find("last_report/report")
    if max_hours <= 0 or last is None or not last.get("id"):
        return None
    ended = (last.findtext("scan_end") or last.findtext("timestamp") or "").strip()
    try:
        when = datetime.fromisoformat(ended.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    age_hours = (now - when).total_seconds() / 3600
    return (last.get("id"), ended) if 0 <= age_hours <= max_hours else None


def run_scan(
    gmp: Any,
    cfg: OpenvasConfig,
    client: str,
    log: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float = 30,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> bytes:
    """Scan with an authenticated python-gvm Gmp object; returns the report XML.

    The target and the task are reused from one run to the next (same name), so gvmd keeps the
    history of the scans; a scan already running for this client is waited for, not doubled; a scan
    that finished less than `reuse_hours` ago is collected as is (e.g. after a job killed by its
    timeout while gvmd went on scanning).
    """
    name = cfg.key(client)
    target_id = _first_id(gmp.get_targets(filter_string=f'name="{name}"'), "target", name)
    if not target_id:
        resp = gmp.create_target(
            name, hosts=cfg.hosts, exclude_hosts=cfg.exclude or None, port_list_id=cfg.port_list,
            comment=f"vulnops, client {client}",
        )  # fmt: skip
        target_id = resp.get("id")
        log(f"openvas: target {name} created ({', '.join(cfg.hosts)})")
    task_id = _first_id(gmp.get_tasks(filter_string=f'name="{name}"'), "task", name)
    if not task_id:
        task_id = gmp.create_task(
            name, cfg.scan_config, target_id, cfg.scanner, comment=f"vulnops, client {client}"
        ).get("id")
        log(f"openvas: task {name} created")

    task = gmp.get_task(task_id).find("task")
    status = task.findtext("status") if task is not None else ""
    recent = _recent_report(task, cfg.reuse_hours, clock()) if status == "Done" else None
    if status in ACTIVE:
        current = task.find("current_report/report")
        report_id = current.get("id") if current is not None else None
        log(f"openvas: a scan is already {status.lower()}, waiting for it")
    elif recent:
        report_id, ended = recent
        log(f"openvas: last scan finished at {ended}, less than {cfg.reuse_hours:g} h ago: collecting it")
    else:
        report_id = gmp.start_task(task_id).findtext("report_id")
        log(f"openvas: scan started, report {report_id}")

    deadline = time.monotonic() + cfg.timeout_minutes * 60
    while True:
        task = gmp.get_task(task_id).find("task")
        status = task.findtext("status") if task is not None else "?"
        if status in FINISHED:
            break
        if time.monotonic() > deadline:
            gmp.stop_task(task_id)
            raise GmpError(f"scan still {status} after {cfg.timeout_minutes} min: stopped")
        log(f"openvas: {status} {task.findtext('progress') or ''}%")
        sleep(poll_seconds)
    if status != "Done":
        log(f"openvas: scan ended as {status}: partial report")
    if not report_id:
        last = task.find("last_report/report") if task is not None else None
        if last is None:
            raise GmpError("the scan ended without a report")
        report_id = last.get("id")
    report = gmp.get_report(
        report_id, report_format_id=XML_REPORT_FORMAT, ignore_pagination=True, details=True,
        filter_string=f"apply_overrides=1 min_qod={cfg.min_qod} levels=hml rows=-1",
    )  # fmt: skip
    from lxml import etree  # python-gvm's dependency

    return etree.tostring(report)


def connect(cfg: OpenvasConfig, env: dict[str, str]):
    """An authenticated Gmp context manager from the CI variables (A2VM_GVM_*)."""
    try:
        from gvm.connections import TLSConnection, UnixSocketConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as exc:  # pragma: no cover - depends on the installation
        raise GmpError("python-gvm is not installed: pip install 'detect[openvas]'") from exc
    user, password = cfg_env("GVM_USER", environ=env) or None, cfg_env("GVM_PASSWORD", environ=env) or None
    if not user or not password:
        raise GmpError("A2VM_GVM_USER and A2VM_GVM_PASSWORD must be set")
    if cfg.gmp.startswith("unix://"):
        connection = UnixSocketConnection(path=cfg.gmp[len("unix://") :], timeout=300)
    else:
        host, _, port = cfg.gmp[len("tls://") :].rpartition(":")
        connection = TLSConnection(
            hostname=host or cfg.gmp[len("tls://") :], port=int(port or 9390), timeout=300,
            cafile=cfg_env("GVM_CA", environ=env) or None,
            certfile=cfg_env("GVM_CERT", environ=env) or None, keyfile=cfg_env("GVM_KEY", environ=env) or None,
        )  # fmt: skip

    class _Session:
        def __enter__(self):
            self.gmp = Gmp(connection, transform=EtreeCheckCommandTransform())
            gmp = self.gmp.__enter__()
            gmp.authenticate(user, password)
            return gmp

        def __exit__(self, *exc):
            return self.gmp.__exit__(*exc)

    return _Session()
