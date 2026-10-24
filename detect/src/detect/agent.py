# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The collector (`detect agent`): run connectors near a network and push their detections to the
detection service of the cluster (LLD vulnerability-detection §8.1).

collector.yaml, on the collector's machine (secrets in files readable by the agent only):

  collector: homelab-lan                  # as declared in the tenant's collectors.yaml
  tenant: homelab
  service: https://detect-homelab.apps.example.org
  token_file: /etc/a2vm/collector/token
  ca_file: /etc/a2vm/collector/ca.pem      # optional: CA of the service's certificate
  work: /var/lib/a2vm/work
  spool: /var/lib/a2vm/spool
  connectors:
    - name: lan
      type: targets                        # SSH (trivy, dnf-updateinfo) and OpenVAS, from a targets file
      targets: /etc/a2vm/collector/targets.yaml
      ssh: true
      openvas: true
    - name: drop
      type: file-import                    # scanner exports dropped in a folder
      source: trivy                        # trivy, dnf-updateinfo or openvas
      folder: /var/lib/a2vm/import/trivy

`detect agent run` runs the connectors (or one, `--connector`) and pushes each detection; a
system timer gives each connector its schedule (docs/collectors.md). A push that fails for a reason
worth retrying (service unreachable, 429, 5xx) is kept in the spool, one file per source (the newest
wins), and pushed again at the next run; a spooled detection the service refuses for good (too old,
source no longer declared) is set aside as `<source>.json.rejected`. The agent only connects out:
to its targets and scanners, and to the service.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml

from a2vm.io import Detection, write_detection

from .collect import collect, load_targets
from .intake.client import IntakeError, push
from .intake.registry import ID
from .openvas import load_openvas_file
from .scanners import load_dnf_file, load_trivy_file, merge

SOURCES_BY_SUFFIX = {"trivy": ".json", "dnf-updateinfo": ".txt", "openvas": ".xml"}


class AgentError(ValueError):
    pass


class Connector(Protocol):
    name: str

    def run(self, tenant: str, work: Path) -> tuple[list[Detection], list[str]]: ...


@dataclass
class TargetsConnector:
    """The present collection: read-only SSH scanners and the OpenVAS network scan (collect.py)."""

    name: str
    targets: Path
    ssh: bool = True
    openvas: bool = True

    def run(self, tenant: str, work: Path) -> tuple[list[Detection], list[str]]:
        tf = load_targets(self.targets)
        if tf.client != tenant:
            return [], [f"{self.name}: targets file of client {tf.client!r}, not {tenant!r}"]
        if not self.openvas:
            tf.openvas = None
        detections, errors = collect(tf, work / "raw" / self.name, ssh=self.ssh)
        return detections, [f"{self.name}: {e}" for e in errors]


@dataclass
class FileImportConnector:
    """Scanner exports dropped in a folder by another tool; each file is imported once."""

    name: str
    source: str
    folder: Path
    min_qod: int = 70

    def run(self, tenant: str, work: Path) -> tuple[list[Detection], list[str]]:
        suffix = SOURCES_BY_SUFFIX[self.source]
        files = sorted(p for p in self.folder.glob(f"*{suffix}") if p.is_file())
        if not files:
            return [], []
        detections, errors = [], []
        for f in files:
            try:
                if self.source == "openvas":
                    detections.append(load_openvas_file(f, tenant, self.min_qod))
                elif self.source == "trivy":
                    detections.append(load_trivy_file(f, tenant))
                else:
                    detections.append(load_dnf_file(f, tenant))
                f.rename(f.with_name(f.name + ".imported"))
            except (OSError, ValueError, KeyError) as exc:
                errors.append(f"{self.name}: {f.name}: {exc}")
        return ([merge(detections)] if detections else []), errors


@dataclass
class AgentConfig:
    collector: str
    tenant: str
    service: str
    token_file: Path
    work: Path
    spool: Path
    connectors: list[Any] = field(default_factory=list)
    ca_file: str | None = None

    def token(self) -> str:
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AgentError(f"token_file {self.token_file}: {exc}") from exc
        if not token:
            raise AgentError(f"token_file {self.token_file} is empty")
        return token


def load_config(path: str | Path) -> AgentConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for key in ("collector", "tenant", "service", "token_file"):
        if not data.get(key):
            raise AgentError(f"{path}: `{key}` is required")
    for key in ("collector", "tenant"):
        if not ID.match(str(data[key])):
            raise AgentError(f"{path}: `{key}` must be lower-case letters, digits and dashes")
    if not str(data["service"]).startswith(("https://", "http://")):
        raise AgentError(f"{path}: `service` must be an http(s) URL")
    connectors: list[Any] = []
    for i, c in enumerate(data.get("connectors") or []):
        where = f"{path}: connectors[{i}]"
        if not isinstance(c, dict):
            raise AgentError(f"{where}: expected a mapping")
        kind, name = c.get("type"), str(c.get("name") or f"connector{i}")
        if not ID.match(name):
            raise AgentError(f"{where}: name {name!r} must be lower-case letters, digits and dashes")
        if kind == "targets":
            if not c.get("targets"):
                raise AgentError(f"{where}: `targets` (a targets file) is required")
            connectors.append(
                TargetsConnector(name, Path(c["targets"]), bool(c.get("ssh", True)), bool(c.get("openvas", True)))
            )
        elif kind == "file-import":
            if c.get("source") not in SOURCES_BY_SUFFIX or not c.get("folder"):
                raise AgentError(f"{where}: `source` ({', '.join(SOURCES_BY_SUFFIX)}) and `folder` are required")
            connectors.append(FileImportConnector(name, c["source"], Path(c["folder"]), int(c.get("min_qod", 70))))
        else:
            raise AgentError(f"{where}: unknown type {kind!r} (targets, file-import)")
    if not connectors:
        raise AgentError(f"{path}: at least one connector is required")
    if len({c.name for c in connectors}) != len(connectors):
        raise AgentError(f"{path}: connector names must be unique")
    return AgentConfig(
        collector=str(data["collector"]),
        tenant=str(data["tenant"]),
        service=str(data["service"]),
        token_file=Path(data["token_file"]),
        work=Path(data.get("work", "/var/lib/a2vm/work")),
        spool=Path(data.get("spool", "/var/lib/a2vm/spool")),
        connectors=connectors,
        ca_file=data.get("ca_file"),
    )


@dataclass
class RunReport:
    pushed: list[str] = field(default_factory=list)
    spooled: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def status(self) -> int:
        """0 all pushed; 3 partial (errors or something spooled); 1 nothing pushed and errors."""
        if self.errors or self.spooled:
            return 3 if self.pushed else 1
        return 0


def _push_or_spool(
    cfg: AgentConfig,
    token: str,
    document: dict[str, Any],
    report: RunReport,
    transport=None,
    spooled: bool = False,
) -> None:
    source = document["source"]
    spool_file = cfg.spool / f"{source}.json"
    try:
        receipt = push(cfg.service, cfg.tenant, token, document, cfg.collector, cfg.ca_file, transport)
        report.pushed.append(f"{source} -> {receipt['id']}{' (already received)' if receipt.get('duplicate') else ''}")
        spool_file.unlink(missing_ok=True)
    except IntakeError as exc:
        if getattr(exc, "retry", False):
            cfg.spool.mkdir(parents=True, exist_ok=True)
            tmp = cfg.spool / f".{source}.json.tmp"
            tmp.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, spool_file)
            report.spooled.append(f"{source}: {exc}")
        else:
            report.errors.append(f"{source}: {exc}")
            if spooled:  # refused for good: kept for a look, never pushed again
                os.replace(spool_file, spool_file.with_name(spool_file.name + ".rejected"))


def run(cfg: AgentConfig, only: str | None = None, transport=None) -> RunReport:
    report = RunReport()
    token = cfg.token()
    # What earlier runs could not push first; a fresher detection of the same source replaces it below.
    for spooled in sorted(cfg.spool.glob("*.json")) if cfg.spool.exists() else []:
        try:
            document = json.loads(spooled.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            report.errors.append(f"spool {spooled.name}: {exc}")
            continue
        if not isinstance(document, dict) or spooled.stem != document.get("source"):
            report.errors.append(f"spool {spooled.name}: not a detection of that source, set aside")
            os.replace(spooled, spooled.with_name(spooled.name + ".rejected"))
            continue
        _push_or_spool(cfg, token, document, report, transport, spooled=True)
    selected = [c for c in cfg.connectors if only in (None, c.name)]
    if only and not selected:
        raise AgentError(f"no connector named {only!r}")
    for connector in selected:
        detections, errors = connector.run(cfg.tenant, cfg.work)
        report.errors.extend(errors)
        for d in detections:
            if d.client_id != cfg.tenant:
                report.errors.append(f"{connector.name}: detection of client {d.client_id!r}, not pushed")
                continue
            path = write_detection(cfg.work / "detect" / cfg.tenant / f"{d.source}.json", d)
            _push_or_spool(cfg, token, json.loads(path.read_text(encoding="utf-8")), report, transport)
    return report
