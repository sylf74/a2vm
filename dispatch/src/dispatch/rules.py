# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Rules of a tenant's dispatch (`dispatch.yaml`, LLD dispatch §4): where the decisions go.

    schema_version: 1
    mode: dry-run                  # dry-run (default): proposed and logged, nothing sent; live: sent
    targets:
      itsm: {type: itop, url: ..., user: ..., organization: ..., caller: ...}
    tickets:
      target: itsm
      automatic: act               # none | act (default) | act-attend: what leaves by itself after each run
      exclude_zones: [lab]
      resolve_when_fixed: true     # resolved in the tool when a scan confirms every fix
      reopen_when_still_seen: true # reopened in the tool when closed there and still seen
    requests:                      # what a person may send from a dashboard (D18)
      targets: [itsm]
      levels: [ACT, ATTEND, TRACK]
      max_tickets: 50

Checked against `a2vm/schemas/dispatch.schema.json`; the credentials are never in this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from a2vm.io import load_schema

SCHEMA = "dispatch"
LEVELS = ("ACT", "ATTEND", "TRACK")
AUTOMATIC = {"none": (), "act": ("ACT",), "act-attend": ("ACT", "ATTEND")}
CONNECTOR_TYPES = ("itop",)


class RulesError(ValueError):
    pass


@dataclass
class Target:
    name: str
    type: str
    settings: dict[str, Any]


@dataclass
class Rules:
    mode: str = "dry-run"
    targets: dict[str, Target] = field(default_factory=dict)
    ticket_target: str | None = None
    automatic: str = "none"
    exclude_zones: tuple[str, ...] = ()
    resolve_when_fixed: bool = True
    reopen_when_still_seen: bool = True
    request_targets: tuple[str, ...] = ()
    request_levels: tuple[str, ...] = LEVELS
    max_tickets: int = 50

    @property
    def live(self) -> bool:
        return self.mode == "live"

    @property
    def automatic_levels(self) -> tuple[str, ...]:
        return AUTOMATIC[self.automatic] if self.ticket_target else ()

    def dispatchable(self, zone: str) -> bool:
        return zone not in self.exclude_zones

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "dispatch.yaml") -> Rules:
        errors = sorted(
            jsonschema.Draft202012Validator(load_schema(SCHEMA)).iter_errors(data), key=lambda e: list(e.absolute_path)
        )
        if errors:
            path = "/".join(str(p) for p in errors[0].absolute_path) or "<root>"
            raise RulesError(f"{where}: {path}: {errors[0].message}")
        targets = {
            name: Target(name, t["type"], {k: v for k, v in t.items() if k != "type"})
            for name, t in (data.get("targets") or {}).items()
        }
        tickets = data.get("tickets") or {}
        requests = data.get("requests") or {}
        out = cls(
            mode=data.get("mode", "dry-run"),
            targets=targets,
            ticket_target=tickets.get("target"),
            automatic=tickets.get("automatic", "act"),
            exclude_zones=tuple(tickets.get("exclude_zones") or ()),
            resolve_when_fixed=bool(tickets.get("resolve_when_fixed", True)),
            reopen_when_still_seen=bool(tickets.get("reopen_when_still_seen", True)),
            request_targets=tuple(requests.get("targets") or ()),
            request_levels=tuple(requests.get("levels") or LEVELS),
            max_tickets=int(requests.get("max_tickets", 50)),
        )
        for name in (out.ticket_target, *out.request_targets):
            if name and name not in targets:
                raise RulesError(f"{where}: target {name!r} is not declared under `targets`")
        return out


def load_rules(path: str | Path | None) -> Rules:
    """The tenant's rules; without a file, nothing leaves (no target)."""
    if not path or not Path(path).exists():
        return Rules()
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RulesError(f"{path}: not YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RulesError(f"{path}: a mapping is expected")
    return Rules.from_dict(data, str(path))
