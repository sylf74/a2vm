# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Connectors of pillar 4 (LLD dispatch §5): each maps a ticket to one tool's fields and back, and
nothing else (no rule, no decision). The credentials are read from files of the tenant's Secret."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..rules import Target
from ..tickets import Ticket


class ConnectorError(RuntimeError):
    """The tool refused or could not be reached; `retry`: worth trying again at the next run."""

    def __init__(self, message: str, retry: bool = True):
        super().__init__(message)
        self.retry = retry


@dataclass
class External:
    ref: str  # the tool's reference, e.g. UserRequest::42
    url: str = ""
    status: str = ""  # the tool's own status, as last read

    def to_dict(self) -> dict[str, str]:
        return {"ref": self.ref, "url": self.url, "status": self.status}


# NGVM's view of a tool's status.
CLOSED = "closed"  # resolved or closed by the team
WORKING = "working"  # new, assigned, pending...
GONE = "gone"  # the tool no longer knows the ticket


class Connector(Protocol):
    def create(self, ticket: Ticket, text: str, title: str) -> External: ...
    def comment(self, external: External, text: str) -> None: ...
    def resolve(self, external: External, text: str) -> None: ...
    def reopen(self, external: External, text: str) -> None: ...
    def status(self, external: External) -> tuple[str, str]: ...  # (the tool's status, CLOSED|WORKING|GONE)
    def close(self) -> None: ...

    # Optional (v0.22.2): `declared_fix(external) -> str`, the date the team says it fixed; and
    # `set_due(external, due) -> bool`, NGVM's due date written into the ticket.


def secret_file(directory: str | Path, name: str) -> str:
    path = Path(directory) / name
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConnectorError(f"secret {name}: {exc.strerror or exc}", retry=False) from exc
    if not value:
        raise ConnectorError(f"secret {name} is empty", retry=False)
    return value


def make(target: Target, secrets_dir: str | Path, **kwargs: Any) -> Connector:
    """The connector of a target; its credential is the secret `dispatch-<target name>`, the CA of
    its certificate, when private, `dispatch-<target name>-ca`."""
    if target.type == "itop":
        from .itop import ItopConnector

        ca = Path(secrets_dir) / f"dispatch-{target.name}-ca"
        kwargs.setdefault("ca_file", str(ca) if ca.is_file() and ca.stat().st_size else None)
        return ItopConnector(target, secret_file(secrets_dir, f"dispatch-{target.name}"), **kwargs)
    raise ConnectorError(f"target {target.name}: unknown type {target.type!r}", retry=False)
