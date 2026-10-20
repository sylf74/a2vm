# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Client contacts (contacts.yaml of the client project): who receives which alerts, and in what role.

  schema_version: 1
  contacts:
    - {name: Jeanne Martin, role: RSSI, email: rssi@client.example}
    - {name: CERT client, role: CERT, email: cert@client.example}
    - {name: Paul Durand, role: DSI, email: dsi@client.example, receive: [urgent]}
    - {role: chef du SOC, email: soc@client.example, active: false, notes: "congés jusqu'au 3/11"}

`receive` (default: urgent and info) filters by alert level; `active: false` keeps a contact on
file without sending to it. The `alerts.recipients` of client.yaml still receive every alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import yaml

from a2vm.io import load_schema
from a2vm.models import ClientProfile


class ContactsError(ValueError):
    pass


@dataclass
class Contact:
    email: str
    name: str = ""
    role: str = ""
    receive: list[str] = field(default_factory=lambda: ["urgent", "info"])
    active: bool = True
    notes: str = ""

    def label(self) -> str:
        who = self.name or self.email
        return f"{who} ({self.role})" if self.role else who


def load_contacts(path: str | Path) -> list[Contact]:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ContactsError(f"{path}: invalid YAML: {exc}") from exc
    errors = sorted(
        jsonschema.Draft202012Validator(load_schema("contacts")).iter_errors(data), key=lambda e: list(e.absolute_path)
    )
    if errors:
        raise ContactsError(
            "\n".join(f"{path}: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors)
        )
    return [Contact(**c) for c in data["contacts"]]


def recipients(level: str, contacts: list[Contact], profile: ClientProfile) -> list[Contact]:
    """Contacts that receive an alert of this level, then the profile's plain recipients."""
    out = [c for c in contacts if c.active and level in c.receive]
    known = {c.email.lower() for c in out}
    for email in profile.alerts.get("recipients", []):
        if email.lower() not in known:
            out.append(Contact(email))
            known.add(email.lower())
    return out
