# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""iTop (LLD dispatch §5.2): remediation tickets as user requests, over the REST API 1.3.

A local account of its own (not the read-only CMDB account of pillar 2), allowed to create and
update user requests in the tenant's organisation. The tickets come from a Person (`caller`), may
be given to a Team (`team`), and are linked to the CMDB item of their asset when it is known.

  create   core/create UserRequest: org_id, caller_id, team_id, title, description (HTML), impact,
           urgency (from the priority of the client's SLA when `priorities` maps it, v0.21.0, else from
           the level), functionalcis_list
  comment  core/update: an entry in public_log
  resolve  core/apply_stimulus ev_resolve (solution, resolution_code "software patch")
  reopen   core/apply_stimulus ev_reopen
  status   core/get: status (new, assigned, pending, escalated_tto, escalated_ttr, resolved, closed)
  declared core/get: resolution_date, the day the team says it fixed (v0.22.2), verified by a scan
  due      core/update of the field `due_field` (an extension's date field, v0.22.2): the due date
           A2VM computed (the client's SLA, else BOD 26-04), on create and whenever it changes
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from a2vm import tls

from ..rules import Target
from ..tickets import Ticket
from . import CLOSED, GONE, WORKING, ConnectorError, External

# Level -> (impact, urgency) of iTop: impact 2 a service, 3 a person; urgency 1 critical .. 4 low.
PRIORITY = {"ACT": ("2", "1"), "ATTEND": ("3", "2"), "TRACK": ("3", "3")}
CLOSED_STATUSES = {"resolved", "closed", "rejected"}


class ItopConnector:
    def __init__(
        self,
        target: Target,
        password: str,
        ca_file: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        s = target.settings
        self.url = str(s["url"]).rstrip("/")
        self.user = str(s["user"])
        self.organization = str(s["organization"])
        self.caller = str(s["caller"])
        # v0.23.3: the caller is looked for in one organisation (that of the tickets, else
        # `caller_organization`), by its e-mail when `caller` holds an @: iTop refuses a name that
        # several persons carry ("Several items found").
        self.caller_organization = str(s.get("caller_organization") or self.organization)
        self.team = str(s.get("team") or "")
        self.cls = str(s.get("class") or "UserRequest")
        # Priority of the client's SLA -> (impact, urgency) (v0.21.0); else those of the level.
        self.priorities = {
            str(k): (str(v["impact"]), str(v["urgency"])) for k, v in (s.get("priorities") or {}).items()
        }
        # The ticket's field that receives A2VM's due date (v0.22.2); "" (default): not pushed.
        self.due_field = str(s.get("due_field") or "")
        self._password = password
        self.http = httpx.Client(
            timeout=httpx.Timeout(float(s.get("timeout_seconds", 60)), connect=10.0),
            verify=tls.verify(ca_file),
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    # -- REST ------------------------------------------------------------------------------------
    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            r = self.http.post(
                f"{self.url}/webservices/rest.php",
                params={"version": "1.3"},
                data={"auth_user": self.user, "auth_pwd": self._password, "json_data": json.dumps(payload)},
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"iTop not reached: {exc}") from exc
        if r.status_code != 200:
            raise ConnectorError(f"iTop answered {r.status_code}", retry=r.status_code >= 500)
        try:
            data = r.json()
        except ValueError as exc:
            raise ConnectorError("iTop answered something else than JSON (URL, sign-in page)", retry=False) from exc
        if data.get("code") != 0:
            raise ConnectorError(f"iTop refused: code {data.get('code')}: {data.get('message')}", retry=False)
        return data

    def _object(self, data: dict[str, Any]) -> dict[str, Any]:
        objects = list((data.get("objects") or {}).values())
        if not objects:
            raise ConnectorError("iTop answered without the object", retry=False)
        obj = objects[0]
        if obj.get("code", 0) != 0:
            raise ConnectorError(f"iTop refused: {obj.get('message')}", retry=False)
        return obj

    def _url(self, key: str) -> str:
        return f"{self.url}/pages/UI.php?operation=details&class={self.cls}&id={key}"

    @staticmethod
    def _key(external: External) -> str:
        return external.ref.split("::", 1)[-1]

    # -- connector ---------------------------------------------------------------------------------
    def create(self, ticket: Ticket, text: str, title: str) -> External:
        impact, urgency = self.priorities.get(ticket.priority) or PRIORITY.get(ticket.level, PRIORITY["TRACK"])
        fields: dict[str, Any] = {
            "org_id": {"name": self.organization},
            "caller_id": self.caller_criteria(),
            "title": title,
            "description": text,
            "impact": impact,
            "urgency": urgency,
        }
        if self.team:
            fields["team_id"] = {"name": self.team}
        if ticket.cmdb.get("key"):
            fields["functionalcis_list"] = [{"functionalci_id": int(ticket.cmdb["key"])}]
        if self.due_field and ticket.due:
            fields[self.due_field] = ticket.due
        data = self._call(
            {
                "operation": "core/create",
                "comment": "A2VM",
                "class": self.cls,
                "output_fields": "id,ref,status",
                "fields": fields,
            }
        )
        obj = self._object(data)
        key = str(obj.get("key") or (obj.get("fields") or {}).get("id"))
        status = str((obj.get("fields") or {}).get("status") or "new")
        ref = (obj.get("fields") or {}).get("ref") or ""
        return External(ref=f"{self.cls}::{key}", url=self._url(key), status=f"{status} {ref}".strip())

    def check(self) -> str:
        """What stops the tickets before any is sent (v0.23.19): the caller must be one Person of its
        organisation. "" when it is; else what to change."""
        key = "email" if "@" in self.caller else "name"

        def q(v: str) -> str:
            return v.replace("\\", "\\\\").replace("'", "\\'")

        oql = f"SELECT Person WHERE {key} = '{q(self.caller)}' AND org_name = '{q(self.caller_organization)}'"
        data = self._call({"operation": "core/get", "class": "Person", "key": oql, "output_fields": "id"})
        n = len(data.get("objects") or {})
        if n == 1:
            return ""
        where = f"{key} {self.caller!r} in {self.caller_organization!r}"
        if n == 0:
            return f"iTop: no Person with {where}: no ticket can be created (dispatch.yaml `caller`)"
        return (
            f'iTop: {n} Persons with {where}: iTop refuses every ticket ("Several items found"); keep one, '
            "or give `caller` the e-mail of one of them"
        )

    def caller_criteria(self) -> dict[str, str]:
        """The iTop Person the tickets come from: its e-mail or its name, in its organisation."""
        key = "email" if "@" in self.caller else "name"
        return {key: self.caller, "org_name": self.caller_organization}

    def comment(self, external: External, text: str) -> None:
        self._call(
            {
                "operation": "core/update",
                "comment": "A2VM",
                "class": self.cls,
                "key": int(self._key(external)),
                "output_fields": "id",
                "fields": {"public_log": text},
            }
        )

    def set_due(self, external: External, due: str) -> bool:
        """Write A2VM's due date into the ticket's `due_field`; False when no field is set."""
        if not self.due_field:
            return False
        self._call(
            {
                "operation": "core/update",
                "comment": "A2VM",
                "class": self.cls,
                "key": int(self._key(external)),
                "output_fields": "id",
                "fields": {self.due_field: due},
            }
        )
        return True

    def declared_fix(self, external: External) -> str:
        """The day the team resolved the ticket in iTop (resolution_date), "" when none."""
        data = self._call(
            {
                "operation": "core/get",
                "class": self.cls,
                "key": int(self._key(external)),
                "output_fields": "resolution_date",
            }
        )
        objects = list((data.get("objects") or {}).values())
        value = str((objects[0].get("fields") or {}).get("resolution_date") or "") if objects else ""
        return value.replace(" ", "T") if value and not value.startswith("0000") else ""

    def _stimulus(self, external: External, stimulus: str, fields: dict[str, Any]) -> None:
        self._call(
            {
                "operation": "core/apply_stimulus",
                "comment": "A2VM",
                "class": self.cls,
                "key": int(self._key(external)),
                "stimulus": stimulus,
                "output_fields": "id,status",
                "fields": fields,
            }
        )

    def resolve(self, external: External, text: str) -> None:
        self._stimulus(external, "ev_resolve", {"solution": text, "resolution_code": "software patch"})

    def reopen(self, external: External, text: str) -> None:
        self._stimulus(external, "ev_reopen", {})
        self.comment(external, text)

    def status(self, external: External) -> tuple[str, str]:
        data = self._call(
            {
                "operation": "core/get",
                "class": self.cls,
                "key": int(self._key(external)),
                "output_fields": "status,ref",
            }
        )
        objects = list((data.get("objects") or {}).values())
        if not objects:
            return "", GONE
        status = str((objects[0].get("fields") or {}).get("status") or "")
        return status, CLOSED if status in CLOSED_STATUSES else WORKING
