# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The tenant's CMDB as a detection source (`cmdb`, LLD vulnerability-detection §3.5): iTop first.

Reads the configuration items over the iTop REST API (`core/get` only: the client refuses any
other operation) and turns each one with a network identity into an asset observation: its name,
its addresses (management IP and those of its interfaces), and in `identifiers.cmdb` its class,
key, status, business criticality, organisation and type. Its criticality and owner go into the
observation's attributes, which the asset context of pillar 3 takes after a declaration of the
profile and before the profile's rules. A CMDB observation carries no finding.

Two root classes are read by default, PhysicalDevice and VirtualDevice, so that every subclass
comes along (Server, VirtualMachine, NetworkDevice, PC, Printer, NAS, IoTDevice of the extension
`deploy/itop/a2vm-iot-device`...), less the classes without a network existence (racks,
enclosures, power, farms). A Hypervisor linked to its Server is left out: the Server is that
machine.

A NetworkDevice with its brand and IOS version (`brand_name`, `model_name`, `iosversion_name`) also
carries its firmware as a component (v0.23.6, `detect.firmware`): the watch matches it against the
CVE records and the vendors' advisories, like the firmware an SNMP connector reads.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from a2vm.io import Detection, now
from a2vm.models import AssetObservation

from .firmware import from_cmdb

SOURCE = "cmdb"
DEFAULT_CLASSES = ("PhysicalDevice", "VirtualDevice")
EXCLUDED_CLASSES = ("Rack", "Enclosure", "PowerConnection", "PowerSource", "PDU", "Farm")
# iTop business_criticity -> SSVC Mission Prevalence (LLD triage §14.3).
CRITICALITY = {"high": "essential", "medium": "support", "low": "minimal"}
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
FQDN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")
READ_ONLY = "core/get"


class CmdbError(RuntimeError):
    pass


@dataclass
class ItopConfig:
    """Settings of an `itop` connector (collector.yaml) or of `detect cmdb fetch`."""

    url: str
    user: str
    password_file: str
    ca_file: str | None = None
    organization: str | None = None  # only the CIs of this organisation (name); all when absent
    classes: list[str] = field(default_factory=lambda: list(DEFAULT_CLASSES))
    exclude_classes: list[str] = field(default_factory=lambda: list(EXCLUDED_CLASSES))
    timeout_seconds: float = 60.0

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "itop") -> ItopConfig:
        unknown = set(data) - set(cls.__dataclass_fields__) - {"name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("url", "user", "password_file"):
            if not data.get(key):
                raise ValueError(f"{where}: `{key}` is required")
        if not str(data["url"]).startswith(("https://", "http://")):
            raise ValueError(f"{where}: `url` must be an http(s) URL")
        out = cls(
            url=str(data["url"]).rstrip("/"),
            user=str(data["user"]),
            password_file=str(data["password_file"]),
            ca_file=data.get("ca_file"),
            organization=data.get("organization"),
            timeout_seconds=float(data.get("timeout_seconds", 60)),
        )
        if data.get("classes"):
            out.classes = [str(c) for c in data["classes"]]
        if "exclude_classes" in data:
            out.exclude_classes = [str(c) for c in data.get("exclude_classes") or []]
        for name in (*out.classes, *out.exclude_classes):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
                raise ValueError(f"{where}: {name!r} is not a class name")
        return out

    def password(self) -> str:
        try:
            value = Path(self.password_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise CmdbError(f"password_file {self.password_file}: {exc}") from exc
        if not value:
            raise CmdbError(f"password_file {self.password_file} is empty")
        return value


class ItopClient:
    """The REST API of iTop, read only: every request is a `core/get`."""

    def __init__(self, cfg: ItopConfig, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        verify: Any = cfg.ca_file or True
        self.http = httpx.Client(timeout=cfg.timeout_seconds, verify=verify, transport=transport)

    def close(self) -> None:
        self.http.close()

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("operation") != READ_ONLY:  # A2VM never writes to a CMDB
            raise CmdbError(f"refused: operation {payload.get('operation')!r}, the CMDB is read only")
        try:
            response = self.http.post(
                f"{self.cfg.url}/webservices/rest.php",
                params={"version": "1.3"},
                data={"auth_user": self.cfg.user, "auth_pwd": self.cfg.password(), "json_data": json.dumps(payload)},
            )
        except httpx.HTTPError as exc:
            raise CmdbError(f"iTop not reached: {exc}") from exc
        if response.status_code != 200:
            raise CmdbError(f"iTop answered {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise CmdbError("iTop answered something else than JSON (wrong URL, or a sign-in page)") from exc
        if data.get("code") != 0:
            raise CmdbError(f"iTop refused: code {data.get('code')}: {data.get('message')}")
        return data

    def get(self, oql: str, fields: str = "*+") -> list[tuple[str, str, dict[str, Any]]]:
        """(class, key, fields) of every object the OQL query selects."""
        data = self._call({"operation": READ_ONLY, "class": oql.split()[1], "key": oql, "output_fields": fields})
        out = []
        for obj in (data.get("objects") or {}).values():
            out.append((str(obj.get("class", "")), str(obj.get("key", "")), dict(obj.get("fields") or {})))
        return out


def _oql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _ips(fields: dict[str, Any]) -> list[str]:
    values = [fields.get("managementip") or ""]
    for key in ("physicalinterface_list", "logicalinterface_list"):
        for interface in fields.get(key) or []:
            if isinstance(interface, dict):
                values.append(interface.get("ipaddress") or "")
    out = []
    for value in values:
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
            out.append(str(ip))
    return list(dict.fromkeys(out))


def _owner(fields: dict[str, Any]) -> str:
    contacts = [c.get("contact_name", "") for c in fields.get("contacts_list") or [] if isinstance(c, dict)]
    contacts = [c for c in contacts if c]
    return sorted(contacts)[0] if contacts else str(fields.get("organization_name") or "")


def observation(cls: str, key: str, fields: dict[str, Any], observed_at: str) -> AssetObservation | None:
    """One configuration item -> one host observation; None for an item without a name."""
    name = str(fields.get("name") or "").strip()
    if not name:
        return None
    identifiers: dict[str, Any] = {}
    lowered = name.lower()
    if FQDN.match(name):
        identifiers["fqdn"] = lowered
        identifiers["hostname"] = lowered.split(".")[0]
    elif HOSTNAME.match(name):
        identifiers["hostname"] = lowered
    ips = _ips(fields)
    if ips:
        identifiers["ips"] = ips
    final = str(fields.get("finalclass") or cls)
    item_type = fields.get("device_type") or fields.get("networkdevicetype_name") or fields.get("type") or ""
    identifiers["cmdb"] = {
        "class": final,
        "key": key,
        "status": str(fields.get("status") or ""),
        "criticality": str(fields.get("business_criticity") or ""),
        "organization": str(fields.get("organization_name") or ""),
        "type": str(item_type),
    }
    attributes = {}
    prevalence = CRITICALITY.get(str(fields.get("business_criticity") or "").lower())
    if prevalence:
        attributes["mission_prevalence"] = prevalence
    owner = _owner(fields)
    if owner:
        attributes["owner"] = owner
    os_name = " ".join(str(fields.get(k) or "") for k in ("osfamily_name", "osversion_name")).strip()
    description = str(fields.get("description") or "").strip() or f"{final} {name} (CMDB)"
    firmware = None
    if fields.get("iosversion_name"):  # a NetworkDevice: its firmware, when the CMDB knows it
        firmware = from_cmdb(
            str(fields.get("brand_name") or ""), str(fields.get("model_name") or ""), str(fields["iosversion_name"])
        )
        if firmware and not os_name:
            os_name = f"{firmware.vendor} {firmware.product} {firmware.version}".strip()
    return AssetObservation(
        ref=f"{final}::{key}",
        kind="host",
        source=SOURCE,
        observed_at=observed_at,
        name=identifiers.get("hostname") or name,
        description=description.splitlines()[0][:300],
        identifiers=identifiers,
        attributes=attributes,
        os=os_name or None,
        components=[firmware.component(SOURCE)] if firmware else [],
    )


def fetch(cfg: ItopConfig, tenant: str, client: ItopClient | None = None, log=print) -> Detection:
    """Every CI of the configured classes, as one detection of source `cmdb` (no finding)."""
    own = client is None
    client = client or ItopClient(cfg)
    observed_at = now()
    seen: dict[str, AssetObservation] = {}
    skipped: dict[str, int] = {}
    try:
        for cls in cfg.classes:
            oql = f"SELECT {cls}"
            if cfg.organization:
                oql += f" WHERE organization_name = {_oql_string(cfg.organization)}"
            items = client.get(oql)
            log(f"cmdb: {cls}: {len(items)} items")
            for item_cls, key, fields in items:
                final = str(fields.get("finalclass") or item_cls)
                if final in cfg.exclude_classes:
                    skipped[f"class {final}"] = skipped.get(f"class {final}", 0) + 1
                    continue
                if final == "Hypervisor" and str(fields.get("server_id") or "0") not in ("", "0"):
                    skipped["hypervisor of a server"] = skipped.get("hypervisor of a server", 0) + 1
                    continue
                obs = observation(final, key, fields, observed_at)
                if obs is None:
                    skipped["item without a name"] = skipped.get("item without a name", 0) + 1
                    continue
                seen.setdefault(obs.ref, obs)
    finally:
        if own:
            client.close()
    return Detection(tenant, SOURCE, sorted(seen.values(), key=lambda o: o.ref), [], skipped=skipped)


# -- seed file for the CMDB ------------------------------------------------------------------------
EXPORT_COLUMNS = ["name", "org_id->name", "status", "managementip", "business_criticity", "description"]


def export_candidates(triage: dict[str, Any], organization: str) -> list[dict[str, str]]:
    """Hosts scanned but not in the CMDB, from a triage document (`a2vm.triage/1`), as rows for the
    CSV import of iTop: a person checks them, chooses their class and imports them. A2VM itself
    never writes to the CMDB.

    With a coverage section (v0.19.0), the assets in state `not-in-cmdb`; without, every host."""
    coverage = triage.get("coverage") or {}
    wanted = {c["asset"] for c in coverage.get("assets", []) if c.get("state") == "not-in-cmdb"}
    rows = []
    for asset in triage.get("assets") or []:
        if asset.get("kind") != "host" or (coverage and asset["id"] not in wanted):
            continue
        scans = asset.get("scans") or {}
        ips = asset.get("ips") or (asset.get("identifiers") or {}).get("ips") or []
        authenticated = any(s in scans for s in ("trivy", "dnf-updateinfo"))
        rows.append(
            {
                "name": asset.get("name") or asset["id"].split(":", 1)[-1],
                "org_id->name": organization,
                "status": "production",
                "managementip": ips[0] if ips else "",
                "business_criticity": "",
                "description": "; ".join(
                    part
                    for part in (
                        f"seen by {', '.join(sorted(scans))}" if scans else "",
                        f"OS: {asset['os']}" if asset.get("os") else "",
                        "likely a server or a virtual machine (scanned with an account)" if authenticated else "",
                        f"addresses: {', '.join(ips)}" if len(ips) > 1 else "",
                    )
                    if part
                ),
            }
        )
    return sorted(rows, key=lambda r: r["name"])
