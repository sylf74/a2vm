# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Appliances and network devices by SNMP (`snmp`, HLD D20, v0.23.6, LLD vulnerability-detection §3.9).

A switch, a router, a firewall or a load balancer has no package an SSH collection could list. What
it says of itself over SNMP is enough to know its exact version: sysDescr, sysObjectID, sysName and,
for some vendors, their own version object (Fortinet, Palo Alto Networks, MikroTik). The connector
reads these few objects on each target, turns them into one component of type `firmware`
(`detect.firmware`) and one observation of the device. It finds no CVE itself: the watch matches the
firmware against the affected ranges of the CVE records and of the vendors' CSAF advisories, with the
level of proof `embedded`. It is not a scan: a device seen by SNMP is not counted as scanned.

Read only: GET requests of a handful of objects, nothing else. SNMPv3 with authentication and
privacy is the default (`authPriv`); SNMPv2c with a community is accepted for old devices. The
secrets are files of the collector, read when the connector runs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from a2vm.io import Detection, now
from a2vm.models import AssetObservation

from .firmware import SYS_DESCR, SYS_NAME, SYS_OBJECT_ID, VENDOR_VERSION, from_snmp

SOURCE = "snmp"
MAX_ADDRESSES = 4096  # the targets of one connector, networks expanded
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")
AUTH = ("sha", "sha224", "sha256", "sha384", "sha512", "md5")
PRIV = ("aes", "aes192", "aes256", "des", "3des", "none")

# One query: (target, oids) -> {oid: value}; empty when the device does not answer.
Query = Callable[[str, list[str]], Awaitable[dict[str, str]]]


class SnmpError(RuntimeError):
    pass


@dataclass
class SnmpConfig:
    """Settings of an `snmp` connector (collector.yaml) or of `detect snmp fetch`."""

    targets: list[str]  # addresses, names or networks (CIDR)
    version: str = "3"  # 3 | 2c
    user: str = ""
    auth_protocol: str = "sha256"
    auth_password_file: str = ""
    priv_protocol: str = "aes"
    priv_password_file: str = ""
    community_file: str = ""  # SNMPv2c only
    port: int = 161
    timeout_seconds: float = 2.0
    retries: int = 1
    concurrency: int = 32
    exclude: list[str] = field(default_factory=list)  # addresses or networks left out

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "snmp") -> SnmpConfig:
        unknown = set(data) - set(cls.__dataclass_fields__) - {"name", "type"}
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        targets = data.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"{where}: `targets` is a list of addresses, names or networks")
        version = str(data.get("version", "3"))
        if version not in ("3", "2c"):
            raise ValueError(f"{where}: `version` is 3 or 2c")
        if version == "3":
            for key in ("user", "auth_password_file"):
                if not data.get(key):
                    raise ValueError(f"{where}: `{key}` is required with SNMPv3")
            if str(data.get("priv_protocol", "aes")) != "none" and not data.get("priv_password_file"):
                raise ValueError(f"{where}: `priv_password_file` is required (or priv_protocol: none)")
        elif not data.get("community_file"):
            raise ValueError(f"{where}: `community_file` is required with SNMPv2c")
        auth, priv = str(data.get("auth_protocol", "sha256")).lower(), str(data.get("priv_protocol", "aes")).lower()
        if auth not in AUTH:
            raise ValueError(f"{where}: `auth_protocol` is one of {', '.join(AUTH)}")
        if priv not in PRIV:
            raise ValueError(f"{where}: `priv_protocol` is one of {', '.join(PRIV)}")
        cfg = cls(
            targets=[str(t).strip() for t in targets],
            version=version,
            user=str(data.get("user", "")),
            auth_protocol=auth,
            auth_password_file=str(data.get("auth_password_file", "")),
            priv_protocol=priv,
            priv_password_file=str(data.get("priv_password_file", "")),
            community_file=str(data.get("community_file", "")),
            port=int(data.get("port", 161)),
            timeout_seconds=float(data.get("timeout_seconds", 2.0)),
            retries=int(data.get("retries", 1)),
            concurrency=max(1, min(int(data.get("concurrency", 32)), 256)),
            exclude=[str(x).strip() for x in data.get("exclude") or []],
        )
        cfg.addresses()  # the targets are checked now, not when the collector runs
        return cfg

    def addresses(self) -> list[str]:
        """The targets, networks expanded (their hosts), without the excluded ones, at most MAX_ADDRESSES."""
        excluded = [ipaddress.ip_network(x, strict=False) for x in self.exclude]
        out: dict[str, None] = {}
        for t in self.targets:
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                except ValueError as exc:
                    raise ValueError(f"snmp: target {t!r}: {exc}") from None
                if net.num_addresses > MAX_ADDRESSES:
                    raise ValueError(f"snmp: target {t}: more than {MAX_ADDRESSES} addresses")
                hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
            elif HOSTNAME.match(t) or _is_ip(t):
                hosts = [t]
            else:
                raise ValueError(f"snmp: target {t!r} is not an address, a name or a network")
            for h in hosts:
                if _is_ip(h) and any(ipaddress.ip_address(h) in n for n in excluded):
                    continue
                out[h] = None
        if len(out) > MAX_ADDRESSES:
            raise ValueError(f"snmp: more than {MAX_ADDRESSES} addresses in the targets")
        return list(out)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _secret(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SnmpError(f"cannot read {path}: {exc.strerror or exc}") from None


def pysnmp_query(cfg: SnmpConfig) -> Query:
    """The query by pysnmp (extra `snmp` of the detect package): GET of the given objects."""
    try:
        from pysnmp.hlapi.v3arch import asyncio as h
    except ImportError as exc:  # pragma: no cover - the extra is installed in the image
        raise SnmpError("pysnmp is missing: install detect[snmp]") from exc
    if cfg.version == "2c":
        auth: Any = h.CommunityData(_secret(cfg.community_file), mpModel=1)
    else:
        protocols = {
            "md5": h.usmHMACMD5AuthProtocol, "sha": h.usmHMACSHAAuthProtocol,
            "sha224": h.usmHMAC128SHA224AuthProtocol, "sha256": h.usmHMAC192SHA256AuthProtocol,
            "sha384": h.usmHMAC256SHA384AuthProtocol, "sha512": h.usmHMAC384SHA512AuthProtocol,
        }  # fmt: skip
        privs = {
            "aes": h.usmAesCfb128Protocol, "aes192": h.usmAesCfb192Protocol, "aes256": h.usmAesCfb256Protocol,
            "des": h.usmDESPrivProtocol, "3des": h.usm3DESEDEPrivProtocol, "none": h.usmNoPrivProtocol,
        }  # fmt: skip
        auth = h.UsmUserData(
            cfg.user,
            authKey=_secret(cfg.auth_password_file),
            privKey=_secret(cfg.priv_password_file) if cfg.priv_protocol != "none" else None,
            authProtocol=protocols[cfg.auth_protocol],
            privProtocol=privs[cfg.priv_protocol],
        )
    engine = h.SnmpEngine()

    async def query(target: str, oids: list[str]) -> dict[str, str]:
        transport_class = h.Udp6TransportTarget if ":" in target else h.UdpTransportTarget
        try:
            transport = await transport_class.create(
                (target, cfg.port), timeout=cfg.timeout_seconds, retries=cfg.retries
            )
        except Exception:  # noqa: BLE001 - a name that does not resolve: the device is not reached
            return {}
        error, status, _index, binds = await h.get_cmd(
            engine, auth, transport, h.ContextData(), *[h.ObjectType(h.ObjectIdentity(o)) for o in oids]
        )
        if error or status:
            return {}
        out: dict[str, str] = {}
        for name, value in binds:
            if value.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                continue
            out[str(name).lstrip(".")] = value.prettyPrint()
        return out

    return query


async def _read(target: str, query: Query) -> dict[str, str]:
    """The system objects of one device, then its vendor's version object when sysDescr has none."""
    values = await query(target, [SYS_DESCR, SYS_OBJECT_ID, SYS_NAME])
    if not values:
        return {}
    oid = values.get(SYS_OBJECT_ID, "").lstrip(".")
    for enterprise, version_oid in VENDOR_VERSION.items():
        if oid.startswith(f"1.3.6.1.4.1.{enterprise}.") or oid == f"1.3.6.1.4.1.{enterprise}":
            values.update(await query(target, [version_oid]))
    return values


def observation(target: str, values: dict[str, str], observed_at: str) -> AssetObservation | None:
    """One device as an observation of source snmp, with its firmware as component."""
    descr = values.get(SYS_DESCR, "").strip()
    if not descr:
        return None
    firmware = from_snmp(values)
    name = values.get(SYS_NAME, "").strip() or target
    identifiers: dict[str, Any] = {}
    if _is_ip(target):
        identifiers["ips"] = [target]
    short = name.split(".")[0]
    if HOSTNAME.match(short) and not _is_ip(name):
        identifiers["hostname"] = short.lower()
        if "." in name:
            identifiers["fqdn"] = name.lower()
    attributes = {"snmp_object_id": values.get(SYS_OBJECT_ID, "").lstrip(".")} if values.get(SYS_OBJECT_ID) else {}
    return AssetObservation(
        ref=f"snmp:{target}",
        kind="host",
        source=SOURCE,
        observed_at=observed_at,
        name=name,
        description=descr[:500],
        identifiers=identifiers,
        attributes=attributes,
        os=f"{firmware.vendor} {firmware.product} {firmware.version}".strip() if firmware else None,
        components=[firmware.component(SOURCE)] if firmware else [],
    )


def fetch(
    cfg: SnmpConfig,
    tenant: str,
    query: Query | None = None,
    log: Callable[[str], None] = print,
) -> Detection:
    """Every target that answers, as one detection of source snmp (observations only, no finding)."""
    query = query or pysnmp_query(cfg)
    targets = cfg.addresses()
    observed_at = now()

    async def run() -> list[tuple[str, dict[str, str]]]:
        gate = asyncio.Semaphore(cfg.concurrency)

        async def one(t: str) -> tuple[str, dict[str, str]]:
            async with gate:
                return t, await _read(t, query)

        return await asyncio.gather(*(one(t) for t in targets))

    observations: list[AssetObservation] = []
    skipped: dict[str, int] = {}
    for target, values in asyncio.run(run()):
        if not values:
            skipped["no answer"] = skipped.get("no answer", 0) + 1
            continue
        obs = observation(target, values, observed_at)
        if obs is None:
            skipped["no sysDescr"] = skipped.get("no sysDescr", 0) + 1
            continue
        observations.append(obs)
    with_firmware = sum(1 for o in observations if o.components)
    log(f"snmp: {len(targets)} targets, {len(observations)} devices, firmware known on {with_firmware}")
    return Detection(tenant, SOURCE, sorted(observations, key=lambda o: o.ref), [], skipped=skipped)
