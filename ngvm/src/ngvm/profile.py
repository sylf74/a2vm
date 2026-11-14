# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Load and validate client profiles (client.yaml of each client project)."""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from . import sla as sla_policy
from .io import load_schema
from .models import (
    DEFAULT_EXPECTED,
    LEGACY_EXPOSURE,
    AttributeRule,
    ClientProfile,
    CoveragePolicy,
    DeclaredAsset,
    ExternalScan,
    Flow,
    PublishedEndpoint,
    Zone,
    exposure_value,
    port_label,
)


class ProfileError(ValueError):
    pass


def _schema() -> dict[str, Any]:
    return load_schema("client_profile")


def _stringify_dates(value: Any) -> Any:
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _stringify_dates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_dates(v) for v in value]
    return value


def validate_profile_data(data: Any, source: str = "<profile>") -> list[str]:
    """Return a list of human-readable errors (empty when the profile is valid)."""
    validator = jsonschema.Draft202012Validator(_schema())
    errors = [
        f"{source}: {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]
    if not errors:
        seen: set[str] = set()
        for asset in data.get("assets", []):
            if asset["id"] in seen:
                errors.append(f"{source}: duplicate asset id {asset['id']!r}")
            seen.add(asset["id"])
        try:
            sla_policy.parse(data.get("sla"), f"{source}: sla")
        except sla_policy.SlaError as exc:
            errors.append(str(exc))
        errors += _zone_errors(data, source)
    return errors


def _zone_errors(data: dict[str, Any], source: str) -> list[str]:
    """Zones with a unique id and valid networks; flows between known zones (v0.24.0)."""
    errors: list[str] = []
    ids: set[str] = set()
    for zone in data.get("zones") or []:
        if zone["id"] in ids:
            errors.append(f"{source}: zones: duplicate zone {zone['id']!r}")
        ids.add(zone["id"])
        for net in zone.get("networks") or []:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                errors.append(f"{source}: zones: {zone['id']}: {net!r} is not a network (CIDR)")
    for i, flow in enumerate(data.get("flows") or []):
        for end in ("from", "to"):
            name = flow[end]
            if name == "*" or name in ids or (end == "from" and name == "internet"):
                continue
            errors.append(f"{source}: flows/{i}: {end} {name!r} is not a zone of `zones`")
        for port in flow.get("ports") or []:
            if not 1 <= int(str(port).split("/")[0]) <= 65535:
                errors.append(f"{source}: flows/{i}: port {port!r} out of range")
    return errors


def load_profile(path: str | Path) -> ClientProfile:
    path = Path(path)
    try:
        data = _stringify_dates(yaml.safe_load(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        raise ProfileError(f"{path}: invalid YAML: {exc}") from exc
    errors = validate_profile_data(data, str(path))
    if errors:
        raise ProfileError("\n".join(errors))
    warnings = _normalise_exposures(data)
    try:
        sla = sla_policy.parse(data.get("sla"), f"{path}: sla")
    except sla_policy.SlaError as exc:
        raise ProfileError(str(exc)) from exc
    assets = [DeclaredAsset(**a) for a in data.get("assets", [])]
    rules = [AttributeRule(**r) for r in data.get("rules", [])]
    client = data["client"]
    return ClientProfile(
        id=client["id"],
        name=client["name"],
        updated=client["updated"],
        assets=assets,
        rules=rules,
        defaults=dict(data.get("defaults", {})),
        source_path=str(path),
        alerts=dict(data.get("alerts", {})),
        warnings=warnings,
        external=ExternalScan(**data["external"]) if data.get("external") else None,
        published=[PublishedEndpoint(**p) for p in data.get("published", [])],
        language=client.get("language", "en"),
        coverage=_coverage(data.get("coverage") or {}),
        sla=sla,
        zones=[Zone(**z) for z in data.get("zones") or []],
        flows=[
            Flow(f["from"], f["to"], [port_label(p) for p in f.get("ports") or []], f.get("description", ""))
            for f in data.get("flows") or []
        ],
        off_premises_days=int(data.get("off_premises_days", 7)),
    )


def _coverage(data: dict[str, Any]) -> CoveragePolicy:
    """`coverage:` merged over the defaults: a class given replaces that class only."""
    expected = dict(DEFAULT_EXPECTED)
    expected.update({str(k): [str(v) for v in vals] for k, vals in (data.get("expected") or {}).items()})
    return CoveragePolicy(stale_days=int(data.get("stale_days", 7)), expected=expected)


def _normalise_exposures(data: dict[str, Any]) -> list[str]:
    """Rewrite the former exposure values (internet, internal, isolated) in place; one warning per value."""
    places = [*data.get("assets", []), *(r["set"] for r in data.get("rules", [])), data.get("defaults", {})]
    seen: dict[str, int] = {}
    for place in places:
        old = place.get("exposure")
        if old in LEGACY_EXPOSURE:
            place["exposure"] = exposure_value(old)
            seen[old] = seen.get(old, 0) + 1
    return [
        f"exposure '{old}' is deprecated, read as '{LEGACY_EXPOSURE[old]}' ({n} place{'s' if n > 1 else ''})"
        for old, n in sorted(seen.items())
    ]
