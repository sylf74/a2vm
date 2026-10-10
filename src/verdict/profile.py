"""Load and validate client profiles (clients/*.yaml)."""

from __future__ import annotations

import datetime as dt
import json
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .models import Asset, ClientProfile


class ProfileError(ValueError):
    pass


def _schema() -> dict[str, Any]:
    text = resources.files("verdict").joinpath("schemas", "client_profile.schema.json").read_text()
    return json.loads(text)


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
        for asset in data["assets"]:
            if asset["id"] in seen:
                errors.append(f"{source}: duplicate asset id {asset['id']!r}")
            seen.add(asset["id"])
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
    assets = [Asset(**a) for a in data["assets"]]
    client = data["client"]
    return ClientProfile(
        id=client["id"],
        name=client["name"],
        updated=client["updated"],
        assets=assets,
        source_path=str(path),
    )
