# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""Extension points between pillars.

The pillars (via, detect, verdict) never import one another: each depends on vulnops only. When a
pillar needs a capability owned by another one, it asks vulnops for it here, and the owner offers it
as a Python entry point in its pyproject.toml. The platform assembles them by installing the pillars
side by side; a pillar that is not installed simply offers nothing.

| Entry-point group             | Offered by | Used by   | What                                                     |
| ----------------------------- | ---------- | --------- | -------------------------------------------------------- |
| vulnops.asset_matcher         | detect     | via watch | factory(settings, llm) -> object with scan(profile, recs) |
| vulnops.remediation_timeline  | verdict    | via sheet | f(settings, record, publicly_exposed) -> French label    |
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any, Protocol

ASSET_MATCHER = "vulnops.asset_matcher"
REMEDIATION_TIMELINE = "vulnops.remediation_timeline"


class ExtensionMissing(RuntimeError):
    """A required capability is offered by no installed pillar."""


class AssetMatcher(Protocol):
    def scan(self, profile: Any, records: Any) -> Any: ...


def _load(group: str) -> Any | None:
    found = sorted(entry_points(group=group), key=lambda ep: ep.name)
    return found[0].load() if found else None


def asset_matcher(settings: Any, llm: Any = None) -> AssetMatcher:
    factory = _load(ASSET_MATCHER)
    if factory is None:
        raise ExtensionMissing(f"no installed pillar offers {ASSET_MATCHER} (install detect)")
    return factory(settings, llm)


def remediation_timeline() -> Callable[[Any, Any, bool], str] | None:
    """The recommended remediation delay of a record, or None when no pillar offers it."""
    return _load(REMEDIATION_TIMELINE)
