# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Remediation timeline offered to the other pillars (entry point a2vm.remediation_timeline)."""

from __future__ import annotations

from a2vm.config import Settings
from a2vm.models import VulnRecord

from . import ssvc
from .rationale import BOD_FR
from .triage import Triage


def remediation_timeline(settings: Settings, record: VulnRecord, publicly_exposed: bool) -> str:
    """CISA BOD 26-04 delay for one record, in French, on an asset exposed or not."""
    inputs = Triage(settings).cve_inputs(record)
    bod = ssvc.bod_timeline(record.in_kev, publicly_exposed, inputs.automatable.value, inputs.technical_impact.value)
    return BOD_FR[bod]
