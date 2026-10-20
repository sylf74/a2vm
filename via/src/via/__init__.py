# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""VIA, pillar 1: Vulnerability Intelligence — Advanced, AI-assisted, Alerting.

intel builds one vulnerability record per CVE; alert watches each client's estate and drafts alert
sheets. VIA depends on vulnops only; asset matching and remediation delays come from the other
pillars through vulnops.extensions.
"""

__version__ = "0.10.0"
