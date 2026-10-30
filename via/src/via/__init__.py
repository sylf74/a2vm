# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""VIA, pillar 1: Vulnerability Intelligence — Advanced, AI-assisted, Alerting.

intel builds one vulnerability record per CVE; alert watches each client's estate and drafts alert
sheets. VIA depends on a2vm only: asset matching (a2vm.declared) and the remediation delay
(a2vm.ssvc) are common libraries, so the watch runs in the via image alone.
"""

__version__ = "0.17.0"
