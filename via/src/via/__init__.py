# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""VIA, pillar 1: Vulnerability Intelligence — Advanced, AI-assisted, Alerting.

intel builds one vulnerability record per CVE; alert watches each client's estate and drafts alert
sheets. VIA depends on ngvm only: asset matching (ngvm.declared) and the remediation delay
(ngvm.ssvc) are common libraries, so the watch runs in the via image alone.
"""

__version__ = "0.25.0"
