# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Decision service of pillar 3, read side first (HLD D15 step 3, LLD triage-prioritization §15).

store    the runs received, the last ones kept
index    read model of one run: summary, decisions, one decision, one CVE, assets
server   the HTTP API (contract: ngvm/schemas/openapi/verdict.v1.yaml)
client   the daily run's push
cli      verdict serve, verdict push
"""
