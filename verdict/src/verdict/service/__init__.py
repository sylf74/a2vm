# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Decision service of pillar 3, read side first (HLD D15 step 3, LLD triage-prioritization §15).

store    the runs received, the last ones kept
index    read model of one run: summary, decisions, one decision, one CVE, assets
server   the HTTP API (contract: a2vm/schemas/openapi/verdict.v1.yaml)
client   the daily run's push
cli      verdict serve, verdict push
"""
