# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Detection service of pillar 2 and its clients (HLD D15 step 2, LLD vulnerability-detection §8).

registry   the collectors a tenant declares (collectors.yaml) and their token digests
store      the detections received, the latest per source kept
server     the HTTP API (contract: ngvm/schemas/openapi/detect.v1.yaml)
client     push (collectors) and fetch (daily run)
"""
