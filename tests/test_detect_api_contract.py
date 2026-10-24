# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Design of the detection service (LLD detection §8): the OpenAPI contract is well formed, its
references resolve, and it states the rules of the design (tenant everywhere, token per
collector, idempotent push of vulnops.detection/1)."""

from __future__ import annotations

from pathlib import Path

import yaml

SCHEMAS = Path(__file__).resolve().parents[1] / "a2vm" / "src" / "a2vm" / "schemas"
SPEC = SCHEMAS / "openapi" / "detect.v1.yaml"


def _refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _refs(item)


def test_contract_is_openapi_31_and_every_reference_resolves():
    spec = yaml.safe_load(SPEC.read_text())
    assert spec["openapi"].startswith("3.1")
    for ref in _refs(spec):
        if ref.startswith("#/"):
            node = spec
            for part in ref[2:].split("/"):
                node = node[part]
        else:
            assert (SPEC.parent / ref).resolve().exists(), ref


def test_every_tenant_call_carries_the_tenant_and_is_authenticated():
    spec = yaml.safe_load(SPEC.read_text())
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if path.startswith("/v1/tenants/{tenant}"):
                assert {"$ref": "#/components/parameters/tenant"} in op["parameters"], (path, method)
                assert op["security"], (path, method)


def test_push_is_idempotent_by_collector_token_and_takes_the_detection_schema():
    spec = yaml.safe_load(SPEC.read_text())
    push = spec["paths"]["/v1/tenants/{tenant}/detections"]["post"]
    assert push["security"] == [{"collectorToken": []}]
    assert any(p.get("name") == "Idempotency-Key" and p["required"] for p in push["parameters"])
    body = push["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    detection = yaml.safe_load((SPEC.parent / body).read_text())
    assert detection["properties"]["schema"]["const"] == "vulnops.detection/1"
    assert {"202", "403", "413", "422"} <= set(push["responses"])
