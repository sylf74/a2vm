#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Values of the analysts' sign-in (OIDC) and of the review page of the alerts, written by the job
deploy-k8s (stdlib only, v0.17.0, docs/sign-in.md).

Reads the tenant project's variables from the environment and writes a values file (JSON, which
Helm reads as YAML). The issuer's host is resolved here, in the job, for the NetworkPolicies.

    A2VM_OIDC_ISSUER            issuer URL of the tenant's identity provider (e.g. Keycloak realm URL)
    A2VM_OIDC_CLIENT_ID         its client for A2VM; the secret is A2VM_OIDC_CLIENT_SECRET (masked)
    A2VM_OIDC_READERS           groups that use the chat and read the alerts (comma-separated)
    A2VM_OIDC_VALIDATORS        groups that also correct, validate and send the alerts
    A2VM_OIDC_ADMINS            optional: groups that administer the chat (else the local admin)
    A2VM_OIDC_PROVIDER_NAME     optional: label of the chat's sign-in button
    A2VM_OIDC_CA                optional, File: CA of the provider's certificate
    A2VM_OIDC_EGRESS            optional: `cidr:port,...` instead of resolving the issuer
    A2VM_OIDC_IN_CLUSTER        optional: true when the provider is reached through the cluster's ingress
    A2VM_ALERTS_HOST            host of the review page (with A2VM_RUN_MODE=kubernetes)
    A2VM_ALERTS_ALLOW           optional: the analysts' networks (CIDR, comma-separated)
    A2VM_ALERTS_TLS_SECRET      optional; ingress controller, class and issuer as the chat's
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chat_values import _list, egress_of  # noqa: E402 - beside this script

GROUP = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. "


def _groups(value: str) -> list[str]:
    out = [g.strip() for g in (value or "").split(",") if g.strip()]
    for g in out:
        if set(g) - set(GROUP):
            raise ValueError(f"group {g!r}: letters, digits, space, - _ . only")
    return out


def values(env: dict[str, str], run_mode: str) -> dict:
    issuer = env.get("A2VM_OIDC_ISSUER", "").rstrip("/")
    u = urlsplit(issuer)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("A2VM_OIDC_ISSUER: https://<host>/... expected")
    if not env.get("A2VM_OIDC_CLIENT_ID"):
        raise ValueError("A2VM_OIDC_CLIENT_ID is required with A2VM_OIDC_ISSUER")
    if not env.get("A2VM_OIDC_CLIENT_SECRET"):
        raise ValueError("A2VM_OIDC_CLIENT_SECRET (masked) is required with A2VM_OIDC_ISSUER")
    readers, validators = _groups(env.get("A2VM_OIDC_READERS", "")), _groups(env.get("A2VM_OIDC_VALIDATORS", ""))
    if not readers and not validators:
        raise ValueError("A2VM_OIDC_READERS or A2VM_OIDC_VALIDATORS: nobody could sign in")
    in_cluster = env.get("A2VM_OIDC_IN_CLUSTER", "").lower() == "true"
    oidc = {
        "issuerUrl": issuer,
        "clientId": env["A2VM_OIDC_CLIENT_ID"],
        "providerName": env.get("A2VM_OIDC_PROVIDER_NAME") or "SSO",
        "readers": readers,
        "validators": validators,
        "admins": _groups(env.get("A2VM_OIDC_ADMINS", "")),
        "ca": bool(env.get("A2VM_OIDC_CA")),
        "inCluster": in_cluster,
        "egress": []
        if in_cluster and not env.get("A2VM_OIDC_EGRESS")
        else egress_of([issuer], env.get("A2VM_OIDC_EGRESS", "")),
    }
    out: dict = {"oidc": oidc}
    host = env.get("A2VM_ALERTS_HOST", "")
    if host:
        if run_mode != "kubernetes":
            raise ValueError("A2VM_ALERTS_HOST needs A2VM_RUN_MODE: kubernetes (the watch service)")
        if not validators:
            raise ValueError("A2VM_ALERTS_HOST needs A2VM_OIDC_VALIDATORS: nobody could validate an alert")
        ingress = {
            "controller": env.get("A2VM_CHAT_INGRESS_CONTROLLER")
            or env.get("A2VM_INTAKE_INGRESS_CONTROLLER")
            or "nginx",
            "className": env.get("A2VM_CHAT_INGRESS_CLASS") or env.get("A2VM_INTAKE_INGRESS_CLASS") or "",
            "tlsSecret": env.get("A2VM_ALERTS_TLS_SECRET", ""),
            "clusterIssuer": env.get("A2VM_CHAT_CLUSTER_ISSUER") or env.get("A2VM_INTAKE_CLUSTER_ISSUER") or "",
            "allowFrom": _list(env.get("A2VM_ALERTS_ALLOW", "")),
        }
        for cidr in ingress["allowFrom"]:
            ipaddress.ip_network(cidr, strict=False)
        out["watch"] = {"review": {"enabled": True, "host": host, "ingress": ingress}}
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: sign_in_values.py RUN_MODE OUT.json", file=sys.stderr)
        return 2
    try:
        v = values(dict(os.environ), argv[0])
    except (ValueError, OSError) as exc:
        print(f"sign-in: {exc}", file=sys.stderr)
        return 1
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(v, f, indent=1)
    o = v["oidc"]
    where = ", ".join(f"{e['cidr']}:{e['port']}" for e in o["egress"]) or "the cluster's ingress"
    print(
        f"sign-in: {o['issuerUrl']} (client {o['clientId']}), readers {o['readers']}, validators "
        f"{o['validators']}, admins {o['admins'] or 'local admin'}, provider at {where}"
    )
    if "watch" in v:
        print(f"review page: https://{v['watch']['review']['host']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
